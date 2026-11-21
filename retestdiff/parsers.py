"""Readers for Nmap XML, Nuclei JSON/JSONL and a generic CSV/JSON format.

Anything a scanner can export can be converted to the generic format:
    CSV columns: id,title,severity,asset[,detail]
    JSON: [{"id": "...", "title": "...", "severity": "high", "asset": "10.0.0.5"}]
"""
from __future__ import annotations

import csv
import io
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path

from .models import Finding, Run, normalize_severity


class ParseError(ValueError):
    pass


def _read_bytes(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except OSError as exc:
        raise ParseError(f"cannot read {path}: {exc}") from None


_PORT_FLAGS = re.compile(r"(?:^|\s)(-p-|-p\s*\S+|--top-ports[ =]\d+|-F)(?=\s|$)")


def _port_spec(args: str) -> str:
    """Which ports the scan asked for, so a retest with a narrower scan can be flagged."""
    return " ".join(m.group(1).replace("-p ", "-p") for m in _PORT_FLAGS.finditer(args or "")) or "default"


def parse_nmap_xml(data: bytes, label: str) -> Run:
    if b"<!ENTITY" in data:  # stdlib XML would expand these; scanner output never needs them
        raise ParseError("refusing XML with entity declarations")
    try:
        root = ET.fromstring(data)
    except ET.ParseError as exc:
        raise ParseError(f"not valid XML ({exc}). Was the Nmap scan interrupted?") from None
    if root.tag != "nmaprun":
        raise ParseError("not an Nmap XML file (expected <nmaprun>); create one with: nmap -oX scan.xml ...")
    run = Run(label=label, covered=set(), kind="nmap", port_spec=_port_spec(root.get("args", "")))
    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue
        ip = next((a.get("addr") for a in host.findall("address") if a.get("addrtype") in ("ipv4", "ipv6")), None)
        if not ip:
            continue
        run.covered.add(ip)
        for port in host.findall("./ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            number, proto = port.get("portid", "?"), port.get("protocol", "tcp")
            service = port.find("service")
            name = (service.get("name") if service is not None else None) or "unknown"
            version = " ".join(filter(None, (
                service.get("product") if service is not None else None,
                service.get("version") if service is not None else None,
            )))
            key = f"nmap:{ip}:{number}/{proto}"
            run.findings[key] = Finding(key, "nmap", ip, f"Open port {number}/{proto} ({name})", "info", version)
    return run


def _nuclei_item(obj: dict, run: Run, where: str) -> None:
    if not isinstance(obj, dict) or "template-id" not in obj:
        run.warnings.append(f"{where}: not a Nuclei result, skipped")
        return
    info = obj.get("info") or {}
    matched = obj.get("matched-at") or obj.get("host") or ""
    key = f"nuclei:{obj['template-id']}:{matched}"
    run.findings[key] = Finding(
        key, "nuclei", str(obj.get("host") or matched), str(info.get("name") or obj["template-id"]),
        normalize_severity(info.get("severity")), str(matched),
    )


def parse_nuclei(data: bytes, label: str) -> Run:
    text = data.decode("utf-8-sig", errors="replace").strip()
    run = Run(label=label, kind="nuclei")
    if text.startswith("["):
        try:
            items = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ParseError(f"invalid JSON: {exc}") from None
        for n, obj in enumerate(items, 1):
            _nuclei_item(obj, run, f"entry {n}")
        return run
    for n, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            _nuclei_item(json.loads(line), run, f"line {n}")
        except json.JSONDecodeError:
            run.warnings.append(f"line {n}: not valid JSON, skipped")
    return run


def _generic_item(row: dict, run: Run, where: str) -> None:
    row = {str(k).strip().lower(): v for k, v in row.items()}
    ident, title = str(row.get("id") or row.get("title") or "").strip(), str(row.get("title") or row.get("id") or "").strip()
    if not ident:
        run.warnings.append(f"{where}: no id or title, skipped")
        return
    asset = str(row.get("asset") or row.get("host") or "").strip()
    key = f"generic:{ident}:{asset}"
    run.findings[key] = Finding(key, "generic", asset, title, normalize_severity(row.get("severity")), str(row.get("detail") or "").strip())


def parse_generic_json(data: bytes, label: str) -> Run:
    try:
        obj = json.loads(data.decode("utf-8-sig", errors="replace"))
    except json.JSONDecodeError as exc:
        raise ParseError(f"invalid JSON: {exc}") from None
    items = obj.get("findings") if isinstance(obj, dict) else obj
    if not isinstance(items, list):
        raise ParseError('expected a JSON list of findings, or {"findings": [...]}')
    run = Run(label=label, kind="generic")
    for n, row in enumerate(items, 1):
        if isinstance(row, dict):
            _generic_item(row, run, f"entry {n}")
        else:
            run.warnings.append(f"entry {n}: not an object, skipped")
    return run


def parse_generic_csv(data: bytes, label: str) -> Run:
    reader = csv.DictReader(io.StringIO(data.decode("utf-8-sig", errors="replace")))
    names = {(f or "").strip().lower() for f in (reader.fieldnames or [])}
    if not names & {"id", "title"}:
        raise ParseError("CSV needs a header row with at least an id or title column (id,title,severity,asset)")
    run = Run(label=label, kind="generic")
    for n, row in enumerate(reader, 2):
        _generic_item(row, run, f"row {n}")
    return run


def detect_format(path: Path, data: bytes) -> str:
    head = data[:4096].lstrip(b"\xef\xbb\xbf").lstrip()
    if head.startswith(b"<"):
        return "nmap"
    suffix = path.suffix.lower()
    if suffix == ".csv":
        return "csv"
    if b"template-id" in data[:200_000]:
        return "nuclei"
    if suffix in (".json", ".jsonl") or head[:1] in (b"[", b"{"):
        return "json"
    return "csv"


def load_run(path: str | Path, fmt: str | None = None) -> Run:
    p = Path(path)
    data = _read_bytes(p)
    if not data.strip():
        raise ParseError(f"{p} is empty")
    fmt = fmt or detect_format(p, data)
    parsers = {"nmap": parse_nmap_xml, "nuclei": parse_nuclei, "json": parse_generic_json, "csv": parse_generic_csv}
    if fmt not in parsers:
        raise ParseError(f"unknown format {fmt!r} (use nmap, nuclei, json or csv)")
    try:
        return parsers[fmt](data, p.name)
    except ParseError as exc:
        raise ParseError(f"{p.name}: {exc}") from None
