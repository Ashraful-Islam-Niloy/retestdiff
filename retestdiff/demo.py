"""Writes three made-up scan rounds so the tool can be tried without scanning anything."""
from __future__ import annotations

from pathlib import Path


def _nmap(args: str, hosts: list[tuple[str, str, list[tuple[int, str, str]]]]) -> str:
    body = ""
    for ip, state, ports in hosts:
        port_xml = "".join(
            f'<port protocol="tcp" portid="{n}"><state state="open"/><service name="{svc}" product="{prod.split(" ")[0]}" version="{" ".join(prod.split(" ")[1:])}"/></port>'
            for n, svc, prod in ports
        )
        body += f'<host><status state="{state}"/><address addr="{ip}" addrtype="ipv4"/><ports>{port_xml}</ports></host>'
    return f'<?xml version="1.0"?><nmaprun scanner="nmap" args="{args}">{body}</nmaprun>'


def _nuclei(items: list[tuple[str, str, str, str]]) -> str:
    import json
    return "\n".join(
        json.dumps({"template-id": t, "info": {"name": n, "severity": s}, "host": h.split("/")[2], "matched-at": h})
        for t, n, s, h in items
    ) + "\n"


def write_demo(out: Path) -> list[Path]:
    out.mkdir(parents=True, exist_ok=True)
    args = "nmap -sV -oX scan.xml 10.0.0.0/24"
    web = "http://10.0.0.5"
    files = {
        "1-initial-nmap.xml": _nmap(args, [
            ("10.0.0.5", "up", [(22, "ssh", "OpenSSH 7.4"), (80, "http", "Apache 2.4.49"), (3306, "mysql", "MySQL 5.7.30")]),
            ("10.0.0.9", "up", [(443, "https", "nginx 1.18.0")]),
        ]),
        "2-retest-nmap.xml": _nmap(args, [
            ("10.0.0.5", "up", [(22, "ssh", "OpenSSH 9.6"), (80, "http", "Apache 2.4.58"), (8080, "http-proxy", "Jetty 9.4")]),
            ("10.0.0.9", "down", []),
        ]),
        "3-final-nmap.xml": _nmap(args, [
            ("10.0.0.5", "up", [(22, "ssh", "OpenSSH 9.6"), (80, "http", "Apache 2.4.58"), (3306, "mysql", "MySQL 8.0.36")]),
            ("10.0.0.9", "up", [(443, "https", "nginx 1.24.0")]),
        ]),
        "1-initial-nuclei.jsonl": _nuclei([
            ("CVE-2021-41773", "Apache 2.4.49 path traversal", "critical", f"{web}/cgi-bin/"),
            ("exposed-admin-panel", "Exposed admin panel", "medium", f"{web}/admin"),
            ("missing-x-frame-options", "Missing X-Frame-Options", "low", f"{web}/"),
        ]),
        "2-retest-nuclei.jsonl": _nuclei([
            ("exposed-admin-panel", "Exposed admin panel", "medium", f"{web}/admin"),
            ("missing-x-frame-options", "Missing X-Frame-Options", "low", f"{web}/"),
            ("git-config-exposure", "Exposed .git/config", "high", f"{web}/.git/config"),
        ]),
    }
    paths = []
    for name, text in files.items():
        path = out / name
        path.write_text(text, encoding="utf-8")
        paths.append(path)
    return paths
