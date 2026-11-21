from __future__ import annotations

from dataclasses import dataclass, field

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def normalize_severity(value: object) -> str:
    text = str(value or "info").strip().lower()
    aliases = {"informational": "info", "information": "info", "moderate": "medium", "severe": "critical", "unknown": "info"}
    text = aliases.get(text, text)
    return text if text in SEVERITY_ORDER else "info"


@dataclass(frozen=True)
class Finding:
    key: str  # stable identity across runs, e.g. "nmap:10.0.0.5:80/tcp"
    source: str  # nmap | nuclei | generic
    asset: str  # host or URL the finding belongs to
    title: str
    severity: str = "info"
    detail: str = ""  # e.g. product/version; a change here shows up as "changed"


@dataclass
class Run:
    label: str
    findings: dict[str, Finding] = field(default_factory=dict)
    # Assets this run demonstrably scanned (hosts that were up in an Nmap scan).
    # None means the format cannot tell us, so absence is taken as "fixed".
    covered: set[str] | None = None
    warnings: list[str] = field(default_factory=list)
    kind: str = ""  # nmap | nuclei | generic
    port_spec: str = ""  # nmap only: which ports the scan asked for
