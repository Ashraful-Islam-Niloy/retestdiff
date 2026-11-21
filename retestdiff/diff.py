"""Compares two or more runs (oldest first) and classifies every finding.

new         only in the latest run
open        in the latest run and the one before it (unchanged)
changed     still there, but severity or detail (e.g. service version) differs
fixed       seen before, absent from the latest run
regressed   was there, then verifiably gone, and is back
unverified  seen before, but its host was NOT scanned successfully in the latest
            run, so "fixed" cannot be claimed

A run in which the finding's host was not scanned (an Nmap host that was down)
is treated as "unknown", not as "fixed": it cannot cause a false regression.
"""
from __future__ import annotations

from dataclasses import dataclass

from .models import SEVERITY_ORDER, Finding, Run

STATUSES = ["regressed", "new", "open", "changed", "unverified", "fixed"]


@dataclass
class Row:
    status: str
    finding: Finding  # latest version of the finding
    previous: Finding | None  # version in the previous run, if any
    seen_in: list[bool | None]  # per run, oldest first: present / absent / None = host not scanned


@dataclass
class Comparison:
    runs: list[Run]
    rows: list[Row]

    def counts(self) -> dict[str, int]:
        out = {s: 0 for s in STATUSES}
        for r in self.rows:
            out[r.status] += 1
        return out

    def by_status(self, status: str) -> list[Row]:
        return [r for r in self.rows if r.status == status]


def _sort_key(row: Row) -> tuple[int, str, str]:
    sev = SEVERITY_ORDER.index(row.finding.severity) if row.finding.severity in SEVERITY_ORDER else len(SEVERITY_ORDER)
    return sev, row.finding.asset, row.finding.title


def _state(run: Run, finding: Finding | None, asset: str) -> bool | None:
    """True = present, False = verifiably absent, None = unknown (host not scanned in this run)."""
    if finding is not None:
        return True
    if run.covered is not None and asset not in run.covered:
        return None
    return False


def compare(runs: list[Run]) -> Comparison:
    if len(runs) < 2:
        raise ValueError("need at least two runs to compare")
    keys: dict[str, None] = {}
    for run in runs:
        for key in run.findings:
            keys.setdefault(key)

    rows: list[Row] = []
    for key in keys:
        versions = [run.findings.get(key) for run in runs]
        latest = next(v for v in reversed(versions) if v is not None)
        states = [_state(run, v, latest.asset) for run, v in zip(runs, versions)]
        earlier = [(st, v) for st, v in zip(states[:-1], versions[:-1]) if st is not None]  # unknown runs prove nothing
        was_present = any(st for st, _ in earlier)
        prev = next((v for st, v in reversed(earlier) if st), None)
        last = states[-1]
        if last:
            if not was_present:
                status = "new"
            elif earlier[-1][0]:
                status = "changed" if (prev.severity, prev.detail) != (latest.severity, latest.detail) else "open"
            else:
                status = "regressed"
        elif last is None:
            status = "unverified"
        else:
            status = "fixed"
        rows.append(Row(status, latest, prev, states))
    rows.sort(key=lambda r: (STATUSES.index(r.status), *_sort_key(r)))
    return Comparison(runs, rows)
