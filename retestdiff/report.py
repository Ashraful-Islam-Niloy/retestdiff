"""Markdown and HTML reports, plus the terminal summary."""
from __future__ import annotations

import datetime as _dt
import html

from .diff import STATUSES, Comparison

LABELS = {
    "regressed": ("Regressed", "was fixed, and is back"),
    "new": ("New", "appeared since the first run"),
    "open": ("Still open", "unchanged since the previous run"),
    "changed": ("Changed", "still present, but severity or version differs"),
    "unverified": ("Unverified", "absent now, but the host was not scanned successfully, so it is NOT confirmed fixed"),
    "fixed": ("Fixed", "was reported before, gone in the latest run"),
}
COLOURS = {"regressed": "#f85149", "new": "#ff8c42", "open": "#e3b341", "changed": "#58a6ff", "unverified": "#bc8cff", "fixed": "#3fb950"}
CAVEAT = (
    "\"Fixed\" means *not seen in the latest run*. It is only meaningful if the retest used the same scan options "
    "and the same targets as the earlier run."
)


def _change_text(row) -> str:  # noqa: ANN001
    if row.status == "changed" and row.previous:
        parts = []
        if row.previous.severity != row.finding.severity:
            parts.append(f"severity {row.previous.severity} -> {row.finding.severity}")
        if row.previous.detail != row.finding.detail:
            parts.append(f"{row.previous.detail or '-'} -> {row.finding.detail or '-'}")
        return "; ".join(parts)
    return row.finding.detail


def _timeline(row, comparison: Comparison) -> str:  # noqa: ANN001
    return " ".join("?" if seen is None else "●" if seen else "○" for seen in row.seen_in)


def to_markdown(comparison: Comparison, warnings: list[str]) -> str:
    counts = comparison.counts()
    lines = [
        "# Retest comparison", "",
        f"- **Generated:** {_dt.datetime.now().isoformat(timespec='seconds')}",
        f"- **Runs (oldest to newest):** {' -> '.join(r.label for r in comparison.runs)}",
        "- **Summary:** " + ", ".join(f"{counts[s]} {LABELS[s][0].lower()}" for s in STATUSES), "",
    ]
    for w in warnings:
        lines.append(f"> ⚠️ {w}")
    if warnings:
        lines.append("")
    for status in STATUSES:
        rows = comparison.by_status(status)
        if not rows:
            continue
        title, meaning = LABELS[status]
        lines += [f"## {title} ({len(rows)})", f"_{meaning}_", "", "| Severity | Asset | Finding | Detail | Runs |", "|---|---|---|---|---|"]
        for r in rows:
            cells = [r.finding.severity, r.finding.asset, r.finding.title, _change_text(r), _timeline(r, comparison)]
            lines.append("| " + " | ".join(c.replace("|", "\\|") for c in cells) + " |")
        lines.append("")
    lines += ["---", f"_{CAVEAT}_", "_Runs column: ● seen, ○ not seen, ? host not scanned; one symbol per run._", ""]
    return "\n".join(lines)


def to_html(comparison: Comparison, warnings: list[str]) -> str:
    esc = html.escape
    counts = comparison.counts()
    chips = "".join(
        f'<div class="chip" style="--c:{COLOURS[s]}"><b>{counts[s]}</b><span>{esc(LABELS[s][0])}</span></div>' for s in STATUSES
    )
    sections = []
    for status in STATUSES:
        rows = comparison.by_status(status)
        if not rows:
            continue
        title, meaning = LABELS[status]
        body = "".join(
            f'<tr><td><span class="sev {esc(r.finding.severity)}">{esc(r.finding.severity)}</span></td>'
            f"<td>{esc(r.finding.asset)}</td><td>{esc(r.finding.title)}</td><td>{esc(_change_text(r))}</td>"
            f'<td class="tl">{esc(_timeline(r, comparison))}</td></tr>'
            for r in rows
        )
        sections.append(
            f'<section style="--c:{COLOURS[status]}"><h2>{esc(title)} <small>{len(rows)}</small></h2><p class="m">{esc(meaning)}</p>'
            f"<table><tr><th>Severity</th><th>Asset</th><th>Finding</th><th>Detail</th><th>Runs</th></tr>{body}</table></section>"
        )
    warn = "".join(f'<div class="warn">⚠️ {esc(w)}</div>' for w in warnings)
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Retest comparison</title><style>
:root{{--bg:#0d1117;--card:#161b22;--line:#30363d;--ink:#e6edf3;--dim:#8b949e}}
@media (prefers-color-scheme:light){{:root{{--bg:#f6f8fa;--card:#fff;--line:#d0d7de;--ink:#1f2328;--dim:#59636e}}}}
*{{box-sizing:border-box}}body{{margin:0;padding:32px 16px;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,Segoe UI,sans-serif}}
main{{max-width:1000px;margin:auto}}h1{{margin:0 0 4px}}.sub{{color:var(--dim);margin:0 0 20px;word-break:break-word}}
.chips{{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:10px;margin-bottom:24px}}
.chip{{background:var(--card);border:1px solid var(--line);border-top:3px solid var(--c);border-radius:10px;padding:12px}}
.chip b{{font-size:26px;display:block}}.chip span{{color:var(--dim);font-size:13px}}
section{{background:var(--card);border:1px solid var(--line);border-left:4px solid var(--c);border-radius:10px;padding:16px;margin-bottom:16px;overflow-x:auto}}
h2{{margin:0}}h2 small{{color:var(--dim);font-weight:400}}.m{{color:var(--dim);margin:2px 0 10px}}
table{{width:100%;border-collapse:collapse;font-size:14px}}th,td{{text-align:left;padding:6px 8px;border-top:1px solid var(--line);vertical-align:top}}
th{{color:var(--dim);font-weight:600;border-top:0}}.tl{{letter-spacing:3px;white-space:nowrap}}
.sev{{padding:1px 8px;border-radius:99px;font-size:12px;border:1px solid var(--line)}}
.sev.critical{{color:#f85149;border-color:#f85149}}.sev.high{{color:#ff8c42;border-color:#ff8c42}}.sev.medium{{color:#d4a72c;border-color:#d4a72c}}.sev.low{{color:#58a6ff;border-color:#58a6ff}}
.warn{{background:#bc8cff22;border:1px solid #bc8cff;border-radius:8px;padding:8px 12px;margin-bottom:10px}}
.foot{{color:var(--dim);font-size:13px;margin-top:20px}}
</style></head><body><main><h1>Retest comparison</h1>
<p class="sub">{esc(' → '.join(r.label for r in comparison.runs))} · generated {esc(_dt.datetime.now().isoformat(timespec='seconds'))}</p>
<div class="chips">{chips}</div>{warn}{''.join(sections) or '<p>No findings in any run.</p>'}
<p class="foot">{esc(CAVEAT.replace('*', ''))} Runs column: ● seen, ○ not seen, ? host not scanned; one symbol per run, oldest first.</p></main></body></html>"""
