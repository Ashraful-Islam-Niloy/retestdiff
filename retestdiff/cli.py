"""retestdiff command line.

Exit codes: 0 nothing new or regressed   1 new or regressed findings (see --fail-on)   2 usage / file error
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .demo import write_demo
from .diff import STATUSES, Comparison, compare
from .models import Run
from .parsers import ParseError, load_run
from .report import COLOURS, LABELS, to_html, to_markdown
from .ui import style

_TERM_COLOUR = {"regressed": "red", "new": "yellow", "open": "yellow", "changed": "cyan", "unverified": "magenta", "fixed": "green"}


def _checks(runs: list[Run]) -> list[str]:
    warnings: list[str] = []
    kinds = {r.kind for r in runs}
    if len(kinds) > 1:
        raise ParseError(f"cannot compare different kinds of scan results ({', '.join(sorted(kinds))}); compare like with like")
    for r in runs:
        warnings += [f"{r.label}: {w}" for w in r.warnings]
    specs = {r.port_spec for r in runs if r.kind == "nmap"}
    if len(specs) > 1:
        warnings.append(
            "The Nmap runs asked for different ports (" + " vs ".join(sorted(specs)) + "). "
            "A port missing from a narrower retest is not proof it was fixed."
        )
    empty = [r.label for r in runs if not r.findings]
    if empty:
        warnings.append("No findings were read from: " + ", ".join(empty) + ". Check the file is the right export.")
    return warnings


def _print(comparison: Comparison, warnings: list[str]) -> None:
    print(style("Retest comparison", "bold"), "  " + " -> ".join(r.label for r in comparison.runs))
    for w in warnings:
        print(style(f"  warning: {w}", "yellow"))
    counts = comparison.counts()
    print("  " + "   ".join(style(f"{counts[s]} {LABELS[s][0].lower()}", _TERM_COLOUR[s]) for s in STATUSES) + "\n")
    for row in comparison.rows:
        extra = row.finding.detail if row.status != "changed" else f"{row.previous.detail or '-'} -> {row.finding.detail or '-'}" if row.previous and row.previous.detail != row.finding.detail else ""
        print(f"  {style(LABELS[row.status][0].upper().ljust(10), _TERM_COLOUR[row.status])} {row.finding.severity.ljust(8)} "
              f"{row.finding.asset.ljust(16)} {row.finding.title}  {style(extra, 'grey')}")
    print()


def _finish(runs: list[Run], args: argparse.Namespace) -> int:
    warnings = _checks(runs)
    comparison = compare(runs)
    _print(comparison, warnings)
    if args.md:
        Path(args.md).write_text(to_markdown(comparison, warnings), encoding="utf-8")
        print(f"Markdown report: {args.md}")
    if args.html:
        Path(args.html).write_text(to_html(comparison, warnings), encoding="utf-8")
        print(f"HTML report:     {args.html}")
    counts = comparison.counts()
    fail = {s.strip() for s in args.fail_on.split(",") if s.strip()}
    unknown = fail - set(STATUSES)
    if unknown:
        raise ParseError(f"unknown --fail-on status: {', '.join(sorted(unknown))} (choose from {', '.join(STATUSES)})")
    return 1 if any(counts[s] for s in fail) else 0


def cmd_compare(args: argparse.Namespace) -> int:
    if len(args.files) < 2:
        print("Give at least two result files, oldest first:  retestdiff compare before.xml after.xml")
        return 2
    runs = [load_run(f, args.format) for f in args.files]
    return _finish(runs, args)


def cmd_demo(args: argparse.Namespace) -> int:
    out = Path(args.out)
    paths = write_demo(out)
    print(f"Wrote {len(paths)} made-up scan files to {out}/ (nothing was scanned)\n")
    nmap = [load_run(p) for p in paths if p.name.endswith(".xml")]
    nuclei = [load_run(p) for p in paths if p.name.endswith(".jsonl")]
    args.md = args.html = None
    args.fail_on = ""
    print(style("== Nmap: initial -> retest (10.0.0.9 was down during the retest) ==", "bold"))
    _finish(nmap[:2], args)
    args.md, args.html = str(out / "demo-report.md"), str(out / "demo-report.html")
    print(style("== Nmap: initial -> retest -> final ==", "bold"))
    _finish(nmap, args)
    args.md = args.html = None
    print(style("== Nuclei: initial -> retest ==", "bold"))
    _finish(nuclei, args)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="retestdiff", description="Show what a retest fixed, what is still open, and what came back.")
    parser.add_argument("--version", action="version", version=f"retestdiff {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("compare", help="compare two or more result files (oldest first)")
    p.add_argument("files", nargs="*")
    p.add_argument("--format", choices=["nmap", "nuclei", "json", "csv"], help="force a format (default: auto-detect)")
    p.add_argument("--md", help="write a Markdown report")
    p.add_argument("--html", help="write a self-contained HTML report")
    p.add_argument("--fail-on", default="new,regressed", help="exit 1 if any of these statuses occur (default: new,regressed)")
    p.set_defaults(func=cmd_compare)
    p = sub.add_parser("demo", help="try it on made-up sample data")
    p.add_argument("--out", default="retestdiff-demo")
    p.set_defaults(func=cmd_demo)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except ParseError as exc:
        print(style(f"Error: {exc}", "red"))
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
