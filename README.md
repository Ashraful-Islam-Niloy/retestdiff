# RetestDiff

**After a pentest, the client fixes things. RetestDiff shows exactly what changed.**

Give it the scan results from before and after (two or more runs, oldest first) and it tells you what is
**fixed**, **still open**, **new**, **changed** (e.g. a service version went from 2.4.49 to 2.4.58) and
**regressed** (fixed once, and back). It produces a terminal summary plus Markdown and a self-contained HTML report.

- No dependencies: Python 3.10+ standard library only. Kali, Linux, macOS and Windows.
- Reads **Nmap XML** (`-oX`), **Nuclei** JSON/JSONL, and a simple **CSV/JSON** format so output from any other
  scanner (Burp, ZAP, Nessus, a spreadsheet) can be compared too.
- Understands that *absence is not proof of a fix*: if a host was down during the retest, its findings are
  marked **unverified** instead of "fixed", and a down host in between never creates a false "regression".
- Warns when the Nmap runs asked for different ports.
- CI-friendly exit code: `1` if anything is new or regressed.

> **Prior art, honestly:** Nmap ships `ndiff` (and Zenmap's compare), which diff two Nmap scans. RetestDiff does the
> same job for more than two runs, adds Nuclei and generic findings, tracks regressions and unverified hosts, and
> writes client-ready reports.

## Quick start

```bash
unzip retestdiff.zip && cd retestdiff

# try it on made-up sample data (nothing is scanned)
python3 -m retestdiff demo

# your own results, oldest first
nmap -sV -oX before.xml 10.0.0.0/24
# ... client fixes things ...
nmap -sV -oX after.xml 10.0.0.0/24
python3 -m retestdiff compare before.xml after.xml --md report.md --html report.html

# Nuclei works the same way
nuclei -u https://app.example.com -jsonl -o before.jsonl
python3 -m retestdiff compare before.jsonl after.jsonl
```

Optional: `pip install .` gives a plain `retestdiff` command. On Windows use `py -m retestdiff ...`.

## Statuses

| Status | Meaning |
|---|---|
| **regressed** | was fixed (verifiably gone) and is back |
| **new** | not in any earlier run |
| **open** | present in the latest and the previous run, unchanged |
| **changed** | still there, but severity or detail (version) differs |
| **unverified** | seen before, absent now, but its host was not scanned in the latest run |
| **fixed** | seen before, gone in the latest run |

## Other formats

CSV (`id,title,severity,asset[,detail]`):

```csv
id,title,severity,asset
CVE-2024-1234,Outdated Jenkins,high,10.0.0.8
```

or JSON: `[{"id": "CVE-2024-1234", "title": "Outdated Jenkins", "severity": "high", "asset": "10.0.0.8"}]`.

## Options

`compare FILE FILE [FILE...] [--format nmap|nuclei|json|csv] [--md FILE] [--html FILE] [--fail-on new,regressed]`

Exit codes: `0` nothing in the `--fail-on` list, `1` something is, `2` usage or file error.

## Things you should know

- **"Fixed" means "not seen in the latest run".** It is only meaningful if the retest used the same scan options and
  targets. RetestDiff warns about differing Nmap port ranges, but it cannot know everything about how you scanned.
- Nmap findings are open ports, so they have severity `info`; they show how the attack surface changed, not
  vulnerabilities. Use Nuclei or your own findings for severity-ranked results.
- Nuclei results do not say which targets were scanned, so a missing finding is treated as fixed. Re-run with the
  same targets and templates.
- All text in HTML reports is escaped, so hostile scan output cannot inject script into your report.

## Development

```bash
python3 -m pytest tests        # 14 tests
```

MIT licensed, by Ashraful Islam Niloy.
