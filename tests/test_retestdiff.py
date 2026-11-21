import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from retestdiff.cli import main
from retestdiff.demo import write_demo
from retestdiff.diff import compare
from retestdiff.models import Finding, Run
from retestdiff.parsers import ParseError, detect_format, load_run, parse_generic_csv, parse_nmap_xml, parse_nuclei
from retestdiff.report import to_html, to_markdown

NMAP = b"""<?xml version="1.0"?><nmaprun args="nmap -sV -p 1-1000 -oX x.xml 10.0.0.0/24">
<host><status state="up"/><address addr="10.0.0.5" addrtype="ipv4"/><hostnames><hostname name="web"/></hostnames><ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="7.4"/></port>
<port protocol="tcp" portid="23"><state state="closed"/><service name="telnet"/></port>
<port protocol="udp" portid="53"><state state="open|filtered"/></port>
<port protocol="tcp" portid="80"><state state="open"/></port></ports></host>
<host><status state="down"/><address addr="10.0.0.6" addrtype="ipv4"/></host></nmaprun>"""


def finding(key, asset="10.0.0.5", sev="info", detail="", title=None):
    return Finding(key, "nmap", asset, title or key, sev, detail)


def run(label, findings, covered=None):
    return Run(label, {f.key: f for f in findings}, covered)


class ParserTests(unittest.TestCase):
    def test_nmap_open_ports_only(self):
        r = parse_nmap_xml(NMAP, "a")
        self.assertEqual(sorted(r.findings), ["nmap:10.0.0.5:22/tcp", "nmap:10.0.0.5:80/tcp"])
        self.assertEqual(r.findings["nmap:10.0.0.5:22/tcp"].detail, "OpenSSH 7.4")
        self.assertEqual(r.covered, {"10.0.0.5"})  # the down host is not "covered"
        self.assertEqual(r.port_spec, "-p1-1000")

    def test_nmap_rejects_bad_input(self):
        for bad in (b"<nmaprun><host>", b"<html></html>", b'<!DOCTYPE x [<!ENTITY a "b">]><nmaprun/>'):
            with self.assertRaises(ParseError):
                parse_nmap_xml(bad, "x")

    def test_nuclei_jsonl_and_array(self):
        line = {"template-id": "cve-1", "info": {"name": "Bad", "severity": "HIGH"}, "host": "h", "matched-at": "http://h/x"}
        r = parse_nuclei((json.dumps(line) + "\n\nnot json\n" + json.dumps({"other": 1}) + "\n").encode(), "n")
        self.assertEqual(len(r.findings), 1)
        self.assertEqual(next(iter(r.findings.values())).severity, "high")
        self.assertEqual(len(r.warnings), 2)
        self.assertEqual(len(parse_nuclei(json.dumps([line]).encode(), "n").findings), 1)

    def test_generic_csv_and_json(self):
        r = parse_generic_csv(b"ID,Title,Severity,Asset\nX1,Weak TLS,Moderate,10.0.0.1\n,,,\n", "c")
        f = next(iter(r.findings.values()))
        self.assertEqual((f.title, f.severity, f.asset), ("Weak TLS", "medium", "10.0.0.1"))
        with self.assertRaises(ParseError):
            parse_generic_csv(b"a,b\n1,2\n", "c")

    def test_detection_and_loading(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "s.xml").write_bytes(NMAP)
            (Path(d) / "e.json").write_text("")
            self.assertEqual(load_run(Path(d) / "s.xml").kind, "nmap")
            with self.assertRaises(ParseError):
                load_run(Path(d) / "e.json")
            with self.assertRaises(ParseError):
                load_run(Path(d) / "missing.xml")
        self.assertEqual(detect_format(Path("a.jsonl"), b'{"template-id":"x"}'), "nuclei")
        self.assertEqual(detect_format(Path("a.json"), b'[{"id":1}]'), "json")


class DiffTests(unittest.TestCase):
    def status(self, c, key):
        return next(r.status for r in c.rows if r.finding.key == key)

    def test_basic_statuses(self):
        a = run("a", [finding("fixedone"), finding("stays"), finding("ver", detail="1.0")], covered={"10.0.0.5"})
        b = run("b", [finding("stays"), finding("ver", detail="2.0"), finding("brandnew")], covered={"10.0.0.5"})
        c = compare([a, b])
        self.assertEqual(self.status(c, "fixedone"), "fixed")
        self.assertEqual(self.status(c, "stays"), "open")
        self.assertEqual(self.status(c, "ver"), "changed")
        self.assertEqual(self.status(c, "brandnew"), "new")

    def test_host_down_is_unverified_not_fixed(self):
        a = run("a", [finding("x")], covered={"10.0.0.5"})
        b = run("b", [], covered={"10.0.0.99"})
        self.assertEqual(self.status(compare([a, b]), "x"), "unverified")

    def test_regression_and_host_down_gap_is_not_a_regression(self):
        f = finding("x")
        fixed_then_back = compare([run("1", [f], {"10.0.0.5"}), run("2", [], {"10.0.0.5"}), run("3", [f], {"10.0.0.5"})])
        self.assertEqual(self.status(fixed_then_back, "x"), "regressed")
        host_was_down = compare([run("1", [f], {"10.0.0.5"}), run("2", [], set()), run("3", [f], {"10.0.0.5"})])
        self.assertEqual(self.status(host_was_down, "x"), "open")

    def test_unknown_coverage_means_absent_is_fixed(self):
        self.assertEqual(self.status(compare([run("a", [finding("x")]), run("b", [])]), "x"), "fixed")

    def test_needs_two_runs_and_sorting(self):
        with self.assertRaises(ValueError):
            compare([run("a", [])])
        c = compare([run("a", []), run("b", [finding("lo", sev="low"), finding("hi", sev="critical")])])
        self.assertEqual([r.finding.key for r in c.rows], ["hi", "lo"])


class ReportAndCliTests(unittest.TestCase):
    def test_html_escapes_untrusted_text(self):
        evil = Finding("k", "generic", "<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "high")
        c = compare([run("a", []), run("<b>b</b>", [evil])])
        out = to_html(c, ["<warn>"])
        self.assertNotIn("<script>alert", out)
        self.assertNotIn("<img src=x", out)
        self.assertIn("&lt;script&gt;", out)
        self.assertIn("|", to_markdown(c, []))

    def run_cli(self, *argv):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = main(list(argv))
        return code, buf.getvalue()

    def test_cli_exit_codes_and_reports(self):
        with tempfile.TemporaryDirectory() as d:
            files = write_demo(Path(d))
            nm = [str(f) for f in files if f.suffix == ".xml"]
            nu = [str(f) for f in files if f.suffix == ".jsonl"]
            code, out = self.run_cli("compare", *nu, "--md", f"{d}/r.md", "--html", f"{d}/r.html")
            self.assertEqual(code, 1)  # a NEW finding appeared
            self.assertTrue(Path(d, "r.md").read_text().startswith("# Retest comparison"))
            self.assertEqual(self.run_cli("compare", *nu, "--fail-on", "regressed")[0], 0)
            self.assertEqual(self.run_cli("compare", *nu, "--fail-on", "bogus")[0], 2)
            self.assertEqual(self.run_cli("compare", nu[0])[0], 2)
            code, out = self.run_cli("compare", nm[0], nu[0])
            self.assertEqual(code, 2)
            self.assertIn("different kinds", out)

    def test_port_range_warning(self):
        with tempfile.TemporaryDirectory() as d:
            a, b = Path(d, "a.xml"), Path(d, "b.xml")
            a.write_bytes(NMAP)
            b.write_bytes(NMAP.replace(b"-p 1-1000", b"-F"))
            code, out = self.run_cli("compare", str(a), str(b))
            self.assertIn("different ports", out)

    def test_demo_runs(self):
        with tempfile.TemporaryDirectory() as d:
            code, out = self.run_cli("demo", "--out", d)
            self.assertEqual(code, 0)
            self.assertIn("UNVERIFIED", out)
            self.assertTrue(Path(d, "demo-report.html").exists())


if __name__ == "__main__":
    unittest.main()
