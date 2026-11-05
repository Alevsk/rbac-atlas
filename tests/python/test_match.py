"""Unit tests for vulnscan.match (compact per-digest match documents)."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

from vulnscan import match, report
from vulnscan.common import read_json, write_json
from vulnscan.scan import summarize_report

TRIVY_REPORT = json.loads((Path(__file__).parent / "fixtures" / "scan" / "trivy_ingress_nginx.json").read_text())


def finding(vid: str, severity: str = "HIGH", fixed: str | None = None, pkg: str = "p", installed: str = "1",
            status: str | None = None, cvss: Any = None, cwes: list[str] | None = None,
            vendor_ids: list[str] | None = None) -> dict[str, Any]:
    return {"id": vid, "severity": severity, "fixed": fixed, "pkg": pkg, "installed": installed,
            "status": status or ("fixed" if fixed else "affected"),
            "cvss": {"score": cvss} if cvss is not None else None, "cwes": cwes or [], "vendor_ids": vendor_ids or []}


def roundtrip(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return match.expand(json.loads(json.dumps(match.compact({"findings": findings}, "t"))))


class CompactTest(unittest.TestCase):
    def test_grouping_equivalent_on_real_trivy_report(self) -> None:
        findings = summarize_report(TRIVY_REPORT)["findings"]
        entries = {"CVE-2024-24790": {"found": True, "kev": {"date_added": "x"}, "aliases": ["GHSA-AAAA-BBBB-CCCC"]}}
        self.assertEqual(report.group_findings(roundtrip(findings), entries), report.group_findings(findings, entries))
        rows = match.compact({"findings": findings}, "t")["vulns"]
        self.assertEqual(len(rows), len({f["id"] for f in findings}))  # one row per unique ID

    def test_row_merges_findings_of_one_id(self) -> None:
        rows = match.compact({"findings": [
            finding("CVE-1-1", "LOW", pkg="a", cvss=3.0, cwes=["CWE-2"], vendor_ids=["DSA-1", "GHSA-AbCd-1234-efgh"]),
            finding("CVE-1-1", "HIGH", pkg="b", cvss=None, cwes=["CWE-1"], status="will_not_fix"),
            finding("CVE-1-1", "HIGH", fixed="2", pkg="c", cvss=7, vendor_ids=["GO-2024-1"]),
            finding("CVE-1-1", "MEDIUM", fixed="9", pkg="0", status="fixed"),
        ]}, "t")["vulns"]
        # worst severity, any 'fixed' status, max score, union of cwes / CVE-GHSA-GO vendor IDs, and the
        # representative finding (most severe, fixable first, then package) for fixed/pkg/installed
        self.assertEqual(rows, [["CVE-1-1", "HIGH", True, 7, "2", "c", "1", ["CWE-1", "CWE-2"],
                                 ["GHSA-AbCd-1234-efgh", "GO-2024-1"]]])

    def test_representative_ties_across_ids_follow_finding_order(self) -> None:
        # Same rank in two IDs merged by a vendor ID: the lower ID's finding wins, as with raw findings.
        findings = [finding("CVE-2024-2", "HIGH", fixed="2.0", pkg="x"),
                    finding("CVE-2024-1", "HIGH", fixed="1.0", pkg="x", vendor_ids=["CVE-2024-2"]),
                    finding("CVE-2024-3", "HIGH", pkg="a")]
        findings.sort(key=lambda f: (f["severity"], f["id"]))  # summarize_report order
        self.assertEqual(report.group_findings(roundtrip(findings), {}), report.group_findings(findings, {}))
        self.assertEqual(report.group_findings(roundtrip(findings), {})[0]["fixed"], "1.0")

    def test_vuln_ids(self) -> None:
        doc = match.compact({"findings": [finding("DSA-1-1", "CRITICAL", vendor_ids=["CVE-2024-2"]),
                                          finding("GHSA-ABCD-1234-EFGH", "LOW"), finding("CVE-2024-2", "LOW"),
                                          finding("TEMP-1", "HIGH")]}, "t")
        self.assertEqual(match.vuln_ids(doc), {"CVE-2024-2": 0, "GHSA-abcd-1234-efgh": 3})


class FormatVersionTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_current_format_roundtrip(self) -> None:
        doc = match.compact(summarize_report(TRIVY_REPORT), "2026-11-04T00:00:00Z")
        match.store(self.dir, "sha256:" + "a" * 64, doc)
        self.assertTrue((self.dir / f"{'a' * 64}.json.gz").is_file())
        self.assertEqual(match.load(self.dir, "sha256:" + "a" * 64), json.loads(json.dumps(doc)))

    def test_format1_is_rederived(self) -> None:
        result = summarize_report(TRIVY_REPORT)
        write_json(match.path(self.dir, "sha256:" + "b" * 64), {"matched_at": "m", "result": result})
        self.assertEqual(match.load(self.dir, "sha256:" + "b" * 64), match.compact(result, "m"))
        self.assertEqual(read_json(match.path(self.dir, "sha256:" + "b" * 64))["result"], result)  # load is read-only

    def test_unknown_or_broken_documents_are_missing(self) -> None:
        for data in ({"format_version": 3, "matched_at": "m", "vulns": []},
                     {"format_version": 2, "matched_at": "m"},
                     {"format_version": 2, "vulns": []},
                     {"matched_at": "m", "result": {"error": "rematch_failed"}},
                     ["not", "a", "dict"]):
            self.assertIsNone(match.migrate(data), data)
        self.assertIsNone(match.load(self.dir, "sha256:" + "c" * 64))

    def test_truncated_or_corrupt_gzip_is_missing(self) -> None:
        digest = "sha256:" + "d" * 64
        match.store(self.dir, digest, match.compact(summarize_report(TRIVY_REPORT), "m"))
        p = match.path(self.dir, digest)
        raw = p.read_bytes()
        p.write_bytes(raw[: len(raw) // 2])  # EOFError inside gzip
        self.assertIsNone(match.load(self.dir, digest))
        p.write_bytes(raw[:10] + bytes([raw[10] ^ 0xFF]) + raw[11:])  # zlib.error: invalid deflate block
        self.assertIsNone(match.load(self.dir, digest))
        p.write_bytes(b"not gzip at all")  # gzip.BadGzipFile (OSError)
        self.assertIsNone(match.load(self.dir, digest))

    def test_scan_format_error(self) -> None:
        self.assertIsNone(match.scan_format_error({}, "s.json"))
        self.assertIsNone(match.scan_format_error({"format_version": match.FORMAT_VERSION, "images": {}}, "s.json"))
        err = match.scan_format_error({"images": {"x:1": {"status": "ok", "findings": []}}}, "s.json")
        self.assertIn("s.json", err)
        self.assertIn("scan-images", err)


if __name__ == "__main__":
    unittest.main()
