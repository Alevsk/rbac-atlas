"""Unit tests for vulnscan.report (no network, synthetic inputs)."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

from vulnscan import report

FIXTURES = Path(__file__).parent / "fixtures" / "report"


def finding(vid: str, severity: str = "HIGH", status: str = "affected", vendor_ids: list[str] | None = None,
            cvss: float | None = None, cwes: list[str] | None = None, pkg: str = "pkg") -> dict[str, Any]:
    return {
        "id": vid, "pkg": pkg, "pkg_type": "debian", "class": "os-pkgs", "installed": "1",
        "fixed": "2" if status == "fixed" else None, "status": status, "severity": severity,
        "severity_source": "nvd", "cvss": {"score": cvss, "vector": None, "version": "3.1", "source": "nvd"} if cvss else None,
        "cwes": cwes or [], "vendor_ids": vendor_ids or [],
    }


def entry(kev: bool = False, epss: bool = False, exploit_db: bool = False, nuclei: bool = False,
          aliases: list[str] | None = None, cvss: float | None = None) -> dict[str, Any]:
    return {
        "found": True, "fetched_at": "2026-11-04T00:00:00Z", "title": "t", "cvss": cvss,
        "kev": {"date_added": "2026-01-01", "due_date": "2026-01-22"} if kev else None,
        "epss_reached": "2026-01-01" if epss else None, "exploit_db": ["1"] if exploit_db else [],
        "metasploit": [], "nuclei": nuclei, "github_poc": [], "ssvc": None, "fixed_in": [],
        "aliases": aliases or [],
    }


def level_of(findings: list[dict[str, Any]], entries: dict[str, Any] | None = None, status: str = "ok") -> str:
    rec, _ = report.summarize_image("x", {"status": status, "findings": findings}, entries or {}, None)
    return rec["risk_level"]


class ImageLevelTests(unittest.TestCase):
    def test_unknown_when_not_ok(self) -> None:
        self.assertEqual(level_of([finding("CVE-1-1", "CRITICAL")], status="unavailable"), "Unknown")
        rec, _ = report.summarize_image("x", None, {}, None)
        self.assertEqual((rec["risk_level"], rec["reason"], rec["score"]), ("Unknown", "not_scanned", None))

    def test_exploited_via_kev(self) -> None:
        self.assertEqual(level_of([finding("CVE-2024-1", "LOW")], {"CVE-2024-1": entry(kev=True)}), "Exploited")

    def test_exploited_via_alias_kev(self) -> None:
        # Finding is a GHSA; its cve.now entry aliases a CVE that is in KEV.
        entries = {"GHSA-aaaa-bbbb-cccc": entry(aliases=["CVE-2024-7"]), "CVE-2024-7": entry(kev=True)}
        self.assertEqual(level_of([finding("GHSA-aaaa-bbbb-cccc", "MEDIUM")], entries), "Exploited")

    def test_high_via_epss_or_exploit_requires_crit_or_high(self) -> None:
        self.assertEqual(level_of([finding("CVE-2024-1", "HIGH")], {"CVE-2024-1": entry(epss=True)}), "High")
        self.assertEqual(level_of([finding("CVE-2024-1", "CRITICAL")], {"CVE-2024-1": entry(nuclei=True)}), "High")
        # MEDIUM with exploit evidence is not "likely".
        self.assertEqual(level_of([finding("CVE-2024-1", "MEDIUM")], {"CVE-2024-1": entry(exploit_db=True)}), "Low")

    def test_high_via_fixable_critical(self) -> None:
        self.assertEqual(level_of([finding("CVE-2024-1", "CRITICAL", "fixed")]), "High")

    def test_elevated_boundaries(self) -> None:
        self.assertEqual(level_of([finding("CVE-2024-1", "CRITICAL", "affected")]), "Elevated")
        ten = [finding(f"CVE-2024-{i}", "HIGH", "fixed") for i in range(10)]
        self.assertEqual(level_of(ten), "Moderate")
        self.assertEqual(level_of(ten + [finding("CVE-2024-99", "HIGH", "fixed")]), "Elevated")

    def test_moderate_and_low(self) -> None:
        self.assertEqual(level_of([finding("CVE-2024-1", "HIGH")]), "Moderate")
        self.assertEqual(level_of([finding("CVE-2024-1", "MEDIUM"), finding("CVE-2024-2", "LOW")]), "Low")
        self.assertEqual(level_of([]), "Low")


class GroupingTests(unittest.TestCase):
    def test_vendor_ids_merge_only_known_id_formats(self) -> None:
        groups = report.group_findings([
            finding("GHSA-aaaa-bbbb-cccc", "HIGH", vendor_ids=["CVE-2024-5"]),
            finding("CVE-2024-5", "CRITICAL"),
            finding("CVE-2024-6", "LOW", vendor_ids=["DSA-1-1"]),
            finding("CVE-2024-8", "LOW", vendor_ids=["DSA-1-1"]),
        ], {})
        self.assertEqual(len(groups), 3)  # DSA must not merge CVE-2024-6 with CVE-2024-8
        merged = groups[0]
        self.assertEqual(merged["id"], "CVE-2024-5")  # CVE preferred as representative
        self.assertEqual(merged["severity"], "CRITICAL")  # max severity across the group
        self.assertEqual(report.severity_counts(groups)["LOW"], 2)

    def test_cvenow_aliases_merge_transitively(self) -> None:
        entries = {"GO-2024-1": entry(aliases=["GHSA-aaaa-bbbb-cccc"]),
                   "GHSA-aaaa-bbbb-cccc": entry(aliases=["CVE-2024-9"])}
        groups = report.group_findings([finding("GO-2024-1"), finding("CVE-2024-9", "MEDIUM")], entries)
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["ids"], ["CVE-2024-9", "GHSA-aaaa-bbbb-cccc", "GO-2024-1"])

    def test_uppercase_ghsa_alias_merges_with_lowercase_trivy_id(self) -> None:
        # Real cve.now data: CVE-2021-3517 lists alias "GHSA-JW9F-HH49-CVP9"; Trivy emits lowercase GHSA.
        entries = {"CVE-2021-3517": entry(kev=True, aliases=["GHSA-JW9F-HH49-CVP9"])}
        groups = report.group_findings(
            [finding("CVE-2021-3517", "HIGH"), finding("GHSA-jw9f-hh49-cvp9", "CRITICAL")], entries)
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["ids"], ["CVE-2021-3517", "GHSA-jw9f-hh49-cvp9"])
        self.assertTrue(groups[0]["kev"])
        self.assertEqual(groups[0]["severity"], "CRITICAL")

    def test_check_only_ids_ignore_ghsa_case(self) -> None:
        check = {"matches": [{"id": "GHSA-JW9F-HH49-CVP9"}, {"id": "GO-2024-7"}]}
        rec, _ = report.summarize_image(
            "x", {"status": "ok", "findings": [finding("GHSA-jw9f-hh49-cvp9")]}, {}, check)
        self.assertEqual(rec["check_only_ids"], 1)

    def test_same_id_multiple_packages_counts_once(self) -> None:
        rec, _ = report.summarize_image("x", {"status": "ok", "findings": [
            finding("CVE-2024-1", "HIGH", "fixed", pkg="a"), finding("CVE-2024-1", "HIGH", pkg="b")]}, {}, None)
        self.assertEqual(rec["counts"]["HIGH"], 1)
        self.assertEqual(rec["fixable_high"], 1)

    def test_not_found_entries_ignored(self) -> None:
        groups = report.group_findings([finding("CVE-2024-1")], {"CVE-2024-1": {"found": False, "kev": {"x": 1}}})
        self.assertFalse(groups[0]["kev"])


class ScoreTests(unittest.TestCase):
    def test_score_formula_and_caps(self) -> None:
        self.assertEqual(report.compute_score({"kev": 1}), 25)
        self.assertEqual(report.compute_score({"kev": 5}), 75)  # capped at 3
        self.assertEqual(report.compute_score({"kev": 3, "likely": 3}), 100)
        self.assertEqual(report.compute_score({"fixable_critical": 20, "other_critical": 3}), 23)
        self.assertEqual(report.compute_score({"fixable_high": 1}), 1)  # 0.5 rounds half up
        self.assertEqual(report.compute_score({"other_high_medium": 100}), 5)
        self.assertEqual(report.compute_score({}), 0)

    def test_buckets_are_exclusive(self) -> None:
        entries = {"CVE-2024-1": entry(kev=True, epss=True), "CVE-2024-2": entry(epss=True)}
        groups = report.group_findings([
            finding("CVE-2024-1", "CRITICAL", "fixed"), finding("CVE-2024-2", "HIGH", "fixed"),
            finding("CVE-2024-3", "CRITICAL", "fixed"), finding("CVE-2024-4", "CRITICAL"),
            finding("CVE-2024-5", "HIGH", "fixed"), finding("CVE-2024-6", "HIGH"), finding("CVE-2024-7", "MEDIUM"),
            finding("CVE-2024-8", "LOW"),
        ], entries)
        self.assertEqual(report.score_buckets(groups), {
            "kev": 1, "likely": 1, "fixable_critical": 1, "other_critical": 1, "fixable_high": 1,
            "other_high_medium": 2})
        # 25 + 10 + 2 + 1 + 0.5 + 0.2 = 38.7 -> 39
        self.assertEqual(report.compute_score(report.score_buckets(groups)), 39)


class ChartRollupTests(unittest.TestCase):
    def test_chart_level(self) -> None:
        self.assertEqual(report.chart_level([]), ("N/A", False))
        self.assertEqual(report.chart_level(["Unknown", "Unknown"]), ("Unknown", False))
        self.assertEqual(report.chart_level(["Low", "Unknown"]), ("Low", True))
        self.assertEqual(report.chart_level(["Moderate", "Exploited", "Low"]), ("Exploited", False))

    def test_chart_score(self) -> None:
        self.assertIsNone(report.chart_score([]))
        self.assertEqual(report.chart_score([40, 10, 20]), 43.0)
        self.assertEqual(report.chart_score([100, 50]), 100.0)


def _inventory(charts: list[dict[str, Any]]) -> dict[str, Any]:
    images = {}
    for c in charts:
        for img in c["images"]:
            if img.get("canonical"):
                images[img["canonical"]] = {"charts": [f"{c['chart']}@{c['version']}"], "roles": [img["role"]]}
    return {"charts": charts, "images": images}


def _img(canonical: str | None, role: str = "main", sa_risk: str | None = None, ref: str = "r") -> dict[str, Any]:
    return {"ref": ref, "canonical": canonical, "role": role, "workloads": [
        {"serviceAccountName": "sa", "namespace": "ns", "workloadType": "Deployment", "workloadName": "w",
         "containerName": "c", "sa_rbac_risk": sa_risk}]}


class BuildSummaryTests(unittest.TestCase):
    def test_partial_unknown_na_and_test_images_ignored(self) -> None:
        inv = _inventory([
            {"chart": "o/partial", "version": "1", "images": [_img("a:1"), _img("b:1")]},
            {"chart": "o/unknown", "version": "1", "images": [_img("b:1"), _img(None, ref="{{bad}}")]},
            {"chart": "o/none", "version": "1", "images": []},
            {"chart": "o/testonly", "version": "1", "images": [_img("a:1", role="test")]},
            {"chart": "o/testcrit", "version": "1", "images": [_img("a:1"), _img("c:1", role="test")]},
        ])
        scan = {"images": {
            "a:1": {"status": "ok", "findings": [finding("CVE-2024-1", "MEDIUM")]},
            "b:1": {"status": "unavailable", "reason": "not_found", "findings": []},
            "c:1": {"status": "ok", "findings": [finding("CVE-2024-2", "CRITICAL", "fixed")]},
        }}
        s = report.build_summary(inv, scan, {})
        ch = s["charts"]
        self.assertEqual((ch["o/partial"]["risk_level"], ch["o/partial"]["partial"]), ("Low", True))
        self.assertEqual(ch["o/partial"]["unavailable"], 1)
        self.assertEqual((ch["o/unknown"]["risk_level"], ch["o/unknown"]["partial"]), ("Unknown", False))
        self.assertIsNone(ch["o/unknown"]["score"])
        self.assertEqual(ch["o/unknown"]["unavailable"], 2)  # invalid ref counts as unavailable
        self.assertEqual(ch["o/none"]["risk_level"], "N/A")
        self.assertEqual(ch["o/testonly"]["risk_level"], "N/A")
        self.assertEqual(ch["o/testcrit"]["risk_level"], "Low")  # test image's CRITICAL ignored
        self.assertEqual(ch["o/testcrit"]["images"], 2)
        self.assertEqual(s["images"]["c:1"]["risk_level"], "High")
        self.assertEqual(s["distribution"]["charts"]["N/A"], 2)
        self.assertEqual(s["stats"]["unavailable_by_reason"], {"not_found": 1})

    def test_exposures(self) -> None:
        inv = _inventory([
            {"chart": "o/kev", "version": "1", "images": [_img("k:1", sa_risk="Critical")]},
            {"chart": "o/likely", "version": "1", "images": [_img("l:1", sa_risk="High")]},
            {"chart": "o/lowsa", "version": "1", "images": [_img("k:1", sa_risk="Medium")]},
            {"chart": "o/nosa", "version": "1", "images": [_img("k:1", sa_risk=None)]},
            {"chart": "o/testimg", "version": "1", "images": [_img("k:1", role="test", sa_risk="Critical")]},
            {"chart": "o/clean", "version": "1", "images": [_img("m:1", sa_risk="Critical")]},
        ])
        scan = {"images": {
            "k:1": {"status": "ok", "findings": [finding("CVE-2024-1", "LOW")]},
            "l:1": {"status": "ok", "findings": [finding("CVE-2024-2", "HIGH"), finding("CVE-2024-3", "MEDIUM")]},
            "m:1": {"status": "ok", "findings": [finding("CVE-2024-4", "CRITICAL", "fixed")]},
        }}
        enr = {"entries": {"CVE-2024-1": entry(kev=True), "CVE-2024-2": entry(exploit_db=True),
                           "CVE-2024-3": entry(epss=True)}}
        s = report.build_summary(inv, scan, enr)
        ch = s["charts"]
        self.assertEqual([(e["id"], e["basis"], e["sa_rbac_risk"]) for e in ch["o/kev"]["exposures"]],
                         [("CVE-2024-1", "kev", "Critical")])
        self.assertEqual([(e["id"], e["basis"]) for e in ch["o/likely"]["exposures"]], [("CVE-2024-2", "likely")])
        for name in ("o/lowsa", "o/nosa", "o/testimg", "o/clean"):
            self.assertEqual(ch[name]["exposures"], [], name)
        self.assertEqual(ch["o/kev"]["kev"], 1)
        self.assertEqual(s["stats"]["exposures"], 2)

    def test_test_workload_on_main_image_is_not_an_exposure(self) -> None:
        img = _img("k:1", sa_risk="Low")
        img["workloads"][0]["role"] = "main"
        img["workloads"].append({"serviceAccountName": "tsa", "namespace": "ns", "workloadType": "Pod",
                                 "workloadName": "x-test-connection", "containerName": "t",
                                 "sa_rbac_risk": "Critical", "role": "test"})
        inv = _inventory([{"chart": "o/c", "version": "1", "images": [img]}])
        scan = {"images": {"k:1": {"status": "ok", "findings": [finding("CVE-2024-1", "LOW")]}}}
        s = report.build_summary(inv, scan, {"entries": {"CVE-2024-1": entry(kev=True)}})
        self.assertEqual(s["charts"]["o/c"]["exposures"], [])
        self.assertEqual(s["stats"]["exposures"], 0)

    def test_invalid_refs_counted_in_unavailable_by_reason(self) -> None:
        inv = _inventory([{"chart": "o/c", "version": "1", "images": [_img(None, ref="{{bad}}")]}])
        inv["invalid"] = [{"ref": "{{bad}}", "reason": "templated", "chart": "o/c@1"}]
        s = report.build_summary(inv, {"images": {}}, {})
        self.assertEqual(s["charts"]["o/c"]["unavailable"], 1)
        self.assertEqual(s["stats"]["unavailable_by_reason"], {"invalid:templated": 1})
        self.assertIn("invalid:templated", report.render_report(s))


class FixtureEndToEndTests(unittest.TestCase):
    def test_cli_on_fixtures(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            summary_path, report_path = Path(tmp) / "summary.json", Path(tmp) / "report.md"
            rc = report.main(["--inventory", str(FIXTURES / "inventory.json"), "--scan", str(FIXTURES / "scan.json"),
                              "--enrichment", str(FIXTURES / "enrichment.json"),
                              "--summary", str(summary_path), "--report", str(report_path)])
            self.assertEqual(rc, 0)
            s = json.loads(summary_path.read_text())
            md = report_path.read_text()

        web = s["images"]["docker.io/acme/web:1.0"]
        # GHSA + CVE-2024-0002 merged via cve.now alias -> 1 MEDIUM; CVE-2024-0001 HIGH in KEV.
        self.assertEqual(web["counts"]["MEDIUM"], 1)
        self.assertEqual(web["counts"]["HIGH"], 1)
        self.assertEqual((web["risk_level"], web["kev"], web["eosl"]), ("Exploited", 1, True))
        self.assertEqual(web["score"], 25)  # kev 25 + 0.1 (merged MEDIUM group) = 25.1
        self.assertEqual(web["check_only_ids"], 1)  # CVE-2024-9999 not seen by Trivy
        self.assertEqual(web["cvenow_coverage_pct"], 66.7)  # 2 of 3 enrichable IDs found
        self.assertEqual(web["top_cwes"], [["CWE-787", 1]])
        self.assertEqual(web["max_cvss"], 8.1)

        charts = s["charts"]
        self.assertEqual(charts["acme/web"]["risk_level"], "Exploited")
        self.assertEqual(charts["acme/web"]["exposures"][0]["basis"], "kev")
        self.assertEqual(charts["acme/gone"]["risk_level"], "Unknown")
        self.assertEqual(charts["acme/crds"]["risk_level"], "N/A")
        self.assertEqual(s["provenance"]["cvenow"]["coverage_pct"], 66.7)
        self.assertEqual(s["provenance"]["trivy"]["version"], "0.58.0")

        self.assertIn("## Top 15 images by score", md)
        self.assertIn("1 exposures across 1 charts (1 KEV-based)", md)
        self.assertIn("| not_found | 1 |", md)
        self.assertNotIn("<", md)  # no HTML
        self.assertNotIn("scan was limited", md)

    def test_limited_scan_is_noted(self) -> None:
        summary = {"stats": {"images": 3, "scan_stats": {"limit": 2}}}
        self.assertIn("limited to the first 2 images", report.render_report(summary))

    def test_missing_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            self.assertEqual(report.main(["--inventory", str(out / "nope.json")]), 1)
            rc = report.main(["--inventory", str(FIXTURES / "inventory.json"), "--scan", str(out / "nope.json"),
                              "--enrichment", str(out / "nope.json"), "--summary", str(out / "s.json"),
                              "--report", str(out / "r.md")])
            self.assertEqual(rc, 0)
            s = json.loads((out / "s.json").read_text())
            self.assertEqual(s["distribution"]["images"]["Unknown"], 3)
            self.assertEqual(s["stats"]["unavailable_by_reason"], {"not_scanned": 3})
            self.assertIn("n/a", (out / "r.md").read_text())


if __name__ == "__main__":
    unittest.main()
