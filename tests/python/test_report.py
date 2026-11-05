"""Unit tests for vulnscan.report (no network, synthetic inputs)."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

from vulnscan import match, report
from vulnscan.common import read_json, write_json

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
          aliases: list[str] | None = None, cvss: float | None = None, metasploit: bool = False,
          github_poc: bool = False) -> dict[str, Any]:
    return {
        "found": True, "fetched_at": "2026-11-04T00:00:00Z", "title": "t", "cvss": cvss,
        "kev": {"date_added": "2026-01-01", "due_date": "2026-01-22"} if kev else None,
        "epss_reached": "2026-01-01" if epss else None, "exploit_db": ["1"] if exploit_db else [],
        "metasploit": ["exploit/x"] if metasploit else [], "nuclei": nuclei,
        "github_poc": ["a/b"] if github_poc else [], "ssvc": None, "fixed_in": [],
        "aliases": aliases or [],
    }


def level_of(findings: list[dict[str, Any]], entries: dict[str, Any] | None = None, status: str = "ok") -> str:
    rec, _ = report.summarize_image("x", {"status": status}, findings, entries or {}, None)
    return rec["risk_level"]


def scan_with_matches(match_dir: Path, images: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """New-layout scan.json for {canonical: record with 'findings'}; 'ok' findings go to the match cache."""
    out = {}
    for i, (canonical, rec) in enumerate(images.items(), 1):
        rec = dict(rec)
        findings = rec.pop("findings", [])
        if rec.get("status") == "ok":
            rec.setdefault("digest", f"sha256:{i:064x}")
            match.store(match_dir, rec["digest"], match.compact({"findings": findings}, "2026-11-04T00:00:00Z"))
        out[canonical] = rec
    return {"images": out}


class ImageLevelTests(unittest.TestCase):
    def test_unknown_when_not_ok(self) -> None:
        self.assertEqual(level_of([finding("CVE-1-1", "CRITICAL")], status="unavailable"), "Unknown")
        rec, _ = report.summarize_image("x", None, [], {}, None)
        self.assertEqual((rec["risk_level"], rec["reason"], rec["score"]), ("Unknown", "not_scanned", None))

    def test_exploited_via_kev(self) -> None:
        self.assertEqual(level_of([finding("CVE-2024-1", "LOW")], {"CVE-2024-1": entry(kev=True)}), "Exploited")

    def test_exploited_via_alias_kev(self) -> None:
        # Finding is a GHSA; its cve.now entry aliases a CVE that is in KEV.
        entries = {"GHSA-aaaa-bbbb-cccc": entry(aliases=["CVE-2024-7"]), "CVE-2024-7": entry(kev=True)}
        self.assertEqual(level_of([finding("GHSA-aaaa-bbbb-cccc", "MEDIUM")], entries), "Exploited")

    def test_high_via_epss_metasploit_or_exploit_db_requires_crit_or_high(self) -> None:
        self.assertEqual(level_of([finding("CVE-2024-1", "HIGH")], {"CVE-2024-1": entry(epss=True)}), "High")
        self.assertEqual(level_of([finding("CVE-2024-1", "CRITICAL")], {"CVE-2024-1": entry(metasploit=True)}), "High")
        self.assertEqual(level_of([finding("CVE-2024-1", "HIGH")], {"CVE-2024-1": entry(exploit_db=True)}), "High")
        # MEDIUM with exploit evidence is not "likely".
        self.assertEqual(level_of([finding("CVE-2024-1", "MEDIUM")], {"CVE-2024-1": entry(exploit_db=True)}), "Low")

    def test_poc_and_nuclei_alone_are_not_likely(self) -> None:
        entries = {"CVE-2024-1": entry(nuclei=True, github_poc=True)}
        self.assertEqual(level_of([finding("CVE-2024-1", "CRITICAL")], entries), "Elevated")
        rec, groups = report.summarize_image("x", {"status": "ok"}, [finding("CVE-2024-1", "CRITICAL")], entries, None)
        self.assertEqual((rec["likely"], rec["public_exploit"]), (0, 1))
        self.assertFalse(groups[0]["likely"])

    def test_fixable_critical_alone_is_elevated(self) -> None:
        self.assertEqual(level_of([finding("CVE-2024-1", "CRITICAL", "fixed")]), "Elevated")
        self.assertEqual(level_of([finding("CVE-2024-1", "CRITICAL", "affected")]), "Elevated")
        many_high = [finding(f"CVE-2024-{i}", "HIGH", "fixed") for i in range(30)]
        self.assertEqual(level_of(many_high), "Moderate")

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
        rec, _ = report.summarize_image("x", {"status": "ok"}, [finding("GHSA-jw9f-hh49-cvp9")], {}, check)
        self.assertEqual(rec["check_only_ids"], 1)

    def test_same_id_multiple_packages_counts_once(self) -> None:
        rec, _ = report.summarize_image("x", {"status": "ok"}, [
            finding("CVE-2024-1", "HIGH", "fixed", pkg="a"), finding("CVE-2024-1", "HIGH", pkg="b")], {}, None)
        self.assertEqual(rec["counts"]["HIGH"], 1)
        self.assertEqual(rec["fixable_high"], 1)

    def test_not_found_entries_ignored(self) -> None:
        groups = report.group_findings([finding("CVE-2024-1")], {"CVE-2024-1": {"found": False, "kev": {"x": 1}}})
        self.assertFalse(groups[0]["kev"])


class ScoreTests(unittest.TestCase):
    def test_score_formula_and_caps(self) -> None:
        self.assertEqual(report.WEIGHTS_VERSION, 2)
        self.assertEqual(report.compute_score({"kev": 1}), 30)
        self.assertEqual(report.compute_score({"kev": 5}), 90)  # capped at 3
        self.assertEqual(report.compute_score({"kev": 3, "likely": 1}), 100)  # 102 capped
        self.assertEqual(report.compute_score({"likely": 9}), 36)
        self.assertEqual(report.compute_score({"critical": 20}), 30)
        self.assertEqual(report.compute_score({"high": 1}), 1)  # 0.5 rounds half up
        self.assertEqual(report.compute_score({"high": 100}), 10)
        self.assertEqual(report.compute_score({}), 0)

    def test_buckets(self) -> None:
        entries = {"CVE-2024-1": entry(kev=True, epss=True), "CVE-2024-2": entry(epss=True),
                   "CVE-2024-7": entry(metasploit=True)}
        groups = report.group_findings([
            finding("CVE-2024-1", "CRITICAL", "fixed"), finding("CVE-2024-2", "HIGH", "fixed"),
            finding("CVE-2024-3", "CRITICAL", "fixed"), finding("CVE-2024-4", "CRITICAL"),
            finding("CVE-2024-5", "HIGH", "fixed"), finding("CVE-2024-6", "HIGH"), finding("CVE-2024-7", "MEDIUM"),
            finding("CVE-2024-8", "LOW"),
        ], entries)
        # kev/likely exclusive; MEDIUM with metasploit is not likely; critical/high count everything
        self.assertEqual(report.score_buckets(groups), {"kev": 1, "likely": 1, "critical": 3, "high": 3})
        # 30 + 12 + 9 + 1.5 = 52.5 -> 53
        self.assertEqual(report.compute_score(report.score_buckets(groups)), 53)

    def test_top_vulns_order_and_fields(self) -> None:
        entries = {"CVE-2024-1": entry(kev=True), "CVE-2024-2": entry(epss=True)}
        rec, _ = report.summarize_image("x", {"status": "ok", "scanned_at": "2026-11-04T01:00:00Z"}, [
            finding("CVE-2024-9", "CRITICAL", cvss=9.0), finding("CVE-2024-8", "CRITICAL", "fixed", cvss=9.8, pkg="z"),
            finding("CVE-2024-8", "HIGH", pkg="a"), finding("CVE-2024-2", "HIGH", cvss=7.0),
            finding("CVE-2024-1", "LOW"), finding("CVE-2024-3", "MEDIUM", cvss=6.0)], entries, None)
        self.assertEqual([t["id"] for t in rec["top"]], ["CVE-2024-1", "CVE-2024-2", "CVE-2024-8", "CVE-2024-9",
                                                         "CVE-2024-3"])
        self.assertEqual(rec["top"][2], {"id": "CVE-2024-8", "severity": "CRITICAL", "cvss": 9.8, "kev": False,
                                         "likely": False, "fixed": "2", "pkg": "z"})
        self.assertEqual((rec["kev_ids"], rec["likely_ids"]), (["CVE-2024-1"], ["CVE-2024-2"]))
        self.assertEqual((rec["risk_level"], rec["scanned_at"]), ("Exploited", "2026-11-04T01:00:00Z"))
        many = [finding(f"CVE-2024-{i}", "HIGH") for i in range(20)]
        rec, _ = report.summarize_image("x", {"status": "ok"}, many,
                                        {f"CVE-2024-{i}": entry(kev=True) for i in range(20)}, None)
        self.assertEqual((len(rec["top"]), len(rec["kev_ids"]), rec["kev"]), (report.TOP_VULNS, report.MAX_IDS, 20))

    def test_merge_groups_matches_regrouping(self) -> None:
        entries = {"GHSA-aaaa-bbbb-cccc": entry(aliases=["CVE-2024-5"]), "CVE-2024-5": entry(kev=True)}
        a = report.group_findings([finding("GHSA-aaaa-bbbb-cccc", "HIGH"), finding("CVE-2024-1", "LOW")], entries)
        b = report.group_findings([finding("CVE-2024-5", "CRITICAL", "fixed"), finding("CVE-2024-1", "MEDIUM")], entries)
        merged = report.merge_groups([a, b])
        regrouped = report.group_findings([finding("GHSA-aaaa-bbbb-cccc", "HIGH"), finding("CVE-2024-1", "LOW"),
                                           finding("CVE-2024-5", "CRITICAL", "fixed"),
                                           finding("CVE-2024-1", "MEDIUM")], entries)
        def strip(gs: list[dict]) -> list[tuple]:
            return [(g["id"], g["ids"], g["severity"], g["fixable"], g["kev"], g["likely"]) for g in gs]
        self.assertEqual(strip(merged), strip(regrouped))


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
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.match_dir = Path(self._tmp.name) / "match"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def build(self, inv: dict[str, Any], images: dict[str, dict[str, Any]], enr: dict[str, Any]) -> dict[str, Any]:
        return report.build_summary(inv, scan_with_matches(self.match_dir, images), enr, match_dir=self.match_dir)

    def test_partial_unknown_na_and_test_images_ignored(self) -> None:
        inv = _inventory([
            {"chart": "o/partial", "version": "1", "images": [_img("a:1"), _img("b:1")]},
            {"chart": "o/unknown", "version": "1", "images": [_img("b:1"), _img(None, ref="{{bad}}")]},
            {"chart": "o/none", "version": "1", "images": []},
            {"chart": "o/testonly", "version": "1", "images": [_img("a:1", role="test")]},
            {"chart": "o/testcrit", "version": "1", "images": [_img("a:1"), _img("c:1", role="test")]},
        ])
        s = self.build(inv, {
            "a:1": {"status": "ok", "findings": [finding("CVE-2024-1", "MEDIUM")]},
            "b:1": {"status": "unavailable", "reason": "not_found"},
            "c:1": {"status": "ok", "findings": [finding("CVE-2024-2", "CRITICAL", "fixed")]},
        }, {})
        ch = s["versions"]
        self.assertEqual((ch["o/partial/1"]["risk_level"], ch["o/partial/1"]["partial"]), ("Low", True))
        self.assertEqual(ch["o/partial/1"]["unavailable"], 1)
        self.assertEqual((ch["o/unknown/1"]["risk_level"], ch["o/unknown/1"]["partial"]), ("Unknown", False))
        self.assertIsNone(ch["o/unknown/1"]["score"])
        self.assertEqual(ch["o/unknown/1"]["unavailable"], 2)  # invalid ref counts as unavailable
        self.assertEqual(ch["o/unknown/1"]["invalid"], [{"ref": "{{bad}}", "reason": None}])
        self.assertEqual(ch["o/unknown/1"]["imgs"], {"r": "b:1"})
        self.assertEqual(ch["o/none/1"]["risk_level"], "N/A")
        self.assertEqual(ch["o/testonly/1"]["risk_level"], "N/A")
        self.assertEqual(ch["o/testcrit/1"]["risk_level"], "Low")  # test image's CRITICAL ignored
        self.assertEqual(ch["o/testcrit/1"]["images"], 2)
        self.assertEqual(s["images"]["c:1"]["risk_level"], "Elevated")
        self.assertEqual(s["landscape"]["distribution"]["charts"]["N/A"], 2)
        self.assertEqual(s["stats"]["unavailable_by_reason"], {"not_found": 1})
        self.assertEqual(s["latest"]["o/partial"], "o/partial/1")  # latest-scope inventory: all latest

    def test_combinations(self) -> None:
        inv = _inventory([
            {"chart": "o/kev", "version": "1", "images": [_img("k:1", sa_risk="High")]},
            {"chart": "o/likely", "version": "1", "images": [_img("l:1", sa_risk="Critical")]},
            {"chart": "o/kevcrit", "version": "1", "images": [_img("k:1", sa_risk="Critical")]},
            {"chart": "o/lowsa", "version": "1", "images": [_img("k:1", sa_risk="Medium")]},
            {"chart": "o/nosa", "version": "1", "images": [_img("k:1", sa_risk=None)]},
            {"chart": "o/testimg", "version": "1", "images": [_img("k:1", role="test", sa_risk="Critical")]},
            {"chart": "o/elevated", "version": "1", "images": [_img("m:1", sa_risk="Critical")]},
            {"chart": "o/poc", "version": "1", "images": [_img("p:1", sa_risk="Critical")]},
        ])
        images = {
            "k:1": {"status": "ok", "findings": [finding("CVE-2024-1", "LOW"), finding("CVE-2024-9", "CRITICAL")]},
            "l:1": {"status": "ok", "findings": [finding("CVE-2024-2", "HIGH"), finding("CVE-2024-3", "MEDIUM")]},
            "m:1": {"status": "ok", "findings": [finding("CVE-2024-4", "CRITICAL", "fixed")]},
            "p:1": {"status": "ok", "findings": [finding("CVE-2024-5", "CRITICAL")]},
        }
        enr = {"entries": {"CVE-2024-1": entry(kev=True), "CVE-2024-2": entry(exploit_db=True),
                           "CVE-2024-3": entry(epss=True), "CVE-2024-5": entry(github_poc=True, nuclei=True)}}
        s = self.build(inv, images, enr)
        ch = s["versions"]
        combo = ch["o/kev/1"]["combos"][0]
        self.assertEqual({k: combo[k] for k in ("chart", "version", "page_version", "key", "url", "workload_kind",
                                                "workload_name", "container", "serviceAccountName", "namespace",
                                                "sa_rbac_risk", "image", "canonical", "image_level", "kev_ids",
                                                "likely_ids", "critical", "high")},
                         {"chart": "o/kev", "version": "1", "page_version": "1", "key": "o/kev/1",
                          "url": "/charts/o/kev/1/", "workload_kind": "Deployment", "workload_name": "w",
                          "container": "c", "serviceAccountName": "sa", "namespace": "ns", "sa_rbac_risk": "High",
                          "image": "r", "canonical": "k:1", "image_level": "Exploited", "kev_ids": ["CVE-2024-1"],
                          "likely_ids": [], "critical": 1, "high": 0})
        self.assertEqual([(c["image_level"], c["likely_ids"]) for c in ch["o/likely/1"]["combos"]],
                         [("High", ["CVE-2024-2"])])  # MEDIUM with EPSS is not likely
        for name in ("o/lowsa", "o/nosa", "o/testimg", "o/elevated", "o/poc"):
            self.assertEqual(ch[f"{name}/1"]["combos"], [], name)
        self.assertEqual(ch["o/kev/1"]["kev"], 1)
        land = s["landscape"]
        # rank: RBAC Critical first, then image level
        self.assertEqual([c["chart"] for c in land["combos"]], ["o/kevcrit", "o/likely", "o/kev"])
        self.assertEqual(land["stats"], {"workloads_total": 7, "workloads_critical_or_high_rbac": 5,
                                         "combos_total": 3, "combos_kev": 2, "charts_with_combos": 3,
                                         "images_exploited": 1})
        self.assertEqual(s["stats"]["combos"], 3)

    def test_test_workload_on_main_image_is_not_a_combination(self) -> None:
        img = _img("k:1", sa_risk="Low")
        img["workloads"][0]["role"] = "main"
        img["workloads"].append({"serviceAccountName": "tsa", "namespace": "ns", "workloadType": "Pod",
                                 "workloadName": "x-test-connection", "containerName": "t",
                                 "sa_rbac_risk": "Critical", "role": "test"})
        inv = _inventory([{"chart": "o/c", "version": "1", "images": [img]}])
        s = self.build(inv, {"k:1": {"status": "ok", "findings": [finding("CVE-2024-1", "LOW")]}},
                       {"entries": {"CVE-2024-1": entry(kev=True)}})
        self.assertEqual(s["versions"]["o/c/1"]["combos"], [])
        self.assertEqual(s["stats"]["combos"], 0)

    def test_all_scope_versions_and_latest_only_landscape(self) -> None:
        inv = _inventory([
            {"chart": "o/c", "version": "v2.0.0-RC", "latest": True, "images": [_img("new:1", sa_risk="Critical")]},
            {"chart": "o/c", "version": "1.0.0", "page_version": "1.0.0", "key": "o/c/1.0.0", "latest": False,
             "images": [_img("old:1", sa_risk="Critical")]},
        ])
        inv["scope"] = "all"
        s = self.build(inv, {"new:1": {"status": "ok", "findings": [finding("CVE-2024-1", "HIGH")]},
                             "old:1": {"status": "ok", "findings": [finding("CVE-2024-2", "LOW")]}},
                       {"entries": {"CVE-2024-2": entry(kev=True)}})
        self.assertEqual(set(s["versions"]), {"o/c/2.0.0-RC", "o/c/1.0.0"})  # leading 'v' dropped like json2hugo
        self.assertEqual(s["latest"], {"o/c": "o/c/2.0.0-RC"})
        self.assertEqual(s["versions"]["o/c/2.0.0-RC"]["url"], "/charts/o/c/2.0.0-rc/")  # Hugo lowercases paths
        self.assertEqual(len(s["versions"]["o/c/1.0.0"]["combos"]), 1)  # old versions get combos too
        land = s["landscape"]
        self.assertEqual(land["combos"], [])  # ... but the landscape is latest-only
        self.assertEqual(land["distribution"]["images"]["Moderate"], 1)
        self.assertEqual(land["distribution"]["images"]["Exploited"], 0)
        self.assertEqual(land["coverage"]["images"], 1)
        self.assertEqual(s["stats"]["versions"], 2)
        self.assertEqual(s["stats"]["distribution_versions"]["Exploited"], 1)
        self.assertIn("All chart versions | 2 | 2", report.render_report(s))

    def test_invalid_refs_counted_in_unavailable_by_reason(self) -> None:
        inv = _inventory([{"chart": "o/c", "version": "1", "images": [_img(None, ref="{{bad}}")]}])
        inv["invalid"] = [{"ref": "{{bad}}", "reason": "templated", "chart": "o/c@1"}]
        s = report.build_summary(inv, {"images": {}}, {}, match_dir=self.match_dir)
        self.assertEqual(s["versions"]["o/c/1"]["unavailable"], 1)
        self.assertEqual(s["stats"]["unavailable_by_reason"], {"invalid:templated": 1})
        self.assertIn("invalid:templated", report.render_report(s))


class StreamingTests(BuildSummaryTests):
    """build_summary reads per-image detail from the match cache, one digest at a time."""

    FINDINGS = [finding("CVE-2024-1", "CRITICAL", "fixed", cvss=9.8, cwes=["CWE-79"], pkg="b"),
                finding("CVE-2024-1", "HIGH", pkg="a"), finding("GHSA-aaaa-bbbb-cccc", "HIGH", vendor_ids=["CVE-2024-5"]),
                finding("CVE-2024-5", "MEDIUM", cvss=5.0), finding("DSA-1-1", "LOW", vendor_ids=["CVE-2024-6"])]

    def test_equivalent_to_raw_findings(self) -> None:
        entries = {"CVE-2024-1": entry(kev=True), "CVE-2024-5": entry(epss=True, aliases=["GO-2024-9"])}
        raw, raw_groups = report.summarize_image("x", {"status": "ok"}, self.FINDINGS, entries, None)
        inv = _inventory([{"chart": "o/c", "version": "1", "images": [_img("x:1")]}])
        s = self.build(inv, {"x:1": {"status": "ok", "findings": self.FINDINGS}}, {"entries": entries})
        rec = dict(s["images"]["x:1"], digest=None)
        self.assertEqual(rec, raw)
        groups = report.group_findings(match.expand(match.load(self.match_dir, f"sha256:{1:064x}")), entries)
        self.assertEqual(groups, raw_groups)

    def test_missing_or_unknown_format_match_is_unavailable(self) -> None:
        inv = _inventory([{"chart": "o/c", "version": "1", "images": [_img("a:1"), _img("b:1"), _img("c:1")]}])
        scan = scan_with_matches(self.match_dir, {c: {"status": "ok", "findings": self.FINDINGS}
                                                  for c in ("a:1", "b:1", "c:1")})
        match.path(self.match_dir, scan["images"]["a:1"]["digest"]).unlink()
        write_json(match.path(self.match_dir, scan["images"]["b:1"]["digest"]),
                   {"format_version": 99, "matched_at": "2026-11-04T00:00:00Z", "vulns": []})
        s = report.build_summary(inv, scan, {}, match_dir=self.match_dir)
        for c in ("a:1", "b:1"):
            self.assertEqual((s["images"][c]["status"], s["images"][c]["reason"], s["images"][c]["risk_level"]),
                             ("unavailable", "match_missing", "Unknown"), c)
        self.assertEqual(s["images"]["c:1"]["risk_level"], "Elevated")
        self.assertEqual(s["stats"]["unavailable_by_reason"], {"match_missing": 2})
        self.assertTrue(s["versions"]["o/c/1"]["partial"])

    def test_truncated_match_is_unavailable_not_fatal(self) -> None:
        inv = _inventory([{"chart": "o/c", "version": "1", "images": [_img("a:1"), _img("b:1")]}])
        scan = scan_with_matches(self.match_dir, {c: {"status": "ok", "findings": self.FINDINGS}
                                                  for c in ("a:1", "b:1")})
        p = match.path(self.match_dir, scan["images"]["a:1"]["digest"])
        p.write_bytes(p.read_bytes()[:20])
        s = report.build_summary(inv, scan, {}, match_dir=self.match_dir)
        self.assertEqual((s["images"]["a:1"]["status"], s["images"]["a:1"]["reason"]),
                         ("unavailable", "match_missing"))
        self.assertEqual(s["images"]["b:1"]["risk_level"], "Elevated")

    def test_format1_match_is_read_through_migration(self) -> None:
        inv = _inventory([{"chart": "o/c", "version": "1", "images": [_img("a:1"), _img("b:1")]}])
        scan = scan_with_matches(self.match_dir, {"a:1": {"status": "ok", "findings": self.FINDINGS}})
        scan["images"]["b:1"] = {"status": "ok", "digest": "sha256:" + "b" * 64}
        write_json(match.path(self.match_dir, "sha256:" + "b" * 64),
                   {"matched_at": "2026-11-04T00:00:00Z", "result": {"findings": self.FINDINGS}})
        s = report.build_summary(inv, scan, {}, match_dir=self.match_dir)
        a, b = s["images"]["a:1"], s["images"]["b:1"]
        self.assertEqual(dict(a, digest=None), dict(b, digest=None))
        self.assertEqual(read_json(match.path(self.match_dir, "sha256:" + "b" * 64))["result"]["findings"],
                         self.FINDINGS)  # the report never writes to the cache

    def test_loads_one_match_per_ok_image(self) -> None:
        inv = _inventory([{"chart": "o/c", "version": "1", "images": [_img(f"i{n}:1") for n in range(4)]}])
        scan = scan_with_matches(self.match_dir, {f"i{n}:1": {"status": "ok", "findings": self.FINDINGS}
                                                  for n in range(3)})
        scan["images"]["i2:1"]["digest"] = scan["images"]["i0:1"]["digest"]  # two images, one digest
        scan["images"]["i3:1"] = {"status": "unavailable", "reason": "not_found", "digest": None}
        loads: list[str] = []
        original = match.load

        def tracking_load(match_dir: Path, digest: str) -> Any:
            loads.append(digest)
            return original(match_dir, digest)

        with mock.patch.object(match, "load", tracking_load):
            s = report.build_summary(inv, scan, {}, match_dir=self.match_dir)
        self.assertEqual(sorted(loads), sorted(scan["images"][f"i{n}:1"]["digest"] for n in range(3)))
        self.assertEqual(s["images"]["i0:1"], s["images"]["i2:1"])
        self.assertEqual(s["versions"]["o/c/1"]["counts"]["CRITICAL"], 1)  # same vulns merged across images


class FixtureEndToEndTests(unittest.TestCase):
    def test_cli_on_fixtures(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            summary_path, report_path = Path(tmp) / "summary.json", Path(tmp) / "report.md"
            match_dir = Path(tmp) / "match"
            for digest, doc in read_json(FIXTURES / "matches.json").items():
                match.store(match_dir, digest, doc)
            rc = report.main(["--inventory", str(FIXTURES / "inventory.json"), "--scan", str(FIXTURES / "scan.json"),
                              "--enrichment", str(FIXTURES / "enrichment.json"), "--match-dir", str(match_dir),
                              "--summary", str(summary_path), "--report", str(report_path)])
            self.assertEqual(rc, 0)
            s = json.loads(summary_path.read_text())
            md = report_path.read_text()

        web = s["images"]["docker.io/acme/web:1.0"]
        # GHSA + CVE-2024-0002 merged via cve.now alias -> 1 MEDIUM; CVE-2024-0001 HIGH in KEV.
        self.assertEqual(web["counts"]["MEDIUM"], 1)
        self.assertEqual(web["counts"]["HIGH"], 1)
        self.assertEqual((web["risk_level"], web["kev"], web["eosl"]), ("Exploited", 1, True))
        self.assertEqual(web["score"], 31)  # kev 30 + 0.5 (the KEV vuln is HIGH) = 30.5 -> 31
        self.assertEqual(web["check_only_ids"], 1)  # CVE-2024-9999 not seen by Trivy
        self.assertEqual(web["cvenow_coverage_pct"], 66.7)  # 2 of 3 enrichable IDs found
        self.assertEqual(web["top_cwes"], [["CWE-787", 1]])
        self.assertEqual(web["max_cvss"], 8.1)

        self.assertEqual(web["top"][0], {"id": "CVE-2024-0001", "severity": "HIGH", "cvss": 8.1, "kev": True,
                                         "likely": True, "fixed": "1.2", "pkg": "openssl"})

        versions = s["versions"]
        self.assertEqual(versions["acme/web/1.2.0"]["risk_level"], "Exploited")
        self.assertEqual(versions["acme/web/1.2.0"]["combos"][0]["kev_ids"], ["CVE-2024-0001"])
        self.assertEqual(versions["acme/web/1.2.0"]["imgs"], {"acme/web:1.0": "docker.io/acme/web:1.0",
                                                              "busybox": "docker.io/library/busybox:latest"})
        self.assertEqual(versions["acme/gone/0.1.0"]["risk_level"], "Unknown")
        self.assertEqual(versions["acme/crds/2.0.0"]["risk_level"], "N/A")
        self.assertEqual(s["provenance"]["cvenow"]["coverage_pct"], 66.7)
        self.assertEqual(s["provenance"]["trivy"]["version"], "0.58.0")

        self.assertIn("## Top 15 images by score (latest versions)", md)
        self.assertIn("1 workload combinations across 1 charts (1 with KEV)", md)
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
                              "--enrichment", str(out / "nope.json"), "--match-dir", str(out / "match"),
                              "--summary", str(out / "s.json"), "--report", str(out / "r.md")])
            self.assertEqual(rc, 0)
            s = json.loads((out / "s.json").read_text())
            self.assertEqual(s["landscape"]["distribution"]["images"]["Unknown"], 3)
            self.assertEqual(s["stats"]["unavailable_by_reason"], {"not_scanned": 3})
            self.assertIn("n/a", (out / "r.md").read_text())

    def test_old_format_scan_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            write_json(out / "scan.json", {"images": {"x:1": {"status": "ok", "findings": []}}})
            with mock.patch("sys.stderr") as err:
                rc = report.main(["--inventory", str(FIXTURES / "inventory.json"), "--scan", str(out / "scan.json"),
                                  "--match-dir", str(out / "match"), "--summary", str(out / "s.json"),
                                  "--report", str(out / "r.md")])
            self.assertEqual(rc, 1)
            self.assertIn("format_version", "".join(c.args[0] for c in err.write.call_args_list))
            self.assertFalse((out / "s.json").exists())


if __name__ == "__main__":
    unittest.main()
