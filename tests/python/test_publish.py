"""Unit tests for vulnscan.publish (no network, synthetic inputs)."""

from __future__ import annotations

import copy
import hashlib
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from typing import Any

from vulnscan import publish

FIXTURES = Path(__file__).parent / "fixtures" / "publish"


def load(name: str) -> dict[str, Any]:
    return json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))


def build_fixture(**overrides: Any) -> dict[str, Any]:
    docs = {name: load(name) for name in ("inventory", "summary", "scan", "enrichment")}
    docs.update(overrides)
    return publish.build(docs["inventory"], docs["summary"], docs["scan"], docs["enrichment"])


def combo(**kw: Any) -> dict[str, Any]:
    base = {"chart": "a/b", "version": "1", "kind": "Deployment", "workload": "w", "container": "c", "canonical": "i",
            "sa_rbac_risk": "High", "image_level": "High", "kev": 0, "likely": 0, "critical": 0}
    base.update(kw)
    return base


class HelperTests(unittest.TestCase):
    def test_shard_is_md5_prefix(self) -> None:
        key = "kubedoop/airflow-operator/0.4.0-dev"
        self.assertEqual(publish.shard(key), hashlib.md5(key.encode()).hexdigest()[:2])

    def test_page_version_and_key(self) -> None:
        self.assertEqual(publish.page_version("v1.2.3"), "1.2.3")
        self.assertEqual(publish.page_version("vv1"), "v1")
        self.assertEqual(publish.version_key_of({"key": "o/c/1.0"}), "o/c/1.0")
        self.assertEqual(publish.version_key_of({"chart": "o/c", "version": "v2.0"}), "o/c/2.0")
        self.assertEqual(publish.version_key_of({"org": "o", "name": "c", "version": "v2", "page_version": "3"}), "o/c/3")

    def test_page_url_lowercases(self) -> None:
        self.assertEqual(publish.page_url("beta/Api/0.1.0-RC"), "/charts/beta/api/0.1.0-rc/")


class ImageTests(unittest.TestCase):
    def test_top_ordering_and_ids(self) -> None:
        scan, ent = load("scan"), load("enrichment")["entries"]
        det = publish.image_details(scan["images"]["docker.io/acme/web:2.0"], ent)
        # KEV first, then likely, then severity, then CVSS.
        self.assertEqual([r[0] for r in det["top"]], ["CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003", "CVE-2024-0004"])
        self.assertEqual(det["top"][0], ["CVE-2024-0001", "MEDIUM", 5.0, 1, 0, None, "openssl"])
        # Two findings of one CVE merge; fixed versions are de-duplicated and clipped, packages joined.
        self.assertEqual(det["top"][1], ["CVE-2024-0002", "HIGH", 7.5, 0, 1, "8.0, 8.1, 8.2 +1", "curl, libcurl"])
        self.assertEqual((det["kev_ids"], det["likely_ids"]), (["CVE-2024-0001"], ["CVE-2024-0002"]))

    def test_top_is_capped(self) -> None:
        findings = [{"id": f"CVE-2024-{i:04d}", "pkg": "p", "severity": "LOW"} for i in range(1, 20)]
        det = publish.image_details({"status": "ok", "findings": findings}, {})
        self.assertEqual(len(det["top"]), publish.TOP_CVES)
        self.assertEqual(det["top"][0][0], "CVE-2024-0001")

    def test_not_scanned_has_no_details(self) -> None:
        self.assertEqual(publish.image_details(None, {})["top"], [])
        self.assertEqual(publish.image_details({"status": "unavailable"}, {})["top"], [])

    def test_image_record_states(self) -> None:
        empty = {"top": [], "kev_ids": [], "likely_ids": []}
        self.assertEqual(publish.image_record(None, None, empty, None), {"lvl": "Unknown", "st": "pending", "rs": "not_scanned"})
        skipped = publish.image_record({"status": "skipped", "reason": "sbom_quota"}, None, empty, None)
        self.assertEqual((skipped["st"], skipped["rs"]), ("pending", "sbom_quota"))
        unavailable = publish.image_record({"status": "unavailable", "reason": "no_amd64", "risk_level": "Unknown"},
                                           None, empty, "2026-11-05T00:00:00Z")
        self.assertEqual((unavailable["st"], unavailable["rs"], unavailable["at"], unavailable["top"]),
                         ("unavailable", "no_amd64", None, []))
        self.assertEqual(publish.image_record({"status": "invalid", "reason": "invalid_tag"}, None, empty, None)["st"], "invalid")

    def test_image_record_ok(self) -> None:
        docs = build_fixture()
        rec = docs["images"]["docker.io/acme/web:2.0"]
        self.assertEqual({k: rec[k] for k in ("lvl", "st", "rs", "os", "eosl", "n", "kev", "lk", "fx", "at")},
                         {"lvl": "Exploited", "st": "ok", "rs": None, "os": "alpine 3.19", "eosl": True,
                          "n": [1, 2, 1, 0, 0], "kev": 1, "lk": 1, "fx": [1, 1], "at": "2026-11-04"})
        self.assertEqual(len(rec["top"]), 4)


class CombinationTests(unittest.TestCase):
    def test_compute_combos_filters_and_dedupes(self) -> None:
        inv = load("inventory")
        images = {"docker.io/acme/web:2.0": {"risk_level": "Exploited"}}
        combos = publish.compute_combos(inv["charts"][0], images)
        # Duplicate main workload collapses; the test Pod and the Low-RBAC/Unknown sidecar are excluded.
        self.assertEqual([(c["workload_kind"], c["workload_name"], c["sa_rbac_risk"]) for c in combos], [("Deployment", "web", "Critical")])
        images["docker.io/acme/web:2.0"]["risk_level"] = "Elevated"
        self.assertEqual(publish.compute_combos(inv["charts"][0], images), [])

    def test_rank_order(self) -> None:
        combos = [
            combo(chart="z", sa_rbac_risk="High", image_level="Exploited", kev=9),
            combo(chart="y", sa_rbac_risk="Critical", image_level="High", likely=5),
            combo(chart="x", sa_rbac_risk="Critical", image_level="Exploited", kev=1),
            combo(chart="w", sa_rbac_risk="Critical", image_level="Exploited", kev=2),
            combo(chart="v", sa_rbac_risk="Critical", image_level="Exploited", kev=2, critical=3),
            combo(chart="u", sa_rbac_risk="Critical", image_level="Exploited", kev=2, critical=3),
        ]
        combos.sort(key=publish.combo_sort_key)
        self.assertEqual([c["chart"] for c in combos], ["u", "v", "w", "x", "y", "z"])

    def test_normalize_summary_combo(self) -> None:
        summary = load("summary")
        raw = summary["versions"]["acme/web/2.0.0"]["combos"][0]
        c = publish.normalize_combo(raw, "acme/web/2.0.0", "acme/web", "v2.0.0", summary["images"], {})
        self.assertEqual(c, {
            "chart": "acme/web", "version": "v2.0.0", "key": "acme/web/2.0.0", "url": "/charts/acme/web/2.0.0/",
            "kind": "Deployment", "workload": "web", "container": "web", "serviceAccountName": "web",
            "namespace": "default", "sa_rbac_risk": "Critical", "image": "acme/web:2.0",
            "canonical": "docker.io/acme/web:2.0", "image_level": "Exploited", "kev": 1, "likely": 1,
            "kev_ids": ["CVE-2024-0001"], "likely_ids": ["CVE-2024-0002"], "critical": 1, "high": 2,
        })


    def test_normalize_report_combo(self) -> None:
        # vulnscan.report layout: 'image' is the raw ref, 'canonical' the normalized one, 'likely' a count.
        raw = {"chart": "beta/Api", "version": "0.1.0", "workload_kind": "StatefulSet", "workload_name": "api",
               "container": "api", "serviceAccountName": "api", "namespace": "beta", "sa_rbac_risk": "High",
               "image": "beta/api:0.1", "canonical": "docker.io/beta/api:0.1", "image_level": "High", "kev": 0,
               "likely": 2, "kev_ids": [], "likely_ids": ["GHSA-aaaa-bbbb-cccc"], "critical": 1, "high": 0}
        c = publish.normalize_combo(raw, "beta/Api/0.1.0", "beta/Api", "0.1.0", {}, {})
        self.assertEqual((c["kind"], c["workload"], c["image"], c["canonical"], c["image_level"], c["likely"], c["critical"]),
                         ("StatefulSet", "api", "beta/api:0.1", "docker.io/beta/api:0.1", "High", 2, 1))


class SummaryDetailsTests(unittest.TestCase):
    def test_summary_top_is_used_without_scan(self) -> None:
        summary = load("summary")
        summary["images"]["docker.io/beta/api:0.1"].update(
            top=[{"id": "CVE-2024-9", "severity": "CRITICAL", "cvss": 9.81, "kev": False, "likely": True,
                  "fixed": "1.0, 1.1, 1.2, 1.3, 1.4", "pkg": "lib"}],
            kev_ids=[], likely_ids=["CVE-2024-9"], scanned_at="2026-11-03T00:00:00Z")
        self.assertTrue(publish.needs_scan(summary))  # acme/web:2.0 still has no 'top'
        docs = build_fixture(summary=summary, scan={}, enrichment={})
        rec = docs["images"]["docker.io/beta/api:0.1"]
        self.assertEqual(rec["top"], [["CVE-2024-9", "CRITICAL", 9.8, 0, 1, "1.0, 1.1, 1.2 +2", "lib"]])
        self.assertEqual(rec["at"], "2026-11-03")
        self.assertEqual(docs["versions"]["beta/Api/0.1.0"]["combos"][0]["likely_ids"], ["CVE-2024-9"])

    def test_needs_scan_false_when_all_have_top(self) -> None:
        self.assertFalse(publish.needs_scan({"images": {"a": {"status": "ok", "top": []}, "b": {"status": "unavailable"}}}))


class BuildTests(unittest.TestCase):
    def test_versions(self) -> None:
        docs = build_fixture()
        versions = docs["versions"]
        # Charts without images are not published; every version (not only latest) is.
        self.assertEqual(sorted(versions), ["acme/web/1.0.0", "acme/web/2.0.0", "beta/Api/0.1.0"])
        web = versions["acme/web/2.0.0"]
        self.assertEqual({k: web[k] for k in ("lvl", "partial", "kev", "crit", "high")},
                         {"lvl": "Exploited", "partial": True, "kev": 1, "crit": 1, "high": 2})
        # Invalid refs have no canonical image and are left out.
        self.assertEqual(web["imgs"], {"acme/web:2.0": "docker.io/acme/web:2.0", "quay.io/acme/sidecar:1.0": "quay.io/acme/sidecar:1.0"})
        self.assertEqual(len(web["combos"]), 1)
        # No rollup in summary: level, partial and combos are computed here.
        api = versions["beta/Api/0.1.0"]
        self.assertEqual((api["lvl"], api["partial"], api["crit"]), ("High", False, 1))
        self.assertEqual([(c["serviceAccountName"], c["sa_rbac_risk"], c["image_level"], c["likely_ids"]) for c in api["combos"]],
                         [("api", "High", "High", ["GHSA-aaaa-bbbb-cccc"])])
        self.assertEqual(versions["acme/web/1.0.0"]["lvl"], "Unknown")
        # every main image of 1.0.0 is still waiting for a scan → flagged pending (others carry no flag)
        self.assertIs(versions["acme/web/1.0.0"].get("pending"), True)
        self.assertNotIn("pending", web)
        self.assertNotIn("pending", api)

    def test_old_per_chart_summary_layout(self) -> None:
        summary = load("summary")
        rollup = summary.pop("versions")["acme/web/2.0.0"]
        summary["charts"] = {"acme/web": dict(rollup, version="v2.0.0")}
        docs = build_fixture(summary=summary)
        self.assertEqual(docs["versions"]["acme/web/2.0.0"]["partial"], True)
        self.assertEqual(docs["versions"]["acme/web/2.0.0"]["combos"][0]["kev_ids"], ["CVE-2024-0001"])

    def test_images_and_meta(self) -> None:
        docs = build_fixture()
        self.assertEqual(docs["images"]["docker.io/acme/web:1.0"], {"lvl": "Unknown", "st": "pending", "rs": "sbom_quota"})
        self.assertEqual(docs["images"]["quay.io/acme/sidecar:1.0"]["st"], "unavailable")
        self.assertEqual(docs["meta"], {
            "generated_at": "2026-11-05T07:00:00Z", "weights_version": 2,
            "trivy": {"version": "0.76.1", "db_updated_at": "2026-11-05T01:00:00Z"},
            "cvenow": {"coverage_pct": 42.5, "requests": 120},
            "images_total": 4, "images_scanned": 2, "images_pending": 1,
            "versions_total": 4, "versions_with_data": 2,
        })

    def test_landscape_latest_only(self) -> None:
        land = build_fixture()["landscape"]
        self.assertEqual([(c["chart"], c["sa_rbac_risk"], c["image_level"]) for c in land["combos"]],
                         [("acme/web", "Critical", "Exploited"), ("beta/Api", "High", "High")])
        self.assertEqual(land["combos"][1]["url"], "/charts/beta/api/0.1.0/")
        self.assertEqual(land["distribution"]["images"]["Exploited"], 1)
        self.assertEqual(land["distribution"]["images"]["Unknown"], 1)  # sidecar; web:1.0 is not latest
        self.assertEqual(land["distribution"]["charts"]["Exploited"], 1)
        self.assertEqual(land["stats"], {"workloads_total": 5, "workloads_critical_or_high_rbac": 3, "combos_total": 2,
                                         "combos_kev": 1, "charts_with_combos": 2, "images_exploited": 1})
        self.assertEqual((land["coverage"]["images"], land["coverage"]["images_scanned"], land["coverage"]["charts"]),
                         (3, 2, 3))
        self.assertEqual(land["distribution"]["charts"]["N/A"], 1)  # gamma/empty has no workloads

    def test_landscape_workload_counts_from_rollup(self) -> None:
        summary = load("summary")
        summary["versions"]["acme/web/2.0.0"].update(workloads=10, workloads_rbac=7)
        stats = build_fixture(summary=summary)["landscape"]["stats"]
        self.assertEqual((stats["workloads_total"], stats["workloads_critical_or_high_rbac"]), (11, 8))

    def test_latest_inferred_when_flags_missing(self) -> None:
        inv = load("inventory")
        for c in inv["charts"]:
            c.pop("latest")
        land = build_fixture(inventory=inv)["landscape"]
        self.assertEqual(land["coverage"]["charts"], 3)
        self.assertNotIn("acme/web/1.0.0", {c["key"] for c in land["combos"]})

    def test_missing_scan_and_enrichment(self) -> None:
        docs = build_fixture(scan={}, enrichment={})
        self.assertEqual(docs["images"]["docker.io/acme/web:2.0"]["top"], [])
        self.assertEqual(docs["images"]["docker.io/acme/web:2.0"]["at"], "2026-11-05")  # provenance scan date
        self.assertEqual(docs["versions"]["beta/Api/0.1.0"]["combos"][0]["kev_ids"], [])

    def test_version_combos_capped(self) -> None:
        inv = load("inventory")
        api = inv["charts"][2]["images"][0]
        api["workloads"] = [dict(api["workloads"][0], workloadName=f"api-{i:02d}") for i in range(30)]
        docs = build_fixture(inventory=inv)
        self.assertEqual(len(docs["versions"]["beta/Api/0.1.0"]["combos"]), publish.VERSION_COMBOS)
        self.assertEqual(docs["landscape"]["stats"]["combos_total"], 31)
        self.assertEqual(len(docs["landscape"]["combos"]), publish.LANDSCAPE_COMBOS)


class WriteTests(unittest.TestCase):
    def test_write_is_deterministic_and_prunes(self) -> None:
        docs = build_fixture()
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "vulns"
            stale = out / "images" / "zz.json"
            stale.parent.mkdir(parents=True)
            stale.write_text("{}")
            first = publish.write_output(docs, out)
            self.assertFalse(stale.exists())
            self.assertEqual(first["removed"], 1)
            self.assertEqual(first["changed"], first["files"])
            again = publish.write_output(copy.deepcopy(docs), out)
            self.assertEqual(again["changed"], 0)

            key = "acme/web/2.0.0"
            shard = out / "versions" / f"{publish.shard(key)}.json"
            text = shard.read_text()
            self.assertIn(f'"{key}":{{', text)  # one compact record per line
            self.assertEqual(json.loads(text)[key]["lvl"], "Exploited")
            for path in out.rglob("*.json"):
                json.loads(path.read_text())
            self.assertFalse(list(out.rglob("*.tmp")))

    def test_dumps_records_empty(self) -> None:
        self.assertEqual(json.loads(publish.dumps_records({})), {})


class CliTests(unittest.TestCase):
    def run_main(self, *extra: str, summary: Path | None = None, out: Path | None = None) -> tuple[int, Path, str]:
        out = out or Path(tempfile.mkdtemp()) / "data" / "vulns"
        args = ["--inventory", str(FIXTURES / "inventory.json"), "--summary", str(summary or FIXTURES / "summary.json"),
                "--scan", str(FIXTURES / "scan.json"), "--enrichment", str(FIXTURES / "enrichment.json"),
                "--output", str(out), *extra]
        err = io.StringIO()
        with redirect_stdout(io.StringIO()), redirect_stderr(err):
            rc = publish.main(args)
        return rc, out, err.getvalue()

    def test_main_writes_files(self) -> None:
        rc, out, _ = self.run_main()
        self.assertEqual(rc, 0)
        self.assertTrue((out / "meta.json").is_file())
        self.assertTrue((out / "landscape.json").is_file())
        self.assertEqual(len(list((out / "versions").glob("*.json"))), len({publish.shard(k) for k in
                                                                          ("acme/web/1.0.0", "acme/web/2.0.0", "beta/Api/0.1.0")}))

    def test_size_cap(self) -> None:
        rc, _, err = self.run_main("--max-mb", "0.0001")
        self.assertEqual(rc, 1)
        self.assertIn("above --max-mb", err)

    def test_regression_guard(self) -> None:
        out = Path(tempfile.mkdtemp()) / "data" / "vulns"
        out.mkdir(parents=True)
        previous = {"images_scanned": 100, "versions_with_data": 2, "versions_total": 4}
        (out / "meta.json").write_text(json.dumps(previous))
        stale = out / "versions" / "zz.json"
        stale.parent.mkdir()
        stale.write_text("{}")
        rc, _, err = self.run_main(out=out)
        self.assertEqual(rc, 1)
        self.assertIn("images_scanned would drop from 100 to 2", err)
        self.assertTrue(stale.exists())  # nothing written or pruned
        self.assertEqual(json.loads((out / "meta.json").read_text()), previous)
        rc, _, _ = self.run_main("--allow-drop", out=out)
        self.assertEqual(rc, 0)
        self.assertFalse(stale.exists())
        # same numbers as published: fine
        rc, _, _ = self.run_main(out=out)
        self.assertEqual(rc, 0)

    def test_regression_errors(self) -> None:
        meta = {"images_scanned": 85, "versions_with_data": 10, "versions_total": 100}
        self.assertEqual(publish.regression_errors(None, meta, 0.2), [])
        self.assertEqual(publish.regression_errors({"images_scanned": 100, "versions_total": 100}, meta, 0.2), [])
        errs = publish.regression_errors({"images_scanned": 100, "versions_with_data": 0, "versions_total": 28000},
                                         meta, 0.2)
        self.assertEqual(len(errs), 1)
        self.assertIn("versions_total", errs[0])

    def test_missing_summary(self) -> None:
        rc, _, err = self.run_main(summary=FIXTURES / "nope.json")
        self.assertEqual(rc, 1)
        self.assertIn("cannot read summary", err)


if __name__ == "__main__":
    unittest.main()
