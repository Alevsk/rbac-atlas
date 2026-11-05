"""Tests for vulnscan.inventory."""

from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from vulnscan import inventory as inv

FIXTURES = Path(__file__).parent / "fixtures" / "inventory" / "manifests"


class VersionTest(unittest.TestCase):
    def test_parse_manifest_name(self) -> None:
        self.assertEqual(inv.parse_manifest_name(Path("my-org__my-chart__1.2.3.json")), ("my-org", "my-chart", "1.2.3"))
        self.assertIsNone(inv.parse_manifest_name(Path("custom-values.json")))
        self.assertIsNone(inv.parse_manifest_name(Path("a__b.json")))
        self.assertIsNone(inv.parse_manifest_name(Path("a__b__c__d.json")))
        self.assertIsNone(inv.parse_manifest_name(Path("a__b__1.0.yaml")))

    def test_is_prerelease(self) -> None:
        for v in ("1.2.0-rc1", "0.0.0-ci-run.9", "7.2.1-0", "v0.24.0-rc.0", "2.34.0-SNAPSHOT.5"):
            self.assertTrue(inv.is_prerelease(v), v)
        for v in ("1.2.0", "v1.2", "10.0.0+521", "2026.5.1004"):
            self.assertFalse(inv.is_prerelease(v), v)

    def test_version_ordering(self) -> None:
        ordered = ["0.9.0", "1.0.0-alpha.1", "1.0.0-alpha.2", "1.0.0-beta", "1.0.0-rc.1", "1.0.0", "1.2", "1.10.0", "v2.0.0", "10.0.0+521"]
        self.assertEqual(sorted(reversed(ordered), key=inv.version_key), ordered)
        self.assertEqual(sorted(["1.0.0-alpha.10", "1.0.0-alpha.9"], key=inv.version_key), ["1.0.0-alpha.9", "1.0.0-alpha.10"])

    def test_latest_versions_skips_prereleases(self) -> None:
        paths = [Path(p) for p in ("a__x__1.9.0.json", "a__x__1.10.0.json", "a__x__2.0.0-rc1.json", "b__y__0.1.0-alpha.1.json", "b__y__0.1.0-alpha.2.json")]
        latest = inv.latest_versions(paths)
        self.assertEqual(latest[("a", "x")][0], "1.10.0")
        self.assertEqual(latest[("b", "y")][0], "0.1.0-alpha.2")


class WorkloadTest(unittest.TestCase):
    def test_is_test_workload(self) -> None:
        def wl(t: str, wn: str, cn: str = "c") -> dict:
            return {"workloadType": t, "workloadName": wn, "containerName": cn}

        self.assertTrue(inv.is_test_workload(wl("Pod", "grafana-test")))
        self.assertTrue(inv.is_test_workload(wl("Pod", "x-test-connection")))
        self.assertTrue(inv.is_test_workload(wl("Job", "test-runner")))
        self.assertTrue(inv.is_test_workload(wl("Pod", "probe", "Test")))
        self.assertFalse(inv.is_test_workload(wl("Deployment", "grafana-test")))
        self.assertFalse(inv.is_test_workload(wl("Pod", "contest-latest")))
        self.assertFalse(inv.is_test_workload(wl("Job", "attestation")))

    def test_sa_rbac_risk(self) -> None:
        index = inv.sa_risk_index(
            [
                {"serviceAccountName": "a", "namespace": "ns1", "riskLevel": "Low"},
                {"serviceAccountName": "a", "namespace": "ns1", "riskLevel": "High"},
                {"serviceAccountName": "a", "namespace": "ns2", "riskLevel": "Critical"},
                {"serviceAccountName": "b", "namespace": "", "riskLevel": "Medium"},
                {"serviceAccountName": "c", "namespace": "ns1", "riskLevel": "Bogus"},
            ]
        )
        self.assertEqual(inv.sa_rbac_risk(index, "a", "ns1"), "High")
        self.assertEqual(inv.sa_rbac_risk(index, "a", ""), "Critical")
        # no permission in the workload's namespace: fall back to the SA name (json2hugo groups by name)
        self.assertEqual(inv.sa_rbac_risk(index, "a", "ns3"), "Critical")
        self.assertEqual(inv.sa_rbac_risk(index, "b", "anything"), "Medium")
        self.assertIsNone(inv.sa_rbac_risk(index, "c", "ns1"))
        self.assertIsNone(inv.sa_rbac_risk(index, "", "ns1"))
        self.assertIsNone(inv.sa_rbac_risk(index, "missing", "ns1"))

    def test_sa_rbac_risk_falls_back_to_name_across_namespaces(self) -> None:
        # istiod: workload rendered in 'default', all bindings in 'istio-system'
        index = inv.sa_risk_index(
            [
                {"serviceAccountName": "istiod", "namespace": "istio-system", "riskLevel": "High"},
                {"serviceAccountName": "istiod", "namespace": "istio-system", "riskLevel": "Critical"},
                {"serviceAccountName": "istiod", "namespace": "istio-system", "riskLevel": "Low"},
            ]
        )
        self.assertEqual(inv.sa_rbac_risk(index, "istiod", "default"), "Critical")
        manifest = {
            "serviceAccountPermissions": [
                {"serviceAccountName": "istiod", "namespace": "istio-system", "riskLevel": "Critical"}
            ],
            "serviceAccountWorkloads": [
                {"serviceAccountName": "istiod", "namespace": "default", "workloadType": "Deployment",
                 "workloadName": "istiod", "containerName": "discovery", "image": "registry.istio.io/release/pilot:1.30.3"}
            ],
        }
        (entry,) = inv.chart_images(manifest)
        self.assertEqual(entry["workloads"][0]["sa_rbac_risk"], "Critical")


class BuildInventoryTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.doc = inv.build_inventory(FIXTURES)
        cls.charts = {c["chart"]: c for c in cls.doc["charts"]}

    def test_top_level_shape(self) -> None:
        self.assertEqual(self.doc["scope"], "latest")
        for key in ("generated_at", "charts", "images", "invalid", "stats"):
            self.assertIn(key, self.doc)

    def test_latest_chart_selection(self) -> None:
        self.assertEqual(set(self.charts), {"acme/web", "beta/tool"})
        web = self.charts["acme/web"]
        self.assertEqual((web["org"], web["name"], web["version"]), ("acme", "web", "1.10.0"))
        self.assertEqual(web["manifest"], "manifests/acme__web__1.10.0.json")
        self.assertEqual(self.charts["beta/tool"]["version"], "0.1.0-alpha.2")
        self.assertEqual(self.doc["stats"]["prerelease_selected"], 1)

    def test_chart_images(self) -> None:
        images = {e["ref"]: e for e in self.charts["acme/web"]["images"]}
        self.assertEqual(images["/grafana/grafana:10.3.3"]["canonical"], "docker.io/grafana/grafana:10.3.3")
        busybox = images["busybox"]
        self.assertEqual(busybox["role"], "test")
        self.assertIsNone(busybox["workloads"][0]["sa_rbac_risk"])
        web = images["acme/web:1.10.0"]
        self.assertEqual(web["role"], "main")
        self.assertEqual(web["workloads"][0]["sa_rbac_risk"], "Critical")
        self.assertEqual(set(web["workloads"][0]), {"serviceAccountName", "namespace", "workloadType", "workloadName", "containerName", "role", "sa_rbac_risk"})
        # namespace mismatch: 'other' only has permissions in kube-system -> falls back to the SA name
        self.assertEqual(images["registry-1.docker.io/bitnami/redis:latest"]["workloads"][0]["sa_rbac_risk"], "High")
        self.assertIsNone(images["{{ .Values.image }}"]["canonical"])

    def test_images_map_merges_aliases(self) -> None:
        redis = self.doc["images"]["docker.io/bitnami/redis:latest"]
        self.assertEqual(redis["registry"], "docker.io")
        self.assertEqual(redis["repository"], "bitnami/redis")
        self.assertEqual(redis["tag"], "latest")
        self.assertIsNone(redis["digest"])
        self.assertEqual(redis["flags"], ["mutable_tag"])
        self.assertEqual(redis["charts"], ["acme/web@1.10.0"])
        self.assertEqual(redis["roles"], ["main"])
        self.assertEqual(redis["refs"], ["docker.io/bitnami/redis:latest", "registry-1.docker.io/bitnami/redis:latest"])
        self.assertEqual(self.doc["images"]["docker.io/library/busybox:latest"]["roles"], ["test"])
        pinned = next(v for k, v in self.doc["images"].items() if k.startswith("registry.k8s.io/"))
        self.assertEqual(pinned["digest"], "sha256:" + "a" * 64)
        self.assertEqual(pinned["charts"], ["beta/tool@0.1.0-alpha.2"])

    def test_invalid_and_stats(self) -> None:
        self.assertEqual(self.doc["invalid"], [{"ref": "{{ .Values.image }}", "reason": "templated", "chart": "acme/web@1.10.0"}])
        stats = self.doc["stats"]
        self.assertEqual(stats["charts"], 2)
        self.assertEqual(stats["unique_images"], 5)
        self.assertEqual(stats["image_refs"], 7)
        self.assertEqual(stats["invalid_by_reason"], {"templated": 1})
        self.assertEqual(stats["test_only_images"], 1)
        self.assertEqual(stats["flags"], {"digest_pinned": 1, "implicit_latest": 1, "mutable_tag": 2})

    def test_latest_scope_version_fields(self) -> None:
        web = self.charts["acme/web"]
        self.assertEqual((web["page_version"], web["key"], web["latest"]), ("1.10.0", "acme/web/1.10.0", True))
        self.assertEqual({img["priority"] for img in self.doc["images"].values()}, {0})
        self.assertEqual(self.doc["stats"]["versions"], 2)

    def test_cli_writes_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out" / "inventory.json"
            with redirect_stdout(io.StringIO()) as buf:
                rc = inv.main(["--manifests", str(FIXTURES), "--output", str(out)])
            self.assertEqual(rc, 0)
            self.assertIn("2 charts", buf.getvalue())
            data = json.loads(out.read_text())
            self.assertEqual(len(data["images"]), 5)



def _manifest(version: str, image: str) -> dict:
    return {"metadata": {"version": version},
            "serviceAccountWorkloads": [{"serviceAccountName": "sa", "namespace": "ns", "workloadType": "Deployment",
                                         "workloadName": "w", "containerName": "c", "image": image}],
            "serviceAccountPermissions": [{"serviceAccountName": "sa", "namespace": "ns", "riskLevel": "Critical"}]}


class AllScopeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.doc = inv.build_inventory(FIXTURES, "all")
        cls.by_key = {c["key"]: c for c in cls.doc["charts"]}

    def test_every_version_with_latest_flag(self) -> None:
        self.assertEqual(self.doc["scope"], "all")
        self.assertEqual(sorted(self.by_key), ["acme/web/1.10.0", "acme/web/1.11.0-rc1", "acme/web/1.9.0",
                                               "beta/tool/0.1.0-alpha.1", "beta/tool/0.1.0-alpha.2"])
        self.assertEqual(sorted(k for k, c in self.by_key.items() if c["latest"]),
                         ["acme/web/1.10.0", "beta/tool/0.1.0-alpha.2"])
        stats = self.doc["stats"]
        self.assertEqual((stats["charts"], stats["versions"], stats["unique_images"], stats["latest_images"]),
                         (2, 5, 7, 5))
        self.assertEqual(stats["prerelease_selected"], 1)  # counted for latest versions only

    def test_priority_and_order(self) -> None:
        images = self.doc["images"]
        self.assertEqual(images["docker.io/acme/web:1.10.0"]["priority"], 0)
        # 1.11.0-rc1 is newer than the latest stable 1.10.0 but not latest: rank 1; 1.9.0: rank 2
        self.assertEqual(images["docker.io/acme/web:1.11.0-rc1"]["priority"], 1)
        self.assertEqual(images["docker.io/acme/web:1.9.0"]["priority"], 2)
        self.assertEqual(list(images)[-2:], ["docker.io/acme/web:1.11.0-rc1", "docker.io/acme/web:1.9.0"])
        priorities = [img["priority"] for img in images.values()]
        self.assertEqual(priorities, sorted(priorities))

    def test_shared_image_takes_best_priority(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp) / "manifests"
            d.mkdir()
            for version, image in (("1.0.0", "x/shared:1"), ("2.0.0", "x/shared:1"), ("3.0.0", "x/new:3")):
                (d / f"o__c__{version}.json").write_text(json.dumps(_manifest(version, image)))
            doc = inv.build_inventory(d, "all")
        self.assertEqual(doc["images"]["docker.io/x/new:3"]["priority"], 0)
        self.assertEqual(doc["images"]["docker.io/x/shared:1"]["priority"], 1)
        self.assertEqual(doc["images"]["docker.io/x/shared:1"]["charts"], ["o/c@1.0.0", "o/c@2.0.0"])

    def test_page_version_follows_json2hugo(self) -> None:
        self.assertEqual(inv.page_version({"metadata": {"version": "v3.18.6-1"}}, "v3.18.6"), "3.18.6-1")
        self.assertEqual(inv.page_version({}, "v1.0"), "1.0")
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp) / "manifests"
            d.mkdir()
            # o__c__1.0.0 claims metadata.version 1.1.0, colliding with the real 1.1.0 page: the real one wins
            (d / "o__c__1.0.0.json").write_text(json.dumps(_manifest("1.1.0", "x/a:1")))
            (d / "o__c__v1.1.0.json").write_text(json.dumps(_manifest("v1.1.0", "x/b:1")))
            (d / "o__c__0.9.0.json").write_text(json.dumps(_manifest("v0.9.0-1", "x/c:1")))
            doc = inv.build_inventory(d, "all")
        by_key = {c["key"]: c for c in doc["charts"]}
        self.assertEqual(sorted(by_key), ["o/c/0.9.0-1", "o/c/1.1.0"])
        self.assertEqual(by_key["o/c/1.1.0"]["version"], "v1.1.0")
        self.assertEqual(doc["stats"]["page_collisions"], 1)

    def test_bad_scope(self) -> None:
        with self.assertRaises(ValueError):
            inv.build_inventory(FIXTURES, "some")

    def test_cli_scope_all(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "inventory.json"
            with redirect_stdout(io.StringIO()) as buf:
                rc = inv.main(["--manifests", str(FIXTURES), "--scope", "all", "--output", str(out)])
            self.assertEqual(rc, 0)
            self.assertIn("5 versions", buf.getvalue())
            self.assertEqual(json.loads(out.read_text())["scope"], "all")


if __name__ == "__main__":
    unittest.main()
