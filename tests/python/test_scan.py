"""Unit tests for vulnscan.scan (no network, no real trivy/crane: commands go through a fake runner)."""

from __future__ import annotations

import gzip
import json
import tempfile
import threading
import unittest
from unittest import mock
from pathlib import Path
from typing import Any

from vulnscan import scan
from vulnscan.scan import Proc, Scanner, build_scan, classify_error, pick_cvss, summarize_report

FIXTURES = Path(__file__).parent / "fixtures" / "scan"
TRIVY_REPORT = json.loads((FIXTURES / "trivy_ingress_nginx.json").read_text())
D1 = "sha256:" + "1" * 64
D2 = "sha256:" + "2" * 64
D3 = "sha256:" + "3" * 64
_quiet = mock.patch.object(scan, "log", lambda message: None)


def setUpModule() -> None:
    _quiet.start()


def tearDownModule() -> None:
    _quiet.stop()


def img(registry: str, repository: str, tag: str | None, digest: str | None = None, roles=("main",)) -> dict:
    return {"registry": registry, "repository": repository, "tag": tag, "digest": digest,
            "flags": [], "charts": ["o/c@1.0.0"], "roles": list(roles)}


class FakeRunner:
    """Emulates crane/trivy. `digests` maps 'repo:tag' → digest or ('error', stderr); `trivy_errors` maps
    'repo@digest' → stderr for `trivy image` failures."""

    def __init__(self, digests: dict[str, Any] | None = None, trivy_errors: dict[str, str] | None = None,
                 report: dict | None = None) -> None:
        self.digests = digests or {}
        self.trivy_errors = trivy_errors or {}
        self.report = report if report is not None else TRIVY_REPORT
        self.calls: list[list[str]] = []
        self._lock = threading.Lock()

    def count(self, *prefix: str) -> int:
        return sum(1 for c in self.calls if tuple(c[: len(prefix)]) == prefix)

    def __call__(self, cmd: list[str], timeout: float) -> Proc:
        with self._lock:
            self.calls.append(cmd)
        tool, sub = cmd[0], cmd[1]
        if tool == "crane" and sub == "digest":
            assert cmd[2:4] == ["--platform", "linux/amd64"]
            value = self.digests.get(cmd[4])
            if isinstance(value, str):
                return Proc(0, value + "\n", "")
            stderr = value[1] if value else f"Error: GET https://x/v2/manifests: MANIFEST_UNKNOWN: {cmd[4]}"
            return Proc(1, "", stderr)
        if tool == "trivy" and sub == "version":
            return Proc(0, json.dumps({"Version": "0.76.1", "VulnerabilityDB": {
                "Version": 2, "UpdatedAt": "2026-11-04T19:02:00Z"}}), "")
        out = Path(cmd[cmd.index("-o") + 1])
        if tool == "trivy" and sub == "image":
            target = cmd[-1]
            if target in self.trivy_errors:
                return Proc(1, "", "FATAL\tFatal error\trun error:\n\t* remote error: " + self.trivy_errors[target])
            out.write_text(json.dumps({"bomFormat": "CycloneDX", "metadata": {"component": {"name": target}}}))
            return Proc(0, "", "INFO done")
        if tool == "trivy" and sub == "sbom":
            sbom = json.loads(Path(cmd[-1]).read_text())
            assert sbom["bomFormat"] == "CycloneDX"
            out.write_text(json.dumps(self.report))
            return Proc(0, "", "")
        raise AssertionError(f"unexpected command {cmd}")


class ClassifyErrorTest(unittest.TestCase):
    def test_reasons(self) -> None:
        cases = {
            "Error: GET https://index.docker.io/v2/x/manifests/v9: MANIFEST_UNKNOWN: manifest unknown": "not_found",
            "NAME_UNKNOWN: repository name not known to registry": "not_found",
            "Error: no child with platform linux/amd64 in index mcr.microsoft.com/windows/nanoserver:ltsc2022":
                "no_amd64",
            "UNAUTHORIZED: authentication required": "unauthorized",
            "DENIED: requested access to the resource is denied": "unauthorized",
            "TOOMANYREQUESTS: You have reached your pull rate limit": "rate_limited",
            "unexpected status code 429 Too Many Requests": "rate_limited",
            "timeout after 90s": "timeout",
            "context deadline exceeded": "timeout",
            "connection reset by peer": "error",
            "cannot execute crane: [Errno 2] No such file or directory": "error",
            "": "error",
        }
        for stderr, expected in cases.items():
            self.assertEqual(classify_error(stderr), expected, stderr)

    def test_last_line_wins_over_retried_429(self) -> None:
        stderr = "retrying after 429 Too Many Requests\nError: GET https://m/v2/x: MANIFEST_UNKNOWN: Failed to fetch"
        self.assertEqual(classify_error(stderr), "not_found")


class PickCvssTest(unittest.TestCase):
    def test_source_preference(self) -> None:
        cvss = {
            "redhat": {"V3Score": 6.7, "V3Vector": "CVSS:3.1/AV:L"},
            "bitnami": {"V3Score": 9.0, "V3Vector": "CVSS:3.1/AV:N"},
            "nvd": {"V3Score": 9.8, "V3Vector": "CVSS:3.0/AV:N"},
        }
        self.assertEqual(pick_cvss(cvss), {"score": 9.8, "vector": "CVSS:3.0/AV:N", "version": "3.0", "source": "nvd"})
        del cvss["nvd"]
        self.assertEqual(pick_cvss(cvss)["source"], "redhat")
        del cvss["redhat"]
        self.assertEqual(pick_cvss(cvss)["source"], "bitnami")
        self.assertEqual(pick_cvss({"ghsa": {"V3Score": 7.5, "V3Vector": "CVSS:3.1/X"}, "amazon": {"V3Score": 1}})
                         ["source"], "ghsa")

    def test_version_preference_within_source(self) -> None:
        nvd = {"V2Score": 5.0, "V2Vector": "AV:N/AC:L/Au:N/C:P/I:N/A:N",
               "V40Score": 8.7, "V40Vector": "CVSS:4.0/AV:N"}
        self.assertEqual(pick_cvss({"nvd": nvd}),
                         {"score": 8.7, "vector": "CVSS:4.0/AV:N", "version": "4.0", "source": "nvd"})
        del nvd["V40Score"], nvd["V40Vector"]
        self.assertEqual(pick_cvss({"nvd": nvd})["version"], "2.0")
        nvd["V3Score"], nvd["V3Vector"] = 7.5, "CVSS:3.1/AV:N"
        self.assertEqual(pick_cvss({"nvd": nvd})["version"], "3.1")

    def test_empty(self) -> None:
        self.assertIsNone(pick_cvss(None))
        self.assertIsNone(pick_cvss({}))
        self.assertIsNone(pick_cvss({"nvd": {}}))
        self.assertEqual(pick_cvss({"nvd": {}, "redhat": {"V3Score": 5.5}})["source"], "redhat")


class SummarizeReportTest(unittest.TestCase):
    def test_real_trivy_fixture(self) -> None:
        s = summarize_report(TRIVY_REPORT)
        self.assertEqual(s["os"], {"family": "alpine", "name": "3.19.0", "eosl": True})
        keys = [(f["id"], f["pkg"], f["installed"]) for f in s["findings"]]
        self.assertEqual(len(keys), len(set(keys)))
        # stdlib CVE appears in two Go binaries with the same (id, pkg, installed) → one finding
        self.assertEqual(sum(1 for k in keys if k[0] == "CVE-2024-24790"), 1)
        # busybox CVE affects three distinct apk packages → three findings, one unique ID
        self.assertEqual(sum(1 for k in keys if k[0] == "CVE-2023-42363"), 3)
        self.assertEqual(s["counts"], {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 1, "LOW": 0, "UNKNOWN": 0})
        stdlib = next(f for f in s["findings"] if f["id"] == "CVE-2024-24790")
        self.assertEqual(stdlib["vendor_ids"], ["GO-2024-2887"])
        self.assertEqual(stdlib["class"], "lang-pkgs")
        self.assertEqual(stdlib["pkg_type"], "gobinary")
        self.assertEqual(stdlib["status"], "fixed")
        self.assertEqual(stdlib["cvss"]["source"], "nvd")
        runc = next(f for f in s["findings"] if f["id"] == "CVE-2024-21626")
        self.assertEqual(runc["cwes"], ["CWE-403", "CWE-668", "CWE-200"])
        self.assertEqual(runc["fixed"], "1.1.12")
        self.assertEqual(s["findings"][0]["severity"], "CRITICAL")  # sorted most severe first
        mods = [tuple(m) for m in s["go_modules"]]
        self.assertEqual(mods, [("github.com/armon/go-proxyproto", "v0.1.0"), ("github.com/beorn7/perks", "v1.0.1"),
                                ("github.com/go-logr/logr", "v1.3.0"), ("github.com/mitchellh/go-ps", "v1.0.0")])
        self.assertFalse(any(m[0] == "stdlib" for m in mods))
        self.assertFalse(any(m[0] == "k8s.io/ingress-nginx" for m in mods))  # versionless main module
        self.assertEqual(mods, sorted(set(mods)))

    def test_unique_id_counts_take_worst_severity_and_handle_missing(self) -> None:
        report = {"Results": [
            {"Class": "os-pkgs", "Type": "debian", "Vulnerabilities": [
                {"VulnerabilityID": "CVE-1", "PkgName": "a", "InstalledVersion": "1", "Severity": "LOW",
                 "Status": "affected"},
                {"VulnerabilityID": "CVE-1", "PkgName": "b", "InstalledVersion": "1", "Severity": "HIGH"},
                {"VulnerabilityID": "TEMP-0001", "PkgName": "c", "InstalledVersion": "1", "Severity": "weird",
                 "FixedVersion": ""},
            ]},
            {"Class": "lang-pkgs", "Type": "gobinary", "Packages": [
                {"Name": "stdlib", "Version": "v1.22.0"}, {"Name": "example.com/app", "Version": "(devel)"},
                {"Name": "example.com/lib", "Version": "v0.1.0"}], "Vulnerabilities": None},
        ]}
        s = summarize_report(report)
        self.assertIsNone(s["os"])
        self.assertEqual(s["counts"]["HIGH"], 1)
        self.assertEqual(s["counts"]["LOW"], 0)
        self.assertEqual(s["counts"]["UNKNOWN"], 1)
        temp = next(f for f in s["findings"] if f["id"] == "TEMP-0001")
        self.assertIsNone(temp["fixed"])
        self.assertIsNone(temp["cvss"])
        self.assertEqual(s["go_modules"], [["example.com/lib", "v0.1.0"]])

    def test_empty_report(self) -> None:
        s = summarize_report({})
        self.assertEqual((s["findings"], s["go_modules"], s["os"]), ([], [], None))
        self.assertEqual(sum(s["counts"].values()), 0)


class ScannerTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.sbom_dir = Path(self._tmp.name) / "sbom"
        self.clock = "2026-11-04T12:00:00Z"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def scanner(self, runner: FakeRunner, cache: dict | None = None, **kw: Any) -> Scanner:
        return Scanner(runner=runner, sbom_dir=self.sbom_dir, resolve_cache=cache if cache is not None else {},
                       now=lambda: self.clock, **kw)


class ResolveTest(ScannerTestBase):
    def test_digest_pinned_skips_crane(self) -> None:
        runner = FakeRunner()
        r = self.scanner(runner).resolve("registry.k8s.io/a:v1@" + D1, img("registry.k8s.io", "a", "v1", D1))
        self.assertEqual(r, {"digest": D1, "pulled_from": None, "stale_resolve": False, "reason": None})
        self.assertEqual(runner.calls, [])

    def test_docker_tries_mirror_first(self) -> None:
        runner = FakeRunner({"mirror.gcr.io/library/redis:7": D1})
        cache: dict = {}
        r = self.scanner(runner, cache).resolve("docker.io/library/redis:7", img("docker.io", "library/redis", "7"))
        self.assertEqual((r["digest"], r["pulled_from"]), (D1, "mirror.gcr.io/library/redis"))
        self.assertEqual(runner.count("crane", "digest"), 1)
        self.assertEqual(cache["docker.io/library/redis:7"]["status"], "ok")
        self.assertEqual(cache["docker.io/library/redis:7"]["resolved_at"], self.clock)

    def test_docker_falls_back_to_docker_io(self) -> None:
        runner = FakeRunner({"docker.io/bitnami/x:1": D2})
        r = self.scanner(runner).resolve("docker.io/bitnami/x:1", img("docker.io", "bitnami/x", "1"))
        self.assertEqual((r["digest"], r["pulled_from"]), (D2, "docker.io/bitnami/x"))
        self.assertEqual([c[4] for c in runner.calls], ["mirror.gcr.io/bitnami/x:1", "docker.io/bitnami/x:1"])

    def test_fresh_cache_hit_and_expiry(self) -> None:
        cache = {"quay.io/a/b:1": {"digest": D1, "resolved_at": "2026-11-04T00:00:00Z", "status": "ok",
                                   "pulled_from": "quay.io/a/b"}}
        runner = FakeRunner({"quay.io/a/b:1": D2})
        s = self.scanner(runner, cache, resolve_max_age_hours=20)
        self.assertEqual(s.resolve("quay.io/a/b:1", img("quay.io", "a/b", "1"))["digest"], D1)
        self.assertEqual(runner.calls, [])
        self.clock = "2026-11-04T21:00:00Z"
        self.assertEqual(s.resolve("quay.io/a/b:1", img("quay.io", "a/b", "1"))["digest"], D2)
        self.assertEqual(cache["quay.io/a/b:1"]["digest"], D2)

    def test_failure_keeps_last_known_digest(self) -> None:
        cache = {"quay.io/a/b:1": {"digest": D1, "resolved_at": "2026-10-01T00:00:00Z", "status": "ok"}}
        runner = FakeRunner({"quay.io/a/b:1": ("error", "TOOMANYREQUESTS: slow down")})
        r = self.scanner(runner, cache).resolve("quay.io/a/b:1", img("quay.io", "a/b", "1"))
        self.assertEqual(r, {"digest": D1, "pulled_from": None, "stale_resolve": True, "reason": "rate_limited"})
        self.assertEqual(cache["quay.io/a/b:1"]["status"], "rate_limited")
        self.assertEqual(cache["quay.io/a/b:1"]["resolved_at"], "2026-10-01T00:00:00Z")
        # a non-ok cache entry is retried on the next call even though it is "fresh"
        runner.digests["quay.io/a/b:1"] = D2
        self.clock = "2026-11-04T12:30:00Z"
        self.assertEqual(self.scanner(runner, cache).resolve("quay.io/a/b:1", img("quay.io", "a/b", "1"))["digest"],
                         D2)

    def test_failure_without_history(self) -> None:
        runner = FakeRunner()
        r = self.scanner(runner).resolve("ghcr.io/a/b:nope", img("ghcr.io", "a/b", "nope"))
        self.assertEqual(r, {"digest": None, "pulled_from": None, "stale_resolve": False, "reason": "not_found"})

    def test_garbage_stdout_is_error(self) -> None:
        runner = FakeRunner({"ghcr.io/a/b:1": "not-a-digest"})
        self.assertEqual(self.scanner(runner).resolve("ghcr.io/a/b:1", img("ghcr.io", "a/b", "1"))["reason"], "error")


class ScanFlowTest(ScannerTestBase):
    IMAGES = {
        "docker.io/library/redis:7": img("docker.io", "library/redis", "7"),
        "registry.k8s.io/ingress-nginx/controller:v1@" + D2: img("registry.k8s.io", "ingress-nginx/controller",
                                                                 "v1", D2),
        "docker.io/bitnami/redis:bad": img("docker.io", "bitnami/redis", "bad"),
        "mcr.microsoft.com/windows/nanoserver:ltsc2022": img("mcr.microsoft.com", "windows/nanoserver", "ltsc2022",
                                                             roles=("test",)),
        "quay.io/a/alias:1": img("quay.io", "a/alias", "1"),  # same digest as redis → one SBOM
    }

    def runner(self) -> FakeRunner:
        return FakeRunner(
            {"mirror.gcr.io/library/redis:7": D1, "quay.io/a/alias:1": D1,
             "mcr.microsoft.com/windows/nanoserver:ltsc2022":
                 ("error", "Error: no child with platform linux/amd64 in index mcr.microsoft.com/...")},
        )

    def test_end_to_end_and_cache_reuse(self) -> None:
        runner = self.runner()
        cache: dict = {}
        doc = build_scan({"images": self.IMAGES, "invalid": [{"ref": "{{ .Values.image }}", "reason": "templated",
                                                              "chart": "o/c"}]},
                         self.scanner(runner, cache))
        images = doc["images"]
        self.assertEqual(doc["trivy"], {"version": "0.76.1", "db_version": 2, "db_updated_at": "2026-11-04T19:02:00Z"})
        redis = images["docker.io/library/redis:7"]
        self.assertEqual(redis["status"], "ok")
        self.assertEqual(redis["digest"], D1)
        self.assertEqual(redis["pulled_from"], "mirror.gcr.io/library/redis")
        self.assertFalse(redis["sbom_cached"])
        self.assertEqual(redis["scanned_at"], self.clock)
        self.assertEqual(redis["os"]["family"], "alpine")
        self.assertEqual(redis["counts"]["CRITICAL"], 1)
        self.assertTrue(redis["go_modules"])
        self.assertEqual(images["quay.io/a/alias:1"]["counts"], redis["counts"])
        pinned = images["registry.k8s.io/ingress-nginx/controller:v1@" + D2]
        self.assertEqual((pinned["status"], pinned["pulled_from"]), ("ok", "registry.k8s.io/ingress-nginx/controller"))
        bad = images["docker.io/bitnami/redis:bad"]
        self.assertEqual((bad["status"], bad["reason"], bad["digest"]), ("unavailable", "not_found", None))
        win = images["mcr.microsoft.com/windows/nanoserver:ltsc2022"]
        self.assertEqual((win["status"], win["reason"]), ("unavailable", "no_amd64"))
        inv = images["{{ .Values.image }}"]
        self.assertEqual((inv["status"], inv["reason"]), ("invalid", "templated"))
        for rec in images.values():
            for key in ("status", "reason", "digest", "pulled_from", "stale_resolve", "os", "sbom_cached",
                        "scanned_at", "findings", "go_modules", "counts"):
                self.assertIn(key, rec)

        image_calls = [c for c in runner.calls if c[:2] == ["trivy", "image"]]
        self.assertEqual(sorted(c[-1] for c in image_calls),
                         ["mirror.gcr.io/library/redis@" + D1, "registry.k8s.io/ingress-nginx/controller@" + D2])
        for c in image_calls:
            for flag in ("--image-src", "remote", "--platform", "linux/amd64", "--scanners", "vuln", "--format",
                         "cyclonedx", "--skip-db-update", "--skip-java-db-update", "--timeout", "10m",
                         "--cache-backend", "memory"):
                self.assertIn(flag, c)
        sbom_calls = [c for c in runner.calls if c[:2] == ["trivy", "sbom"]]
        self.assertEqual(len(sbom_calls), 2)
        for flag in ("--list-all-pkgs", "--skip-db-update", "--skip-java-db-update", "json"):
            self.assertIn(flag, sbom_calls[0])
        self.assertTrue((self.sbom_dir / f"{'1' * 64}.cdx.json.gz").is_file())
        with gzip.open(self.sbom_dir / f"{'1' * 64}.cdx.json.gz", "rt") as fh:
            self.assertEqual(json.load(fh)["bomFormat"], "CycloneDX")

        stats = doc["stats"]
        self.assertEqual(stats["images"], 6)
        self.assertEqual(stats["ok"], 3)
        self.assertEqual(stats["invalid"], 1)
        self.assertEqual(stats["unavailable_by_reason"], {"no_amd64": 1, "not_found": 1})
        self.assertEqual((stats["new_sboms"], stats["rematched"]), (2, 2))
        self.assertIn("seconds", stats)

        # second run: SBOMs are cached, tags fresh in resolve cache → only rematch + retries of failures
        runner2 = self.runner()
        doc2 = build_scan({"images": self.IMAGES}, self.scanner(runner2, cache))
        self.assertEqual(runner2.count("trivy", "image"), 0)
        self.assertEqual(runner2.count("trivy", "sbom"), 2)
        self.assertTrue(doc2["images"]["docker.io/library/redis:7"]["sbom_cached"])
        self.assertEqual(doc2["stats"]["new_sboms"], 0)
        resolved_refs = {c[4] for c in runner2.calls if c[:2] == ["crane", "digest"]}
        self.assertNotIn("mirror.gcr.io/library/redis:7", resolved_refs)
        self.assertIn("docker.io/bitnami/redis:bad", resolved_refs)

    def test_quota_prioritizes_main_images(self) -> None:
        images = {
            "ghcr.io/z/test:1": img("ghcr.io", "z/test", "1", D1, roles=("test",)),
            "ghcr.io/a/main:1": img("ghcr.io", "a/main", "1", D2),
            "ghcr.io/b/main:1": img("ghcr.io", "b/main", "1", D3),
        }
        doc = build_scan({"images": images}, self.scanner(FakeRunner(), max_new_sboms=2))
        statuses = {c: (r["status"], r["reason"]) for c, r in doc["images"].items()}
        self.assertEqual(statuses["ghcr.io/z/test:1"], ("skipped", "sbom_quota"))
        self.assertEqual(statuses["ghcr.io/a/main:1"], ("ok", None))
        self.assertEqual(statuses["ghcr.io/b/main:1"], ("ok", None))
        self.assertEqual(doc["stats"]["skipped"], 1)

    def test_sbom_failure_falls_back_and_classifies(self) -> None:
        images = {"docker.io/library/gone:1": img("docker.io", "library/gone", "1", D1),
                  "docker.io/library/mirrored:1": img("docker.io", "library/mirrored", "1", D2)}
        runner = FakeRunner(trivy_errors={
            "mirror.gcr.io/library/gone@" + D1: "GET https://mirror.gcr.io/...: MANIFEST_UNKNOWN: Failed to fetch",
            "docker.io/library/gone@" + D1: "GET https://index.docker.io/...: MANIFEST_UNKNOWN: manifest unknown",
            "mirror.gcr.io/library/mirrored@" + D2: "GET https://mirror.gcr.io/...: UNAUTHORIZED",
        })
        doc = build_scan({"images": images}, self.scanner(runner))
        gone = doc["images"]["docker.io/library/gone:1"]
        self.assertEqual((gone["status"], gone["reason"]), ("unavailable", "not_found"))
        mirrored = doc["images"]["docker.io/library/mirrored:1"]
        self.assertEqual((mirrored["status"], mirrored["pulled_from"]), ("ok", "docker.io/library/mirrored"))
        self.assertFalse((self.sbom_dir / f"{'1' * 64}.cdx.json.gz").exists())

    def test_stale_resolve_uses_cached_sbom(self) -> None:
        self.sbom_dir.mkdir(parents=True)
        (self.sbom_dir / f"{'1' * 64}.cdx.json.gz").write_bytes(gzip.compress(b'{"bomFormat": "CycloneDX"}'))
        cache = {"quay.io/a/b:1": {"digest": D1, "resolved_at": "2026-01-01T00:00:00Z", "status": "ok"}}
        runner = FakeRunner({"quay.io/a/b:1": ("error", "Get https://quay.io: dial tcp: i/o timeout")})
        doc = build_scan({"images": {"quay.io/a/b:1": img("quay.io", "a/b", "1")}}, self.scanner(runner, cache))
        rec = doc["images"]["quay.io/a/b:1"]
        self.assertEqual((rec["status"], rec["stale_resolve"], rec["sbom_cached"]), ("ok", True, True))
        self.assertEqual(doc["stats"]["stale_resolve"], 1)

    def test_corrupt_sbom_and_rematch_failure_do_not_crash(self) -> None:
        self.sbom_dir.mkdir(parents=True)
        (self.sbom_dir / f"{'1' * 64}.cdx.json.gz").write_bytes(b"not gzip")
        images = {"ghcr.io/a/b:1": img("ghcr.io", "a/b", "1", D1)}
        doc = build_scan({"images": images}, self.scanner(FakeRunner()))
        rec = doc["images"]["ghcr.io/a/b:1"]
        self.assertEqual((rec["status"], rec["reason"]), ("unavailable", "sbom_corrupt"))
        self.assertFalse((self.sbom_dir / f"{'1' * 64}.cdx.json.gz").exists())

        class Failing(FakeRunner):
            def __call__(self, cmd: list[str], timeout: float) -> Proc:
                if cmd[:2] == ["trivy", "sbom"]:
                    return Proc(1, "", "FATAL boom")
                return super().__call__(cmd, timeout)

        doc = build_scan({"images": images}, self.scanner(Failing()))
        self.assertEqual(doc["images"]["ghcr.io/a/b:1"]["reason"], "rematch_failed")

    def test_unexpected_exception_is_contained(self) -> None:
        class Exploding(FakeRunner):
            def __call__(self, cmd: list[str], timeout: float) -> Proc:
                if cmd[:2] == ["crane", "digest"] and "boom" in cmd[4]:
                    raise RuntimeError("boom")
                return super().__call__(cmd, timeout)

        images = {"ghcr.io/boom/x:1": img("ghcr.io", "boom/x", "1"), "ghcr.io/ok/x:1": img("ghcr.io", "ok/x", "1")}
        runner = Exploding({"ghcr.io/ok/x:1": D1})
        doc = build_scan({"images": images}, self.scanner(runner))
        self.assertEqual(doc["images"]["ghcr.io/boom/x:1"]["status"], "unavailable")
        self.assertEqual(doc["images"]["ghcr.io/ok/x:1"]["status"], "ok")

    def test_limit(self) -> None:
        doc = build_scan({"images": self.IMAGES, "invalid": [{"ref": "x y", "reason": "whitespace"}]},
                         self.scanner(self.runner()), limit=2)
        self.assertEqual(len(doc["images"]), 2)
        self.assertEqual(list(doc["images"]), sorted(self.IMAGES)[:2])
        self.assertEqual(doc["stats"]["limit"], 2)


class MainTest(unittest.TestCase):
    def test_cli_writes_scan_and_resolve_cache(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            inv = root / "inventory.json"
            inv.write_text(json.dumps({"images": {"ghcr.io/a/b:1": img("ghcr.io", "a/b", "1")}, "invalid": []}))
            runner = FakeRunner({"ghcr.io/a/b:1": D1})
            env = {"TRIVY": "trivy", "CRANE": "crane"}
            with mock.patch.object(scan, "run_command", runner), mock.patch.dict("os.environ", env):
                rc = scan.main(["--inventory", str(inv), "--output", str(root / "out" / "scan.json"),
                                "--sbom-dir", str(root / "sbom"), "--resolve-file", str(root / "resolve.json"),
                                "--workers", "1"])
            self.assertEqual(rc, 0)
            out = json.loads((root / "out" / "scan.json").read_text())
            self.assertEqual(out["images"]["ghcr.io/a/b:1"]["status"], "ok")
            self.assertEqual(json.loads((root / "resolve.json").read_text())["ghcr.io/a/b:1"]["digest"], D1)

    def test_cli_missing_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(scan.main(["--inventory", str(Path(tmp) / "nope.json")]), 1)


if __name__ == "__main__":
    unittest.main()
