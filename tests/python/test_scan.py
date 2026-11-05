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

from vulnscan import match, scan
from vulnscan.scan import Proc, Scanner, build_scan, classify_error, pick_cvss, scan_order, summarize_report

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
        kw.setdefault("match_dir", Path(self._tmp.name) / "match")
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
        self.assertEqual(redis["go_modules"], 4)  # a count; the modules themselves live in the match cache
        self.assertEqual(images["quay.io/a/alias:1"]["counts"], redis["counts"])
        # scan.json carries no findings: the detail is in the per-digest match, plus a global ids map
        self.assertEqual(doc["format_version"], match.FORMAT_VERSION)
        self.assertEqual(doc["ids"], {vid: scan.SEVERITIES[r] for vid, r in sorted(match.vuln_ids(
            match.compact(summarize_report(TRIVY_REPORT), None)).items())})
        self.assertEqual(doc["ids"]["GO-2024-2887"], doc["ids"]["CVE-2024-24790"])  # vendor ID inherits severity
        m = match.load(Path(self._tmp.name) / "match", D1)
        self.assertEqual((m["format_version"], m["matched_at"], m["os"]), (2, self.clock, redis["os"]))
        self.assertEqual(len(m["go"]), 4)
        self.assertEqual(len({row[0] for row in m["vulns"]}), len(m["vulns"]))
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
                        "scanned_at", "go_modules", "counts", "priority"):
                self.assertIn(key, rec)
            self.assertNotIn("findings", rec)

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

    def test_quota_follows_inventory_priority(self) -> None:
        # priority beats role and chart count: an old-version-only image waits for latest-version ones.
        old = dict(img("ghcr.io", "a/old", "1", D1), priority=3, charts=["o/c@0.1.0", "o/d@0.1.0"])
        test_latest = dict(img("ghcr.io", "z/test", "1", D2, roles=("test",)), priority=0)
        main_latest = dict(img("ghcr.io", "b/main", "1", D3), priority=0)
        images = {"ghcr.io/a/old:1": old, "ghcr.io/z/test:1": test_latest, "ghcr.io/b/main:1": main_latest}
        self.assertEqual(scan_order(images), ["ghcr.io/b/main:1", "ghcr.io/z/test:1", "ghcr.io/a/old:1"])
        doc = build_scan({"images": images}, self.scanner(FakeRunner(), max_new_sboms=2))
        self.assertEqual(doc["images"]["ghcr.io/a/old:1"]["reason"], "sbom_quota")
        self.assertEqual(doc["images"]["ghcr.io/z/test:1"]["status"], "ok")
        limited = build_scan({"images": images}, self.scanner(FakeRunner()), limit=1)
        self.assertEqual(list(limited["images"]), ["ghcr.io/b/main:1"])

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


class BoundedWorkTest(ScannerTestBase):
    """Per-run work stays bounded as the cache grows (scope 'all')."""

    def test_old_images_use_longer_resolve_max_age(self) -> None:
        cache = {c: {"digest": D1, "resolved_at": "2026-11-03T00:00:00Z", "status": "ok"}
                 for c in ("quay.io/a/new:1", "quay.io/a/old:1")}
        runner = FakeRunner({"quay.io/a/new:1": D2, "quay.io/a/old:1": D2})
        s = self.scanner(runner, cache, resolve_max_age_hours=20, resolve_max_age_hours_old=168)
        self.assertEqual(s.resolve("quay.io/a/new:1", dict(img("quay.io", "a/new", "1"), priority=0))["digest"], D2)
        self.assertEqual(s.resolve("quay.io/a/old:1", dict(img("quay.io", "a/old", "1"), priority=4))["digest"], D1)
        self.assertEqual([c[4] for c in runner.calls], ["quay.io/a/new:1"])

    def test_sbom_failures_back_off_and_do_not_use_quota(self) -> None:
        images = {"ghcr.io/a/slow:1": dict(img("ghcr.io", "a/slow", "1", D1), priority=0),
                  "ghcr.io/a/next:1": dict(img("ghcr.io", "a/next", "1", D2), priority=1)}
        failures: dict = {}
        runner = FakeRunner(trivy_errors={"ghcr.io/a/slow@" + D1: "context deadline exceeded"})
        doc = build_scan({"images": images}, self.scanner(runner, sbom_failures=failures, max_new_sboms=1))
        self.assertEqual(doc["images"]["ghcr.io/a/slow:1"]["reason"], "timeout")
        self.assertEqual(doc["images"]["ghcr.io/a/next:1"]["reason"], "sbom_quota")
        self.assertEqual(failures[D1], {"reason": "timeout", "attempted_at": self.clock, "attempts": 1})

        # next day (< 1 day backoff): not retried, and the quota goes to the next image
        self.clock = "2026-11-05T06:00:00Z"
        runner2 = FakeRunner(trivy_errors=runner.trivy_errors)
        doc2 = build_scan({"images": images}, self.scanner(runner2, sbom_failures=failures, max_new_sboms=1))
        self.assertEqual([c[-1] for c in runner2.calls if c[:2] == ["trivy", "image"]], ["ghcr.io/a/next@" + D2])
        self.assertEqual((doc2["images"]["ghcr.io/a/slow:1"]["status"], doc2["images"]["ghcr.io/a/slow:1"]["reason"]),
                         ("unavailable", "timeout"))
        self.assertEqual(doc2["images"]["ghcr.io/a/next:1"]["status"], "ok")
        self.assertEqual(doc2["stats"]["sbom_backoff"], 1)

        # after the backoff it is retried; a second failure doubles the wait, a success clears it
        self.clock = "2026-11-05T13:00:00Z"
        build_scan({"images": images}, self.scanner(FakeRunner(trivy_errors=runner.trivy_errors),
                                                    sbom_failures=failures))
        self.assertEqual(failures[D1]["attempts"], 2)
        self.clock = "2026-11-06T14:00:00Z"  # 25h later: still inside the 2-day backoff
        self.assertEqual(self.scanner(FakeRunner(), sbom_failures=failures).in_backoff(D1), "timeout")
        self.clock = "2026-11-07T14:00:00Z"
        build_scan({"images": images}, self.scanner(FakeRunner(), sbom_failures=failures))
        self.assertNotIn(D1, failures)

    def test_rate_limited_is_not_backed_off(self) -> None:
        failures = {D1: {"reason": "rate_limited", "attempted_at": self.clock, "attempts": 3}}
        self.assertIsNone(self.scanner(FakeRunner(), sbom_failures=failures).in_backoff(D1))

    def test_rematch_cache_and_quota(self) -> None:
        match_dir = Path(self._tmp.name) / "match"
        images = {"ghcr.io/a/latest:1": dict(img("ghcr.io", "a/latest", "1", D1), priority=0),
                  "ghcr.io/a/old:1": dict(img("ghcr.io", "a/old", "1", D2), priority=2),
                  "ghcr.io/a/older:1": dict(img("ghcr.io", "a/older", "1", D3), priority=3)}
        kw = {"match_dir": match_dir, "max_rematch": 1, "rematch_max_age_hours": 168}
        doc = build_scan({"images": images}, self.scanner(FakeRunner(), **kw))
        st = {c: (r["status"], r["reason"]) for c, r in doc["images"].items()}
        # latest always rematched; one old digest within the quota, the other waits (pending, not an error)
        self.assertEqual(st["ghcr.io/a/latest:1"], ("ok", None))
        self.assertEqual(st["ghcr.io/a/old:1"], ("ok", None))
        self.assertEqual(st["ghcr.io/a/older:1"], ("skipped", "rematch_quota"))
        self.assertTrue((match_dir / f"{'2' * 64}.json.gz").is_file())

        # next day: old's cached match is fresh → reused without trivy; older (missing) gets the quota
        first_clock, self.clock = self.clock, "2026-11-05T12:00:00Z"
        runner = FakeRunner()
        doc2 = build_scan({"images": images}, self.scanner(runner, **kw))
        self.assertEqual(runner.count("trivy", "sbom"), 2)
        old = doc2["images"]["ghcr.io/a/old:1"]
        self.assertEqual((old["status"], old["scanned_at"]), ("ok", first_clock))
        self.assertEqual(old["counts"], doc2["images"]["ghcr.io/a/latest:1"]["counts"])
        self.assertEqual(doc2["images"]["ghcr.io/a/older:1"]["scanned_at"], self.clock)
        self.assertEqual(doc2["stats"]["match_reused"], 1)

        # a week later both old matches are due; the oldest goes first
        self.clock = "2026-11-11T13:00:00Z"
        runner3 = FakeRunner()
        doc3 = build_scan({"images": images}, self.scanner(runner3, **kw))
        self.assertEqual(doc3["images"]["ghcr.io/a/old:1"]["scanned_at"], self.clock)
        self.assertEqual(doc3["images"]["ghcr.io/a/older:1"]["scanned_at"], "2026-11-05T12:00:00Z")

    def test_failed_rematch_falls_back_to_cached_match(self) -> None:
        match_dir = Path(self._tmp.name) / "match"
        images = {"ghcr.io/a/b:1": dict(img("ghcr.io", "a/b", "1", D1), priority=0)}
        build_scan({"images": images}, self.scanner(FakeRunner(), match_dir=match_dir))

        class Failing(FakeRunner):
            def __call__(self, cmd: list[str], timeout: float) -> Proc:
                if cmd[:2] == ["trivy", "sbom"]:
                    return Proc(1, "", "FATAL boom")
                return super().__call__(cmd, timeout)

        first_clock, self.clock = self.clock, "2026-11-05T12:00:00Z"
        rec = build_scan({"images": images}, self.scanner(Failing(), match_dir=match_dir))["images"]["ghcr.io/a/b:1"]
        self.assertEqual((rec["status"], rec["scanned_at"]), ("ok", first_clock))

    def test_old_format_match_is_migrated_not_rematched(self) -> None:
        match_dir = Path(self._tmp.name) / "match"
        self.sbom_dir.mkdir(parents=True)
        (self.sbom_dir / f"{'2' * 64}.cdx.json.gz").write_bytes(gzip.compress(b'{"bomFormat": "CycloneDX"}'))
        result = summarize_report(TRIVY_REPORT)
        scan.write_json(match.path(match_dir, D2), {"matched_at": "2026-11-04T06:00:00Z", "result": result})
        images = {"ghcr.io/a/old:1": dict(img("ghcr.io", "a/old", "1", D2), priority=2)}
        runner = FakeRunner()
        doc = build_scan({"images": images}, self.scanner(runner, max_rematch=10, match_dir=match_dir))
        rec = doc["images"]["ghcr.io/a/old:1"]
        self.assertEqual(runner.count("trivy", "sbom"), 0)  # fresh format-1 match: re-derived, no rematch
        self.assertEqual((rec["status"], rec["scanned_at"], rec["counts"]), ("ok", "2026-11-04T06:00:00Z",
                                                                             result["counts"]))
        self.assertEqual(scan.read_json(match.path(match_dir, D2)),
                         match.compact(result, "2026-11-04T06:00:00Z"))  # rewritten in the current format
        self.assertIn("CVE-2024-21626", doc["ids"])

        # an unknown format is never read as data: the digest counts as never matched and is rematched
        scan.write_json(match.path(match_dir, D2), {"format_version": 99, "matched_at": "2026-11-04T06:00:00Z",
                                                    "vulns": [["CVE-1999-1", "CRITICAL"]]})
        runner = FakeRunner()
        doc = build_scan({"images": images}, self.scanner(runner, max_rematch=10, match_dir=match_dir))
        self.assertEqual(runner.count("trivy", "sbom"), 1)
        self.assertEqual(doc["images"]["ghcr.io/a/old:1"]["scanned_at"], self.clock)
        self.assertNotIn("CVE-1999-1", doc["ids"])
        self.assertEqual(match.load(match_dir, D2)["format_version"], match.FORMAT_VERSION)

        # a truncated gzip (e.g. an interrupted cache restore) is also missing, not fatal: rematched
        p = match.path(match_dir, D2)
        p.write_bytes(p.read_bytes()[:20])
        runner = FakeRunner()
        doc = build_scan({"images": images}, self.scanner(runner, max_rematch=10, match_dir=match_dir))
        self.assertEqual(runner.count("trivy", "sbom"), 1)
        self.assertEqual(doc["images"]["ghcr.io/a/old:1"]["status"], "ok")
        self.assertIsNotNone(match.load(match_dir, D2))

    def test_time_budget_stops_new_work_but_writes_results(self) -> None:
        ticks = iter([0.0] + [10_000.0] * 50)
        images = {"ghcr.io/a/b:1": img("ghcr.io", "a/b", "1", D1)}
        runner = FakeRunner()
        doc = build_scan({"images": images},
                         self.scanner(runner, time_budget_seconds=60, clock=lambda: next(ticks)))
        rec = doc["images"]["ghcr.io/a/b:1"]
        self.assertEqual((rec["status"], rec["reason"]), ("skipped", "time_budget"))
        self.assertEqual(runner.count("trivy", "image"), 0)
        self.assertTrue(doc["stats"]["time_budget_exceeded"])


class TimedRunner(FakeRunner):
    """FakeRunner with a simulated clock: each crane call costs 1 s, each SBOM `cost` s, each rematch 2 s."""

    def __init__(self, *a: Any, cost: float = 10.0, **kw: Any) -> None:
        super().__init__(*a, **kw)
        self.t, self.cost = 0.0, cost

    def __call__(self, cmd: list[str], timeout: float) -> Proc:
        with self._lock:
            self.t += {"digest": 1.0, "image": self.cost, "sbom": 2.0}.get(cmd[1], 0.0)
        return super().__call__(cmd, timeout)


def digest(i: int) -> str:
    return "sha256:" + f"{i:064x}"


class BatchTest(ScannerTestBase):
    """Batched resolve → SBOM → rematch: a time budget never leaves finished batches without results."""

    def inventory(self, n: int, latest: int = 0) -> tuple[dict, dict]:
        """n tag-only images (o/img-NN:1, priority 0 for the first `latest`, then 1, 2, ...) and their digests."""
        images, digests = {}, {}
        for i in range(n):
            c = f"ghcr.io/o/img-{i:02d}:1"
            images[c] = dict(img("ghcr.io", f"o/img-{i:02d}", "1"), priority=0 if i < latest else i)
            digests[f"ghcr.io/o/img-{i:02d}:1"] = digest(i + 1)
        return images, digests

    def test_budget_expiring_mid_run_keeps_earlier_batches(self) -> None:
        images, digests = self.inventory(16, latest=4)
        runner = TimedRunner(digests, cost=10.0)
        s = self.scanner(runner, batch_size=4, workers=1, rematch_workers=1, time_budget_seconds=110,
                         clock=lambda: runner.t)
        doc = build_scan({"images": images}, s)
        st = {c: (r["status"], r["reason"]) for c, r in doc["images"].items()}
        order = scan_order(images)
        # batches 1-2 (t = 0..~100) finish; batch 3 starts before the deadline, generates SBOMs until it
        # passes and still rematches them; batch 4 never starts and is never resolved.
        self.assertEqual([st[c] for c in order[:8]], [("ok", None)] * 8)
        self.assertEqual([st[c][0] for c in order[8:12]].count("ok"), 1)
        self.assertEqual([st[c] for c in order[9:12]], [("skipped", "time_budget")] * 3)
        self.assertEqual([st[c] for c in order[12:]], [("skipped", "time_budget")] * 4)
        resolved = [c[4] for c in runner.calls if c[:2] == ["crane", "digest"]]
        self.assertEqual(sorted(resolved), sorted(order[:12]))
        self.assertEqual(runner.count("trivy", "sbom"), 9)  # every generated SBOM was rematched
        stats = doc["stats"]
        self.assertEqual((stats["ok"], stats["batches"], stats["batches_done"], stats["images_processed"],
                          stats["images_not_processed"], stats["new_sboms"], stats["rematched"]),
                         (9, 4, 3, 12, 4, 9, 9))
        self.assertTrue(stats["time_budget_exceeded"])
        self.assertTrue(doc["ids"])
        for c in order[12:]:
            self.assertIsNone(doc["images"][c]["digest"])

    def test_incident_shape_scope_all(self) -> None:
        # 2026-11-05: many images, a small SBOM quota and a budget that runs out long before the end.
        # The old single-phase scan ended with ok=0 and rematched=0; batches keep everything finished.
        images, digests = self.inventory(60, latest=6)
        runner = TimedRunner(digests, cost=5.0)
        s = self.scanner(runner, batch_size=10, workers=1, rematch_workers=1, max_new_sboms=25,
                         time_budget_seconds=150, clock=lambda: runner.t)
        stats = build_scan({"images": images}, s)["stats"]
        self.assertGreater(stats["ok"], 0)
        self.assertEqual(stats["ok"], stats["rematched"])
        self.assertEqual(stats["ok"], stats["new_sboms"])
        self.assertTrue(stats["time_budget_exceeded"])
        self.assertLess(stats["images_processed"], 60)  # the tail was never resolved
        self.assertEqual(stats["images_processed"] + stats["images_not_processed"], 60)
        self.assertEqual(stats["ok"] + stats["skipped"], 60)

    def test_unprocessed_images_reuse_cached_matches_without_crane(self) -> None:
        images, digests = self.inventory(6, latest=2)
        cache: dict = {}
        first = build_scan({"images": images}, self.scanner(FakeRunner(digests), cache, batch_size=2))
        self.assertEqual(first["stats"]["ok"], 6)
        images["ghcr.io/o/new:1"] = dict(img("ghcr.io", "o/new", "1"), priority=99)

        # next day the budget is gone before the first batch: nothing is resolved or scanned, but every
        # image with a known digest and a cached match keeps its (dated) result; the new one waits
        first_clock, self.clock = self.clock, "2026-11-05T12:00:00Z"
        ticks = iter([0.0] + [10_000.0] * 50)
        runner = FakeRunner(digests)
        doc = build_scan({"images": images}, self.scanner(runner, cache, batch_size=2, time_budget_seconds=60,
                                                           clock=lambda: next(ticks)))
        self.assertEqual(runner.calls, [["trivy", "version", "-f", "json"]])
        for c in list(images)[:6]:
            rec = doc["images"][c]
            self.assertEqual((rec["status"], rec["scanned_at"], rec["sbom_cached"]), ("ok", first_clock, True))
        self.assertEqual((doc["images"]["ghcr.io/o/new:1"]["status"], doc["images"]["ghcr.io/o/new:1"]["reason"]),
                         ("skipped", "time_budget"))
        self.assertEqual(doc["ids"], first["ids"])
        self.assertEqual((doc["stats"]["batches_done"], doc["stats"]["not_processed_reused"]), (0, 6))

    def test_priority_order_and_quota_across_batches(self) -> None:
        images, digests = self.inventory(5, latest=1)
        images = dict(reversed(list(images.items())))  # inventory order must not matter
        runner = FakeRunner(digests)
        doc = build_scan({"images": images}, self.scanner(runner, batch_size=2, workers=1, max_new_sboms=3))
        order = scan_order(images)
        self.assertEqual(order[0], "ghcr.io/o/img-00:1")
        self.assertEqual([c[4] for c in runner.calls if c[:2] == ["crane", "digest"]][:2], sorted(order[:2]))
        self.assertEqual([c[-1] for c in runner.calls if c[:2] == ["trivy", "image"]],
                         [f"ghcr.io/o/img-{i:02d}@{digest(i + 1)}" for i in range(3)])
        self.assertEqual([doc["images"][c]["reason"] for c in order], [None, None, None, "sbom_quota", "sbom_quota"])

    def test_resolve_past_budget_uses_last_digest_without_crane(self) -> None:
        cache = {"quay.io/a/b:1": {"digest": D1, "resolved_at": "2026-11-01T00:00:00Z", "status": "ok",
                                   "pulled_from": "quay.io/a/b"}}
        runner = FakeRunner({"quay.io/a/b:1": D2, "quay.io/a/new:1": D2})
        s = self.scanner(runner, cache, clock=lambda: 100.0)
        s._deadline = 50.0
        self.assertEqual(s.resolve("quay.io/a/b:1", img("quay.io", "a/b", "1")),
                         {"digest": D1, "pulled_from": "quay.io/a/b", "stale_resolve": True, "reason": None})
        self.assertEqual(s.resolve("quay.io/a/new:1", img("quay.io", "a/new", "1")),
                         {"digest": None, "pulled_from": None, "stale_resolve": False, "reason": "time_budget"})
        self.assertEqual(runner.calls, [])
        self.assertEqual(cache["quay.io/a/b:1"]["resolved_at"], "2026-11-01T00:00:00Z")  # not marked checked

    def test_budget_expiring_inside_a_batch_bounds_resolve_and_rematch(self) -> None:
        images, digests = self.inventory(4, latest=4)
        cache: dict = {}
        first = build_scan({"images": images}, self.scanner(FakeRunner(digests), cache, batch_size=4))
        self.assertEqual(first["stats"]["ok"], 4)
        # one digest lost its cached match (its SBOM is still cached); a new image has no SBOM yet
        match_dir = Path(self._tmp.name) / "match"
        no_match = digest(2)
        match.path(match_dir, no_match).unlink()
        images["ghcr.io/o/new:1"] = dict(img("ghcr.io", "o/new", "1"), priority=0)
        digests["ghcr.io/o/new:1"] = digest(99)
        cache["ghcr.io/o/new:1"] = {"digest": digest(99), "resolved_at": "2026-11-01T00:00:00Z", "status": "ok"}

        # next day (every resolve entry stale): the deadline passes right after the batch starts
        first_clock, self.clock = self.clock, "2026-11-05T12:00:00Z"
        for now, rematched in ((100.0, 1), (100.0 + scan.REMATCH_GRACE_SECONDS, 0)):
            ticks = iter([0.0, 0.0])
            runner = FakeRunner(digests)
            s = self.scanner(runner, cache, batch_size=10, time_budget_seconds=60,
                             clock=lambda: next(ticks, now))
            doc = build_scan({"images": images}, s)
            self.assertEqual(runner.count("crane"), 0)  # stale cached digests, no crane call
            self.assertEqual(runner.count("trivy", "image"), 0)  # no new SBOM past the budget
            # only the digest without any cached match is rematched, and only within the grace period
            self.assertEqual(runner.count("trivy", "sbom"), rematched)
            recs = doc["images"]
            self.assertEqual((recs["ghcr.io/o/new:1"]["status"], recs["ghcr.io/o/new:1"]["reason"]),
                             ("skipped", "time_budget"))
            for i in (0, 2, 3):
                rec = recs[f"ghcr.io/o/img-{i:02d}:1"]
                self.assertEqual((rec["status"], rec["stale_resolve"], rec["scanned_at"]), ("ok", True, first_clock))
            rec = recs["ghcr.io/o/img-01:1"]
            if rematched:
                self.assertEqual((rec["status"], rec["scanned_at"]), ("ok", self.clock))
            else:
                self.assertEqual((rec["status"], rec["reason"]), ("skipped", "time_budget"))
            self.assertEqual(doc["stats"]["batches_done"], 1)
            match.path(match_dir, no_match).unlink(missing_ok=True)

    def test_shared_digest_across_batches_scanned_once(self) -> None:
        images, digests = self.inventory(4, latest=4)
        digests["ghcr.io/o/img-03:1"] = digests["ghcr.io/o/img-00:1"]
        runner = FakeRunner(digests)
        doc = build_scan({"images": images}, self.scanner(runner, batch_size=1))
        self.assertEqual(runner.count("trivy", "image"), 3)
        self.assertEqual(runner.count("trivy", "sbom"), 3)
        self.assertEqual(doc["images"]["ghcr.io/o/img-03:1"]["counts"], doc["images"]["ghcr.io/o/img-00:1"]["counts"])
        self.assertEqual(doc["stats"]["unique_digests"], 3)


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
                                "--sbom-failures-file", str(root / "failures.json"),
                                "--match-dir", str(root / "match"), "--workers", "1"])
            self.assertEqual(rc, 0)
            out = json.loads((root / "out" / "scan.json").read_text())
            self.assertEqual(out["images"]["ghcr.io/a/b:1"]["status"], "ok")
            self.assertEqual(json.loads((root / "resolve.json").read_text())["ghcr.io/a/b:1"]["digest"], D1)
            self.assertEqual(json.loads((root / "failures.json").read_text()), {})
            self.assertTrue((root / "match" / f"{'1' * 64}.json.gz").is_file())

    def test_cli_missing_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(scan.main(["--inventory", str(Path(tmp) / "nope.json")]), 1)


if __name__ == "__main__":
    unittest.main()
