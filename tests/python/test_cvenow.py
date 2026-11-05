"""Unit tests for vulnscan.cvenow (no network: the HTTP layer is a fake transport)."""

from __future__ import annotations

import datetime as _dt
import json
import tempfile
import unittest
from pathlib import Path
from typing import Any, Callable
from unittest import mock

from vulnscan import cvenow, match
from vulnscan.common import read_json, write_json

FIXTURES = Path(__file__).parent / "fixtures" / "cvenow"
NOW = _dt.datetime(2026, 11, 4, 12, 0, 0, tzinfo=_dt.timezone.utc)
_LOG_PATCH = mock.patch.object(cvenow, "log")


def setUpModule() -> None:
    _LOG_PATCH.start()


def tearDownModule() -> None:
    _LOG_PATCH.stop()


def fixture(name: str) -> dict[str, Any]:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def iso(dt: _dt.datetime) -> str:
    return dt.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def finding(vid: str, severity: str = "MEDIUM", vendor_ids: list[str] | None = None) -> dict[str, Any]:
    return {"id": vid, "pkg": "p", "installed": "1", "severity": severity, "vendor_ids": vendor_ids or []}


def scan_doc(images: dict[str, list[dict[str, Any]]], go: dict[str, list[list[str]]] | None = None,
             match_dir: Path | None = None, priority: dict[str, int] | None = None) -> dict:
    """New-layout scan.json: findings only feed the global 'ids' map; Go modules go to match_dir."""
    go, priority = go or {}, priority or {}
    out: dict[str, Any] = {"format_version": match.FORMAT_VERSION, "images": {}, "ids": {}}
    for i, (ref, findings) in enumerate(images.items(), 1):
        digest = f"sha256:{i:064x}"
        doc = match.compact({"findings": findings, "go_modules": go.get(ref, [])}, "2026-11-04T00:00:00Z")
        if match_dir is not None:
            match.store(match_dir, digest, doc)
        out["images"][ref] = {"status": "ok", "digest": digest, "go_modules": len(doc["go"]),
                              "priority": priority.get(ref, 0)}
        for vid, rank in match.vuln_ids(doc).items():
            if vid not in out["ids"] or rank < cvenow.SEVERITIES.index(out["ids"][vid]):
                out["ids"][vid] = cvenow.SEVERITIES[rank]
    return out


class FakeTransport:
    """Records calls; answers via a handler(method, path, body) -> (status, payload) or raises."""

    def __init__(self, handler: Callable[[str, str, Any], tuple[int, Any]]) -> None:
        self.handler = handler
        self.calls: list[tuple[str, str]] = []
        self.bodies: list[Any] = []

    def __call__(self, method: str, url: str, body: bytes | None = None) -> tuple[int, bytes]:
        path = url.removeprefix(cvenow.BASE_URL)
        self.calls.append((method, path))
        parsed = json.loads(body) if body else None
        self.bodies.append(parsed)
        status, payload = self.handler(method, path, parsed)
        data = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        return status, data

    def entry_ids(self) -> list[str]:
        prefix = "/api/v1/entries/"
        return [p[len(prefix) :] for m, p in self.calls if p.startswith(prefix)]


def entry_for(vid: str, **extra: Any) -> dict[str, Any]:
    base = fixture("CVE-2017-17740.json")
    base["id"] = vid
    base.update(extra)
    return base


def default_handler(feeds: dict[str, list[str]] | None = None, missing: set[str] | None = None):
    feeds = feeds or {}
    missing = missing or set()

    def handler(method: str, path: str, body: Any) -> tuple[int, Any]:
        if path.startswith("/api/v1/entries?filter="):
            name = path.split("filter=")[1].split("&")[0]
            return 200, {"items": [{"id": i, "title": "x"} for i in feeds.get(name, [])]}
        if path.startswith("/api/v1/entries/"):
            vid = path.rsplit("/", 1)[1]
            if vid in missing:
                return 404, {"error": "not found"}
            return 200, entry_for(vid)
        if path == "/api/v1/check":
            return 200, fixture("check_sample.json")
        return 400, {"error": "bad"}

    return handler


class Base(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.entries_dir = root / "entries"
        self.check_dir = root / "check"
        self.match_dir = root / "match"
        self.sleeps: list[float] = []

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def client(self, transport: FakeTransport, budget: int = 3000, rps: float = 0) -> cvenow.Client:
        return cvenow.Client(transport, budget=budget, rps=rps, sleep=self.sleeps.append, monotonic=lambda: 0.0)

    def run_stage(self, scan: dict, client: cvenow.Client, now: _dt.datetime = NOW, **kw: Any) -> dict:
        return cvenow.run(
            scan, client, entries_dir=self.entries_dir, check_dir=self.check_dir, match_dir=self.match_dir,
            now=lambda: now, **kw
        )

    def seed(self, vid: str, fetched_at: _dt.datetime, status: int = 200) -> None:
        entry = entry_for(vid) if status == 200 else None
        write_json(self.entries_dir / f"{vid}.json", {"fetched_at": iso(fetched_at), "status": status, "entry": entry})


class TestHelpers(unittest.TestCase):
    def test_ghsa_ids_are_case_insensitive_and_canonicalized(self) -> None:
        self.assertEqual(cvenow.canonical_id("GHSA-JW9F-HH49-CVP9"), "GHSA-jw9f-hh49-cvp9")
        self.assertEqual(cvenow.canonical_id("CVE-2021-3517"), "CVE-2021-3517")
        self.assertTrue(cvenow.ID_RE.match("GHSA-JW9F-HH49-CVP9"))
        self.assertIsNone(cvenow.ID_RE.match("cve-2021-3517"))  # only the GHSA suffix is case-insensitive
        ids = cvenow.collect_ids(scan_doc({"a": [finding("CVE-2024-1", "LOW", ["GHSA-ABCD-1234-EFGH"])]}))
        self.assertEqual(set(ids), {"CVE-2024-1", "GHSA-abcd-1234-efgh"})

    def test_collect_ids_filters_prefixes_and_keeps_worst_severity(self) -> None:
        scan = scan_doc(
            {
                "a": [
                    finding("CVE-2024-1", "LOW", ["GHSA-abcd-1234-efgh", "DLA-1234-1"]),
                    finding("TEMP-0001-ABC", "HIGH"),
                    finding("DSA-5000-1", "CRITICAL", ["CVE-2024-2"]),
                ],
                "b": [finding("CVE-2024-1", "CRITICAL"), finding("GO-2023-1234", "UNKNOWN")],
            }
        )
        ids = cvenow.collect_ids(scan)
        self.assertEqual(set(ids), {"CVE-2024-1", "GHSA-abcd-1234-efgh", "CVE-2024-2", "GO-2023-1234"})
        self.assertEqual(ids["CVE-2024-1"], 0)  # CRITICAL wins over LOW
        self.assertEqual(ids["CVE-2024-2"], 0)  # vendor id inherits finding severity
        self.assertEqual(ids["GHSA-abcd-1234-efgh"], 3)

    def test_image_packages_sorted_dedup_and_key_stable(self) -> None:
        a = cvenow.image_packages([["b", "v2"], ["a", "v1"], ["b", "v2"], ["", "x"]])
        b = cvenow.image_packages([["a", "v1"], ["b", "v2"]])
        self.assertEqual(a, [{"ecosystem": "go", "name": "a", "version": "v1"}, {"ecosystem": "go", "name": "b", "version": "v2"}])
        self.assertEqual(cvenow.packages_key(a), cvenow.packages_key(b))

    def test_normalize_real_entry_with_exploit_evidence(self) -> None:
        raw = fixture("CVE-2007-4559.json")
        out = cvenow.normalize_entry("CVE-2007-4559", {"fetched_at": "t", "status": 200, "entry": raw})
        self.assertTrue(out["found"])
        self.assertEqual(out["cvss"], 9.8)
        self.assertEqual(out["vector"], "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        self.assertEqual(out["severity_source"], "cisa-adp")
        self.assertIsNone(out["kev"])
        self.assertEqual(out["epss_reached"], "2026-11-02")
        self.assertEqual(len(out["github_poc"]), 7)
        self.assertEqual(out["exploit_db"], [])
        self.assertFalse(out["nuclei"])
        self.assertEqual(out["ssvc"]["exploitation"], "poc")
        self.assertEqual(out["url"], "https://cve.now/CVE-2007-4559")
        self.assertEqual(out["cvenow_status"], "published")

    def test_normalize_real_entry_with_nulls(self) -> None:
        raw = fixture("CVE-2017-17740.json")
        out = cvenow.normalize_entry("CVE-2017-17740", {"fetched_at": "t", "status": 200, "entry": raw})
        self.assertTrue(out["found"])
        self.assertIsNone(out["cvss"])
        self.assertIsNone(out["ssvc"])
        self.assertEqual(out["fixed_in"], [])
        self.assertEqual(out["metasploit"], [])

    def test_normalize_kev_and_404(self) -> None:
        raw = entry_for(
            "CVE-2024-3",
            exploitation={
                "kev": {"dateAdded": "2024-05-01", "dueDate": "2024-05-22"},
                "epssReached": None,
                "exploitDb": {"ids": ["51234"], "publishedAt": "2024-05-02"},
                "metasploit": {"modules": ["exploit/linux/x"]},
                "nuclei": {"templates": ["t"]},
                "githubPoc": None,
            },
            statedSeverity={"source": "vendor", "value": "Important"},
            aliases=["GHSA-aaaa-bbbb-cccc"],
        )
        out = cvenow.normalize_entry("CVE-2024-3", {"fetched_at": "t", "status": 200, "entry": raw})
        self.assertEqual(out["kev"], {"date_added": "2024-05-01", "due_date": "2024-05-22"})
        self.assertEqual(out["exploit_db"], ["51234"])
        self.assertEqual(out["metasploit"], ["exploit/linux/x"])
        self.assertTrue(out["nuclei"])
        self.assertEqual(out["stated_severity"], "Important")
        self.assertEqual(out["aliases"], ["GHSA-aaaa-bbbb-cccc"])
        gone = cvenow.normalize_entry("DLA-1", {"fetched_at": "t", "status": 404, "entry": None})
        self.assertEqual(gone["found"], False)
        self.assertEqual(gone["fetched_at"], "t")

    def test_normalize_real_check_response(self) -> None:
        matches = cvenow.normalize_matches(fixture("check_sample.json"))
        self.assertEqual(len(matches), 3)
        grafana = next(m for m in matches if m["id"] == "CVE-2024-9264")
        self.assertEqual(grafana["package"], "github.com/grafana/grafana")
        self.assertEqual(grafana["version"], "10.3.3")
        self.assertTrue(grafana["publicExploit"])
        self.assertTrue(grafana["epssReached"])
        self.assertFalse(grafana["kev"])
        self.assertEqual(grafana["rating"], "critical")
        self.assertEqual(grafana["cvss"], 9.4)
        self.assertEqual(len(grafana["fixed"]), 3)


class TestClient(Base):
    def test_403_backoff_then_blocked(self) -> None:
        t = FakeTransport(lambda m, p, b: (403, b"forbidden"))
        c = self.client(t)
        self.assertIsNone(c.request("GET", "/api/v1/entries/CVE-1"))
        self.assertEqual(c.stopped_reason, "blocked")
        self.assertEqual(len(t.calls), 3)
        self.assertEqual(self.sleeps, [30, 60])
        self.assertIsNone(c.request("GET", "/api/v1/entries/CVE-2"))
        self.assertEqual(len(t.calls), 3)  # stopped: no further traffic

    def test_transient_block_recovers_and_resets(self) -> None:
        answers = iter([(429, b""), (503, b""), (200, b"{}"), (403, b""), (200, b"{}")])
        t = FakeTransport(lambda m, p, b: next(answers))
        c = self.client(t)
        self.assertEqual(c.request("GET", "/a"), (200, b"{}"))
        self.assertEqual(c.request("GET", "/b"), (200, b"{}"))
        self.assertIsNone(c.stopped_reason)
        self.assertEqual(self.sleeps, [30, 60, 30])
        self.assertEqual(c.requests, 5)
        self.assertEqual(c.blocked_responses, 3)

    def test_unreachable_stops_fast(self) -> None:
        def boom(m: str, p: str, b: Any) -> tuple[int, Any]:
            raise ConnectionError("TLS handshake failed")

        t = FakeTransport(boom)
        c = self.client(t)
        self.assertIsNone(c.request("GET", "/x"))
        self.assertEqual(c.stopped_reason, "unreachable")
        self.assertEqual(len(t.calls), 3)
        self.assertTrue(all(s <= 2 for s in self.sleeps))

    def test_budget_counts_retries(self) -> None:
        answers = iter([(403, b""), (403, b"")])
        t = FakeTransport(lambda m, p, b: next(answers))
        c = self.client(t, budget=2)
        self.assertIsNone(c.request("GET", "/x"))
        self.assertEqual(c.stopped_reason, "budget")
        self.assertEqual(c.requests, 2)

    def test_pacing_sleeps_between_requests(self) -> None:
        t = FakeTransport(lambda m, p, b: (200, b"{}"))
        c = cvenow.Client(t, rps=2.0, sleep=self.sleeps.append, monotonic=lambda: 10.0)
        for _ in range(3):
            c.request("GET", "/x")
        self.assertEqual(self.sleeps, [0.5, 0.5])

    def test_404_is_final_not_blocked(self) -> None:
        t = FakeTransport(lambda m, p, b: (404, {"error": "not found"}))
        c = self.client(t)
        status, _ = c.request("GET", "/x")
        self.assertEqual(status, 404)
        self.assertIsNone(c.stopped_reason)
        self.assertEqual(self.sleeps, [])


class TestRun(Base):
    def test_ordering_feeds_first_then_critical_high_uncached(self) -> None:
        scan = scan_doc(
            {
                "img": [
                    finding("CVE-2024-0003", "LOW"),
                    finding("CVE-2024-0002", "HIGH"),
                    finding("CVE-2024-0004", "MEDIUM"),
                    finding("CVE-2024-0001", "CRITICAL"),
                ]
            }
        )
        t = FakeTransport(default_handler())
        result = self.run_stage(scan, self.client(t))
        self.assertEqual(t.calls[0][1], "/api/v1/entries?filter=kev&limit=200")
        self.assertEqual(t.calls[1][1], "/api/v1/entries?filter=critical&limit=200")
        self.assertEqual(t.entry_ids(), ["CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0004", "CVE-2024-0003"])
        self.assertIsNone(result["stopped_reason"])
        self.assertEqual(result["requests"], 6)
        self.assertEqual(result["stats"]["found"], 4)
        self.assertEqual(result["stats"]["coverage_pct"], 100.0)
        self.assertTrue((self.entries_dir / "CVE-2024-0001.json").exists())

    def test_budget_exhaustion_keeps_partial_and_reports(self) -> None:
        scan = scan_doc({"img": [finding(f"CVE-2024-{i:04d}", "HIGH") for i in range(1, 11)]})
        t = FakeTransport(default_handler())
        result = self.run_stage(scan, self.client(t, budget=5))
        self.assertEqual(result["stopped_reason"], "budget")
        self.assertEqual(result["requests"], 5)
        self.assertEqual(result["budget"], 5)
        self.assertEqual(len(t.entry_ids()), 3)
        self.assertEqual(result["stats"]["found"], 3)
        self.assertEqual(result["stats"]["uncached"], 7)
        self.assertEqual(len(result["entries"]), 3)

    def test_blocked_mid_run(self) -> None:
        count = {"n": 0}
        base = default_handler()

        def handler(m: str, p: str, b: Any) -> tuple[int, Any]:
            count["n"] += 1
            return (403, b"") if count["n"] > 4 else base(m, p, b)

        scan = scan_doc({"img": [finding(f"CVE-2024-{i:04d}", "HIGH") for i in range(1, 6)]})
        t = FakeTransport(handler)
        result = self.run_stage(scan, self.client(t))
        self.assertEqual(result["stopped_reason"], "blocked")
        self.assertEqual(result["stats"]["found"], 2)
        self.assertEqual(result["stats"]["blocked_responses"], 3)
        self.assertEqual(self.sleeps, [30, 60])

    def test_404_cached_and_not_refetched_until_max_age(self) -> None:
        scan = scan_doc({"img": [finding("CVE-2024-0404", "HIGH")]})
        t = FakeTransport(default_handler(missing={"CVE-2024-0404"}))
        result = self.run_stage(scan, self.client(t))
        self.assertEqual(result["entries"]["CVE-2024-0404"]["found"], False)
        self.assertEqual(result["stats"]["not_found"], 1)
        cached = read_json(self.entries_dir / "CVE-2024-0404.json")
        self.assertEqual(cached["status"], 404)
        self.assertIsNone(cached["entry"])

        t2 = FakeTransport(default_handler(missing={"CVE-2024-0404"}))
        self.run_stage(scan, self.client(t2), now=NOW + _dt.timedelta(days=3))
        self.assertEqual(t2.entry_ids(), [])

        t3 = FakeTransport(default_handler())
        result3 = self.run_stage(scan, self.client(t3), now=NOW + _dt.timedelta(days=8))
        self.assertEqual(t3.entry_ids(), ["CVE-2024-0404"])
        self.assertTrue(result3["entries"]["CVE-2024-0404"]["found"])

    def test_unexpected_status_not_cached(self) -> None:
        base = default_handler()

        def handler(m: str, p: str, b: Any) -> tuple[int, Any]:
            return (400, {"error": "bad id"}) if p.endswith("CVE-2024-0400") else base(m, p, b)

        scan = scan_doc({"img": [finding("CVE-2024-0400", "HIGH")]})
        result = self.run_stage(scan, self.client(FakeTransport(handler)))
        self.assertFalse((self.entries_dir / "CVE-2024-0400.json").exists())
        self.assertEqual(result["stats"]["fetched"]["errors"], 1)
        self.assertNotIn("CVE-2024-0400", result["entries"])

    def test_unreachable_uses_cache(self) -> None:
        self.seed("CVE-2024-0001", NOW - _dt.timedelta(days=30))

        def boom(m: str, p: str, b: Any) -> tuple[int, Any]:
            raise ConnectionError("TLS error")

        scan = scan_doc({"img": [finding("CVE-2024-0001", "CRITICAL"), finding("CVE-2024-0002", "HIGH")]})
        t = FakeTransport(boom)
        result = self.run_stage(scan, self.client(t))
        self.assertEqual(result["stopped_reason"], "unreachable")
        self.assertEqual(len(t.calls), 3)
        self.assertEqual(result["stats"]["found"], 1)
        self.assertEqual(result["stats"]["uncached"], 1)
        self.assertTrue(result["entries"]["CVE-2024-0001"]["found"])

    def test_feed_refresh_then_stale_oldest_first(self) -> None:
        self.seed("CVE-2024-0001", NOW - _dt.timedelta(hours=1))  # fresh, in kev feed → refresh
        self.seed("CVE-2024-0002", NOW - _dt.timedelta(days=1))  # fresh, not in feed → skip
        self.seed("CVE-2024-0003", NOW - _dt.timedelta(days=9))  # stale
        self.seed("CVE-2024-0004", NOW - _dt.timedelta(days=20), status=404)  # stale 404, oldest
        self.seed("CVE-2024-0005", NOW - _dt.timedelta(days=10))  # stale, also in critical feed
        scan = scan_doc(
            {
                "img": [
                    finding("CVE-2024-0001", "LOW"),
                    finding("CVE-2024-0002", "CRITICAL"),
                    finding("CVE-2024-0003", "HIGH"),
                    finding("CVE-2024-0004", "HIGH"),
                    finding("CVE-2024-0005", "HIGH"),
                    finding("CVE-2024-0009", "LOW"),  # uncached
                ]
            }
        )
        feeds = {"kev": ["CVE-2024-0001", "CVE-1999-0001"], "critical": ["CVE-2024-0005"]}
        t = FakeTransport(default_handler(feeds=feeds))
        result = self.run_stage(scan, self.client(t))
        self.assertEqual(
            t.entry_ids(), ["CVE-2024-0009", "CVE-2024-0001", "CVE-2024-0005", "CVE-2024-0004", "CVE-2024-0003"]
        )
        self.assertEqual(result["stats"]["fetched"], {"new": 1, "feed": 2, "stale": 2, "errors": 0})
        self.assertEqual(result["stats"]["feed_ids_in_scan"], 2)
        self.assertEqual(result["entries"]["CVE-2024-0002"]["fetched_at"], iso(NOW - _dt.timedelta(days=1)))
        self.assertEqual(result["entries"]["CVE-2024-0004"]["fetched_at"], iso(NOW))

    def test_uppercase_ghsa_in_feed_refreshes_lowercase_cached_id(self) -> None:
        self.seed("GHSA-jw9f-hh49-cvp9", NOW - _dt.timedelta(hours=1))
        scan = scan_doc({"img": [finding("GHSA-jw9f-hh49-cvp9", "HIGH")]})
        t = FakeTransport(default_handler(feeds={"kev": ["GHSA-JW9F-HH49-CVP9"]}))
        result = self.run_stage(scan, self.client(t))
        self.assertEqual(t.entry_ids(), ["GHSA-jw9f-hh49-cvp9"])
        self.assertEqual(result["stats"]["fetched"]["feed"], 1)

    def test_feed_failure_does_not_stop_entries(self) -> None:
        base = default_handler()

        def handler(m: str, p: str, b: Any) -> tuple[int, Any]:
            return (400, b"nope") if "filter=" in p else base(m, p, b)

        scan = scan_doc({"img": [finding("CVE-2024-0001", "HIGH")]})
        result = self.run_stage(scan, self.client(FakeTransport(handler)))
        self.assertEqual(result["stats"]["found"], 1)
        self.assertEqual(result["stats"]["feed_ids"], 0)


class TestChecks(Base):
    def test_check_posted_once_per_package_list_and_cached(self) -> None:
        go = {
            "a": [["github.com/grafana/grafana", "10.3.3"], ["stdlib", "1.21"]],
            "b": [["stdlib", "1.21"], ["github.com/grafana/grafana", "10.3.3"]],  # same set, other order
            "c": [],
        }
        scan = scan_doc({"a": [], "b": [], "c": []}, go=go, match_dir=self.match_dir)
        t = FakeTransport(default_handler())
        result = self.run_stage(scan, self.client(t))
        posts = [c for c in t.calls if c[0] == "POST"]
        self.assertEqual(posts, [("POST", "/api/v1/check")])
        body = next(b for b in t.bodies if b)
        self.assertEqual([p["name"] for p in body["packages"]], ["github.com/grafana/grafana", "stdlib"])
        self.assertEqual(body["packages"][0]["ecosystem"], "go")
        self.assertEqual(set(result["checks"]), {"a", "b"})
        self.assertEqual(result["checks"]["a"]["status"], "ok")
        self.assertEqual(len(result["checks"]["b"]["matches"]), 3)
        self.assertEqual(result["requests"], 3)  # 2 feeds + 1 check
        self.assertEqual(len(list(self.check_dir.glob("*.json"))), 1)

        t2 = FakeTransport(default_handler())
        result2 = self.run_stage(scan, self.client(t2), now=NOW + _dt.timedelta(hours=12))
        self.assertEqual([c for c in t2.calls if c[0] == "POST"], [])
        self.assertEqual(result2["checks"]["a"]["status"], "cached")
        self.assertEqual(len(result2["checks"]["a"]["matches"]), 3)

        t3 = FakeTransport(default_handler())
        self.run_stage(scan, self.client(t3), now=NOW + _dt.timedelta(days=1))
        self.assertEqual(len([c for c in t3.calls if c[0] == "POST"]), 1)

    def test_check_uses_stale_cache_when_stopped(self) -> None:
        scan = scan_doc({"a": []}, go={"a": [["m", "v1"]]}, match_dir=self.match_dir)
        self.run_stage(scan, self.client(FakeTransport(default_handler())))
        t = FakeTransport(default_handler())
        result = self.run_stage(scan, self.client(t, budget=2), now=NOW + _dt.timedelta(days=2))
        self.assertEqual(result["stopped_reason"], "budget")
        self.assertEqual(result["checks"]["a"]["status"], "stale")
        self.assertEqual(len(result["checks"]["a"]["matches"]), 3)

    def test_check_not_fetched_when_no_budget_and_no_cache(self) -> None:
        scan = scan_doc({"a": []}, go={"a": [["m", "v1"]]}, match_dir=self.match_dir)
        result = self.run_stage(scan, self.client(FakeTransport(default_handler()), budget=2))
        self.assertEqual(result["checks"]["a"]["status"], "not_fetched")
        self.assertEqual(result["checks"]["a"]["matches"], [])
        self.assertFalse(self.check_dir.exists() and any(self.check_dir.iterdir()))

    def test_check_batches_large_package_lists(self) -> None:
        scan = scan_doc({"a": []}, go={"a": [[f"m{i:05d}", "v1"] for i in range(cvenow.CHECK_BATCH + 5)]},
                        match_dir=self.match_dir)
        t = FakeTransport(default_handler())
        result = self.run_stage(scan, self.client(t))
        sizes = [len(b["packages"]) for b in t.bodies if b]
        self.assertEqual(sizes, [cvenow.CHECK_BATCH, 5])
        self.assertEqual(len(result["checks"]["a"]["matches"]), 6)


    def test_check_only_latest_ok_images_read_from_match_cache(self) -> None:
        go = {name: [["m", "v1"]] for name in ("latest", "old", "failed")}
        scan = scan_doc({"latest": [], "old": [], "failed": []}, go=go, match_dir=self.match_dir,
                        priority={"old": 3})
        scan["images"]["failed"]["status"] = "unavailable"
        result = self.run_stage(scan, self.client(FakeTransport(default_handler())))
        self.assertEqual(set(result["checks"]), {"latest"})
        self.assertEqual(result["stats"]["checks"]["images"], 1)
        # without its match document an image has no module list to check
        match.path(self.match_dir, scan["images"]["latest"]["digest"]).unlink()
        result = self.run_stage(scan, self.client(FakeTransport(default_handler())))
        self.assertEqual(result["checks"], {})


class TestMain(Base):
    def test_main_writes_enrichment_when_unreachable(self) -> None:
        root = Path(self.tmp.name)
        scan_path = root / "scan.json"
        out_path = root / "enrichment.json"
        write_json(scan_path, scan_doc({"img": [finding("CVE-2024-0001", "HIGH")]}))

        def boom(self: Any, m: str, u: str, b: bytes | None = None) -> tuple[int, bytes]:
            raise ConnectionError("TLS error")

        dirs = {"entries_dir": self.entries_dir, "check_dir": self.check_dir}
        with mock.patch.object(cvenow.UrllibTransport, "__call__", boom), mock.patch.object(
            cvenow.time, "sleep"
        ), mock.patch.dict(cvenow.run.__kwdefaults__, dirs):
            rc = cvenow.main(["--scan", str(scan_path), "--output", str(out_path)])
        self.assertEqual(rc, 0)
        out = read_json(out_path)
        self.assertEqual(out["stopped_reason"], "unreachable")
        self.assertEqual(out["source"], "https://cve.now")
        self.assertEqual(out["entries"], {})

    def test_main_refuses_old_format_scan(self) -> None:
        root = Path(self.tmp.name)
        scan_path, out_path = root / "scan.json", root / "enrichment.json"
        write_json(scan_path, {"images": {"img": {"status": "ok", "findings": [finding("CVE-2024-0001", "HIGH")]}}})
        transport = mock.Mock(side_effect=AssertionError("no request expected"))
        with mock.patch.object(cvenow.UrllibTransport, "__call__", transport), mock.patch.object(cvenow, "log") as log:
            rc = cvenow.main(["--scan", str(scan_path), "--output", str(out_path)])
        self.assertEqual(rc, 1)
        self.assertIn("format_version", log.call_args[0][0])
        self.assertFalse(out_path.exists())


if __name__ == "__main__":
    unittest.main()
