"""Stage 3: enrich scan.json vulnerability IDs with cve.now data (writes enrichment.json).

Work order within the request budget (every HTTP attempt counts, retries included):

  1. the kev and critical feeds (2 requests; also act as the reachability probe),
  2. uncached IDs, CRITICAL/HIGH first,
  3. cached IDs that appear in this run's feed responses,
  4. stale cached entries (older than --max-age-days), oldest first,
  5. POST /check for images used by a latest chart version (scan priority 0) with Go modules
     (informational cross-check only; module lists are read from the match cache one digest at a time).

IDs come from scan.json's global 'ids' map, so per-image findings are never loaded.
enrichment.json is always rebuilt from the on-disk cache, so data from earlier runs is
used even when this run could not reach cve.now.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import http.client
import json
import re
import time
import urllib.error
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Any, Callable, Iterable

from . import match
from .common import (
    CVENOW_CHECK_DIR,
    CVENOW_ENTRIES_DIR,
    ENRICHMENT_FILE,
    MATCH_DIR,
    SCAN_FILE,
    SEVERITIES,
    log,
    parse_time,
    read_json,
    utcnow,
    write_json,
)

BASE_URL = "https://cve.now"
USER_AGENT = "rbac-atlas/1.0 (+https://rbac-atlas.github.io)"
# GHSA suffixes are matched case-insensitively: Trivy emits them lowercase, cve.now aliases uppercase.
ID_RE = re.compile(r"^(CVE-\d{4}-\d+|GHSA-(?i:[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4})|GO-\d{4}-\d+)$")
# Unanchored variant used to pull IDs out of feed responses whose exact shape is unverified.
FEED_ID_RE = re.compile(r"\b(CVE-\d{4}-\d+|GHSA-(?i:[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4})|GO-\d{4}-\d+)\b")
FEEDS = ("kev", "critical")
FEED_LIMIT = 200
BACKOFF_SECONDS = (30, 60, 120)
MAX_CONSECUTIVE_FAILURES = 3
CHECK_MAX_AGE = _dt.timedelta(hours=20)  # "1 day", with slack so a daily schedule refreshes daily
CHECK_BATCH = 10000
BLOCKED_STATUSES = {403, 429}

# transport(method, url, body) -> (http_status, body_bytes); raises ConnectionError when the
# server cannot be reached at all (DNS, TLS, refused, timeout).
Transport = Callable[[str, str, "bytes | None"], "tuple[int, bytes]"]


class UrllibTransport:
    """Default HTTP layer: urllib, follows redirects, returns non-2xx statuses instead of raising."""

    def __init__(self, timeout: float = 20.0) -> None:
        self.timeout = timeout

    def __call__(self, method: str, url: str, body: bytes | None = None) -> tuple[int, bytes]:
        headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            try:
                payload = exc.read()
            except OSError:
                payload = b""
            return exc.code, payload
        except (urllib.error.URLError, OSError, http.client.HTTPException) as exc:
            raise ConnectionError(str(exc)) from exc


class Client:
    """Budgeted, paced cve.now client with backoff and stop conditions.

    request() returns (status, body) for any final response (200, 404, other 4xx) or None
    when the client has stopped (stopped_reason is then "budget", "blocked" or "unreachable").
    """

    def __init__(
        self,
        transport: Transport,
        *,
        budget: int = 3000,
        rps: float = 1.0,
        base_url: str = BASE_URL,
        sleep: Callable[[float], None] | None = None,
        monotonic: Callable[[], float] | None = None,
    ) -> None:
        self.transport = transport
        self.budget = budget
        self.interval = 1.0 / rps if rps > 0 else 0.0
        self.base_url = base_url.rstrip("/")
        self.sleep = sleep or time.sleep
        self.monotonic = monotonic or time.monotonic
        self.requests = 0
        self.responses = 0  # any HTTP response received (proves reachability)
        self.blocked_responses = 0
        self.connection_errors = 0
        self.stopped_reason: str | None = None
        self._last: float | None = None

    def _pace(self) -> None:
        if self._last is not None and self.interval:
            wait = self.interval - (self.monotonic() - self._last)
            if wait > 0:
                self.sleep(wait)
        self._last = self.monotonic()

    def request(self, method: str, path: str, payload: Any = None) -> tuple[int, bytes] | None:
        body = json.dumps(payload).encode("utf-8") if payload is not None else None
        url = f"{self.base_url}{path}"
        failures = 0
        while True:
            if self.stopped_reason:
                return None
            if self.requests >= self.budget:
                self.stopped_reason = "budget"
                return None
            self._pace()
            self.requests += 1
            try:
                status, data = self.transport(method, url, body)
            except ConnectionError as exc:
                self.connection_errors += 1
                failures += 1
                log(f"cve.now: connection error on {path}: {exc}")
                if failures >= MAX_CONSECUTIVE_FAILURES:
                    self.stopped_reason = "unreachable"
                    return None
                # Never reached the server yet: stop fast instead of backing off for minutes.
                self.sleep(2.0 if self.responses == 0 else BACKOFF_SECONDS[failures - 1])
                continue
            self.responses += 1
            if status in BLOCKED_STATUSES or status >= 500:
                self.blocked_responses += 1
                failures += 1
                log(f"cve.now: HTTP {status} on {path} ({failures}/{MAX_CONSECUTIVE_FAILURES})")
                if failures >= MAX_CONSECUTIVE_FAILURES:
                    self.stopped_reason = "blocked"
                    return None
                self.sleep(BACKOFF_SECONDS[failures - 1])
                continue
            return status, data


# ───────────────────────────── scan.json helpers ──────────────────────────────


def canonical_id(vid: str) -> str:
    """One spelling per ID: GHSA suffixes lowercased (Trivy's form), everything else unchanged."""
    return "GHSA-" + vid[5:].lower() if vid.upper().startswith("GHSA-") else vid


def _severity_rank(severity: str | None) -> int:
    try:
        return SEVERITIES.index((severity or "UNKNOWN").upper())
    except ValueError:
        return len(SEVERITIES)


def collect_ids(scan: dict[str, Any]) -> dict[str, int]:
    """Map every enrichable ID in scan.json's 'ids' map ({ID: worst severity}) to its severity rank."""
    ids: dict[str, int] = {}
    for vid, severity in (scan.get("ids") or {}).items():
        if isinstance(vid, str) and ID_RE.match(vid):
            vid = canonical_id(vid)
            rank = _severity_rank(severity)
            ids[vid] = min(rank, ids.get(vid, rank))
    return ids


def image_packages(go_modules: Iterable[list[str]]) -> list[dict[str, str]]:
    """Sorted, de-duplicated /check package list for an image's Go modules."""
    pairs = {(str(m[0]), str(m[1])) for m in go_modules if len(m) >= 2 and m[0] and m[1]}
    return [{"ecosystem": "go", "name": n, "version": v} for n, v in sorted(pairs)]


def packages_key(packages: list[dict[str, str]]) -> str:
    return hashlib.sha256(json.dumps(packages, sort_keys=True).encode("utf-8")).hexdigest()


# ───────────────────────────── normalization ──────────────────────────────


def _get(obj: Any, *keys: str) -> Any:
    for key in keys:
        if not isinstance(obj, dict):
            return None
        obj = obj.get(key)
    return obj


def _list(value: Any) -> list:
    return list(value) if isinstance(value, list) else []


def normalize_entry(vid: str, cached: dict[str, Any]) -> dict[str, Any]:
    """Flatten a cached cve.now entry into the enrichment.json entry shape."""
    entry = cached.get("entry") if cached.get("status") == 200 else None
    out: dict[str, Any] = {
        "found": isinstance(entry, dict),
        "fetched_at": cached.get("fetched_at"),
        "url": f"{BASE_URL}/{vid}",
    }
    if not isinstance(entry, dict):
        return out
    exploitation = entry.get("exploitation") or {}
    kev = exploitation.get("kev")
    ssvc = entry.get("ssvc")
    out.update(
        {
            "canonical_id": entry.get("id") or vid,
            "title": entry.get("title"),
            "cvss": _get(entry, "severity", "cvss"),
            "vector": _get(entry, "severity", "vector"),
            "severity_source": _get(entry, "severity", "source"),
            "stated_severity": _get(entry, "statedSeverity", "value"),
            "stated_severity_source": _get(entry, "statedSeverity", "source"),
            "kev": (
                {"date_added": kev.get("dateAdded"), "due_date": kev.get("dueDate")}
                if isinstance(kev, dict)
                else None
            ),
            "epss_reached": _get(exploitation, "epssReached", "date"),
            "exploit_db": _list(_get(exploitation, "exploitDb", "ids")),
            "metasploit": _list(_get(exploitation, "metasploit", "modules")),
            "nuclei": bool(exploitation.get("nuclei")),
            "github_poc": _list(_get(exploitation, "githubPoc", "repos")),
            "ssvc": ssvc if isinstance(ssvc, dict) else None,
            "fixed_in": _list(entry.get("fixedIn")),
            "aliases": _list(entry.get("aliases")),
            "superseded_by": _list(entry.get("supersededBy")),
            "cvenow_status": entry.get("status"),
            "published_at": entry.get("publishedAt"),
            "modified_at": entry.get("modifiedAt"),
        }
    )
    return out


def normalize_matches(response: dict[str, Any] | None) -> list[dict[str, Any]]:
    matches = []
    for item in _list((response or {}).get("affected")):
        if not isinstance(item, dict):
            continue
        matches.append(
            {
                "id": item.get("id"),
                "package": _get(item, "package", "name"),
                "version": _get(item, "package", "version"),
                "rating": item.get("rating"),
                "kev": bool(item.get("kev")),
                "activelyExploited": bool(item.get("activelyExploited")),
                "publicExploit": bool(item.get("publicExploit")),
                "epssReached": bool(item.get("epssReached")),
                "fixed": _list(item.get("fixed")),
                "cvss": _get(item, "severity", "cvss"),
            }
        )
    return matches


# ───────────────────────────── stage ──────────────────────────────


def _age(cached: dict[str, Any] | None, now: _dt.datetime) -> _dt.timedelta | None:
    try:
        return now - parse_time(cached["fetched_at"])  # type: ignore[index]
    except (KeyError, TypeError, ValueError):
        return None


def _decode(data: bytes) -> Any:
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None


def _iso(now: _dt.datetime) -> str:
    return now.astimezone(_dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def fetch_feeds(client: Client) -> set[str]:
    """IDs mentioned in the kev and critical feeds (extracted by regex; shape unverified)."""
    ids: set[str] = set()
    for name in FEEDS:
        result = client.request("GET", f"/api/v1/entries?filter={name}&limit={FEED_LIMIT}")
        if result is None:
            break
        status, data = result
        if status == 200:
            ids.update(canonical_id(v) for v in FEED_ID_RE.findall(data.decode("utf-8", "replace")))
        else:
            log(f"cve.now: feed {name} returned HTTP {status}")
    return ids


def run(
    scan: dict[str, Any],
    client: Client,
    *,
    entries_dir: Path = CVENOW_ENTRIES_DIR,
    check_dir: Path = CVENOW_CHECK_DIR,
    match_dir: Path = MATCH_DIR,
    max_age_days: float = 7.0,
    now: Callable[[], _dt.datetime] = lambda: _dt.datetime.now(_dt.timezone.utc),
) -> dict[str, Any]:
    """Refresh the cve.now cache within the client's budget and build enrichment.json."""
    started = time.monotonic()
    run_now = now()
    max_age = _dt.timedelta(days=max_age_days)
    ids = collect_ids(scan)
    cache: dict[str, dict[str, Any] | None] = {vid: read_json(entries_dir / f"{vid}.json") for vid in ids}
    done: set[str] = set()
    fetched = {"new": 0, "feed": 0, "stale": 0, "errors": 0}

    def fetch_entry(vid: str, phase: str) -> bool:
        """Fetch one entry; False once the client has stopped."""
        result = client.request("GET", f"/api/v1/entries/{vid}")
        if result is None:
            return False
        done.add(vid)
        status, data = result
        entry = _decode(data) if status == 200 else None
        if (status == 200 and isinstance(entry, dict)) or status == 404:
            record = {"fetched_at": _iso(now()), "status": status, "entry": entry}
            write_json(entries_dir / f"{vid}.json", record)
            cache[vid] = record
            fetched[phase] += 1
        else:
            fetched["errors"] += 1
            log(f"cve.now: unexpected HTTP {status} for {vid}")
        return True

    feed_ids = fetch_feeds(client)

    uncached = sorted((vid for vid, c in cache.items() if not c), key=lambda v: (ids[v], v))
    feed_refresh = sorted(vid for vid in ids if cache[vid] and vid in feed_ids)
    ages = {vid: _age(c, run_now) for vid, c in cache.items() if c}
    # A cached record without a parseable fetched_at is treated as stale.
    ages = {vid: max_age if age is None else age for vid, age in ages.items()}
    stale = sorted((vid for vid, age in ages.items() if age >= max_age), key=lambda v: (-ages[v], v))

    for phase, todo in (("new", uncached), ("feed", feed_refresh), ("stale", stale)):
        for vid in todo:
            if vid in done:
                continue
            if not fetch_entry(vid, phase):
                break
        if client.stopped_reason:
            break

    checks, check_stats = run_checks(scan, client, check_dir=check_dir, match_dir=match_dir, now=now)

    entries = {vid: normalize_entry(vid, c) for vid, c in sorted(cache.items()) if c}
    found = sum(1 for e in entries.values() if e["found"])
    prefixes = dict(Counter(vid.split("-", 1)[0] for vid in ids))
    stats = {
        "ids": len(ids),
        "ids_by_prefix": prefixes,
        "found": found,
        "not_found": len(entries) - found,
        "uncached": len(ids) - len(entries),
        "coverage_pct": round(100.0 * found / len(ids), 1) if ids else 0.0,
        "fetched": fetched,
        "feed_ids": len(feed_ids),
        "feed_ids_in_scan": len(feed_ids & set(ids)),
        "blocked_responses": client.blocked_responses,
        "connection_errors": client.connection_errors,
        "checks": check_stats,
        "seconds": round(time.monotonic() - started, 1),
    }
    return {
        "generated_at": utcnow(),
        "source": BASE_URL,
        "requests": client.requests,
        "budget": client.budget,
        "stopped_reason": client.stopped_reason,
        "entries": entries,
        "checks": checks,
        "stats": stats,
    }


def run_checks(
    scan: dict[str, Any],
    client: Client,
    *,
    check_dir: Path = CVENOW_CHECK_DIR,
    match_dir: Path = MATCH_DIR,
    now: Callable[[], _dt.datetime] = lambda: _dt.datetime.now(_dt.timezone.utc),
) -> tuple[dict[str, Any], dict[str, int]]:
    """POST /check once per distinct Go package list (cached), mapped back to each image.

    Only 'ok' images used by a latest chart version (priority 0) that have Go modules are checked."""
    stats = {"images": 0, "fetched": 0, "cached": 0, "stale": 0, "errors": 0, "not_fetched": 0}
    checks: dict[str, Any] = {}
    results: dict[str, tuple[str, str | None, list[dict[str, Any]]]] = {}

    def check_batch(packages: list[dict[str, str]]) -> tuple[str, str | None, list[dict[str, Any]]]:
        key = packages_key(packages)
        if key in results:
            return results[key]
        path = check_dir / f"{key}.json"
        cached = read_json(path)
        age = _age(cached, now())
        if cached and age is not None and age < CHECK_MAX_AGE:
            res = ("cached", cached.get("fetched_at"), normalize_matches(cached.get("response")))
        else:
            result = client.request("POST", "/api/v1/check", {"packages": packages})
            response = _decode(result[1]) if result and result[0] == 200 else None
            if isinstance(response, dict):
                record = {"fetched_at": _iso(now()), "status": 200, "response": response}
                write_json(path, record)
                res = ("ok", record["fetched_at"], normalize_matches(response))
            elif cached:
                res = ("stale", cached.get("fetched_at"), normalize_matches(cached.get("response")))
            else:
                res = ("not_fetched" if result is None else "error", None, [])
        results[key] = res
        return res

    for canonical, image in sorted((scan.get("images") or {}).items()):
        if image.get("status") != "ok" or (image.get("priority") or 0) != 0 or not image.get("go_modules"):
            continue
        packages = image_packages((match.load(match_dir, image["digest"]) or {}).get("go") or [])
        if not packages:
            continue
        stats["images"] += 1
        statuses, matches, fetched_at = [], [], None
        for i in range(0, len(packages), CHECK_BATCH):
            status, at, found = check_batch(packages[i : i + CHECK_BATCH])
            statuses.append(status)
            matches.extend(found)
            fetched_at = min(filter(None, (fetched_at, at)), default=None)
        # Worst batch status wins so a partial result is never reported as complete.
        status = next(s for s in ("not_fetched", "error", "stale", "cached", "ok") if s in statuses)
        stats["fetched" if status == "ok" else status] += 1
        checks[canonical] = {"status": status, "fetched_at": fetched_at, "packages": len(packages), "matches": matches}
    return checks, stats


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Enrich scan.json vulnerability IDs with cve.now.")
    parser.add_argument("--scan", type=Path, default=SCAN_FILE, help="scan.json path")
    parser.add_argument("--match-dir", type=Path, default=MATCH_DIR, help="per-digest match cache (Go modules)")
    parser.add_argument("--output", type=Path, default=ENRICHMENT_FILE, help="enrichment.json path")
    parser.add_argument("--budget", type=int, default=3000, help="max HTTP requests this run (retries count)")
    parser.add_argument("--rps", type=float, default=1.0, help="max requests per second")
    parser.add_argument("--max-age-days", type=float, default=7.0, help="refresh cached entries older than this")
    parser.add_argument("--timeout", type=float, default=20.0, help="per-request timeout in seconds")
    args = parser.parse_args(argv)

    scan = read_json(args.scan)
    if not isinstance(scan, dict):
        log(f"cve.now: cannot read {args.scan}")
        return 1
    if err := match.scan_format_error(scan, args.scan):
        log(f"cve.now: {err}")
        return 1
    client = Client(UrllibTransport(args.timeout), budget=args.budget, rps=args.rps)
    result = run(scan, client, match_dir=args.match_dir, max_age_days=args.max_age_days)
    write_json(args.output, result)
    s = result["stats"]
    log(
        f"cve.now: {s['ids']} ids, {s['found']} found, {s['not_found']} not found, {s['uncached']} uncached "
        f"({s['coverage_pct']}%); {result['requests']}/{result['budget']} requests; "
        f"stopped_reason={result['stopped_reason']}; checks={s['checks']}; wrote {args.output}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
