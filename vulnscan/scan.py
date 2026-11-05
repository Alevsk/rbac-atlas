"""Scan stage: resolve image digests, cache one CycloneDX SBOM per digest, rematch every SBOM with Trivy.

Reads inventory.json (vulnscan.inventory) and writes scan.json. scan.json stays small (per image: status,
digest, os, counts, ...; plus a global 'ids' map {vulnerability ID: worst severity} for cvenow); the
per-vulnerability detail of each digest lives only in the match cache (vulnscan.match, MATCH_DIR), which
report and cvenow read one digest at a time.

  1. resolve   tag → linux/amd64 digest with `crane digest` (cached in resolve.json, re-resolved after
               --resolve-max-age-hours, or --resolve-max-age-hours-old for images not used by a latest chart
               version; docker.io refs try mirror.gcr.io first). Digest-pinned refs skip it.
  2. sbom      `trivy image --image-src remote --format cyclonedx` once per digest, gzipped into SBOM_DIR
               (at most --max-new-sboms new SBOMs per run, highest inventory priority first; the rest are
               'skipped' with reason 'sbom_quota'). Failures are remembered in SBOM_FAILURES_FILE and
               permanent-looking ones (timeout, no_amd64, unauthorized, not_found) back off exponentially.
  3. rematch   `trivy sbom` on cached SBOMs against the current DB, summarized and stored per digest in
               MATCH_DIR (vulnscan.match format; older formats are re-derived or treated as missing). Digests used by a latest chart version are rematched every run; the
               others when their cached match is missing or older than --rematch-max-age-hours, at most
               --max-rematch per run (missing first, then oldest); the rest reuse their cached match.

--time-budget-minutes stops starting new SBOMs/rematches once exceeded (cached matches are still used), so
the run always finishes and writes its outputs.

The Trivy DB (and Java DB) must already be downloaded by the caller; every Trivy call uses
--skip-db-update/--skip-java-db-update. Binaries come from $TRIVY and $CRANE; this module never installs them.
One failing image never aborts the run.
"""

from __future__ import annotations

import argparse
import gzip
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from vulnscan import match
from vulnscan.common import (
    INVENTORY_FILE,
    MATCH_DIR,
    RESOLVE_FILE,
    SBOM_DIR,
    SBOM_FAILURES_FILE,
    SCAN_FILE,
    SEVERITIES,
    log,
    parse_time,
    read_json,
    utcnow,
    write_json,
)

PLATFORM = "linux/amd64"
DOCKER_MIRROR = "mirror.gcr.io"
CRANE_TIMEOUT = 90.0
SBOM_TIMEOUT = 660.0  # trivy's own --timeout is 10m; this is the hard stop around it
REMATCH_TIMEOUT = 600.0
RESOLVE_WORKERS = 6
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
# Within one CVSS source, preferred vector families in order: (score key, vector key, default version).
CVSS_SOURCE_ORDER = ("nvd", "ghsa", "redhat")
CVSS_KINDS = (("V3Score", "V3Vector", "3.1"), ("V40Score", "V40Vector", "4.0"), ("V2Score", "V2Vector", "2.0"))
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}
# SBOM failures that are unlikely to change by tomorrow: retry after 1, 2, 4, ... (max 30) days.
BACKOFF_REASONS = {"timeout", "no_amd64", "unauthorized", "not_found"}
BACKOFF_MAX_DAYS = 30


@dataclass
class Proc:
    """Result of an external command (subset of subprocess.CompletedProcess)."""

    returncode: int
    stdout: str
    stderr: str


Runner = Callable[[list[str], float], Proc]


def run_command(cmd: list[str], timeout: float) -> Proc:
    """Run a command, never raising: timeouts map to rc 124, a missing binary to rc 127."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, errors="replace")
        return Proc(p.returncode, p.stdout, p.stderr)
    except subprocess.TimeoutExpired:
        return Proc(124, "", f"timeout after {timeout:.0f}s")
    except OSError as exc:
        return Proc(127, "", f"cannot execute {cmd[0]}: {exc}")


# ───────────────────────────── Error classification ──────────────────────────────
_ERROR_PATTERNS = (
    ("no_amd64", re.compile(r"no child with platform|no matching manifest", re.I)),
    ("rate_limited", re.compile(r"TOOMANYREQUESTS|\b429\b|too many requests", re.I)),
    ("unauthorized", re.compile(r"UNAUTHORIZED|DENIED", re.I)),
    ("not_found", re.compile(r"MANIFEST_UNKNOWN|NAME_UNKNOWN|not found", re.I)),
    ("timeout", re.compile(r"timeout|timed out|deadline exceeded", re.I)),
)


def classify_error(stderr: str) -> str:
    """Map crane/trivy stderr to a reason: not_found, unauthorized, no_amd64, rate_limited, timeout or error."""
    stderr = stderr or ""
    if stderr.startswith("cannot execute "):
        return "error"
    # The final error line is authoritative (earlier lines may be retried 429s); fall back to the whole text.
    for text in (_tail(stderr, 2000), stderr):
        for reason, pattern in _ERROR_PATTERNS:
            if pattern.search(text):
                return reason
    return "error"


def _tail(text: str, limit: int = 300) -> str:
    """Last non-empty line of a command's stderr, trimmed (for logs)."""
    lines = [ln for ln in (text or "").strip().splitlines() if ln.strip()]
    return (lines[-1] if lines else "")[-limit:]


# ───────────────────────────── Trivy JSON summary ──────────────────────────────
def cvss_version(vector: str | None, default: str) -> str:
    """CVSS version from a vector prefix such as 'CVSS:3.0/...'; default when there is no prefix."""
    m = re.match(r"CVSS:(\d\.\d)/", vector or "")
    return m.group(1) if m else default


def pick_cvss(cvss: dict[str, Any] | None) -> dict[str, Any] | None:
    """Choose one CVSS rating: source nvd > ghsa > redhat > others (alphabetical); within it V3 > V4.0 > V2."""
    if not cvss:
        return None
    others = sorted(s for s in cvss if s not in CVSS_SOURCE_ORDER)
    for source in [s for s in CVSS_SOURCE_ORDER if s in cvss] + others:
        data = cvss.get(source) or {}
        for score_key, vector_key, default_version in CVSS_KINDS:
            score, vector = data.get(score_key), data.get(vector_key)
            if score is None and not vector:
                continue
            return {
                "score": score,
                "vector": vector,
                "version": cvss_version(vector, default_version),
                "source": source,
            }
    return None


def summarize_report(report: dict[str, Any]) -> dict[str, Any]:
    """Reduce a Trivy JSON report to {os, findings, go_modules, counts} (compacted by match.compact)."""
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    go_modules: set[tuple[str, str]] = set()
    worst: dict[str, str] = {}
    for result in report.get("Results") or []:
        rclass, rtype = result.get("Class"), result.get("Type")
        if rtype == "gobinary":
            for pkg in result.get("Packages") or []:
                name, version = pkg.get("Name"), pkg.get("Version")
                if name and version and name != "stdlib" and version != "(devel)":
                    go_modules.add((name, version))
        for v in result.get("Vulnerabilities") or []:
            vid, pkg, installed = v.get("VulnerabilityID"), v.get("PkgName"), v.get("InstalledVersion")
            if not vid or (vid, pkg, installed) in seen:
                continue
            seen.add((vid, pkg, installed))
            severity = (v.get("Severity") or "UNKNOWN").upper()
            if severity not in SEVERITY_RANK:
                severity = "UNKNOWN"
            findings.append({
                "id": vid,
                "pkg": pkg,
                "pkg_type": rtype,
                "class": rclass,
                "installed": installed,
                "fixed": v.get("FixedVersion") or None,
                "status": v.get("Status"),
                "severity": severity,
                "severity_source": v.get("SeveritySource"),
                "cvss": pick_cvss(v.get("CVSS")),
                "cwes": list(v.get("CweIDs") or []),
                "vendor_ids": list(v.get("VendorIDs") or []),
            })
            if vid not in worst or SEVERITY_RANK[severity] < SEVERITY_RANK[worst[vid]]:
                worst[vid] = severity
    counts = {s: 0 for s in SEVERITIES}
    for severity in worst.values():
        counts[severity] += 1
    os_meta = (report.get("Metadata") or {}).get("OS")
    os_info = None
    if os_meta:
        os_info = {"family": os_meta.get("Family"), "name": os_meta.get("Name"), "eosl": bool(os_meta.get("EOSL"))}
    findings.sort(key=lambda f: (SEVERITY_RANK[f["severity"]], f["id"], f["pkg"] or "", f["installed"] or ""))
    return {
        "os": os_info,
        "findings": findings,
        "go_modules": [list(m) for m in sorted(go_modules)],
        "counts": counts,
    }


# ───────────────────────────── Scanner ──────────────────────────────
def image_sources(info: dict[str, Any]) -> list[str]:
    """Repository locations to try, in order (docker.io → mirror.gcr.io first)."""
    registry, repository = info["registry"], info["repository"]
    if registry == "docker.io":
        return [f"{DOCKER_MIRROR}/{repository}", f"docker.io/{repository}"]
    return [f"{registry}/{repository}"]


def trivy_metadata(trivy: str, runner: Runner) -> dict[str, Any]:
    """Trivy version and vulnerability DB metadata from `trivy version -f json`."""
    p = runner([trivy, "version", "-f", "json"], 60.0)
    try:
        data = json.loads(p.stdout) if p.returncode == 0 else {}
    except ValueError:
        data = {}
    db = data.get("VulnerabilityDB") or {}
    return {"version": data.get("Version"), "db_version": db.get("Version"), "db_updated_at": db.get("UpdatedAt")}


def scan_order(images: dict[str, dict[str, Any]]) -> list[str]:
    """Canonical refs in scan order: inventory priority (0 = used by a latest chart version), then
    main-role images, then images used by more chart versions, then name."""
    def key(c: str) -> tuple[int, bool, int, str]:
        info = images[c]
        priority = info.get("priority")
        return (priority if isinstance(priority, int) else 0, "main" not in (info.get("roles") or ["main"]),
                -len(info.get("charts") or []), c)

    return sorted(images, key=key)


class Scanner:
    """Runs resolve → SBOM → rematch for a set of inventory images, sharing one resolve cache."""

    def __init__(
        self,
        *,
        trivy: str = "trivy",
        crane: str = "crane",
        runner: Runner | None = None,
        sbom_dir: Path = SBOM_DIR,
        resolve_cache: dict[str, Any] | None = None,
        resolve_max_age_hours: float = 20.0,
        resolve_max_age_hours_old: float | None = None,
        max_new_sboms: int = 200,
        workers: int = 3,
        rematch_workers: int = 4,
        sbom_failures: dict[str, Any] | None = None,
        match_dir: Path = MATCH_DIR,
        max_rematch: int | None = None,
        rematch_max_age_hours: float = 168.0,
        time_budget_seconds: float | None = None,
        now: Callable[[], str] = utcnow,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.trivy, self.crane, self.runner = trivy, crane, runner or run_command
        self.sbom_dir = Path(sbom_dir)
        self.resolve_cache = resolve_cache if resolve_cache is not None else {}
        self.resolve_max_age_hours = resolve_max_age_hours
        self.resolve_max_age_hours_old = (resolve_max_age_hours if resolve_max_age_hours_old is None
                                          else resolve_max_age_hours_old)
        self.max_new_sboms = max_new_sboms
        self.workers, self.rematch_workers = max(1, workers), max(1, rematch_workers)
        self.sbom_failures = sbom_failures if sbom_failures is not None else {}
        self.match_dir = Path(match_dir)
        self.max_rematch = max_rematch
        self.rematch_max_age_hours = rematch_max_age_hours
        self.time_budget_seconds = time_budget_seconds
        self.now = now
        self.clock = clock
        self._deadline: float | None = None
        self._lock = threading.Lock()
        self.ids: dict[str, str] = {}

    def sbom_path(self, digest: str) -> Path:
        return self.sbom_dir / f"{digest.split(':', 1)[1]}.cdx.json.gz"

    def _age_hours(self, stamp: Any) -> float | None:
        try:
            return (parse_time(self.now()) - parse_time(stamp)).total_seconds() / 3600
        except (TypeError, ValueError, AttributeError):
            return None

    def _out_of_time(self) -> bool:
        return self._deadline is not None and self.clock() >= self._deadline

    # ── resolve ──
    def _fresh(self, entry: dict[str, Any], max_age_hours: float | None = None) -> bool:
        age = self._age_hours(entry.get("resolved_at"))
        limit = self.resolve_max_age_hours if max_age_hours is None else max_age_hours
        return age is not None and age < limit

    def resolve(self, canonical: str, info: dict[str, Any]) -> dict[str, Any]:
        """Return {digest, pulled_from, stale_resolve, reason}; digest is None when unresolvable and never seen."""
        if info.get("digest"):
            return {"digest": info["digest"], "pulled_from": None, "stale_resolve": False, "reason": None}
        with self._lock:
            entry = dict(self.resolve_cache.get(canonical) or {})
        max_age = self.resolve_max_age_hours if (info.get("priority") or 0) == 0 else self.resolve_max_age_hours_old
        if entry.get("status") == "ok" and entry.get("digest") and self._fresh(entry, max_age):
            return {"digest": entry["digest"], "pulled_from": entry.get("pulled_from"),
                    "stale_resolve": False, "reason": None}
        tag = info.get("tag") or "latest"
        reason = "error"
        for source in image_sources(info):
            p = self.runner([self.crane, "digest", "--platform", PLATFORM, f"{source}:{tag}"], CRANE_TIMEOUT)
            digest = p.stdout.strip()
            if p.returncode == 0 and DIGEST_RE.match(digest):
                with self._lock:
                    self.resolve_cache[canonical] = {"digest": digest, "resolved_at": self.now(),
                                                     "status": "ok", "pulled_from": source}
                return {"digest": digest, "pulled_from": source, "stale_resolve": False, "reason": None}
            reason = classify_error(p.stderr) if p.returncode != 0 else "error"
            log(f"  resolve {source}:{tag}: {reason} {_tail(p.stderr)}")
        with self._lock:
            entry = self.resolve_cache.setdefault(canonical, {})
            entry.update({"status": reason, "checked_at": self.now()})
            last = entry.get("digest")
        if last:
            return {"digest": last, "pulled_from": entry.get("pulled_from"), "stale_resolve": True, "reason": reason}
        return {"digest": None, "pulled_from": None, "stale_resolve": False, "reason": reason}

    # ── SBOM generation ──
    def generate_sbom(self, digest: str, sources: list[str]) -> tuple[bool, str | None, str | None]:
        """Create the cached SBOM for a digest; return (ok, reason, pulled_from)."""
        dest = self.sbom_path(digest)
        dest.parent.mkdir(parents=True, exist_ok=True)
        reason: str | None = "error"
        with tempfile.TemporaryDirectory(prefix="vulnscan-sbom-") as tmp:
            out = Path(tmp) / "sbom.cdx.json"
            for source in sources:
                cmd = [self.trivy, "image", "--image-src", "remote", "--platform", PLATFORM,
                       "--scanners", "vuln", "--format", "cyclonedx", "--skip-db-update",
                       "--skip-java-db-update", "--timeout", "10m",
                       # The default fs layer cache is a single-writer BoltDB: concurrent `trivy image`
                       # runs fail with "cache may be in use by another process". SBOMs are cached per
                       # digest by us, so the layer cache adds nothing.
                       "--cache-backend", "memory",
                       "-o", str(out), f"{source}@{digest}"]
                p = self.runner(cmd, SBOM_TIMEOUT)
                if p.returncode == 0 and out.is_file() and out.stat().st_size > 0:
                    with open(out, "rb") as src:
                        if src.read(1) != b"{":
                            reason = "error"
                            continue
                        src.seek(0)
                        part = dest.with_name(f".{dest.name}.{os.getpid()}.{threading.get_ident()}.tmp")
                        with gzip.GzipFile(part, "wb", mtime=0) as gz:
                            shutil.copyfileobj(src, gz)
                    os.replace(part, dest)
                    return True, None, source
                reason = classify_error(p.stderr) if p.returncode != 0 else "error"
                log(f"  sbom {source}@{digest[:19]}: {reason} {_tail(p.stderr)}")
                if reason in ("timeout", "no_amd64"):
                    break  # same outcome from any mirror; don't spend another 10 minutes
        return False, reason, None

    # ── rematch ──
    def rematch(self, digest: str) -> dict[str, Any]:
        """Run `trivy sbom` on the cached SBOM; return summarize_report() output or {'error': reason}."""
        with tempfile.TemporaryDirectory(prefix="vulnscan-rematch-") as tmp:
            sbom = Path(tmp) / "sbom.cdx.json"
            try:
                with gzip.open(self.sbom_path(digest), "rb") as src, open(sbom, "wb") as dst:
                    shutil.copyfileobj(src, dst)
            except (OSError, EOFError) as exc:
                log(f"  rematch {digest[:19]}: corrupt SBOM ({exc}); removing it")
                self.sbom_path(digest).unlink(missing_ok=True)
                return {"error": "sbom_corrupt"}
            out = Path(tmp) / "report.json"
            cmd = [self.trivy, "sbom", "--scanners", "vuln", "--list-all-pkgs", "--skip-db-update",
                   "--skip-java-db-update", "--cache-backend", "memory", "-f", "json", "-o", str(out), str(sbom)]
            p = self.runner(cmd, REMATCH_TIMEOUT)
            if p.returncode != 0:
                log(f"  rematch {digest[:19]}: failed {_tail(p.stderr)}")
                return {"error": "rematch_failed"}
            report = read_json(out)
            if not isinstance(report, dict):
                return {"error": "rematch_failed"}
            return summarize_report(report)

    def in_backoff(self, digest: str) -> str | None:
        """Stored failure reason when the digest's last SBOM failure is still backing off, else None."""
        entry = self.sbom_failures.get(digest)
        if not isinstance(entry, dict) or entry.get("reason") not in BACKOFF_REASONS:
            return None
        attempts = entry.get("attempts") if isinstance(entry.get("attempts"), int) else 1
        wait_days = min(2 ** max(0, attempts - 1), BACKOFF_MAX_DAYS)
        age = self._age_hours(entry.get("attempted_at"))
        return entry["reason"] if age is not None and age < wait_days * 24 else None

    def _record_sbom(self, digest: str, reason: str | None) -> None:
        with self._lock:
            if reason is None:
                self.sbom_failures.pop(digest, None)
                return
            prev = self.sbom_failures.get(digest)
            attempts = (prev.get("attempts") or 0) if isinstance(prev, dict) else 0
            self.sbom_failures[digest] = {"reason": reason, "attempted_at": self.now(),
                                          "attempts": (attempts if isinstance(attempts, int) else 0) + 1}

    def cached_match(self, digest: str) -> dict[str, Any] | None:
        """The last successful rematch of this digest (vulnscan.match format), or None.

        A format-1 entry is re-derived and rewritten in the current format; an unknown one is ignored."""
        data = read_json(match.path(self.match_dir, digest))
        doc = match.migrate(data)
        if doc is not None and doc is not data:
            try:
                match.store(self.match_dir, digest, doc)
            except OSError as exc:
                log(f"  match {digest[:19]}: cannot rewrite migrated match ({exc})")
        return doc

    # ── orchestration ──
    def scan(self, images: dict[str, dict[str, Any]]) -> tuple[dict[str, Any], dict[str, Any]]:
        """Scan inventory images ({canonical: info}); return (scan.json 'images', stats).

        Also sets self.ids: {vulnerability ID: worst severity} over every 'ok' digest (scan.json 'ids')."""
        started = time.monotonic()
        if self.time_budget_seconds is not None:
            self._deadline = self.clock() + self.time_budget_seconds
        canonicals = scan_order(images)

        def _resolve(c: str) -> dict[str, Any]:
            try:
                return self.resolve(c, images[c])
            except Exception as exc:  # one image must never abort the run
                log(f"  resolve {c}: unexpected {exc!r}")
                return {"digest": None, "pulled_from": None, "stale_resolve": False, "reason": "error"}

        log(f"resolve: {len(canonicals)} images")
        with ThreadPoolExecutor(RESOLVE_WORKERS) as pool:
            resolved = dict(zip(canonicals, pool.map(_resolve, canonicals)))

        # SBOM work is per unique digest, in scan_order (so the quota goes to the highest priority).
        by_digest: dict[str, list[str]] = {}
        for c in scan_order(images):
            if resolved[c]["digest"]:
                by_digest.setdefault(resolved[c]["digest"], []).append(c)
        cached = {d for d in by_digest if self.sbom_path(d).is_file()}
        # Failing digests in backoff are not retried and do not use the new-SBOM quota.
        backoff = {d: r for d in by_digest if d not in cached and (r := self.in_backoff(d))}
        missing = [d for d in by_digest if d not in cached and d not in backoff]
        to_generate, over_quota = missing[: self.max_new_sboms], set(missing[self.max_new_sboms:])

        sbom_failed: dict[str, str] = dict(backoff)
        pulled: dict[str, str] = {}
        out_of_time: set[str] = set()

        def _generate(digest: str) -> None:
            if self._out_of_time():
                with self._lock:
                    out_of_time.add(digest)
                return
            first = by_digest[digest][0]
            sources = image_sources(images[first])
            hint = resolved[first]["pulled_from"]
            if hint in sources:
                sources = [hint] + [s for s in sources if s != hint]
            try:
                ok, reason, source = self.generate_sbom(digest, sources)
            except Exception as exc:
                log(f"  sbom {first}: unexpected {exc!r}")
                ok, reason, source = False, "error", None
            if ok:
                pulled[digest] = source
            else:
                sbom_failed[digest] = reason or "error"
            self._record_sbom(digest, None if ok else (reason or "error"))

        log(f"sbom: {len(cached)} cached, {len(to_generate)} to generate, {len(over_quota)} over quota, "
            f"{len(backoff)} in failure backoff")
        with ThreadPoolExecutor(self.workers) as pool:
            list(pool.map(_generate, to_generate))

        have_sbom = [d for d in by_digest if d not in over_quota and d not in sbom_failed and d not in out_of_time]
        # Digest priority: best (lowest) inventory priority of the images that resolve to it.
        digest_priority = {d: min((images[c].get("priority") or 0) for c in cs) for d, cs in by_digest.items()}
        # Only matched_at is kept per digest: match documents are read one at a time (memory stays flat).
        previous = {d: m["matched_at"] for d in have_sbom if (m := self.cached_match(d))}
        always, due = [], []
        for d in have_sbom:
            if digest_priority[d] == 0 or self.max_rematch is None:
                always.append(d)
                continue
            age = self._age_hours(previous[d]) if d in previous else None
            if age is None or age >= self.rematch_max_age_hours:
                due.append(d)
        # missing matches first, then the oldest ones
        due.sort(key=lambda d: (d in previous, previous.get(d, ""), d))
        rematch_digests = always + due[: max(0, self.max_rematch or 0)] if self.max_rematch is not None else always

        def _rematch(digest: str) -> str | None:
            """Rematch and store one digest; None on success, else the error reason."""
            if self._out_of_time():
                return "time_budget"
            try:
                result = self.rematch(digest)
            except Exception as exc:
                log(f"  rematch {digest[:19]}: unexpected {exc!r}")
                return "rematch_failed"
            if "error" in result:
                return result["error"]
            try:
                match.store(self.match_dir, digest, match.compact(result, self.now()))
            except OSError as exc:
                log(f"  rematch {digest[:19]}: cannot cache match ({exc})")
                return "rematch_failed"
            return None

        log(f"rematch: {len(rematch_digests)} SBOMs ({len(always)} every run, {len(due)} due), "
            f"{len(previous)} cached matches")
        with ThreadPoolExecutor(self.rematch_workers) as pool:
            fresh = dict(zip(rematch_digests, pool.map(_rematch, rematch_digests)))
        # matched[d]: {os, counts, matched_at, go_modules} of the match now in the cache — this run's
        # rematch, else the previous one (also when this run's rematch failed or ran out of time) — or
        # {'error': reason}. Each document is read once, folded into the global 'ids' map and dropped.
        matched: dict[str, dict[str, Any]] = {}
        ids: dict[str, int] = {}
        reused = 0
        for d in have_sbom:
            error = fresh.get(d, "rematch_quota")
            doc = self.cached_match(d) if error is None or d in previous else None
            if doc is None:
                matched[d] = {"error": error or "rematch_failed"}
                continue
            reused += error is not None
            matched[d] = {"os": doc.get("os"), "counts": doc["counts"], "matched_at": doc["matched_at"],
                          "go_modules": len(doc.get("go") or [])}
            for vid, rank in match.vuln_ids(doc).items():
                ids[vid] = min(rank, ids.get(vid, rank))
        self.ids = {vid: SEVERITIES[rank] for vid, rank in sorted(ids.items())}

        out: dict[str, Any] = {}
        for c in sorted(canonicals):
            r = resolved[c]
            digest = r["digest"]
            rec: dict[str, Any] = {
                "status": "ok", "reason": None, "digest": digest,
                "pulled_from": (pulled.get(digest) or r["pulled_from"]) if digest else None,
                "stale_resolve": r["stale_resolve"], "os": None,
                "sbom_cached": bool(digest) and digest in cached, "scanned_at": None,
                "go_modules": 0, "counts": {s: 0 for s in SEVERITIES},
                "priority": images[c].get("priority") or 0,
            }
            if not digest:
                rec.update(status="unavailable", reason=r["reason"])
            elif digest in over_quota:
                rec.update(status="skipped", reason="sbom_quota")
            elif digest in out_of_time:
                rec.update(status="skipped", reason="time_budget")
            elif digest in sbom_failed:
                rec.update(status="unavailable", reason=sbom_failed[digest])
            elif "error" in matched[digest]:
                reason = matched[digest]["error"]
                status = "skipped" if reason in ("time_budget", "rematch_quota") else "unavailable"
                rec.update(status=status, reason=reason)
            else:
                m = matched[digest]
                rec.update(os=m["os"], counts=m["counts"], go_modules=m["go_modules"], scanned_at=m["matched_at"])
            if rec["status"] != "ok" and r["reason"] and rec["reason"] != r["reason"]:
                rec["resolve_reason"] = r["reason"]
            out[c] = rec

        unavailable: dict[str, int] = {}
        for rec in out.values():
            if rec["status"] == "unavailable":
                unavailable[rec["reason"]] = unavailable.get(rec["reason"], 0) + 1
        stats = {
            "images": len(out),
            "ok": sum(1 for r in out.values() if r["status"] == "ok"),
            "skipped": sum(1 for r in out.values() if r["status"] == "skipped"),
            "unavailable_by_reason": dict(sorted(unavailable.items())),
            "stale_resolve": sum(1 for r in out.values() if r["stale_resolve"]),
            "unique_digests": len(by_digest),
            "sbom_cached": len(cached),
            "new_sboms": len(pulled),
            "sbom_attempts": len(to_generate) - len(out_of_time),
            "sbom_backoff": len(backoff),
            "rematched": sum(1 for e in fresh.values() if e is None),
            "match_reused": reused,
            "time_budget_exceeded": self._out_of_time(),
            "seconds": round(time.monotonic() - started, 1),
        }
        return out, stats


def build_scan(inventory: dict[str, Any], scanner: Scanner, *, limit: int | None = None) -> dict[str, Any]:
    """Build the scan.json document for an inventory (inventory 'invalid' refs are listed with status 'invalid')."""
    images = inventory.get("images") or {}
    names = scan_order(images)
    if limit is not None:
        names = names[:limit]
    results, stats = scanner.scan({c: images[c] for c in names})
    invalid = 0
    if limit is None:
        for item in inventory.get("invalid") or []:
            ref = (item.get("ref") or "").strip()
            if not ref or ref in results:
                continue
            results[ref] = {
                "status": "invalid", "reason": item.get("reason"), "digest": None, "pulled_from": None,
                "stale_resolve": False, "os": None, "sbom_cached": False, "scanned_at": None,
                "go_modules": 0, "counts": {s: 0 for s in SEVERITIES}, "priority": 0,
            }
            invalid += 1
    stats["images"] += invalid
    stats["invalid"] = invalid
    stats["limit"] = limit
    return {
        "format_version": match.FORMAT_VERSION,
        "generated_at": utcnow(),
        "trivy": trivy_metadata(scanner.trivy, scanner.runner),
        "images": results,
        "ids": scanner.ids,
        "stats": stats,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Scan inventory images with Trivy using an SBOM-per-digest cache.")
    parser.add_argument("--inventory", type=Path, default=INVENTORY_FILE, help="input inventory.json")
    parser.add_argument("--output", type=Path, default=SCAN_FILE, help="output scan.json")
    parser.add_argument("--sbom-dir", type=Path, default=SBOM_DIR, help="SBOM cache directory")
    parser.add_argument("--resolve-file", type=Path, default=RESOLVE_FILE, help="digest resolve cache")
    parser.add_argument("--workers", type=int, default=3, help="parallel SBOM generations")
    parser.add_argument("--rematch-workers", type=int, default=4, help="parallel SBOM rematches")
    parser.add_argument("--max-new-sboms", type=int, default=200, help="new SBOMs generated per run")
    parser.add_argument("--resolve-max-age-hours", type=float, default=20.0, help="re-resolve tags older than this")
    parser.add_argument("--resolve-max-age-hours-old", type=float, default=168.0,
                        help="re-resolve tags of images not used by a latest chart version older than this")
    parser.add_argument("--sbom-failures-file", type=Path, default=SBOM_FAILURES_FILE, help="SBOM failure backoff state")
    parser.add_argument("--match-dir", type=Path, default=MATCH_DIR, help="per-digest rematch result cache")
    parser.add_argument("--max-rematch", type=int, default=4000,
                        help="rematches per run of digests not used by a latest chart version (-1 = no limit)")
    parser.add_argument("--rematch-max-age-hours", type=float, default=168.0,
                        help="rematch digests not used by a latest chart version once their match is older than this")
    parser.add_argument("--time-budget-minutes", type=float, default=None,
                        help="stop starting new SBOMs/rematches after this many minutes (outputs are still written)")
    parser.add_argument("--limit", type=int, default=None, help="only scan the first N images in priority order (testing)")
    args = parser.parse_args(argv)

    inventory = read_json(args.inventory)
    if not isinstance(inventory, dict):
        log(f"error: cannot read inventory {args.inventory}")
        return 1
    resolve_cache = read_json(args.resolve_file, {})
    if not isinstance(resolve_cache, dict):
        resolve_cache = {}
    sbom_failures = read_json(args.sbom_failures_file, {})
    if not isinstance(sbom_failures, dict):
        sbom_failures = {}
    scanner = Scanner(
        trivy=os.environ.get("TRIVY", "trivy"),
        crane=os.environ.get("CRANE", "crane"),
        sbom_dir=args.sbom_dir,
        resolve_cache=resolve_cache,
        resolve_max_age_hours=args.resolve_max_age_hours,
        resolve_max_age_hours_old=args.resolve_max_age_hours_old,
        max_new_sboms=args.max_new_sboms,
        workers=args.workers,
        rematch_workers=args.rematch_workers,
        sbom_failures=sbom_failures,
        match_dir=args.match_dir,
        max_rematch=None if args.max_rematch < 0 else args.max_rematch,
        rematch_max_age_hours=args.rematch_max_age_hours,
        time_budget_seconds=None if args.time_budget_minutes is None else args.time_budget_minutes * 60,
    )
    try:
        doc = build_scan(inventory, scanner, limit=args.limit)
    finally:
        write_json(args.resolve_file, resolve_cache)
        write_json(args.sbom_failures_file, sbom_failures)
    write_json(args.output, doc, indent=None)
    s = doc["stats"]
    log(f"scan: {s['ok']}/{s['images']} ok, {s['skipped']} skipped, unavailable {s['unavailable_by_reason']}, "
        f"{s['new_sboms']} new SBOMs, {s['rematched']} rematched, {s['match_reused']} cached matches reused, "
        f"{s['sbom_backoff']} in SBOM backoff in {s['seconds']}s → {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
