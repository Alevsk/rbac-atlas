"""Report stage: per-image / per-version risk levels, score, RBAC combinations and report.md.

Reads inventory.json, scan.json and enrichment.json (missing scan/enrichment are treated as
empty) and writes summary.json plus a Markdown report suitable for $GITHUB_STEP_SUMMARY.
Per-image vulnerabilities are streamed from the match cache (--match-dir, vulnscan.match): one
digest is loaded at a time and only its summary record plus its slim, interned vulnerability
groups are kept, so memory does not grow with the findings of every image. An 'ok' image whose
match is missing (or in an unknown format) becomes 'unavailable' with reason 'match_missing'.

Image risk level (weights_version 2), first match wins:
  Unknown    scan status is not 'ok'
  Exploited  any vulnerability (ID or alias) in CISA KEV per cve.now
  High       any CRITICAL/HIGH vulnerability that is "likely" exploitable: its cve.now entry reached
             the EPSS threshold or lists Metasploit modules or Exploit-DB IDs (GitHub PoCs and nuclei
             templates alone do not count)
  Elevated   any CRITICAL
  Moderate   any HIGH
  Low        otherwise

A version's level is the worst level among its main (non-test) images. A combination is a main
workload whose service account has Critical/High RBAC risk running an Exploited/High image.

summary.json layout:
  images    {canonical: image record (level, counts, kev/likely IDs, top vulnerabilities, ...)}
  versions  {'org/chart/<page version>': version rollup incl. imgs {raw ref: canonical} and combos}
  latest    {'org/chart': version key of the latest version}
  landscape latest versions only: distribution, combos (ranked), stats, coverage

Usage: python -m vulnscan.report [--inventory P] [--scan P] [--enrichment P] [--match-dir P]
                                 [--summary P] [--report P] [--top N]
"""

from __future__ import annotations

import argparse
import math
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

from vulnscan import match
from vulnscan.common import (
    ENRICHMENT_FILE,
    INVENTORY_FILE,
    MATCH_DIR,
    REPORT_FILE,
    SCAN_FILE,
    SEVERITIES,
    SUMMARY_FILE,
    log,
    read_json,
    utcnow,
    write_json,
)
from vulnscan.cvenow import ID_RE, canonical_id

WEIGHTS_VERSION = 2
# bucket -> (points per vulnerability, cap on vulnerabilities counted).
# kev and likely are exclusive (a KEV vulnerability is not also counted as likely); critical and
# high count every unique CRITICAL/HIGH vulnerability, including KEV/likely ones.
WEIGHTS: dict[str, tuple[float, int]] = {
    "kev": (30, 3),
    "likely": (12, 3),
    "critical": (3, 10),
    "high": (0.5, 20),
}
CHART_OTHERS_WEIGHT = 0.1
TOP_VULNS = 8
MAX_IDS = 5

# Most severe first. "Unknown" is worst-ranked only when nothing else is known.
LEVELS = ("Exploited", "High", "Elevated", "Moderate", "Low", "Unknown")
LEVEL_ORDER = {level: i for i, level in enumerate(LEVELS)}
CHART_LEVELS = LEVELS + ("N/A",)
COMBO_RBAC = {"Critical": 2, "High": 1}
COMBO_IMAGE = {"Exploited": 2, "High": 1}

# IDs that cve.now knows and that may be merged as aliases (DSA/DLA/TEMP etc. are never merged,
# since one advisory covers many CVEs).
# GHSA IDs are compared in canonical (lowercase-suffix) form via canonical_id.
ALIAS_ID_RE = ID_RE
SEV_RANK = {sev: i for i, sev in enumerate(SEVERITIES)}


# ───────────────────────────── vulnerability grouping ──────────────────────────────
class _UnionFind:
    def __init__(self) -> None:
        self.parent: dict[str, str] = {}

    def add(self, x: str) -> None:
        self.parent.setdefault(x, x)

    def find(self, x: str) -> str:
        self.add(x)
        root = x
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[x] != root:
            self.parent[x], x = root, self.parent[x]
        return root

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra


def _id_sort_key(vid: str) -> tuple[int, str]:
    """Representative ID preference: CVE, GHSA, GO, then anything else; then lexical."""
    for i, prefix in enumerate(("CVE-", "GHSA-", "GO-")):
        if vid.startswith(prefix):
            return (i, vid)
    return (3, vid)


def _norm_severity(value: Any) -> str:
    sev = str(value or "UNKNOWN").upper()
    return sev if sev in SEV_RANK else "UNKNOWN"


def _entry(entries: dict[str, Any], vid: str) -> dict[str, Any] | None:
    e = entries.get(vid)
    return e if isinstance(e, dict) and e.get("found") else None


def has_exploit_evidence(entry: dict[str, Any]) -> bool:
    """Any public exploit evidence in a cve.now entry (informational; includes PoCs and nuclei)."""
    return bool(entry.get("exploit_db") or entry.get("metasploit") or entry.get("nuclei") or entry.get("github_poc"))


def has_weaponized_exploit(entry: dict[str, Any]) -> bool:
    """Metasploit modules or Exploit-DB IDs (the exploit evidence that counts towards 'likely')."""
    return bool(entry.get("exploit_db") or entry.get("metasploit"))


def _finding_rank(f: dict[str, Any]) -> tuple[int, bool, str, str]:
    # representative finding of a group: most severe, fixable first, then package name
    return (SEV_RANK[_norm_severity(f.get("severity"))], not f.get("fixed"), str(f.get("pkg") or ""),
            str(f.get("installed") or ""))


def group_findings(findings: Iterable[dict[str, Any]], entries: dict[str, Any]) -> list[dict[str, Any]]:
    """Merge findings into unique vulnerabilities.

    A finding's id is linked with its CVE/GHSA/GO vendor_ids and with the CVE/GHSA/GO aliases of
    any cve.now entry in the group. Returns one dict per group with: id (representative), ids,
    severity (max), fixable, fixed and pkg (of the most severe finding), kev, likely, epss_reached,
    public_exploit, cvss (max score), cwes.
    """
    findings = [f for f in findings if isinstance(f, dict) and f.get("id")]
    uf = _UnionFind()
    for f in findings:
        fid = canonical_id(f["id"])
        uf.add(fid)
        for v in f.get("vendor_ids") or []:
            if isinstance(v, str) and ALIAS_ID_RE.match(v):
                uf.union(fid, canonical_id(v))
    # Expand with cve.now aliases until no new IDs appear (aliases of aliases).
    seen: set[str] = set()
    frontier = list(uf.parent)
    while frontier:
        vid = frontier.pop()
        if vid in seen:
            continue
        seen.add(vid)
        e = _entry(entries, vid)
        for alias in (e or {}).get("aliases") or []:
            if isinstance(alias, str) and ALIAS_ID_RE.match(alias):
                alias = canonical_id(alias)
                uf.union(vid, alias)
                frontier.append(alias)

    groups: dict[str, dict[str, Any]] = {}
    for f in findings:
        root = uf.find(canonical_id(f["id"]))
        g = groups.setdefault(root, {"severity": "UNKNOWN", "fixable": False, "cvss": None, "cwes": set(),
                                     "best": None})
        sev = _norm_severity(f.get("severity"))
        if SEV_RANK[sev] < SEV_RANK[g["severity"]]:
            g["severity"] = sev
        if str(f.get("status") or "").lower() == "fixed":
            g["fixable"] = True
        if g["best"] is None or _finding_rank(f) < _finding_rank(g["best"]):
            g["best"] = f
        score = (f.get("cvss") or {}).get("score")
        if isinstance(score, (int, float)) and (g["cvss"] is None or score > g["cvss"]):
            g["cvss"] = float(score)
        g["cwes"].update(c for c in f.get("cwes") or [] if isinstance(c, str))

    members: dict[str, list[str]] = {}
    for vid in uf.parent:
        members.setdefault(uf.find(vid), []).append(vid)

    out = []
    for root, g in groups.items():
        ids = sorted(members[root], key=_id_sort_key)
        ents = [e for e in (_entry(entries, i) for i in ids) if e]
        for e in ents:
            if isinstance(e.get("cvss"), (int, float)) and (g["cvss"] is None or e["cvss"] > g["cvss"]):
                g["cvss"] = float(e["cvss"])
        epss = any(e.get("epss_reached") for e in ents)
        weaponized = any(has_weaponized_exploit(e) for e in ents)
        out.append({
            "id": ids[0],
            "ids": ids,
            "severity": g["severity"],
            "fixable": g["fixable"],
            "fixed": g["best"].get("fixed") or None,
            "pkg": g["best"].get("pkg") or None,
            "kev": any(e.get("kev") for e in ents),
            "likely": g["severity"] in ("CRITICAL", "HIGH") and (epss or weaponized),
            "epss_reached": epss,
            "public_exploit": any(has_exploit_evidence(e) for e in ents),
            "cvss": g["cvss"],
            "cwes": sorted(g["cwes"]),
        })
    out.sort(key=lambda g: (SEV_RANK[g["severity"]], _id_sort_key(g["id"])))
    return out


def merge_groups(group_lists: Iterable[list[dict[str, Any]]]) -> list[dict[str, Any]]:
    """Merge per-image vulnerability groups that share any ID (same result as re-grouping all findings).

    Only the fields needed for rollups are kept: id, ids, severity, fixable, kev, likely.
    """
    uf = _UnionFind()
    flat = [g for gs in group_lists for g in gs]
    for g in flat:
        for vid in g["ids"]:
            uf.union(g["ids"][0], vid)
    merged: dict[str, dict[str, Any]] = {}
    for g in flat:
        m = merged.setdefault(uf.find(g["ids"][0]), {"ids": set(), "severity": "UNKNOWN", "fixable": False,
                                                     "kev": False, "likely": False})
        m["ids"].update(g["ids"])
        if SEV_RANK[g["severity"]] < SEV_RANK[m["severity"]]:
            m["severity"] = g["severity"]
        for flag in ("fixable", "kev", "likely"):
            m[flag] = m[flag] or g[flag]
    out = []
    for m in merged.values():
        ids = sorted(m["ids"], key=_id_sort_key)
        out.append(dict(m, id=ids[0], ids=ids))
    out.sort(key=lambda g: (SEV_RANK[g["severity"]], _id_sort_key(g["id"])))
    return out


def severity_counts(groups: Iterable[dict[str, Any]]) -> dict[str, int]:
    counts = {sev: 0 for sev in SEVERITIES}
    for g in groups:
        counts[g["severity"]] += 1
    return counts


def _vuln_rank(g: dict[str, Any]) -> tuple:
    """Display order: KEV first, then likely, then severity, then CVSS (desc), then ID."""
    return (not g["kev"], not g["likely"], SEV_RANK[g["severity"]],
            -(g["cvss"] if g.get("cvss") is not None else -1.0), _id_sort_key(g["id"]))


def top_vulns(groups: Iterable[dict[str, Any]], limit: int = TOP_VULNS) -> list[dict[str, Any]]:
    """The most relevant vulnerabilities of an image (see _vuln_rank)."""
    return [
        {"id": g["id"], "severity": g["severity"], "cvss": g["cvss"], "kev": g["kev"],
         "likely": g["likely"], "fixed": g["fixed"], "pkg": g["pkg"]}
        for g in sorted(groups, key=_vuln_rank)[:limit]
    ]


# ───────────────────────────── scoring and levels ──────────────────────────────
def score_buckets(groups: Iterable[dict[str, Any]]) -> dict[str, int]:
    """Count unique vulnerabilities per scoring bucket (kev/likely exclusive; see WEIGHTS)."""
    buckets = {name: 0 for name in WEIGHTS}
    for g in groups:
        if g["kev"]:
            buckets["kev"] += 1
        elif g["likely"]:
            buckets["likely"] += 1
        if g["severity"] == "CRITICAL":
            buckets["critical"] += 1
        elif g["severity"] == "HIGH":
            buckets["high"] += 1
    return buckets


def compute_score(buckets: dict[str, int]) -> int:
    """0-100 score from buckets using WEIGHTS (half-up rounding)."""
    raw = sum(w * min(buckets.get(name, 0), cap) for name, (w, cap) in WEIGHTS.items())
    return min(100, math.floor(raw + 0.5 + 1e-9))


def image_level(status: str, kev: int, likely: int, counts: dict[str, int]) -> str:
    """Per-image risk level (first match wins); likely counts CRITICAL/HIGH likely-exploitable vulns."""
    if status != "ok":
        return "Unknown"
    if kev > 0:
        return "Exploited"
    if likely > 0:
        return "High"
    if counts.get("CRITICAL", 0) > 0:
        return "Elevated"
    if counts.get("HIGH", 0) > 0:
        return "Moderate"
    return "Low"


def chart_level(levels: list[str]) -> tuple[str, bool]:
    """Roll main-image levels up to a chart level; returns (level, partial)."""
    if not levels:
        return "N/A", False
    known = [lv for lv in levels if lv != "Unknown"]
    if not known:
        return "Unknown", False
    return min(known, key=LEVEL_ORDER.__getitem__), len(known) < len(levels)


def chart_score(scores: list[int]) -> float | None:
    if not scores:
        return None
    ordered = sorted(scores, reverse=True)
    return round(min(100.0, ordered[0] + CHART_OTHERS_WEIGHT * sum(ordered[1:])), 1)


# ───────────────────────────── summary building ──────────────────────────────
def summarize_image(canonical: str, scan_img: dict[str, Any] | None, findings: Iterable[dict[str, Any]] | None,
                    entries: dict[str, Any], check: dict[str, Any] | None
                    ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Build the summary record for one image from its scan.json record and findings (match.expand
    of its match document); also returns its vulnerability groups."""
    scan_img = scan_img or {"status": "skipped", "reason": "not_scanned"}
    status = scan_img.get("status") or "skipped"
    groups = group_findings(findings or [], entries) if status == "ok" else []
    counts = severity_counts(groups)
    ranked = sorted(groups, key=_vuln_rank)
    kev_ids = [g["id"] for g in ranked if g["kev"]]
    likely_ids = [g["id"] for g in ranked if g["likely"] and not g["kev"]]
    level = image_level(status, len(kev_ids), len(likely_ids), counts)

    cwe_counter: Counter[str] = Counter()
    for g in groups:
        cwe_counter.update(g["cwes"])
    scores = [g["cvss"] for g in groups if g["cvss"] is not None]

    all_ids = {i for g in groups for i in g["ids"]}
    enrichable = {i for g in groups for i in g["ids"] if ALIAS_ID_RE.match(i)}
    found = sum(1 for i in enrichable if _entry(entries, i))
    check_ids = {canonical_id(str(m["id"])) for m in (check or {}).get("matches") or []
                 if isinstance(m, dict) and m.get("id")}
    os_info = scan_img.get("os") or None

    record = {
        "status": status,
        "reason": scan_img.get("reason") if status != "ok" else None,
        "digest": scan_img.get("digest"),
        "scanned_at": scan_img.get("scanned_at") if status == "ok" else None,
        "os": os_info,
        "eosl": bool((os_info or {}).get("eosl")),
        "counts": counts,
        "kev": len(kev_ids),
        "likely": len(likely_ids),
        "kev_ids": kev_ids[:MAX_IDS],
        "likely_ids": likely_ids[:MAX_IDS],
        "public_exploit": sum(1 for g in groups if g["public_exploit"]),
        "epss_reached": sum(1 for g in groups if g["epss_reached"]),
        "fixable_critical": sum(1 for g in groups if g["severity"] == "CRITICAL" and g["fixable"]),
        "fixable_high": sum(1 for g in groups if g["severity"] == "HIGH" and g["fixable"]),
        "max_cvss": max(scores) if scores else None,
        "top_cwes": [[cwe, n] for cwe, n in sorted(cwe_counter.items(), key=lambda kv: (-kv[1], kv[0]))[:5]],
        "top": top_vulns(ranked),
        "risk_level": level,
        "score": compute_score(score_buckets(groups)) if status == "ok" else None,
        "cvenow_coverage_pct": round(100.0 * found / len(enrichable), 1) if enrichable else None,
        "check_only_ids": len(check_ids - all_ids),
    }
    return record, groups


def page_version(version: str) -> str:
    """json2hugo's page filename rule: drop one leading 'v'."""
    return version[1:] if version.startswith("v") else version


def combo_rank(c: dict[str, Any]) -> tuple:
    """Sort key for combinations, riskiest first."""
    return (-COMBO_RBAC.get(c["sa_rbac_risk"], 0), -COMBO_IMAGE.get(c["image_level"], 0), -c["kev"], -c["likely"],
            -c["critical"], c["chart"], c["page_version"], c["workload_kind"], c["workload_name"], c["container"],
            c["image"])


def version_combos(chart: dict[str, Any], base: dict[str, Any], images: dict[str, dict[str, Any]]) -> list[dict]:
    """Combinations for one chart version: main workloads with a Critical/High RBAC service account
    running an Exploited/High image."""
    combos: list[dict[str, Any]] = []
    seen: set[tuple] = set()
    for img in chart.get("images") or []:
        c = img.get("canonical") if isinstance(img, dict) else None
        rec = images.get(c) if c else None
        if not rec or img.get("role", "main") != "main" or rec["risk_level"] not in COMBO_IMAGE:
            continue
        for w in img.get("workloads") or []:
            # Only main workloads count; test Pods/Jobs can share a main image.
            if w.get("role", "main") != "main" or w.get("sa_rbac_risk") not in COMBO_RBAC:
                continue
            key = (w.get("workloadType"), w.get("workloadName"), w.get("containerName"),
                   w.get("serviceAccountName"), w.get("namespace"), c)
            if key in seen:
                continue
            seen.add(key)
            combos.append(dict(
                base,
                workload_kind=w.get("workloadType") or "",
                workload_name=w.get("workloadName") or "",
                container=w.get("containerName") or "",
                serviceAccountName=w.get("serviceAccountName") or "",
                namespace=w.get("namespace") or "",
                sa_rbac_risk=w.get("sa_rbac_risk"),
                image=img.get("ref") or "",
                canonical=c,
                image_level=rec["risk_level"],
                kev=rec["kev"],
                likely=rec["likely"],
                kev_ids=rec["kev_ids"],
                likely_ids=rec["likely_ids"],
                critical=rec["counts"].get("CRITICAL", 0),
                high=rec["counts"].get("HIGH", 0),
            ))
    combos.sort(key=combo_rank)
    return combos


def summarize_version(chart: dict[str, Any], latest: bool, images: dict[str, dict[str, Any]],
                      image_groups: dict[str, list[dict[str, Any]]]) -> tuple[str, dict[str, Any]]:
    """Roll one inventory chart-version entry up; returns (version key, record)."""
    name = chart.get("chart") or f"{chart.get('org')}/{chart.get('name')}"
    version = str(chart.get("version") or "")
    pversion = chart.get("page_version") or page_version(version)
    key = chart.get("key") or f"{name}/{pversion}"
    org, _, short = name.partition("/")
    refs = [img for img in chart.get("images") or [] if isinstance(img, dict)]
    all_keys = {img.get("canonical") or f"invalid:{img.get('ref')}" for img in refs}
    main = [img for img in refs if img.get("role", "main") == "main"]
    main_levels: list[str] = []
    main_scores: list[int] = []
    main_canon: list[str] = []
    for img in main:
        c = img.get("canonical")
        rec = images.get(c) if c else None
        main_levels.append(rec["risk_level"] if rec else "Unknown")
        if rec and rec["score"] is not None:
            main_scores.append(rec["score"])
        if c and c not in main_canon:
            main_canon.append(c)
    level, partial = chart_level(main_levels)
    # Chart-wide unique vulnerabilities across main images (aliases merge across images).
    chart_groups = merge_groups(image_groups.get(c) or [] for c in main_canon)

    base = {"chart": name, "org": org, "name": short, "version": version, "page_version": pversion, "key": key,
            "url": f"/charts/{name}/{pversion}/".lower(), "latest": latest}  # Hugo lowercases page paths
    main_workloads = [w for img in main for w in img.get("workloads") or [] if w.get("role", "main") == "main"]
    record = dict(
        base,
        manifest=chart.get("manifest"),
        risk_level=level,
        partial=partial,
        score=chart_score(main_scores),
        images=len(all_keys),
        main_images=len(main_canon),
        unavailable=sum(1 for k in all_keys
                        if k.startswith("invalid:") or images.get(k, {}).get("risk_level") == "Unknown"),
        counts=severity_counts(chart_groups),
        kev=sum(1 for g in chart_groups if g["kev"]),
        likely=sum(1 for g in chart_groups if g["likely"] and not g["kev"]),
        imgs={img["ref"]: img["canonical"] for img in refs if img.get("canonical") and isinstance(img.get("ref"), str)},
        invalid=[{"ref": img.get("ref"), "reason": img.get("reason")} for img in refs if not img.get("canonical")],
        workloads=len(main_workloads),
        workloads_rbac=sum(1 for w in main_workloads if w.get("sa_rbac_risk") in COMBO_RBAC),
        combos=version_combos(chart, base, images),
    )
    return key, record


def _coverage(groups: Iterable[list[dict[str, Any]]], entries: dict[str, Any]) -> tuple[int, int, float | None]:
    ids = {i for gs in groups for g in gs for i in g["ids"] if ALIAS_ID_RE.match(i)}
    covered = sum(1 for i in ids if _entry(entries, i))
    return len(ids), covered, (round(100.0 * covered / len(ids), 1) if ids else None)


def load_image(scan_img: dict[str, Any] | None, match_dir: Path) -> tuple[dict[str, Any] | None, list[dict]]:
    """(scan record, findings) of one image, reading its match document for 'ok' images."""
    if not scan_img or scan_img.get("status") != "ok":
        return scan_img, []
    doc = match.load(match_dir, scan_img["digest"]) if scan_img.get("digest") else None
    if doc is None:
        return dict(scan_img, status="unavailable", reason="match_missing"), []
    return scan_img, match.expand(doc)


def build_summary(inventory: dict[str, Any], scan: dict[str, Any], enrichment: dict[str, Any],
                  started: float | None = None, *, match_dir: Path = MATCH_DIR) -> dict[str, Any]:
    """Build summary.json from the three stage outputs and the match cache."""
    started = time.monotonic() if started is None else started
    entries = enrichment.get("entries") or {}
    checks = enrichment.get("checks") or {}
    scan_images = scan.get("images") or {}
    scope = inventory.get("scope") or "latest"
    inv_charts = [c for c in inventory.get("charts") or [] if isinstance(c, dict)]

    canonicals = set(inventory.get("images") or {})
    for chart in inv_charts:
        canonicals.update(img["canonical"] for img in chart.get("images") or [] if img.get("canonical"))

    images: dict[str, dict[str, Any]] = {}
    # Per image only the fields merge_groups/_coverage need, as shared objects: the same group recurs
    # across many images, so this stays small even with every chart version scanned.
    image_groups: dict[str, tuple[dict[str, Any], ...]] = {}
    interned: dict[tuple, dict[str, Any]] = {}
    for canonical in sorted(canonicals):
        scan_img, findings = load_image(scan_images.get(canonical), match_dir)
        images[canonical], groups = summarize_image(canonical, scan_img, findings, entries, checks.get(canonical))
        slim = []
        for g in groups:
            key = (tuple(g["ids"]), g["severity"], g["fixable"], g["kev"], g["likely"])
            if key not in interned:
                interned[key] = {"ids": g["ids"], "severity": g["severity"], "fixable": g["fixable"],
                                 "kev": g["kev"], "likely": g["likely"]}
            slim.append(interned[key])
        image_groups[canonical] = tuple(slim)

    versions: dict[str, dict[str, Any]] = {}
    latest: dict[str, str] = {}
    for chart in inv_charts:
        # a latest-scope inventory has no 'latest' flags: every entry is the latest version
        is_latest = bool(chart.get("latest", scope != "all"))
        key, record = summarize_version(chart, is_latest, images, image_groups)
        versions[key] = record
        if is_latest:
            latest[record["chart"]] = key

    # ── landscape: latest versions only ──
    latest_recs = [versions[k] for k in sorted(set(latest.values()))]
    latest_images = sorted({c for r in latest_recs for c in r["imgs"].values()})
    combos = sorted((c for r in latest_recs for c in r["combos"]), key=combo_rank)
    _, _, latest_cov = _coverage((image_groups[c] for c in latest_images), entries)
    landscape = {
        "distribution": {
            "images": {lv: sum(1 for c in latest_images if images[c]["risk_level"] == lv) for lv in LEVELS},
            "charts": {lv: sum(1 for r in latest_recs if r["risk_level"] == lv) for lv in CHART_LEVELS},
        },
        "combos": combos,
        "stats": {
            "workloads_total": sum(r["workloads"] for r in latest_recs),
            "workloads_critical_or_high_rbac": sum(r["workloads_rbac"] for r in latest_recs),
            "combos_total": len(combos),
            "combos_kev": sum(1 for c in combos if c["kev"]),
            "charts_with_combos": sum(1 for r in latest_recs if r["combos"]),
            "images_exploited": sum(1 for c in latest_images if images[c]["risk_level"] == "Exploited"),
        },
        "coverage": {
            "charts": len(latest_recs),
            "charts_with_data": sum(1 for r in latest_recs if r["risk_level"] not in ("Unknown", "N/A")),
            "charts_partial": sum(1 for r in latest_recs if r["partial"]),
            "images": len(latest_images),
            "images_scanned": sum(1 for c in latest_images if images[c]["status"] == "ok"),
            "cvenow_coverage_pct": latest_cov,
        },
    }

    # Provenance / coverage across all unique enrichable IDs.
    enrichable, covered, coverage_pct = _coverage(image_groups.values(), entries)
    unavailable_by_reason: Counter[str] = Counter(
        rec["reason"] or rec["status"] for rec in images.values() if rec["status"] != "ok")
    # Invalid refs never get a canonical image, but they do degrade their chart; bucket them too.
    unavailable_by_reason.update(
        f"invalid:{inv.get('reason') or 'unknown'}" for inv in inventory.get("invalid") or [] if isinstance(inv, dict))

    return {
        "generated_at": utcnow(),
        "scope": scope,
        "since": inventory.get("since"),
        "weights_version": WEIGHTS_VERSION,
        "weights": {k: list(v) for k, v in WEIGHTS.items()},
        "provenance": {
            "trivy": scan.get("trivy"),
            "scan_generated_at": scan.get("generated_at"),
            "inventory_generated_at": inventory.get("generated_at"),
            "inventory_scope": scope,
            "inventory_since": inventory.get("since"),
            "cvenow": {
                "requests": enrichment.get("requests", 0),
                "stopped_reason": enrichment.get("stopped_reason"),
                "coverage_pct": coverage_pct,
                "generated_at": enrichment.get("generated_at"),
            },
        },
        "images": images,
        "versions": versions,
        "latest": dict(sorted(latest.items())),
        "landscape": landscape,
        "stats": {
            "images": len(images),
            "images_ok": sum(1 for r in images.values() if r["status"] == "ok"),
            "images_pending": sum(1 for r in images.values() if r["status"] == "skipped"),
            "unavailable_by_reason": dict(sorted(unavailable_by_reason.items())),
            "versions": len(versions),
            "versions_with_data": sum(1 for r in versions.values() if r["risk_level"] not in ("Unknown", "N/A")),
            "versions_partial": sum(1 for r in versions.values() if r["partial"]),
            "versions_with_combos": sum(1 for r in versions.values() if r["combos"]),
            "combos": sum(len(r["combos"]) for r in versions.values()),
            "distribution_versions": {lv: sum(1 for r in versions.values() if r["risk_level"] == lv)
                                      for lv in CHART_LEVELS},
            "enrichable_ids": enrichable,
            "enrichable_ids_covered": covered,
            "scan_stats": scan.get("stats"),
            "enrichment_stats": enrichment.get("stats"),
            "seconds": round(time.monotonic() - started, 2),
        },
    }


# ───────────────────────────── Markdown ──────────────────────────────
def _cell(value: Any) -> str:
    if value is None:
        return "-"
    return str(value).replace("|", "\\|").replace("\n", " ")


def _table(headers: list[str], rows: list[list[Any]]) -> str:
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    lines += ["| " + " | ".join(_cell(v) for v in row) + " |" for row in rows]
    return "\n".join(lines) + "\n"


def render_report(summary: dict[str, Any], top: int = 15, max_combos: int = 25) -> str:
    """Render summary.json as Markdown (no HTML). Rankings cover latest chart versions only."""
    prov = summary.get("provenance") or {}
    trivy = prov.get("trivy") or {}
    cvenow = prov.get("cvenow") or {}
    stats = summary.get("stats") or {}
    images = summary.get("images") or {}
    versions = summary.get("versions") or {}
    landscape = summary.get("landscape") or {}
    dist = landscape.get("distribution") or {}
    lstats = landscape.get("stats") or {}
    cov = landscape.get("coverage") or {}
    latest = [versions[k] for k in (summary.get("latest") or {}).values() if k in versions]
    latest_images = {c for r in latest for c in (r.get("imgs") or {}).values()}

    out = ["# Image vulnerability report", ""]
    out.append(f"Generated {summary.get('generated_at')} - weights v{summary.get('weights_version')} - "
               f"inventory scope {summary.get('scope') or 'latest'}"
               + (f" (versions latest on/after or first seen since {summary['since']})" if summary.get("since") else "")
               + ".")
    out += ["", "## Provenance", ""]
    out.append(_table(["Source", "Detail"], [
        ["Trivy", f"{trivy.get('version') or '?'} (DB {trivy.get('db_version') or '?'}, "
                  f"updated {trivy.get('db_updated_at') or '?'})"],
        ["cve.now", f"{cvenow.get('requests', 0)} requests, stopped: {cvenow.get('stopped_reason') or 'no'}, "
                    f"coverage {_pct(cvenow.get('coverage_pct'))} "
                    f"({stats.get('enrichable_ids_covered', 0)}/{stats.get('enrichable_ids', 0)} IDs)"],
    ]))

    out += ["## Coverage", ""]
    out.append(_table(["Scope", "Total", "With data", "Detail"], [
        ["Latest chart versions", cov.get("charts", 0), cov.get("charts_with_data", 0),
         f"{cov.get('charts_partial', 0)} partial"],
        ["Images in latest versions", cov.get("images", 0), cov.get("images_scanned", 0),
         f"cve.now coverage {_pct(cov.get('cvenow_coverage_pct'))}"],
        ["All chart versions", stats.get("versions", 0), stats.get("versions_with_data", 0),
         f"{stats.get('versions_partial', 0)} partial, {stats.get('versions_with_combos', 0)} with combinations"],
        ["All images", stats.get("images", 0), stats.get("images_ok", 0),
         f"{stats.get('images_pending', 0)} pending"],
    ]))
    scan_stats = stats.get("scan_stats") or {}
    if scan_stats.get("time_budget_exceeded"):
        out.append(f"Note: the scan time budget ran out after {scan_stats.get('batches_done', '?')} of "
                   f"{scan_stats.get('batches', '?')} batches; {scan_stats.get('images_not_processed', '?')} images "
                   f"were not processed ({scan_stats.get('not_processed_reused', 0)} of them reuse an earlier match).\n")
    limit = scan_stats.get("limit")
    if limit:
        out.append(f"Note: the scan was limited to the first {limit} images; the rest are Unknown "
                   "(`not_scanned`), so chart levels are incomplete.\n")

    out += ["## Risk level distribution (latest versions)", ""]
    img_dist, chart_dist = dist.get("images") or {}, dist.get("charts") or {}
    out.append(_table(["Level", "Images", "Charts"],
                      [[lv, img_dist.get(lv, 0), chart_dist.get(lv, 0)] for lv in CHART_LEVELS]))

    out += ["## Unavailable images by reason", ""]
    reasons = stats.get("unavailable_by_reason") or {}
    out.append(_table(["Reason", "Images"], sorted(reasons.items(), key=lambda kv: -kv[1])) if reasons else "None.\n")

    combos = landscape.get("combos") or []
    out += ["## Riskiest combinations (Critical/High RBAC service account running an Exploited/High image)", ""]
    out.append(f"{lstats.get('combos_total', 0)} workload combinations across {lstats.get('charts_with_combos', 0)} "
               f"charts ({lstats.get('combos_kev', 0)} with KEV); {lstats.get('workloads_critical_or_high_rbac', 0)} "
               f"of {lstats.get('workloads_total', 0)} main workloads run with Critical/High RBAC risk.\n")
    if combos:
        out.append(_table(
            ["Chart", "Version", "Workload", "ServiceAccount", "RBAC", "Image", "Level", "KEV", "Likely", "Crit"],
            [[c["chart"], c["version"], f"{c['workload_kind']}/{c['workload_name']}", c["serviceAccountName"],
              c["sa_rbac_risk"], f"`{c['image']}`", c["image_level"], ", ".join(c["kev_ids"]) or "-",
              ", ".join(c["likely_ids"]) or "-", c["critical"]] for c in combos[:max_combos]]))
        if len(combos) > max_combos:
            out.append(f"... {len(combos) - max_combos} more in summary.json.\n")

    out += [f"## Top {top} images by score (latest versions)", ""]
    ranked = sorted(((c, images[c]) for c in latest_images if images[c].get("score") is not None),
                    key=lambda cr: (-cr[1]["score"], cr[0]))[:top]
    out.append(_table(
        ["Image", "Level", "Score", "Crit", "High", "Med", "KEV", "Likely", "Fixable C/H", "EOSL"],
        [[f"`{c}`", r["risk_level"], r["score"], r["counts"].get("CRITICAL", 0), r["counts"].get("HIGH", 0),
          r["counts"].get("MEDIUM", 0), r["kev"], r["likely"],
          f"{r['fixable_critical']}/{r['fixable_high']}", "yes" if r.get("eosl") else ""] for c, r in ranked],
    ) if ranked else "No scanned images.\n")

    out += [f"## Top {top} charts by score (latest versions)", ""]
    ranked_c = sorted((r for r in latest if r.get("score") is not None),
                      key=lambda r: (-r["score"], r["chart"]))[:top]
    out.append(_table(
        ["Chart", "Version", "Level", "Score", "Images", "Unavailable", "Crit", "High", "KEV", "Combinations"],
        [[r["chart"], r["version"], r["risk_level"] + (" (partial)" if r["partial"] else ""), r["score"], r["images"],
          r["unavailable"], r["counts"].get("CRITICAL", 0), r["counts"].get("HIGH", 0), r["kev"],
          len(r["combos"])] for r in ranked_c],
    ) if ranked_c else "No scored charts.\n")

    out += ["## Runtime", ""]
    rows = [["report seconds", stats.get("seconds")]]
    for key in ("images", "ok", "new_sboms", "rematched", "batches_done", "batches", "images_not_processed",
                "not_processed_reused", "time_budget_exceeded", "seconds"):
        if key in scan_stats:
            rows.append([f"scan {key}", scan_stats[key]])
    for key, value in sorted((stats.get("enrichment_stats") or {}).items()):
        if isinstance(value, (int, float, str)) or value is None:
            rows.append([f"cve.now {key}", value])
    out.append(_table(["Metric", "Value"], rows))
    return "\n".join(out)


def _pct(value: Any) -> str:
    return "n/a" if value is None else f"{value}%"


# ───────────────────────────── CLI ──────────────────────────────
def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build summary.json and report.md from the vulnscan stages.")
    parser.add_argument("--inventory", type=Path, default=INVENTORY_FILE)
    parser.add_argument("--scan", type=Path, default=SCAN_FILE)
    parser.add_argument("--enrichment", type=Path, default=ENRICHMENT_FILE)
    parser.add_argument("--match-dir", type=Path, default=MATCH_DIR, help="per-digest match cache (vulnscan.scan)")
    parser.add_argument("--summary", type=Path, default=SUMMARY_FILE)
    parser.add_argument("--report", type=Path, default=REPORT_FILE)
    parser.add_argument("--top", type=int, default=15, help="rows in the top images/charts tables")
    args = parser.parse_args(argv)

    started = time.monotonic()
    inventory = read_json(args.inventory)
    if not isinstance(inventory, dict):
        print(f"error: cannot read inventory {args.inventory}", file=sys.stderr)
        return 1
    scan = read_json(args.scan, {}) or {}
    if err := match.scan_format_error(scan, args.scan):
        print(f"error: {err}", file=sys.stderr)
        return 1
    enrichment = read_json(args.enrichment, {}) or {}
    summary = build_summary(inventory, scan, enrichment, started, match_dir=args.match_dir)
    write_json(args.summary, summary, indent=None)  # tens of MB with scope 'all'
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(render_report(summary, top=args.top), encoding="utf-8")
    s, ls = summary["stats"], summary["landscape"]
    log(f"report: {s['images']} images, {s['versions']} versions ({s['versions_with_data']} with data), latest "
        f"images {ls['distribution']['images']}, latest charts {ls['distribution']['charts']}, "
        f"{ls['stats']['combos_total']} latest combinations, {s['combos']} combinations in all versions "
        f"-> {args.summary}, {args.report}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
