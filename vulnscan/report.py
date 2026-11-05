"""Report stage: provisional per-image / per-chart risk levels, score, exposures and report.md.

Reads inventory.json, scan.json and enrichment.json (missing scan/enrichment are treated as
empty) and writes summary.json plus a Markdown report suitable for $GITHUB_STEP_SUMMARY.

Usage: python -m vulnscan.report [--inventory P] [--scan P] [--enrichment P]
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

from vulnscan.common import (
    ENRICHMENT_FILE,
    INVENTORY_FILE,
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

WEIGHTS_VERSION = 1
# bucket -> (points per vulnerability, cap on vulnerabilities counted). Buckets are exclusive:
# each unique vulnerability lands in the first bucket it qualifies for, in this order.
WEIGHTS: dict[str, tuple[float, int]] = {
    "kev": (25, 3),
    "likely": (10, 3),
    "fixable_critical": (2, 10),
    "other_critical": (1, 10),
    "fixable_high": (0.5, 20),
    "other_high_medium": (0.1, 50),
}
CHART_OTHERS_WEIGHT = 0.1
FIXABLE_HIGH_ELEVATED = 10  # fixable HIGH strictly above this makes an image Elevated

# Most severe first. "Unknown" is worst-ranked only when nothing else is known.
LEVELS = ("Exploited", "High", "Elevated", "Moderate", "Low", "Unknown")
LEVEL_ORDER = {level: i for i, level in enumerate(LEVELS)}
CHART_LEVELS = LEVELS + ("N/A",)
EXPOSED_RBAC = {"Critical", "High"}

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
    """Public exploit evidence in a cve.now enrichment entry."""
    return bool(entry.get("exploit_db") or entry.get("metasploit") or entry.get("nuclei") or entry.get("github_poc"))


def group_findings(findings: Iterable[dict[str, Any]], entries: dict[str, Any]) -> list[dict[str, Any]]:
    """Merge findings into unique vulnerabilities.

    A finding's id is linked with its CVE/GHSA/GO vendor_ids and with the CVE/GHSA/GO aliases of
    any cve.now entry in the group. Returns one dict per group with: id (representative), ids,
    severity (max), fixable, kev, likely, epss_reached, public_exploit, cvss (max score), cwes.
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
        g = groups.setdefault(root, {"severity": "UNKNOWN", "fixable": False, "cvss": None, "cwes": set()})
        sev = _norm_severity(f.get("severity"))
        if SEV_RANK[sev] < SEV_RANK[g["severity"]]:
            g["severity"] = sev
        if str(f.get("status") or "").lower() == "fixed":
            g["fixable"] = True
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
        exploit = any(has_exploit_evidence(e) for e in ents)
        out.append({
            "id": ids[0],
            "ids": ids,
            "severity": g["severity"],
            "fixable": g["fixable"],
            "kev": any(e.get("kev") for e in ents),
            "likely": g["severity"] in ("CRITICAL", "HIGH") and (epss or exploit),
            "epss_reached": epss,
            "public_exploit": exploit,
            "cvss": g["cvss"],
            "cwes": sorted(g["cwes"]),
        })
    out.sort(key=lambda g: (SEV_RANK[g["severity"]], _id_sort_key(g["id"])))
    return out


def severity_counts(groups: Iterable[dict[str, Any]]) -> dict[str, int]:
    counts = {sev: 0 for sev in SEVERITIES}
    for g in groups:
        counts[g["severity"]] += 1
    return counts


# ───────────────────────────── scoring and levels ──────────────────────────────
def score_buckets(groups: Iterable[dict[str, Any]]) -> dict[str, int]:
    """Assign each unique vulnerability to the first (exclusive) scoring bucket it qualifies for."""
    buckets = {name: 0 for name in WEIGHTS}
    for g in groups:
        sev = g["severity"]
        if g["kev"]:
            buckets["kev"] += 1
        elif g["likely"]:
            buckets["likely"] += 1
        elif sev == "CRITICAL":
            buckets["fixable_critical" if g["fixable"] else "other_critical"] += 1
        elif sev == "HIGH" and g["fixable"]:
            buckets["fixable_high"] += 1
        elif sev in ("HIGH", "MEDIUM"):
            buckets["other_high_medium"] += 1
    return buckets


def compute_score(buckets: dict[str, int]) -> int:
    """0-100 score from exclusive buckets using WEIGHTS (half-up rounding)."""
    raw = sum(w * min(buckets.get(name, 0), cap) for name, (w, cap) in WEIGHTS.items())
    return min(100, math.floor(raw + 0.5 + 1e-9))


def image_level(status: str, kev: int, likely: int, counts: dict[str, int], fixable_critical: int,
                fixable_high: int) -> str:
    """Provisional per-image risk level (first match wins)."""
    if status != "ok":
        return "Unknown"
    if kev > 0:
        return "Exploited"
    if likely > 0 or fixable_critical > 0:
        return "High"
    if counts.get("CRITICAL", 0) > 0 or fixable_high > FIXABLE_HIGH_ELEVATED:
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
def summarize_image(canonical: str, scan_img: dict[str, Any] | None, entries: dict[str, Any],
                    check: dict[str, Any] | None) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Build the summary record for one image; also returns its vulnerability groups."""
    scan_img = scan_img or {"status": "skipped", "reason": "not_scanned"}
    status = scan_img.get("status") or "skipped"
    groups = group_findings(scan_img.get("findings") or [], entries) if status == "ok" else []
    counts = severity_counts(groups)
    fixable_critical = sum(1 for g in groups if g["severity"] == "CRITICAL" and g["fixable"])
    fixable_high = sum(1 for g in groups if g["severity"] == "HIGH" and g["fixable"])
    kev = sum(1 for g in groups if g["kev"])
    likely = sum(1 for g in groups if g["likely"] and not g["kev"])
    level = image_level(status, kev, likely, counts, fixable_critical, fixable_high)

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
        "os": os_info,
        "eosl": bool((os_info or {}).get("eosl")),
        "counts": counts,
        "kev": kev,
        "likely": likely,
        "public_exploit": sum(1 for g in groups if g["public_exploit"]),
        "epss_reached": sum(1 for g in groups if g["epss_reached"]),
        "fixable_critical": fixable_critical,
        "fixable_high": fixable_high,
        "max_cvss": max(scores) if scores else None,
        "top_cwes": [[cwe, n] for cwe, n in sorted(cwe_counter.items(), key=lambda kv: (-kv[1], kv[0]))[:5]],
        "risk_level": level,
        "score": compute_score(score_buckets(groups)) if status == "ok" else None,
        "cvenow_coverage_pct": round(100.0 * found / len(enrichable), 1) if enrichable else None,
        "check_only_ids": len(check_ids - all_ids),
    }
    return record, groups


def _workload_label(w: dict[str, Any]) -> str:
    return f"{w.get('workloadType') or '?'}/{w.get('workloadName') or '?'}"


def build_summary(inventory: dict[str, Any], scan: dict[str, Any], enrichment: dict[str, Any],
                  started: float | None = None) -> dict[str, Any]:
    """Build summary.json from the three stage outputs."""
    started = time.monotonic() if started is None else started
    entries = enrichment.get("entries") or {}
    checks = enrichment.get("checks") or {}
    scan_images = scan.get("images") or {}

    canonicals = set(inventory.get("images") or {})
    for chart in inventory.get("charts") or []:
        canonicals.update(img["canonical"] for img in chart.get("images") or [] if img.get("canonical"))

    images: dict[str, dict[str, Any]] = {}
    image_groups: dict[str, list[dict[str, Any]]] = {}
    for canonical in sorted(canonicals):
        images[canonical], image_groups[canonical] = summarize_image(
            canonical, scan_images.get(canonical), entries, checks.get(canonical))

    charts: dict[str, dict[str, Any]] = {}
    for chart in inventory.get("charts") or []:
        name = chart.get("chart") or f"{chart.get('org')}/{chart.get('name')}"
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

        # Chart-wide unique vulnerabilities across main images (re-grouped so aliases merge across images).
        main_findings = [f for c in main_canon if images[c]["status"] == "ok"
                         for f in (scan_images.get(c) or {}).get("findings") or []]
        chart_groups = group_findings(main_findings, entries)

        exposures = []
        seen_exp: set[tuple] = set()
        for img in main:
            c = img.get("canonical")
            if not c:
                continue
            flagged = [(g, "kev" if g["kev"] else "likely") for g in image_groups.get(c, []) if g["kev"] or g["likely"]]
            if not flagged:
                continue
            for w in img.get("workloads") or []:
                # Only main workloads count; test Pods/Jobs can share a main image.
                if w.get("role", "main") != "main" or w.get("sa_rbac_risk") not in EXPOSED_RBAC:
                    continue
                for g, basis in flagged:
                    key = (_workload_label(w), w.get("namespace"), w.get("serviceAccountName"), c, g["id"])
                    if key in seen_exp:
                        continue
                    seen_exp.add(key)
                    exposures.append({
                        "workload": _workload_label(w),
                        "container": w.get("containerName"),
                        "serviceAccountName": w.get("serviceAccountName"),
                        "namespace": w.get("namespace"),
                        "sa_rbac_risk": w.get("sa_rbac_risk"),
                        "image": c,
                        "id": g["id"],
                        "basis": basis,
                    })
        exposures.sort(key=lambda e: (e["basis"] != "kev", e["image"], e["id"], e["workload"]))

        unavailable = sum(1 for k in all_keys if k.startswith("invalid:") or images.get(k, {}).get("risk_level") == "Unknown")
        charts[name] = {
            "version": chart.get("version"),
            "risk_level": level,
            "partial": partial,
            "score": chart_score(main_scores),
            "images": len(all_keys),
            "main_images": len(main_canon),
            "unavailable": unavailable,
            "counts": severity_counts(chart_groups),
            "kev": sum(1 for g in chart_groups if g["kev"]),
            "exposures": exposures,
        }

    # Provenance / coverage across all unique enrichable IDs.
    all_enrichable = {i for gs in image_groups.values() for g in gs for i in g["ids"] if ALIAS_ID_RE.match(i)}
    covered = sum(1 for i in all_enrichable if _entry(entries, i))
    unavailable_by_reason: Counter[str] = Counter(
        rec["reason"] or rec["status"] for rec in images.values() if rec["status"] != "ok")
    # Invalid refs never get a canonical image, but they do degrade their chart; bucket them too.
    unavailable_by_reason.update(
        f"invalid:{inv.get('reason') or 'unknown'}" for inv in inventory.get("invalid") or [] if isinstance(inv, dict))

    return {
        "generated_at": utcnow(),
        "weights_version": WEIGHTS_VERSION,
        "weights": {k: list(v) for k, v in WEIGHTS.items()},
        "provenance": {
            "trivy": scan.get("trivy"),
            "scan_generated_at": scan.get("generated_at"),
            "inventory_generated_at": inventory.get("generated_at"),
            "cvenow": {
                "requests": enrichment.get("requests", 0),
                "stopped_reason": enrichment.get("stopped_reason"),
                "coverage_pct": round(100.0 * covered / len(all_enrichable), 1) if all_enrichable else None,
                "generated_at": enrichment.get("generated_at"),
            },
        },
        "images": images,
        "charts": charts,
        "distribution": {
            "images": {lv: sum(1 for r in images.values() if r["risk_level"] == lv) for lv in LEVELS},
            "charts": {lv: sum(1 for r in charts.values() if r["risk_level"] == lv) for lv in CHART_LEVELS},
        },
        "stats": {
            "images": len(images),
            "images_ok": sum(1 for r in images.values() if r["status"] == "ok"),
            "unavailable_by_reason": dict(sorted(unavailable_by_reason.items())),
            "charts": len(charts),
            "charts_partial": sum(1 for r in charts.values() if r["partial"]),
            "exposures": sum(len(r["exposures"]) for r in charts.values()),
            "charts_with_exposures": sum(1 for r in charts.values() if r["exposures"]),
            "enrichable_ids": len(all_enrichable),
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


def render_report(summary: dict[str, Any], top: int = 15, max_exposures: int = 50) -> str:
    """Render summary.json as Markdown (no HTML)."""
    prov = summary.get("provenance") or {}
    trivy = prov.get("trivy") or {}
    cvenow = prov.get("cvenow") or {}
    stats = summary.get("stats") or {}
    dist = summary.get("distribution") or {}
    images = summary.get("images") or {}
    charts = summary.get("charts") or {}

    out = ["# Image vulnerability calibration report", ""]
    out.append(f"Generated {summary.get('generated_at')} - weights v{summary.get('weights_version')} - "
               "provisional levels, not published.")
    out += ["", "## Provenance", ""]
    out.append(_table(["Source", "Detail"], [
        ["Trivy", f"{trivy.get('version') or '?'} (DB {trivy.get('db_version') or '?'}, "
                  f"updated {trivy.get('db_updated_at') or '?'})"],
        ["cve.now", f"{cvenow.get('requests', 0)} requests, stopped: {cvenow.get('stopped_reason') or 'no'}, "
                    f"coverage {_pct(cvenow.get('coverage_pct'))} "
                    f"({stats.get('enrichable_ids_covered', 0)}/{stats.get('enrichable_ids', 0)} IDs)"],
    ]))

    out += ["## Risk level distribution", ""]
    img_dist, chart_dist = dist.get("images") or {}, dist.get("charts") or {}
    out.append(_table(["Level", "Images", "Charts"],
                      [[lv, img_dist.get(lv, 0), chart_dist.get(lv, 0)] for lv in CHART_LEVELS]))
    out.append(f"Images: {stats.get('images', 0)} ({stats.get('images_ok', 0)} scanned). "
               f"Charts: {stats.get('charts', 0)} ({stats.get('charts_partial', 0)} partial).\n")
    limit = (stats.get("scan_stats") or {}).get("limit")
    if limit:
        out.append(f"Note: the scan was limited to the first {limit} images; the rest are Unknown "
                   "(`not_scanned`), so chart levels are incomplete.\n")

    out += ["## Unavailable images by reason", ""]
    reasons = stats.get("unavailable_by_reason") or {}
    out.append(_table(["Reason", "Images"], sorted(reasons.items(), key=lambda kv: -kv[1])) if reasons else "None.\n")

    out += [f"## Top {top} images by score", ""]
    ranked = sorted(((c, r) for c, r in images.items() if r.get("score") is not None),
                    key=lambda cr: (-cr[1]["score"], cr[0]))[:top]
    out.append(_table(
        ["Image", "Level", "Score", "Crit", "High", "Med", "KEV", "Exploit", "Fixable C/H", "EOSL"],
        [[f"`{c}`", r["risk_level"], r["score"], r["counts"].get("CRITICAL", 0), r["counts"].get("HIGH", 0),
          r["counts"].get("MEDIUM", 0), r["kev"], r["public_exploit"],
          f"{r['fixable_critical']}/{r['fixable_high']}", "yes" if r.get("eosl") else ""] for c, r in ranked],
    ) if ranked else "No scanned images.\n")

    out += [f"## Top {top} charts by score", ""]
    ranked_c = sorted(((n, r) for n, r in charts.items() if r.get("score") is not None),
                      key=lambda nr: (-nr[1]["score"], nr[0]))[:top]
    out.append(_table(
        ["Chart", "Version", "Level", "Score", "Images", "Unavailable", "Crit", "High", "KEV", "Exposures"],
        [[n, r["version"], r["risk_level"] + (" (partial)" if r["partial"] else ""), r["score"], r["images"],
          r["unavailable"], r["counts"].get("CRITICAL", 0), r["counts"].get("HIGH", 0), r["kev"],
          len(r["exposures"])] for n, r in ranked_c],
    ) if ranked_c else "No scored charts.\n")

    exposures = [dict(e, chart=n) for n, r in charts.items() for e in r.get("exposures") or []]
    out += ["## Exposures (Critical/High RBAC service account running an exploited or likely-exploitable image)", ""]
    out.append(f"{len(exposures)} exposures across {stats.get('charts_with_exposures', 0)} charts "
               f"({sum(1 for e in exposures if e['basis'] == 'kev')} KEV-based).\n")
    if exposures:
        exposures.sort(key=lambda e: (e["basis"] != "kev", e["chart"], e["workload"], e["id"]))
        out.append(_table(["Chart", "Workload", "ServiceAccount", "RBAC", "Image", "ID", "Basis"],
                          [[e["chart"], e["workload"], e["serviceAccountName"], e["sa_rbac_risk"], f"`{e['image']}`",
                            e["id"], e["basis"]] for e in exposures[:max_exposures]]))
        if len(exposures) > max_exposures:
            out.append(f"... {len(exposures) - max_exposures} more in summary.json.\n")

    out += ["## Runtime", ""]
    scan_stats = stats.get("scan_stats") or {}
    rows = [["report seconds", stats.get("seconds")]]
    for key in ("images", "ok", "new_sboms", "rematched", "seconds"):
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
    enrichment = read_json(args.enrichment, {}) or {}
    summary = build_summary(inventory, scan, enrichment, started)
    write_json(args.summary, summary)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(render_report(summary, top=args.top), encoding="utf-8")
    d = summary["distribution"]
    log(f"report: {summary['stats']['images']} images {d['images']}, {summary['stats']['charts']} charts "
          f"{d['charts']}, {summary['stats']['exposures']} exposures -> {args.summary}, {args.report}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
