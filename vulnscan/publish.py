"""Publish stage: turn the pipeline outputs into compact Hugo data files under data/vulns/.

Reads inventory.json and summary.json (required). Per-image top-CVE lists and KEV/likely IDs come
from summary.json; scan.json and enrichment.json are only read when an (older) summary lacks them.
Writes:

  data/vulns/meta.json        {generated_at, scope, since, weights_version, trivy{version,db_updated_at},
                               cvenow{coverage_pct,requests}, images_total, images_scanned,
                               images_pending, versions_total, versions_with_data}
                              versions_total counts inventoried version pages; versions_with_data those
                              with at least one scanned image.
  data/vulns/images/<s>.json  s = md5(canonical)[:2]
                              {canonical: {lvl, st: ok|unavailable|invalid|pending, rs: reason|null,
                                           os: "alpine 3.19"|null, eosl, n: [crit,high,med,low,unk],
                                           kev, lk, fx: [fixable_crit, fixable_high],
                                           top: [[id, sev, cvss|null, kev 0/1, likely 0/1, fixed|null, pkg], <=8],
                                           at: "YYYY-MM-DD"|null}}
                              Images not scanned yet are {lvl: "Unknown", st: "pending", rs: reason}.
  data/vulns/versions/<s>.json  s = md5(key)[:2], key = "org/chart/<filename-version>" (json2hugo's rule:
                              metadata.version without one leading "v", i.e. the content file's base name)
                              {key: {lvl, partial, kev, crit, high, imgs: {raw_ref: canonical},
                                     combos: [combination, <=20], [pending: true],
                                     sas: {serviceAccountName: {lvl, n, [partial], [pending], [kev], [crit], [high]}}}}
                              Only versions with at least one valid image reference get a record;
                              "pending" is set (only) when none of its main images has been scanned yet.
                              "sas" summarizes the distinct valid images of each ServiceAccount's main
                              workloads (n images; kev/crit/high each the max over them, omitted when 0).
  data/vulns/landscape.json   latest versions only:
                              {generated_at,
                               coverage {charts, images, images_scanned, images_pending, scanned_pct, cvenow_pct},
                               distribution {images: {level: n}, charts: {level|"N/A": n}},
                               combos: [combination, top 25 ranked],
                               stats {workloads_total, workloads_critical_or_high_rbac, combos_total, combos_kev,
                                      charts_with_combos, images_exploited}}

A combination (decision 2) is a role=main workload whose ServiceAccount has Critical/High RBAC risk
running an image whose level is Exploited or High:
  {chart, version, key, url, kind, workload, container, serviceAccountName, namespace, sa_rbac_risk,
   image (raw ref), canonical, image_level, kev, likely (counts), kev_ids (<=5), likely_ids (<=5),
   critical, high}

Per-version rollups and combinations are taken from summary.json when it provides them (summary
"versions", or "charts" keyed by version key) and computed here from the inventory otherwise.
Output is deterministic (sorted keys, one record per line), written atomically, stale shard files are
removed, and the run fails when data/vulns grows beyond --max-mb.

Guards (nothing is written or pruned when one trips; the exit status is 1):
  absolute  always, also on the first publish: images_scanned is 0, no version has data, or fewer than
            --min-latest-coverage (default 60%) of the images used by latest chart versions were scanned
            (invalid refs have no canonical image and are not counted). --allow-drop does not bypass it.
  relative  when data/vulns/meta.json exists: images_scanned, versions_with_data or the number of scanned
            latest-version images (landscape.json coverage.images_scanned) would drop by more than --max-drop
            (default 20%), e.g. a --limit run, a night where every rematch failed, or a scope 'forward' run
            over published scope 'all' (backfill) data, which would delete the backfilled version records.
            versions_total is only compared when the published data has the same inventory scope and since
            date (a missing scope is 'all'). --allow-drop overrides the relative guard.

Usage: python -m vulnscan.publish [--inventory P] [--summary P] [--scan P] [--enrichment P]
                                  [--output data/vulns] [--max-mb 80] [--max-drop 0.2] [--allow-drop]
                                  [--min-latest-coverage 0.6]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
from collections import defaultdict
from pathlib import Path
from typing import Any

from vulnscan import report
from vulnscan.common import ENRICHMENT_FILE, INVENTORY_FILE, SCAN_FILE, SUMMARY_FILE, log, read_json
from vulnscan.cvenow import canonical_id
from vulnscan.inventory import is_prerelease, version_key

OUTPUT_DIR = Path("data/vulns")
DEFAULT_MAX_MB = 80.0  # full "all" coverage (~29k images) measured ~44 MB
DEFAULT_MAX_DROP = 0.2
DEFAULT_MIN_LATEST_COVERAGE = 0.6
# Compared with the published meta.json whatever its scope; SCOPED_GUARDED_META only for the same scope/since.
GUARDED_META = ("images_scanned", "versions_with_data")
SCOPED_GUARDED_META = ("versions_total",)
TOP_CVES = 8
MAX_IDS = 5
VERSION_COMBOS = 20
LANDSCAPE_COMBOS = 25
COMBO_RBAC = {"Critical": 2, "High": 1}
COMBO_LEVELS = {"Exploited": 2, "High": 1}
SEV_RANK = {sev: i for i, sev in enumerate(("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"))}
PENDING_STATUSES = {"skipped", "pending"}


# ───────────────────────────── helpers ──────────────────────────────
def shard(key: str) -> str:
    """Shard name for a data key: first two hex chars of md5 (Hugo: substr (md5 $key) 0 2)."""
    return hashlib.md5(key.encode("utf-8")).hexdigest()[:2]


def page_version(version: str) -> str:
    """json2hugo's filename rule: drop one leading 'v'."""
    return version[1:] if version.startswith("v") else version


def version_key_of(chart: dict[str, Any]) -> str:
    """'org/chart/<filename-version>' for an inventory chart entry."""
    if isinstance(chart.get("key"), str) and chart["key"].count("/") == 2:
        return chart["key"]
    org = chart.get("org") or str(chart.get("chart") or "?/?").split("/")[0]
    name = chart.get("name") or str(chart.get("chart") or "?/?").split("/")[-1]
    version = chart.get("page_version") or chart.get("metadata_version") or chart.get("version") or ""
    return f"{org}/{name}/{page_version(str(version))}"


def page_url(key: str) -> str:
    """Site URL of a version page (Hugo lowercases content paths by default)."""
    return f"/charts/{key.lower()}/"


def _int(value: Any) -> int:
    return int(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else 0


def _os_label(os_info: Any) -> str | None:
    if not isinstance(os_info, dict):
        return None
    label = " ".join(str(os_info[k]) for k in ("family", "name") if os_info.get(k))
    return label or None


def _status(rec: dict[str, Any] | None) -> tuple[str, str | None]:
    """Published status and reason for a summary image record."""
    if not rec:
        return "pending", "not_scanned"
    status = str(rec.get("status") or "skipped")
    reason = rec.get("reason")
    if status == "ok":
        return "ok", None
    if status in PENDING_STATUSES or reason in ("not_scanned", "sbom_quota"):
        return "pending", reason or "not_scanned"
    if status == "invalid":
        return "invalid", reason
    return "unavailable", reason


def _clip(values: list[str], keep: int = 3) -> str:
    """'a, b, c +N' (keeps published rows short; Trivy lists one fixed version per release branch)."""
    return ", ".join(values[:keep]) + (f" +{len(values) - keep}" if len(values) > keep else "")


# ───────────────────────────── per-image data ──────────────────────────────
def image_details(scan_img: dict[str, Any] | None, entries: dict[str, Any]) -> dict[str, Any]:
    """Top CVEs and KEV/likely IDs of one scanned image (empty when not scanned or no findings)."""
    if not isinstance(scan_img, dict) or scan_img.get("status") != "ok":
        return {"top": [], "kev_ids": [], "likely_ids": []}
    findings = [f for f in scan_img.get("findings") or [] if isinstance(f, dict) and f.get("id")]
    by_id: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for f in findings:
        by_id[canonical_id(str(f["id"]))].append(f)
    rows = []
    for g in report.group_findings(findings, entries):
        members = [f for vid in g["ids"] for f in by_id.get(vid, [])]
        fixed = list(dict.fromkeys(v.strip() for f in members if f.get("fixed") for v in str(f["fixed"]).split(",")))
        pkgs = sorted({str(f["pkg"]) for f in members if f.get("pkg")})
        kev, likely = bool(g.get("kev")), bool(g.get("likely")) and not g.get("kev")
        cvss = round(float(g["cvss"]), 1) if isinstance(g.get("cvss"), (int, float)) else None
        rows.append([g["id"], g["severity"], cvss, int(kev), int(likely), _clip([v for v in fixed if v]) or None,
                     _clip(pkgs)])
    rows.sort(key=lambda r: (-r[3], -r[4], SEV_RANK.get(r[1], 9), -(r[2] or 0), r[0]))
    return {
        "top": rows[:TOP_CVES],
        "kev_ids": [r[0] for r in rows if r[3]][:MAX_IDS],
        "likely_ids": [r[0] for r in rows if r[4]][:MAX_IDS],
    }


def summary_details(rec: dict[str, Any] | None) -> dict[str, Any] | None:
    """Top CVEs and KEV/likely IDs from a summary.json image record (None when it has no 'top')."""
    if not isinstance(rec, dict) or not isinstance(rec.get("top"), list):
        return None
    rows = []
    for v in rec["top"][:TOP_CVES]:
        if not isinstance(v, dict) or not v.get("id"):
            continue
        cvss = round(float(v["cvss"]), 1) if isinstance(v.get("cvss"), (int, float)) else None
        fixed = [x.strip() for x in str(v.get("fixed") or "").split(",") if x.strip()]
        kev = bool(v.get("kev"))
        rows.append([str(v["id"]), str(v.get("severity") or "UNKNOWN"), cvss, int(kev),
                     int(bool(v.get("likely")) and not kev), _clip(fixed) or None, str(v.get("pkg") or "")])
    return {"top": rows, "kev_ids": list(rec.get("kev_ids") or [])[:MAX_IDS],
            "likely_ids": list(rec.get("likely_ids") or [])[:MAX_IDS]}


def needs_scan(summary: dict[str, Any]) -> bool:
    """True when some scanned image in summary.json lacks a 'top' list (older report.py)."""
    return any(isinstance(r, dict) and r.get("status") == "ok" and not isinstance(r.get("top"), list)
               for r in (summary.get("images") or {}).values())


def image_record(rec: dict[str, Any] | None, scan_img: dict[str, Any] | None, details: dict[str, Any],
                 fallback_date: str | None) -> dict[str, Any]:
    st, rs = _status(rec)
    if st == "pending" or rec is None:
        return {"lvl": "Unknown", "st": "pending", "rs": rs}
    counts = rec.get("counts") or {}
    scanned = rec.get("scanned_at") or (scan_img or {}).get("scanned_at") or fallback_date
    return {
        "lvl": rec.get("risk_level") or "Unknown",
        "st": st,
        "rs": rs,
        "os": _os_label(rec.get("os")),
        "eosl": bool(rec.get("eosl")),
        "n": [_int(counts.get(sev)) for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")],
        "kev": _int(rec.get("kev")),
        "lk": _int(rec.get("likely")),
        "fx": [_int(rec.get("fixable_critical")), _int(rec.get("fixable_high"))],
        "top": details["top"] if st == "ok" else [],
        "at": str(scanned)[:10] if scanned and st == "ok" else None,
    }


# ───────────────────────────── per-version data ──────────────────────────────
def _rollup_index(summary: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Per-version rollups from summary.json keyed by version key (tolerates the old per-chart layout)."""
    out: dict[str, dict[str, Any]] = {}
    for source in ("versions", "charts"):
        recs = summary.get(source)
        if not isinstance(recs, dict):
            continue
        for key, rec in recs.items():
            if not isinstance(rec, dict):
                continue
            if key.count("/") != 2:  # old layout: 'org/chart' -> rec['version']
                if not rec.get("version"):
                    continue
                key = f"{key}/{page_version(str(rec['version']))}"
            out.setdefault(key, rec)
    return out


def _first(d: dict[str, Any], *names: str) -> Any:
    for n in names:
        if d.get(n) not in (None, ""):
            return d[n]
    return None


def normalize_combo(c: dict[str, Any], key: str, chart: str, version: str,
                    images: dict[str, dict[str, Any]], details: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Map a combination record (from summary.json or computed here) onto the published schema."""
    kind = _first(c, "kind", "workload_kind", "workloadType")
    name = _first(c, "workload_name", "workloadName", "name")
    label = c.get("workload")
    if isinstance(label, str) and "/" in label and not (kind and name):
        kind, name = label.split("/", 1)
    elif isinstance(label, str) and not name:
        name = label
    # 'image' is the raw ref when 'canonical' is present (vulnscan.report layout), else the canonical one
    canonical = _first(c, "canonical") or _first(c, "image") or ""
    raw_ref = _first(c, "ref", "image_ref", "raw_ref") or (_first(c, "image") if c.get("canonical") else None)
    img = images.get(canonical) or {}
    det = details.get(canonical) or {}
    kev_ids = _first(c, "kev_ids") or det.get("kev_ids") or []
    likely_ids = _first(c, "likely_ids") or det.get("likely_ids") or []
    counts = img.get("counts") or {}
    return {
        "chart": _first(c, "chart") or chart,
        "version": str(_first(c, "version") or version),
        "key": key,
        "url": page_url(key),
        "kind": kind or "",
        "workload": name or "",
        "container": _first(c, "container", "containerName") or "",
        "serviceAccountName": _first(c, "serviceAccountName", "sa") or "",
        "namespace": _first(c, "namespace", "ns") or "",
        "sa_rbac_risk": _first(c, "sa_rbac_risk", "rbac") or "",
        "image": raw_ref or canonical,
        "canonical": canonical,
        "image_level": _first(c, "image_level", "lvl") or img.get("risk_level") or "Unknown",
        "kev": _int(_first(c, "kev", "kev_count")) or _int(img.get("kev")) or len(kev_ids),
        "likely": _int(_first(c, "likely", "lk", "likely_count")) or _int(img.get("likely")) or len(likely_ids),
        "kev_ids": list(kev_ids)[:MAX_IDS],
        "likely_ids": list(likely_ids)[:MAX_IDS],
        "critical": _int(_first(c, "critical", "crit")) or _int(counts.get("CRITICAL")),
        "high": _int(_first(c, "high")) or _int(counts.get("HIGH")),
    }


def compute_combos(chart_entry: dict[str, Any], images: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    """Decision 2 combinations for one inventory version entry (raw records for normalize_combo)."""
    out, seen = [], set()
    for img in chart_entry.get("images") or []:
        c = img.get("canonical") if isinstance(img, dict) else None
        if not c or img.get("role", "main") != "main":
            continue
        level = (images.get(c) or {}).get("risk_level")
        if level not in COMBO_LEVELS:
            continue
        for w in img.get("workloads") or []:
            if w.get("role", "main") != "main" or w.get("sa_rbac_risk") not in COMBO_RBAC:
                continue
            ident = (w.get("workloadType"), w.get("workloadName"), w.get("containerName"),
                     w.get("namespace"), w.get("serviceAccountName"), c)
            if ident in seen:
                continue
            seen.add(ident)
            out.append({"workload_kind": w.get("workloadType"), "workload_name": w.get("workloadName"),
                        "container": w.get("containerName"), "serviceAccountName": w.get("serviceAccountName"),
                        "namespace": w.get("namespace"), "sa_rbac_risk": w.get("sa_rbac_risk"),
                        "image": img.get("ref"), "canonical": c, "image_level": level})
    return out


def combo_sort_key(c: dict[str, Any]) -> tuple:
    """Rank (desc): RBAC, image level, KEV, likely, critical; then chart/version/workload ascending."""
    return (-COMBO_RBAC.get(c["sa_rbac_risk"], 0), -COMBO_LEVELS.get(c["image_level"], 0), -c["kev"], -c["likely"],
            -c["critical"], c["chart"], c["version"], c["kind"], c["workload"], c["container"], c["canonical"])


def _fallback_counts(main: list[str], images: dict[str, dict[str, Any]]) -> tuple[int, int, int]:
    """Version KEV/critical/high when summary has no rollup: max over main images (lower bound)."""
    recs = [images.get(c) or {} for c in main]
    return (max((_int(r.get("kev")) for r in recs), default=0),
            max((_int((r.get("counts") or {}).get("CRITICAL")) for r in recs), default=0),
            max((_int((r.get("counts") or {}).get("HIGH")) for r in recs), default=0))


def sa_summaries(chart_entry: dict[str, Any], images: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Per-ServiceAccount image CVE summary for the Overview table of a version page.

    Keyed by serviceAccountName (json2hugo anchors use the name only, so namespaces are merged) over the
    distinct valid images of its role=main workloads: {lvl, n: images, [partial, pending, kev, crit, high]};
    kev/crit/high are each the maximum over those images and are left out when 0."""
    by_sa: dict[str, dict[str, None]] = defaultdict(dict)
    for img in chart_entry.get("images") or []:
        c = img.get("canonical") if isinstance(img, dict) else None
        if not c:
            continue
        for w in img.get("workloads") or []:
            if isinstance(w, dict) and w.get("role", "main") == "main":
                by_sa[str(w.get("serviceAccountName") or "")][c] = None
    out: dict[str, dict[str, Any]] = {}
    for sa, canonicals in sorted(by_sa.items()):
        recs = [images.get(c) or {} for c in canonicals]
        level, partial = report.chart_level([r.get("risk_level") or "Unknown" for r in recs])
        kev, crit, high = _fallback_counts(list(canonicals), images)
        rec: dict[str, Any] = {"lvl": level, "n": len(canonicals)}
        if partial:
            rec["partial"] = True
        if all(_status(images.get(c))[0] == "pending" for c in canonicals):
            rec["pending"] = True
        rec.update({k: v for k, v in (("kev", kev), ("crit", crit), ("high", high)) if v})
        out[sa] = rec
    return out


def version_record(chart_entry: dict[str, Any], key: str, rollup: dict[str, Any] | None,
                   images: dict[str, dict[str, Any]], details: dict[str, dict[str, Any]]) -> dict[str, Any] | None:
    refs = [img for img in chart_entry.get("images") or [] if isinstance(img, dict)]
    imgs = {str(img.get("ref")): img["canonical"] for img in refs if img.get("canonical") and img.get("ref") is not None}
    if not imgs:
        return None
    main_refs = [img for img in refs if img.get("role", "main") == "main"]
    main = list(dict.fromkeys(img["canonical"] for img in main_refs if img.get("canonical")))
    chart = chart_entry.get("chart") or "/".join(key.split("/")[:2])
    version = str(chart_entry.get("version") or key.split("/")[-1])
    if rollup:
        level, partial = rollup.get("risk_level") or rollup.get("lvl"), bool(rollup.get("partial"))
        counts = rollup.get("counts") or {}
        kev, crit, high = _int(rollup.get("kev")), _int(counts.get("CRITICAL")), _int(counts.get("HIGH"))
        raw_combos = rollup.get("combos")
        if not isinstance(raw_combos, list):
            raw_combos = compute_combos(chart_entry, images)
    else:
        level = None
        raw_combos = compute_combos(chart_entry, images)
    if not level:
        levels = [(images.get(img.get("canonical") or "") or {}).get("risk_level") or "Unknown" for img in main_refs]
        level, partial = report.chart_level(levels)
        kev, crit, high = _fallback_counts(main, images)
    combos = [normalize_combo(c, key, chart, version, images, details) for c in raw_combos if isinstance(c, dict)]
    combos.sort(key=combo_sort_key)
    out = {"lvl": level, "partial": partial, "kev": kev, "crit": crit, "high": high,
           "imgs": dict(sorted(imgs.items())), "combos": combos, "sas": sa_summaries(chart_entry, images)}
    if main and all(_status(images.get(c))[0] == "pending" for c in main):
        out["pending"] = True  # not scanned yet: pages say "pending scan", not "Unknown"
    return out


def latest_keys(charts: list[dict[str, Any]], scope: str) -> set[int]:
    """Indexes of inventory entries that are the latest version of their chart."""
    if scope == "latest" or not any("latest" in c for c in charts):
        if scope == "latest" or not charts:
            return set(range(len(charts)))
        grouped: dict[str, list[int]] = defaultdict(list)
        for i, c in enumerate(charts):
            grouped[c.get("chart") or f"{c.get('org')}/{c.get('name')}"].append(i)
        out = set()
        for idxs in grouped.values():
            stable = [i for i in idxs if not is_prerelease(str(charts[i].get("version") or ""))] or idxs
            out.add(max(stable, key=lambda i: version_key(str(charts[i].get("version") or ""))))
        return out
    return {i for i, c in enumerate(charts) if c.get("latest")}


# ───────────────────────────── build ──────────────────────────────
def build(inventory: dict[str, Any], summary: dict[str, Any], scan: dict[str, Any],
          enrichment: dict[str, Any]) -> dict[str, Any]:
    """Build every published document; returns {'meta', 'landscape', 'images', 'versions'}."""
    entries = enrichment.get("entries") or {}
    scan_images = scan.get("images") or {}
    sum_images = summary.get("images") or {}
    charts = [c for c in inventory.get("charts") or [] if isinstance(c, dict)]
    generated_at = summary.get("generated_at")
    scan_date = (summary.get("provenance") or {}).get("scan_generated_at") or scan.get("generated_at")

    referenced = set(inventory.get("images") or {})
    for c in charts:
        referenced.update(img["canonical"] for img in c.get("images") or [] if isinstance(img, dict) and img.get("canonical"))

    details = {c: summary_details(sum_images.get(c)) or image_details(scan_images.get(c), entries)
               for c in sorted(referenced)}
    images_out = {c: image_record(sum_images.get(c), scan_images.get(c), details[c], scan_date) for c in sorted(referenced)}

    rollups = _rollup_index(summary)
    latest = latest_keys(charts, str(inventory.get("scope") or "latest"))
    versions_out: dict[str, dict[str, Any]] = {}
    version_keys: set[str] = set()
    latest_records: list[tuple[dict[str, Any], dict[str, Any] | None]] = []
    for i, c in enumerate(charts):
        key = version_key_of(c)
        if key in version_keys:  # two manifests mapping to one page: keep the first
            continue
        version_keys.add(key)
        rec = version_record(c, key, rollups.get(key), sum_images, details)
        if i in latest:
            latest_records.append((c, rec))  # uncapped combos for the landscape ranking
        if rec is not None:
            versions_out[key] = dict(rec, combos=rec["combos"][:VERSION_COMBOS])

    # Landscape over latest versions only.
    latest_images: set[str] = set()
    all_combos: list[dict[str, Any]] = []
    workloads = rbac_workloads = 0
    chart_dist = {lv: 0 for lv in report.CHART_LEVELS}
    for c, rec in latest_records:
        rollup = rollups.get(version_key_of(c)) or {}
        main = [w for img in c.get("images") or [] if img.get("role", "main") == "main"
                for w in img.get("workloads") or [] if w.get("role", "main") == "main"]
        workloads += _int(rollup["workloads"]) if "workloads" in rollup else len(main)
        rbac_workloads += (_int(rollup["workloads_rbac"]) if "workloads_rbac" in rollup
                           else sum(1 for w in main if w.get("sa_rbac_risk") in COMBO_RBAC))
        # no record: no valid image ref (Unknown when main refs are all invalid, N/A without workloads)
        lvl = rec["lvl"] if rec else rollup.get("risk_level") or report.chart_level(
            ["Unknown" for img in c.get("images") or [] if img.get("role", "main") == "main"])[0]
        chart_dist[lvl] = chart_dist.get(lvl, 0) + 1
        if rec is not None:
            latest_images.update(rec["imgs"].values())
            all_combos.extend(rec["combos"])
    all_combos.sort(key=combo_sort_key)
    image_dist = {lv: 0 for lv in report.LEVELS}
    for canonical in latest_images:
        lvl = images_out[canonical]["lvl"]
        image_dist[lvl] = image_dist.get(lvl, 0) + 1

    prov = summary.get("provenance") or {}
    cvenow = prov.get("cvenow") or {}
    trivy = prov.get("trivy") or scan.get("trivy") or {}
    scanned = sum(1 for r in images_out.values() if r["st"] == "ok")
    pending = sum(1 for r in images_out.values() if r["st"] == "pending")
    latest_scanned = sum(1 for c in latest_images if images_out[c]["st"] == "ok")
    landscape = {
        "generated_at": generated_at,
        "coverage": {
            "images": len(latest_images),
            "images_scanned": latest_scanned,
            "images_pending": sum(1 for c in latest_images if images_out[c]["st"] == "pending"),
            "scanned_pct": round(100.0 * latest_scanned / len(latest_images), 1) if latest_images else None,
            "cvenow_pct": ((summary.get("landscape") or {}).get("coverage") or {}).get("cvenow_coverage_pct",
                                                                                     cvenow.get("coverage_pct")),
            "charts": len(latest_records),
        },
        "distribution": {"images": image_dist, "charts": chart_dist},
        "combos": all_combos[:LANDSCAPE_COMBOS],
        "stats": {
            "workloads_total": workloads,
            "workloads_critical_or_high_rbac": rbac_workloads,
            "combos_total": len(all_combos),
            "combos_kev": sum(1 for x in all_combos if x["kev"]),
            "charts_with_combos": len({x["chart"] for x in all_combos}),
            "images_exploited": image_dist.get("Exploited", 0),
        },
    }
    meta = {
        "generated_at": generated_at,
        # 'all' for older inventories without a scope: only full runs were ever published
        "scope": str(inventory.get("scope") or "all"),
        "since": inventory.get("since"),
        "weights_version": summary.get("weights_version"),
        "trivy": {"version": trivy.get("version"), "db_updated_at": trivy.get("db_updated_at")},
        "cvenow": {"coverage_pct": cvenow.get("coverage_pct"), "requests": cvenow.get("requests")},
        "images_total": len(images_out),
        "images_scanned": scanned,
        "images_pending": pending,
        "versions_total": len(version_keys),
        "versions_with_data": sum(1 for r in versions_out.values()
                                  if any(images_out.get(c, {}).get("st") == "ok" for c in r["imgs"].values())),
    }
    return {"meta": meta, "landscape": landscape, "images": images_out, "versions": versions_out}


# ───────────────────────────── writing ──────────────────────────────
def dumps_records(records: dict[str, Any]) -> str:
    """Sorted JSON object with one compact record per line (small git diffs)."""
    if not records:
        return "{}\n"
    lines = [json.dumps(k, ensure_ascii=False) + ":" + json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
             for k, v in sorted(records.items())]
    return "{\n" + ",\n".join(lines) + "\n}\n"


def write_text(path: Path, text: str) -> bool:
    """Atomically write text when it differs; returns True if the file changed."""
    data = text.encode("utf-8")
    try:
        if path.read_bytes() == data:
            return False
    except OSError:
        pass
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return True


def sharded(records: dict[str, Any]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = defaultdict(dict)
    for key, rec in records.items():
        out[shard(key)][key] = rec
    return out


def write_output(docs: dict[str, Any], out_dir: Path) -> dict[str, Any]:
    """Write all documents under out_dir, remove stale shards; returns write stats."""
    files: dict[Path, str] = {
        out_dir / "meta.json": json.dumps(docs["meta"], indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        out_dir / "landscape.json": json.dumps(docs["landscape"], indent=1, sort_keys=True, ensure_ascii=False) + "\n",
    }
    for sub in ("images", "versions"):
        for name, recs in sharded(docs[sub]).items():
            files[out_dir / sub / f"{name}.json"] = dumps_records(recs)
    changed = sum(write_text(path, text) for path, text in sorted(files.items()))
    removed = 0
    for sub in ("images", "versions"):
        for path in sorted((out_dir / sub).glob("*.json")):
            if path not in files:
                path.unlink()
                removed += 1
    return {"files": len(files), "changed": changed, "removed": removed}


def size_report(out_dir: Path) -> dict[str, Any]:
    sizes: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    for path in out_dir.rglob("*.json"):
        group = path.parent.name if path.parent != out_dir else path.name
        sizes[group][0] += 1
        sizes[group][1] += path.stat().st_size
    total = sum(b for _, b in sizes.values())
    return {"total_bytes": total, "groups": {k: {"files": n, "bytes": b} for k, (n, b) in sorted(sizes.items())}}


def floor_errors(docs: dict[str, Any], min_latest_coverage: float) -> list[str]:
    """Reasons the new data must never be published, whatever was published before (empty when fine)."""
    meta, cov = docs["meta"], docs["landscape"]["coverage"]
    errors = []
    if _int(meta.get("images_scanned")) == 0:
        errors.append(f"no image was scanned (0 of {_int(meta.get('images_total'))})")
    if _int(meta.get("versions_with_data")) == 0:
        errors.append(f"no chart version has data (0 of {_int(meta.get('versions_total'))})")
    latest, scanned = _int(cov.get("images")), _int(cov.get("images_scanned"))
    if latest and scanned < latest * min_latest_coverage:
        errors.append(f"only {scanned} of {latest} latest-version images were scanned "
                      f"({scanned / latest:.0%}, minimum {min_latest_coverage:.0%})")
    return errors


def comparable(previous: dict[str, Any], meta: dict[str, Any]) -> bool:
    """True when both metas come from the same inventory scope and since date (a missing scope is 'all')."""
    return ((previous.get("scope") or "all"), previous.get("since")) == ((meta.get("scope") or "all"), meta.get("since"))


def regression_errors(previous: Any, meta: dict[str, Any], max_drop: float,
                      previous_landscape: Any = None, landscape: dict[str, Any] | None = None) -> list[str]:
    """Reasons the new data is a sharp regression from the published one (empty when fine or no previous).

    Scanned images, versions with data and scanned latest-version images are compared across scope and
    since changes (e.g. scope 'forward' over published 'all' backfill data); versions_total only when the
    previous meta has the same scope and since date."""
    if not isinstance(previous, dict):
        return []
    pairs = [(f, _int(previous.get(f)), _int(meta.get(f))) for f in GUARDED_META]
    if comparable(previous, meta):
        pairs += [(f, _int(previous.get(f)), _int(meta.get(f))) for f in SCOPED_GUARDED_META]
    if isinstance(previous_landscape, dict) and isinstance(landscape, dict):
        old_cov, new_cov = previous_landscape.get("coverage") or {}, landscape.get("coverage") or {}
        pairs.append(("latest-version images_scanned", _int(old_cov.get("images_scanned")),
                      _int(new_cov.get("images_scanned"))))
    return [f"{field} would drop from {old} to {new} (more than {max_drop:.0%})"
            for field, old, new in pairs if old > 0 and new < old * (1 - max_drop)]


# ───────────────────────────── CLI ──────────────────────────────
def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Publish vulnerability data as Hugo data files (data/vulns).")
    parser.add_argument("--inventory", type=Path, default=INVENTORY_FILE)
    parser.add_argument("--summary", type=Path, default=SUMMARY_FILE)
    parser.add_argument("--scan", type=Path, default=SCAN_FILE, help="optional; needed for top-CVE lists")
    parser.add_argument("--enrichment", type=Path, default=ENRICHMENT_FILE, help="optional; KEV/likely per CVE")
    parser.add_argument("--output", type=Path, default=OUTPUT_DIR)
    parser.add_argument("--max-mb", type=float, default=DEFAULT_MAX_MB, help="fail when the output exceeds this size")
    parser.add_argument("--max-drop", type=float, default=DEFAULT_MAX_DROP,
                        help="refuse to write when scanned images/versions (also across a scope change) drop by more than "
                             "this fraction")
    parser.add_argument("--allow-drop", action="store_true",
                        help="write even when the relative regression guard trips (never bypasses the absolute one)")
    parser.add_argument("--min-latest-coverage", type=float, default=DEFAULT_MIN_LATEST_COVERAGE,
                        help="refuse to write when fewer than this fraction of latest-version images were scanned")
    args = parser.parse_args(argv)

    inventory, summary = read_json(args.inventory), read_json(args.summary)
    for name, doc, path in (("inventory", inventory, args.inventory), ("summary", summary, args.summary)):
        if not isinstance(doc, dict):
            print(f"error: cannot read {name} {path}", file=sys.stderr)
            return 1
    # scan.json is large with scope 'all'; only older summaries without per-image 'top' lists need it
    scan: dict[str, Any] = {}
    enrichment: dict[str, Any] = {}
    if needs_scan(summary):
        scan = read_json(args.scan, {}) or {}
        enrichment = read_json(args.enrichment, {}) or {}
        if not scan.get("images"):
            log(f"publish: warning: no scan data at {args.scan}; top-CVE lists will be empty")

    docs = build(inventory, summary, scan, enrichment)
    floor = floor_errors(docs, args.min_latest_coverage)
    if floor:
        for msg in floor:
            print(f"error: {msg}; not publishing", file=sys.stderr)
        return 1
    previous = read_json(args.output / "meta.json")
    if isinstance(previous, dict) and not comparable(previous, docs["meta"]):
        log(f"publish: note: published data is from scope {previous.get('scope') or 'all'} "
            f"(since {previous.get('since')}), now {docs['meta']['scope']} (since {docs['meta']['since']}); "
            "versions_total is not compared")
    errors = regression_errors(previous, docs["meta"], args.max_drop,
                               read_json(args.output / "landscape.json"), docs["landscape"])
    if errors and not args.allow_drop:
        for msg in errors:
            print(f"error: {msg}; not publishing (use --allow-drop to override)", file=sys.stderr)
        return 1
    for msg in errors:
        log(f"publish: warning: {msg} (--allow-drop)")
    stats = write_output(docs, args.output)
    sizes = size_report(args.output)
    for group, s in sizes["groups"].items():
        log(f"publish: {group}: {s['files']} files, {s['bytes'] / 1e6:.2f} MB")
    m = docs["meta"]
    log(f"publish: {m['images_total']} images ({m['images_scanned']} scanned, {m['images_pending']} pending), "
        f"{m['versions_total']} versions ({m['versions_with_data']} with data), "
        f"{docs['landscape']['stats']['combos_total']} latest combos; {stats['files']} files, "
        f"{stats['changed']} changed, {stats['removed']} removed, {sizes['total_bytes'] / 1e6:.2f} MB -> {args.output}")
    if sizes["total_bytes"] > args.max_mb * 1e6:
        print(f"error: {args.output} is {sizes['total_bytes'] / 1e6:.2f} MB, above --max-mb {args.max_mb}",
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
