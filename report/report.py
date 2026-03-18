#!/usr/bin/env python3
"""
RBAC Atlas Report Generator

Reads JSON manifests from ../manifests/, produces:
  1. rbac_report.csv            – one row per manifest (flat), in report/
  2. reports/YYYY-MM-DD.json    – dated aggregated snapshot (accumulates daily)

Usage:
    uv run report/report.py                          # defaults
    uv run report/report.py --manifests /path        # custom manifests dir
    uv run report/report.py --reports-dir /path      # custom reports output dir
    uv run report/report.py --date 2026-01-15        # override snapshot date
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from datetime import date
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# 1. Manifest parsing helpers
# ---------------------------------------------------------------------------

def parse_manifest(path: Path) -> dict[str, Any] | None:
    """Load a single manifest JSON and return a parsed record, or None on error."""
    try:
        data = json.loads(path.read_text())
    except Exception as e:
        print(f"  WARN: skipping {path.name}: {e}", file=sys.stderr)
        return None

    meta = data.get("metadata", {})
    extra_helm = meta.get("extra", {}).get("helm", {})

    sa_data = data.get("serviceAccountData", [])
    sa_perms = data.get("serviceAccountPermissions", [])
    sa_workloads = data.get("serviceAccountWorkloads", [])

    # Count risk levels
    risk_counts: Counter[str] = Counter()
    for perm in sa_perms:
        level = perm.get("riskLevel", "").lower()
        if level:
            risk_counts[level] += 1

    # Collect tags and matched risk rule names
    tags: list[str] = []
    rule_names: list[str] = []
    for perm in sa_perms:
        tags.extend(perm.get("tags", []))
        for rule in perm.get("matchedRiskRules", []):
            name = rule.get("name", "")
            if name:
                rule_names.append(name)

    return {
        # Metadata
        "project_name": meta.get("name", ""),
        "version": meta.get("version", ""),
        "source": meta.get("source", ""),
        "helm_description": extra_helm.get("description", ""),
        "helm_home": extra_helm.get("home", ""),
        # Counts
        "service_account_count": len(sa_data),
        "permission_count": len(sa_perms),
        "workload_count": len(sa_workloads),
        "risk_critical": risk_counts.get("critical", 0),
        "risk_high": risk_counts.get("high", 0),
        "risk_medium": risk_counts.get("medium", 0),
        "risk_low": risk_counts.get("low", 0),
        # Raw lists (for aggregation, not written to CSV)
        "_tags": tags,
        "_rule_names": rule_names,
        # Source
        "source_file": path.name,
    }


def load_manifests(manifests_dir: Path) -> list[dict[str, Any]]:
    """Load all JSON manifests and return parsed records."""
    files = sorted(manifests_dir.glob("*.json"))
    print(f"Found {len(files)} manifest files in {manifests_dir}")

    records = []
    for f in files:
        rec = parse_manifest(f)
        if rec:
            records.append(rec)

    print(f"Successfully parsed {len(records)} manifests")
    return records


# ---------------------------------------------------------------------------
# 2. CSV generation
# ---------------------------------------------------------------------------

CSV_COLUMNS = [
    "source_file",
    "project_name",
    "version",
    "source",
    "helm_description",
    "helm_home",
    "service_account_count",
    "permission_count",
    "workload_count",
    "risk_critical",
    "risk_high",
    "risk_medium",
    "risk_low",
]


def write_csv(records: list[dict[str, Any]], output: Path) -> None:
    """Write flat CSV report."""
    import csv

    with output.open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_COLUMNS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(records)

    print(f"CSV report written to {output} ({len(records)} rows)")


# ---------------------------------------------------------------------------
# 3. Aggregation & JSON report
# ---------------------------------------------------------------------------

def risk_score(rec: dict[str, Any]) -> int:
    """Weighted risk score: critical*10 + high*5 + medium*2 + low*1."""
    return (
        rec["risk_critical"] * 10
        + rec["risk_high"] * 5
        + rec["risk_medium"] * 2
        + rec["risk_low"]
    )


def aggregate(records: list[dict[str, Any]], snapshot_date: str) -> dict[str, Any]:
    """Build aggregated insights from parsed records."""
    n = len(records)
    if n == 0:
        return {"error": "no records"}

    # -- Deduplicate to latest version per project ---
    latest: dict[str, dict[str, Any]] = {}
    for rec in records:
        name = rec["project_name"]
        if name not in latest or rec["version"] > latest[name]["version"]:
            latest[name] = rec
    latest_records = list(latest.values())

    report: dict[str, Any] = {"date": snapshot_date}

    # -- Top 10 RBAC risk tags (latest version per project only) --
    tag_counter: Counter[str] = Counter()
    for rec in latest_records:
        tag_counter.update(rec["_tags"])
    report["top_10_risk_tags"] = {
        tag: count for tag, count in tag_counter.most_common(10)
    }

    # -- Top 10 matched risk rules (latest version per project only) --
    rule_counter: Counter[str] = Counter()
    for rec in latest_records:
        rule_counter.update(rec["_rule_names"])
    report["top_10_risk_rules"] = {
        name: count for name, count in rule_counter.most_common(10)
    }

    # -- Top 10 riskiest projects (latest version only, scored) --
    ranked = sorted(latest_records, key=risk_score, reverse=True)[:10]
    report["top_10_riskiest_projects"] = {
        rec["project_name"]: {
            "version": rec["version"],
            "critical": rec["risk_critical"],
            "high": rec["risk_high"],
            "medium": rec["risk_medium"],
            "low": rec["risk_low"],
            "risk_score": risk_score(rec),
        }
        for rec in ranked
    }

    # -- Summary statistics (latest version per project) --
    ln = len(latest_records)

    def avg(field: str) -> float:
        return round(sum(r[field] for r in latest_records) / ln, 2)

    report["summary"] = {
        "total_manifest_versions": n,
        "unique_projects": ln,
        "avg_service_accounts": avg("service_account_count"),
        "avg_permissions": avg("permission_count"),
        "avg_workloads": avg("workload_count"),
        "avg_critical_risks": avg("risk_critical"),
        "avg_high_risks": avg("risk_high"),
        "avg_medium_risks": avg("risk_medium"),
        "avg_low_risks": avg("risk_low"),
    }

    # -- Risk distribution across all unique projects --
    total_critical = sum(r["risk_critical"] for r in latest_records)
    total_high = sum(r["risk_high"] for r in latest_records)
    total_medium = sum(r["risk_medium"] for r in latest_records)
    total_low = sum(r["risk_low"] for r in latest_records)
    total_all = total_critical + total_high + total_medium + total_low or 1

    report["risk_distribution"] = {
        "total_permissions_analyzed": total_all,
        "critical": total_critical,
        "critical_pct": round(total_critical / total_all * 100, 2),
        "high": total_high,
        "high_pct": round(total_high / total_all * 100, 2),
        "medium": total_medium,
        "medium_pct": round(total_medium / total_all * 100, 2),
        "low": total_low,
        "low_pct": round(total_low / total_all * 100, 2),
    }

    # -- Projects with zero permissions (no RBAC footprint) --
    zero_perms = [r for r in latest_records if r["permission_count"] == 0]
    report["projects_with_no_permissions"] = len(zero_perms)

    # -- Projects with at least one critical risk --
    critical_projects = [r for r in latest_records if r["risk_critical"] > 0]
    report["projects_with_critical_risks"] = len(critical_projects)

    # -- Top 10 projects by permission count --
    by_perms = sorted(latest_records, key=lambda r: r["permission_count"], reverse=True)[:10]
    report["top_10_most_permissions"] = {
        r["project_name"]: r["permission_count"] for r in by_perms
    }

    return report


# ---------------------------------------------------------------------------
# 4. Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="RBAC Atlas Report Generator")
    parser.add_argument(
        "--manifests",
        type=Path,
        default=Path(__file__).resolve().parent.parent / "manifests",
        help="Path to manifests directory (default: ../manifests)",
    )
    parser.add_argument(
        "--reports-dir",
        type=Path,
        default=Path(__file__).resolve().parent.parent / "reports",
        help="Directory for dated JSON snapshots (default: ../reports)",
    )
    parser.add_argument(
        "--csv-dir",
        type=Path,
        default=Path(__file__).resolve().parent,
        help="Directory for CSV output (default: report/)",
    )
    parser.add_argument(
        "--date",
        type=str,
        default=date.today().isoformat(),
        help="Snapshot date for the JSON filename (default: today)",
    )
    args = parser.parse_args()

    if not args.manifests.is_dir():
        print(f"ERROR: manifests directory not found: {args.manifests}", file=sys.stderr)
        sys.exit(1)

    args.reports_dir.mkdir(parents=True, exist_ok=True)
    args.csv_dir.mkdir(parents=True, exist_ok=True)

    records = load_manifests(args.manifests)
    if not records:
        print("No records found, exiting.", file=sys.stderr)
        sys.exit(1)

    # CSV (local to report/)
    write_csv(records, args.csv_dir / "rbac_report.csv")

    # Dated JSON snapshot → reports/YYYY-MM-DD.json
    report = aggregate(records, args.date)
    json_path = args.reports_dir / f"{args.date}.json"
    json_path.write_text(json.dumps(report, indent=2) + "\n")
    print(f"JSON snapshot written to {json_path}")

    # Print a quick summary to stdout
    s = report.get("summary", {})
    print(f"\n--- Summary ({args.date}) ---")
    print(f"  Unique projects:      {s.get('unique_projects')}")
    print(f"  Total versions:       {s.get('total_manifest_versions')}")
    print(f"  Avg service accounts: {s.get('avg_service_accounts')}")
    print(f"  Avg permissions:      {s.get('avg_permissions')}")
    print(f"  Avg critical risks:   {s.get('avg_critical_risks')}")
    print(f"  Projects with critical risks: {report.get('projects_with_critical_risks')}")


if __name__ == "__main__":
    main()
