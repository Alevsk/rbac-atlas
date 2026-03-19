#!/usr/bin/env python3
"""
backfill_reports.py – Generate historical report snapshots from git history.

Uses git log to find when each content/charts/ markdown file was added,
parses frontmatter to extract risk data, and builds cumulative daily
snapshots in reports/ for every date that had new content.

This lets the time-series charts show historical trends instead of a
single data point.

Usage:
    uv run report/backfill_reports.py
    uv run report/backfill_reports.py --sample-interval 7   # weekly snapshots
    uv run report/backfill_reports.py --since 2025-09-01    # from a specific date
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections import Counter
from datetime import date
from pathlib import Path
from typing import Any


def git_file_dates(repo_root: Path) -> dict[str, str]:
    """Return {relative_path: YYYY-MM-DD} for every file added under content/charts/.

    Uses git log to find the commit that first added each file.
    """
    result = subprocess.run(
        [
            "git", "log", "--diff-filter=A", "--format=%ai",
            "--name-only", "--", "content/charts/",
        ],
        cwd=repo_root,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(f"ERROR: git log failed: {result.stderr}", file=sys.stderr)
        sys.exit(1)

    file_dates: dict[str, str] = {}
    current_date = ""
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        # Date lines look like: 2025-06-02 10:30:00 -0700
        if re.match(r"\d{4}-\d{2}-\d{2} ", line):
            current_date = line[:10]
        elif line.startswith("content/charts/") and line.endswith(".md"):
            # Skip _index.md files (section pages, not chart versions)
            if line.endswith("_index.md"):
                continue
            # First occurrence in git log is the file's creation date
            if line not in file_dates:
                file_dates[line] = current_date

    return file_dates


def parse_frontmatter(filepath: Path) -> dict[str, Any] | None:
    """Parse YAML frontmatter from a Hugo markdown file."""
    try:
        text = filepath.read_text()
    except Exception:
        return None

    if not text.startswith("---"):
        return None

    end = text.find("---", 3)
    if end == -1:
        return None

    fm_text = text[3:end]

    # Simple YAML parsing for the fields we need (avoids pyyaml dependency)
    def get_field(name: str) -> str:
        pattern = rf"^{name}:\s*(.+)$"
        m = re.search(pattern, fm_text, re.MULTILINE)
        return m.group(1).strip().strip('"').strip("'") if m else ""

    def get_int(name: str) -> int:
        val = get_field(name)
        try:
            return int(val)
        except (ValueError, TypeError):
            return 0

    # Extract tags list
    tags: list[str] = []
    tags_match = re.search(r"tags:\s*\[([^\]]*)\]", fm_text)
    if tags_match:
        raw = tags_match.group(1)
        tags = [t.strip().strip('"').strip("'") for t in raw.split(",") if t.strip()]
    else:
        # Multi-line tags format
        in_tags = False
        for line in fm_text.splitlines():
            if line.strip().startswith("tags:"):
                in_tags = True
                continue
            if in_tags:
                if line.strip().startswith("- "):
                    tags.append(line.strip()[2:].strip().strip('"').strip("'"))
                elif line.strip() and not line.startswith(" "):
                    break

    # Filter out letter- tags (used for alphabetical grouping)
    tags = [t for t in tags if not t.startswith("letter-")]

    title = get_field("title")
    version = get_field("version")

    return {
        "project_name": title,
        "version": version,
        "service_account_count": get_int("service_accounts"),
        "permission_count": get_int("bindings"),
        "workload_count": get_int("workloads"),
        "risk_critical": get_int("critical_findings"),
        "risk_high": get_int("high_findings"),
        "risk_medium": get_int("medium_findings"),
        "risk_low": get_int("low_findings"),
        "_tags": tags,
        "_rule_names": [],  # Not available in frontmatter
    }


def risk_score(rec: dict[str, Any]) -> int:
    return (
        rec["risk_critical"] * 10
        + rec["risk_high"] * 5
        + rec["risk_medium"] * 2
        + rec["risk_low"]
    )


def aggregate(records: list[dict[str, Any]], snapshot_date: str) -> dict[str, Any]:
    """Build aggregated report from parsed records (same logic as report.py)."""
    n = len(records)
    if n == 0:
        return {"error": "no records", "date": snapshot_date}

    # Deduplicate to latest version per project
    latest: dict[str, dict[str, Any]] = {}
    for rec in records:
        name = rec["project_name"]
        if name not in latest or rec["version"] > latest[name]["version"]:
            latest[name] = rec
    latest_records = list(latest.values())

    report: dict[str, Any] = {"date": snapshot_date}

    # Top 10 risk tags
    tag_counter: Counter[str] = Counter()
    for rec in latest_records:
        tag_counter.update(rec["_tags"])
    report["top_10_risk_tags"] = {
        tag: count for tag, count in tag_counter.most_common(10)
    }

    # Top 10 risk rules (empty since frontmatter doesn't have rule data)
    report["top_10_risk_rules"] = {}

    # Top 10 riskiest projects
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

    # Summary statistics
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

    # Risk distribution
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

    # Projects with zero permissions
    report["projects_with_no_permissions"] = len(
        [r for r in latest_records if r["permission_count"] == 0]
    )

    # Projects with critical risks
    report["projects_with_critical_risks"] = len(
        [r for r in latest_records if r["risk_critical"] > 0]
    )

    # Top 10 by permission count
    by_perms = sorted(
        latest_records, key=lambda r: r["permission_count"], reverse=True
    )[:10]
    report["top_10_most_permissions"] = {
        r["project_name"]: r["permission_count"] for r in by_perms
    }

    return report


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Backfill historical report snapshots from git history."
    )
    ap.add_argument(
        "--sample-interval",
        type=int,
        default=7,
        help="Generate a snapshot every N days (default: 7 = weekly)",
    )
    ap.add_argument(
        "--since",
        type=str,
        default=None,
        help="Only backfill from this date onwards (YYYY-MM-DD)",
    )
    ap.add_argument(
        "--reports-dir",
        type=Path,
        default=Path(__file__).resolve().parent.parent / "reports",
        help="Output directory for JSON snapshots (default: ../reports)",
    )
    args = ap.parse_args()

    repo_root = Path(__file__).resolve().parent.parent

    print("Scanning git history for content/charts/ additions...")
    file_dates = git_file_dates(repo_root)
    print(f"  Found {len(file_dates)} chart version files with dates")

    if not file_dates:
        print("No files found, exiting.", file=sys.stderr)
        sys.exit(1)

    # Build {date: [file_paths]} mapping
    dates_files: dict[str, list[str]] = {}
    for fpath, fdate in file_dates.items():
        dates_files.setdefault(fdate, []).append(fpath)

    all_dates = sorted(dates_files.keys())
    print(f"  Date range: {all_dates[0]} to {all_dates[-1]}")

    # Apply --since filter
    if args.since:
        all_dates = [d for d in all_dates if d >= args.since]
        print(f"  After --since filter: {len(all_dates)} dates")

    # Sample dates at the specified interval
    sampled_dates = []
    for i, d in enumerate(all_dates):
        if i == 0 or i == len(all_dates) - 1:
            sampled_dates.append(d)
        elif i % args.sample_interval == 0:
            sampled_dates.append(d)
    # Deduplicate while preserving order
    sampled_dates = list(dict.fromkeys(sampled_dates))

    print(f"  Will generate {len(sampled_dates)} snapshots (interval={args.sample_interval})")

    # Parse all content files once (they don't change, only their existence date matters)
    print("Parsing frontmatter from all chart files...")
    parsed_files: dict[str, dict[str, Any]] = {}
    for fpath in file_dates:
        full_path = repo_root / fpath
        if full_path.exists():
            rec = parse_frontmatter(full_path)
            if rec and rec["project_name"]:
                parsed_files[fpath] = rec

    print(f"  Successfully parsed {len(parsed_files)} files")

    # Generate cumulative snapshots
    args.reports_dir.mkdir(parents=True, exist_ok=True)
    cumulative_files: list[str] = []
    date_idx = 0

    for snapshot_date in sampled_dates:
        # Add all files from dates up to and including this snapshot date
        while date_idx < len(all_dates) and all_dates[date_idx] <= snapshot_date:
            d = all_dates[date_idx]
            cumulative_files.extend(dates_files.get(d, []))
            date_idx += 1

        # Build records for this snapshot
        records = [
            parsed_files[f] for f in cumulative_files if f in parsed_files
        ]

        if not records:
            continue

        report = aggregate(records, snapshot_date)
        out_path = args.reports_dir / f"{snapshot_date}.json"

        # Don't overwrite existing snapshots (e.g., today's real report)
        if out_path.exists():
            print(f"  SKIP {snapshot_date} (already exists)")
            continue

        out_path.write_text(json.dumps(report, indent=2) + "\n")
        s = report.get("summary", {})
        print(
            f"  {snapshot_date}: {s.get('unique_projects', 0)} projects, "
            f"{s.get('total_manifest_versions', 0)} versions"
        )

    print(f"\nDone. Snapshots written to {args.reports_dir}/")


if __name__ == "__main__":
    main()
