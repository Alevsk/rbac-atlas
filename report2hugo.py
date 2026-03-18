#!/usr/bin/env python3
"""
report2hugo.py – convert dated report JSON snapshots into Hugo Markdown pages.

Reads JSON files from reports/ and generates:
  - content/pages/threat-landscape.md  (latest snapshot, the main page)

Usage:
    uv run report2hugo.py
    uv run report2hugo.py -f reports/ -o content/
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any


def load_latest_report(reports_dir: Path) -> dict[str, Any] | None:
    """Find the most recent dated JSON in reports/ and load it."""
    files = sorted(reports_dir.glob("*.json"))
    if not files:
        return None
    latest = files[-1]  # filenames are YYYY-MM-DD.json, so sorted = chronological
    print(f"Using latest report: {latest.name}")
    return json.loads(latest.read_text())


def build_markdown(report: dict[str, Any]) -> str:
    """Build Hugo-ready Markdown from a report JSON snapshot."""
    snapshot_date = report.get("date", "unknown")
    summary = report.get("summary", {})
    risk_dist = report.get("risk_distribution", {})
    risk_tags = report.get("top_10_risk_tags", {})
    risk_rules = report.get("top_10_risk_rules", {})
    riskiest = report.get("top_10_riskiest_projects", {})
    most_perms = report.get("top_10_most_permissions", {})

    # -- Front matter --
    lines = [
        "---",
        'title: "Cloud-Native Threat Landscape"',
        f'description: "RBAC risk analysis across {summary.get("unique_projects", 0)} Kubernetes open-source projects"',
        f'date: "{snapshot_date}"',
        "---",
        "",
    ]

    # -- Intro --
    lines.append(
        f"This report is auto-generated from the latest RBAC Atlas scan "
        f"(**{snapshot_date}**). It analyzes the RBAC permissions of "
        f"**{summary.get('unique_projects', 0)}** Kubernetes open-source projects "
        f"across **{summary.get('total_manifest_versions', 0)}** manifest versions "
        f"to provide a snapshot of the current cloud-native threat landscape.\n"
    )

    # -- Summary stats --
    lines.append("## At a Glance\n")
    lines.append("| Metric | Value |")
    lines.append("|--------|-------|")
    lines.append(f"| Projects analyzed | {summary.get('unique_projects', 0)} |")
    lines.append(f"| Total manifest versions | {summary.get('total_manifest_versions', 0)} |")
    lines.append(f"| Avg service accounts per project | {summary.get('avg_service_accounts', 0)} |")
    lines.append(f"| Avg permission bindings per project | {summary.get('avg_permissions', 0)} |")
    lines.append(f"| Avg workloads per project | {summary.get('avg_workloads', 0)} |")
    lines.append(f"| Avg critical risks per project | {summary.get('avg_critical_risks', 0)} |")
    lines.append(f"| Avg high risks per project | {summary.get('avg_high_risks', 0)} |")
    lines.append(f"| Avg medium risks per project | {summary.get('avg_medium_risks', 0)} |")
    lines.append(f"| Avg low risks per project | {summary.get('avg_low_risks', 0)} |")
    lines.append(f"| Projects with critical risks | {report.get('projects_with_critical_risks', 0)} |")
    lines.append(f"| Projects with no RBAC permissions | {report.get('projects_with_no_permissions', 0)} |")
    lines.append("")

    # -- Risk distribution --
    lines.append("## Risk Distribution\n")
    lines.append("| Risk Level | Count | Percentage |")
    lines.append("|------------|-------|------------|")
    for level in ["critical", "high", "medium", "low"]:
        count = risk_dist.get(level, 0)
        pct = risk_dist.get(f"{level}_pct", 0)
        lines.append(f"| {{{{< risk \"{level.capitalize()}\" >}}}} | {count} | {pct}% |")
    lines.append(f"| **Total** | **{risk_dist.get('total_permissions_analyzed', 0)}** | |")
    lines.append("")

    # -- Top 10 risk tags --
    lines.append("## Top 10 RBAC Risk Tags\n")
    lines.append("| Risk Tag | Occurrences |")
    lines.append("|----------|-------------|")
    for tag, count in risk_tags.items():
        lines.append(f"| {{{{< tag \"{tag}\" >}}}} | {count} |")
    lines.append("")

    # -- Top 10 risk rules --
    lines.append("## Top 10 Triggered Risk Rules\n")
    lines.append("| Rule | Occurrences |")
    lines.append("|------|-------------|")
    for rule, count in risk_rules.items():
        lines.append(f"| {rule} | {count} |")
    lines.append("")

    # -- Top 10 riskiest projects --
    lines.append("## Top 10 Riskiest Projects\n")
    lines.append(
        "Ranked by weighted risk score "
        "(`critical×10 + high×5 + medium×2 + low×1`), "
        "using only the latest version of each project.\n"
    )
    lines.append("| Project | Version | Critical | High | Medium | Low | Score |")
    lines.append("|---------|---------|----------|------|--------|-----|-------|")
    for project, data in riskiest.items():
        lines.append(
            f"| [{project}](/charts/{project}/) | {data['version']} "
            f"| {data['critical']} | {data['high']} "
            f"| {data['medium']} | {data['low']} "
            f"| **{data['risk_score']}** |"
        )
    lines.append("")

    # -- Top 10 most permissions --
    lines.append("## Top 10 Projects by Permission Count\n")
    lines.append("| Project | Permissions |")
    lines.append("|---------|-------------|")
    for project, count in most_perms.items():
        lines.append(f"| [{project}](/charts/{project}/) | {count} |")
    lines.append("")

    return "\n".join(lines) + "\n"


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Convert report JSON snapshots to Hugo Markdown pages."
    )
    ap.add_argument(
        "-f", "--reports-dir",
        type=Path,
        default=Path("reports"),
        help="Path to the reports directory containing dated JSON files (default: reports/)",
    )
    ap.add_argument(
        "-o", "--output-dir",
        type=Path,
        default=Path("content"),
        help="Hugo content output directory (default: content/)",
    )
    args = ap.parse_args()

    if not args.reports_dir.is_dir():
        ap.error(f"Reports directory not found: {args.reports_dir}")

    report = load_latest_report(args.reports_dir)
    if not report:
        ap.error(f"No JSON files found in {args.reports_dir}")

    markdown = build_markdown(report)

    # Write to content/pages/threat-landscape.md
    pages_dir = args.output_dir / "pages"
    pages_dir.mkdir(parents=True, exist_ok=True)
    output_path = pages_dir / "threat-landscape.md"
    output_path.write_text(markdown)
    print(f"Wrote: {output_path}")


if __name__ == "__main__":
    main()
