#!/usr/bin/env python3
"""
json2hugo.py – convert a knowledge-base JSON file into a Hugo-ready Markdown page
using the “Overview + per-identity” layout.

• Overview table shows one row per ServiceAccount plus quick counts.
• Each identity then gets its own section with its permissions & workloads.
• Output path:  content/<metadata.name>/<metadata.version>.md
"""

from __future__ import annotations
import argparse
import json
import os
import re
import yaml
from collections import Counter, defaultdict
from datetime import datetime
from typing import Any, Dict, List, TypedDict

# ───────────────────────────── Markdown helpers ──────────────────────────────
def h(level: int, text: str) -> str:
    return f'{"#" * level} {text}\n\n'


def bullet(text: str) -> str:
    return f"- {text}\n"


def table(headers: List[str], rows: List[List[str]]) -> str:
    header = "|" + "|".join(headers) + "|\n"
    sep    = "|" + "|".join("---" for _ in headers) + "|\n"
    body   = "".join("|" + "|".join(row) + "|\n" for row in rows)
    return header + sep + body + "\n"


def slug(text: str) -> str:
    """Turn a SA name into a stable anchor id."""
    text = text or "none"
    return "sa-" + re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


# ───────────────────────────── Conversion logic ──────────────────────────────
def build_markdown(data: Dict[str, Any]) -> str:
    meta = data["metadata"]
    name, version = meta["name"], meta["version"]

    description = ""
    if 'extra' in meta and 'helm' in meta['extra'] and 'description' in meta['extra']['helm']:
        description = meta['extra']['helm']['description']

    # ts = meta.get("timestamp")
    risk_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    perms = sorted(data.get("serviceAccountPermissions", []),
                  key=lambda x: (risk_order.get(x.get("riskLevel", ""), 4), x.get("roleName", "")))
    workloads = sorted(data.get("serviceAccountWorkloads", []),
                  key=lambda x: (x.get("workloadType", ""), x.get("workloadName", ""), x.get("containerName", "")))

    # index by SA
    perms_by_sa: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for p in perms:
        perms_by_sa[p["serviceAccountName"]].append(p)

    # Helper function to get highest risk for a service account
    def get_highest_risk(sa_name: str) -> int:
        risks = {p["riskLevel"] for p in perms_by_sa[sa_name]}
        return min((risk_order.get(r, 4) for r in risks), default=4)

    # Sort service accounts by risk level (highest risk first) then by name
    sa_data = sorted(data.get("serviceAccountData", []),
                    key=lambda x: (get_highest_risk(x.get("serviceAccountName", "")),
                                 x.get("serviceAccountName", "")))
    wl_by_sa: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for w in workloads:
        wl_by_sa[w["serviceAccountName"]].append(w)

    # Overview counts
    perm_counts = Counter(p["serviceAccountName"] for p in perms)
    wl_counts   = Counter(w["serviceAccountName"] for w in workloads)
    risk_counts = Counter(p["riskLevel"] for p in perms)

    # Create semantic version order key
    def get_version_order(v):
        # Remove 'v' prefix if present
        v = v.lstrip('v')
        # Split into major, minor, patch
        parts = v.split('.')
        # Pad with zeros if needed
        while len(parts) < 3:
            parts.append('0')
        try:
            # Convert to integers
            major = int(parts[0])
            minor = int(parts[1])
            patch = int(parts[2])
            # Convert to hex with left padding
            # This gives us a sortable string that will work with Hugo
            major_hex = f"{major:04x}"
            minor_hex = f"{minor:04x}"
            patch_hex = f"{patch:04x}"
            # Combine in reverse order for descending sort
            return f"f{major_hex}f{minor_hex}f{patch_hex}"
        except (ValueError, IndexError):
            return "f0000f0000f0000"  # Default for invalid versions

    # ── page header ──
    out = "---\n"
    out += f"title: {name}\n"
    out += f"description: {description}\n"
    if not version.startswith("v"):
        version = "v" + version
    out += f"version: {version}\n"
    # Add version order key for sorting
    out += f"version_order: {get_version_order(version)}\n"
    out += "date: \"\"\n"
    out += f"service_accounts: {len(perms_by_sa)}\n"
    out += f"workloads: {len(wl_by_sa)}\n"
    out += f"bindings: {len(perms)}\n"
    out += f"critical_findings: {risk_counts['Critical']}\n"
    out += f"high_findings: {risk_counts['High']}\n"
    out += f"medium_findings: {risk_counts['Medium']}\n"
    out += f"low_findings: {risk_counts['Low']}\n"

    # Extract categories from metadata.extra.helm.keywords if available
    categories = []
    if 'extra' in meta and 'helm' in meta['extra'] and 'keywords' in meta['extra']['helm']:
        categories = meta['extra']['helm']['keywords'] or []
    out += f"categories: [{', '.join(categories)}]\n"

    # Extract and deduplicate tags from all service account permissions
    tags = set()
    for p in perms:
        perm_tags = p.get("tags", []) or []
        tags.update(perm_tags)

    out += f"tags: [{', '.join(sorted(tags))}]\n"
    out += "---\n\n"

    # ── Description ──
    out += h(2, "Description")
    out += description + "\n\n"

    # Add sources if available
    if 'extra' in meta and 'helm' in meta['extra'] and 'sources' in meta['extra']['helm']:
        sources = meta['extra']['helm']['sources'] or []
        for source in sources:
            out += bullet(source)
        out += "\n"

    # ── Overview table ──
    out += h(2, "Overview")
    overview_rows = []
    for sa in sa_data:
        sa_name = sa["serviceAccountName"]
        anchor  = slug(sa_name)
        # Get highest risk for this service account
        highest_risk = get_highest_risk(sa_name)
        risk_map = {0: "Critical", 1: "High", 2: "Medium", 3: "Low", 4: "—"}
        risk_display = risk_map[highest_risk]
        risk_class = risk_display.lower() if risk_display != "—" else ""
        risk_cell = f'{{{{< risk "{risk_display}" >}}}}' if risk_display != "—" else "—"

        overview_rows.append([
            f"[`{sa_name or '—'}`](#{anchor})",
            sa["namespace"],
            "✅" if sa["automountToken"] else "❌",
            ", ".join(sa["secrets"] or []) or "—",
            str(perm_counts.get(sa_name, 0)),
            str(wl_counts.get(sa_name, 0)),
            risk_cell
        ])
    out += table(
        ["Identity", "Namespace", "Automount", "Secrets",
         "Permissions", "Workloads", "Risk"],
        overview_rows,
    )
    out += (
        "\n> *Numbers in the last two columns indicate how many bindings or "
        "workloads involve each ServiceAccount.*\n\n"
        "---\n\n"
    )

    # ── Per-identity sections ──
    out += h(2, "Identities")
    # sort: highest risk permissions first (Critical > Medium > Low > none),
    # then by permission count, then name
    risk_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    def sort_key(sa: Dict[str, Any]) -> tuple:
        risks = {p["riskLevel"] for p in perms_by_sa[sa["serviceAccountName"]]}
        top_risk = min((risk_order.get(r, 4) for r in risks), default=4)
        return (top_risk,
                -perm_counts.get(sa["serviceAccountName"], 0),
                sa["serviceAccountName"])
    for sa in sorted(sa_data, key=sort_key):
        sa_name = sa["serviceAccountName"]
        anchor  = slug(sa_name)

        header  = f"### 🤖 `{sa_name or '—'}` {{#{anchor}}}\n"
        header += (
            f"**Namespace:** `{sa['namespace']}` &nbsp;|&nbsp; "
            f"**Automount:** {'✅' if sa['automountToken'] else '❌'}"
        )
        secrets = ", ".join(sa["secrets"] or [])
        if secrets:
            header += f" &nbsp;|&nbsp; **Secrets:** {secrets}"
        header += "\n\n"
        out += header

        # Permissions
        sa_perms = perms_by_sa[sa_name]
        out += h(4, f"🔑 Permissions ({len(sa_perms)})").rstrip() + "\n"
        if sa_perms:
            # Sort permissions by risk level
            sorted_perms = sorted(sa_perms, key=lambda p: (risk_order.get(p["riskLevel"], 4), p["roleType"], p["roleName"]))
            perm_rows = [
                [
                    p["roleType"] + f" `{p['roleName']}`",
                    f"{p['apiGroup'] or 'core'}/{p['resource']}",
                    " · ".join(p["verbs"]),
                    "{{< risk " + p['riskLevel'] + " >}}",
                    " ".join(["{{< tag \"" + tag + "\" >}}" for tag in sorted(p.get("tags", []))[:5]] +
                        [(f"(+{len(p.get('tags', [])) - 5} more)" if len(p.get('tags', [])) > 5 else "")])
                ]
                for p in sorted_perms
            ]
            out += table(["Role", "Resource", "Verbs", "Risk", "Tags"], perm_rows)
        else:
            out += "_No explicit RBAC bindings._\n\n"

        # Abuse
        if sa_perms:
            # Collect all unique rule IDs from all permissions
            all_risk_rules = set()
            for perm in sa_perms:
                risk_rules = perm.get('riskRules', [])
                all_risk_rules.update(risk_rules)

            if all_risk_rules:
                out += h(4, f"⚠️ Potential Abuse ({len(all_risk_rules)})").rstrip() + "\n"
                out += "The following security risks were detected based on the above permissions:\n\n"
                for rule_id in sorted(all_risk_rules):
                    if rule_id in rules_dict:
                        rule = rules_dict[rule_id]
                        out += f"- [{rule['name']}](/rules/{rule_id})\n"
                out += "\n"

        # Workloads
        sa_wl = wl_by_sa[sa_name]
        out += h(4, f"📦 Workloads ({len(sa_wl)})").rstrip() + "\n"
        if sa_wl:
            wl_rows = [
                [w["workloadType"], w["workloadName"],
                 w["containerName"], w["image"]]
                for w in sa_wl
            ]
            out += table(["Kind", "Name", "Container", "Image"], wl_rows)
        else:
            out += "_No workloads use this ServiceAccount._\n\n"

        out += "---\n\n"

    return out


# ────────────────────────────── File writer ──────────────────────────────────
def write_markdown(markdown: str, meta: Dict[str, str], output_dir: str) -> str:

    if output_dir == "":
        output_dir = "content"

    path = os.path.join(
        output_dir, meta["name"], f"{meta['version']}.md"
    )
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(markdown)

    # Create _index.md file with metadata inside the folder_path
    folder_path = os.path.join(output_dir, meta["name"])
    index_path = os.path.join(folder_path, "_index.md")
    index_content = "---\n"
    index_content += f"title: {meta['name']}\n"
    if 'extra' in meta and 'helm' in meta['extra'] and 'description' in meta['extra']['helm']:
        index_content += f"description: {meta['extra']['helm']['description']}\n"
    index_content += "---\n\n"

    # Add title and description
    index_content += f"## {meta['name']}\n\n"
    if 'extra' in meta and 'helm' in meta['extra'] and 'description' in meta['extra']['helm']:
        index_content += f"{meta['extra']['helm']['description']}\n\n"

    # Add sources if available
    if 'extra' in meta and 'helm' in meta['extra'] and 'sources' in meta['extra']['helm']:
        sources = meta['extra']['helm']['sources'] or []
        if sources:
            index_content += "## Sources\n\n"
            for source in sources:
                index_content += f"- {source}\n"
            index_content += "\n"

    with open(index_path, "w", encoding="utf-8") as fh:
        fh.write(index_content)

    return path


# ──────────────────────────────── CLI ────────────────────────────────────────
# Global rules dictionary
rules_dict: Dict[int, Dict[str, Any]] = {}

def parse_rules_yaml(yaml_path: str) -> Dict[int, Dict[str, Any]]:
    """Parse the rules YAML file and return a dictionary with rule IDs as keys."""
    global rules_dict
    try:
        with open(yaml_path, encoding="utf-8") as fh:
            rules = yaml.safe_load(fh)

        # Convert list to dictionary with rule IDs as keys
        rules_dict = {rule['id']: rule for rule in rules}

        # Generate markdown files for each rule
        for rule_id, rule in rules_dict.items():
            content = f"---\n"
            content += f"title: \"{rule['name']}\"\n"
            content += f"description: \"{rule['description']}\"\n"
            content += f"category: {rule['category']}\n"
            content += f"risk_level: {rule['risk_level']}\n"
            content += f"date: \"\"\n"
            content += "---\n\n"

            content += "## Overview\n\n"
            # Add rule information in a table format
            content += "| Field | Value |\n"
            content += "|-------|-------|\n"
            content += f"| ID | {rule['id']} |\n"
            content += f"| Name | {rule['name']} |\n"
            content += f"| Risk Category | {rule['category']} |\n"
            risk_level = rule['risk_level'].replace('RiskLevel', '')
            content += f"| Risk Level | {{{{< risk {risk_level} >}}}} |\n"
            content += f"| Role Type | {rule['role_type']} |\n"
            api_groups = ['core' if group == '' else group for group in rule['api_groups']]
            content += f"| API Groups | {', '.join(api_groups)} |\n"
            content += f"| Resources | {', '.join(rule['resources'])} |\n"
            content += f"| Verbs | {', '.join(rule['verbs'])} |\n"
            tags_formatted = " ".join(["{{< tag \"" + tag + "\" >}}" for tag in sorted(rule['tags'])[:5]] +
                [(f"(+{len(rule['tags']) - 5} more)" if len(rule['tags']) > 5 else "")])
            content += f"| Tags | {tags_formatted} |\n\n"

            # Add description section
            content += "## Description\n\n"
            content += f"{rule['description']}\n"

            # Create rules directory if it doesn't exist
            rules_dir = os.path.join("content", "rules")
            os.makedirs(rules_dir, exist_ok=True)

            # Write the markdown file
            rule_file = os.path.join(rules_dir, f"{rule_id}.md")
            with open(rule_file, "w", encoding="utf-8") as f:
                f.write(content)

            print(f"Generated {rule_file}")

        return rules_dict
    except (IOError, yaml.YAMLError) as exc:
        raise Exception(f"Unable to read YAML file: {exc}")

def process_json_file(json_file: str, output_dir: str) -> None:
    """Process a single JSON file and generate its markdown."""
    try:
        with open(json_file, encoding="utf-8") as fh:
            data = json.load(fh)
        md = build_markdown(data)
        dest = write_markdown(md, data["metadata"], output_dir)
        print(f"Wrote {dest}")
    except (IOError, json.JSONDecodeError) as exc:
        print(f"Warning: Unable to process {json_file}: {exc}")

def main() -> None:
    ap = argparse.ArgumentParser(description="Convert JSON manifests to Hugo markdown")
    ap.add_argument(
        "-f", "--folder", required=True,
        help="Path to the folder containing JSON manifests"
    )
    ap.add_argument(
        "-r", "--rules",
        default="/home/alevsk/Development/rbac-ops/internal/policyevaluation/risks.yaml",
        help="Path to the rules YAML file"
    )
    ap.add_argument(
        "-o", "--output-dir", default=".",
        help="Site root (directory that contains 'content/')"
    )
    args = ap.parse_args()

    # First parse the rules YAML (only once)
    try:
        rules_dict = parse_rules_yaml(args.rules)
        print(f"Parsed {len(rules_dict)} rules from {args.rules}")
    except Exception as exc:
        ap.error(str(exc))

    # Process all JSON files in the specified folder
    if not os.path.isdir(args.folder):
        ap.error(f"Folder not found: {args.folder}")

    json_files = [f for f in os.listdir(args.folder) if f.endswith('.json')]
    if not json_files:
        ap.error(f"No JSON files found in {args.folder}")

    for json_file in json_files:
        full_path = os.path.join(args.folder, json_file)
        process_json_file(full_path, args.output_dir)


if __name__ == "__main__":
    main()
