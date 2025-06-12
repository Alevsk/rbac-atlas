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
from typing import Any, Dict, List, Optional

# ───────────────────────────── Constants ──────────────────────────────
# Order for sorting risk levels (lower number means higher risk)
RISK_ORDER: Dict[str, int] = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
# Default sort value for unknown risk levels, placing them at the end
DEFAULT_RISK_SORT_VALUE: int = 4
# Mapping from sorted risk value to display string
RISK_DISPLAY_MAP: Dict[int, str] = {
    0: "Critical",
    1: "High",
    2: "Medium",
    3: "Low",
    DEFAULT_RISK_SORT_VALUE: "—"
}
# Default API group for core resources when not specified
CORE_API_GROUP: str = "core"

# ───────────────────────────── Markdown helpers ──────────────────────────────
def h(level: int, text: str) -> str:
    """Generates a Markdown heading."""
    return f'{"#" * level} {text}\n\n'


def bullet(text: str) -> str:
    """Generates a Markdown bullet point."""
    return f"- {text}\n"


def table(headers: List[str], rows: List[List[str]]) -> str:
    """Generates a Markdown table."""
    header_line = "|" + "|".join(headers) + "|\n"
    separator_line = "|" + "|".join("---" for _ in headers) + "|\n"
    body_lines = "".join("|" + "|".join(row) + "|\n" for row in rows)
    return header_line + separator_line + body_lines + "\n"


def slug(text: str) -> str:
    """Turns a string into a stable anchor ID suitable for Markdown/HTML."""
    text = text or "none"
    # Replace non-alphanumeric characters with hyphens, convert to lowercase, and strip leading/trailing hyphens
    return "sa-" + re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")

def format_tags_for_markdown(tags: Optional[List[str]], max_display: int = 5) -> str:
    """
    Formats a list of tags into a Markdown string with Hugo shortcodes.
    Limits the number of displayed tags and adds a "(+X more)" if applicable.
    """
    if not tags:
        return ""
    sorted_tags = sorted(tags)
    displayed_tags = sorted_tags[:max_display]
    remaining_tags_count = len(sorted_tags) - max_display

    tag_shortcodes = [f"{{{{< tag \"{tag}\" >}}}}" for tag in displayed_tags]
    if remaining_tags_count > 0:
        tag_shortcodes.append(f"(+{remaining_tags_count} more)")
    return " ".join(tag_shortcodes)

def get_nested_value(data: Dict[str, Any], keys: List[str], default: Any = None) -> Any:
    """
    Safely retrieves a value from a nested dictionary using a list of keys.
    Returns the default value if any key in the path is not found or if an intermediate
    value is not a dictionary.
    """
    current = data
    for key in keys:
        if isinstance(current, dict) and key in current:
            current = current[key]
        else:
            return default
    return current

# ───────────────────────────── Conversion logic ──────────────────────────────
def build_markdown(data: Dict[str, Any], rules_data: Dict[int, Dict[str, Any]]) -> str:
    """
    Builds the Hugo-ready Markdown content from the parsed JSON data.

    Args:
        data: The parsed JSON data representing the knowledge base entry.
        rules_data: A dictionary of security rules, keyed by rule ID.

    Returns:
        A string containing the full Markdown content for the Hugo page.
    """
    meta = data["metadata"]
    name, version = meta["name"], meta["version"]

    description = get_nested_value(meta, ['extra', 'helm', 'description'], "")
    sources = get_nested_value(meta, ['extra', 'helm', 'sources'], [])
    categories = get_nested_value(meta, ['extra', 'helm', 'keywords'], []) or []

    perms = sorted(data.get("serviceAccountPermissions", []),
                   key=lambda x: (RISK_ORDER.get(x.get("riskLevel", ""), DEFAULT_RISK_SORT_VALUE),
                                  x.get("roleName", "")))
    workloads = sorted(data.get("serviceAccountWorkloads", []),
                       key=lambda x: (x.get("workloadType", ""), x.get("workloadName", ""), x.get("containerName", "")))

    # Index permissions and workloads by ServiceAccount name for easy lookup
    perms_by_sa: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for p in perms:
        perms_by_sa[p["serviceAccountName"]].append(p)

    wl_by_sa: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for w in workloads:
        wl_by_sa[w["serviceAccountName"]].append(w)

    def get_highest_risk_for_sa(sa_name: str) -> int:
        """Helper function to get the highest risk level (lowest sort value) for a service account."""
        risks = {p["riskLevel"] for p in perms_by_sa[sa_name]}
        return min((RISK_ORDER.get(r, DEFAULT_RISK_SORT_VALUE) for r in risks), default=DEFAULT_RISK_SORT_VALUE)

    # Sort service accounts for the overview table by highest risk first, then by name
    sa_data = sorted(data.get("serviceAccountData", []),
                     key=lambda x: (get_highest_risk_for_sa(x.get("serviceAccountName", "")),
                                    x.get("serviceAccountName", "")))

    # Calculate overview counts
    perm_counts = Counter(p["serviceAccountName"] for p in perms)
    wl_counts   = Counter(w["serviceAccountName"] for w in workloads)
    risk_counts = Counter(p["riskLevel"] for p in perms)

    # Extract and deduplicate tags from all service account permissions
    tags = set()
    for p in perms:
        perm_tags = p.get("tags", []) or []
        tags.update(perm_tags)

    # Add a tag based on the first letter of the application name
    letter = name[0].upper() if name else ""
    tags.add(f"letter-{letter}")

    def get_version_order(v: str) -> str:
        """
        Creates a semantic version order key suitable for Hugo's string sorting.
        Pads version parts with zeros and converts to hex for consistent length.
        The 'f' prefix ensures lexicographical sorting in Hugo.
        """
        v = v.lstrip('v')
        parts = v.split('.')
        # Pad with zeros if needed to ensure 3 parts (major.minor.patch)
        while len(parts) < 3:
            parts.append('0')
        try:
            major = int(parts[0])
            minor = int(parts[1])
            patch = int(parts[2])
            # Convert to hex with left padding to 4 characters for consistent length
            major_hex = f"{major:04x}"
            minor_hex = f"{minor:04x}"
            patch_hex = f"{patch:04x}"
            # Combine with 'f' prefix for Hugo's string sorting
            return f"f{major_hex}f{minor_hex}f{patch_hex}"
        except (ValueError, IndexError):
            # Fallback for invalid versions, ensures they sort consistently at the end
            return "f0000f0000f0000"

    # ── Page Header (YAML Front Matter) ──
    # Ensure version starts with 'v' for consistency in Hugo
    if not version.startswith("v"):
        version = "v" + version

    front_matter_lines = [
        "---",
        f"title: {name}",
        f"description: {description}",
        f"version: {version}",
        f"version_order: {get_version_order(version)}",
        "date: \"\"", # Keep as empty string as per original
        f"service_accounts: {len(perms_by_sa)}",
        f"workloads: {len(wl_by_sa)}",
        f"bindings: {len(perms)}",
        f"critical_findings: {risk_counts['Critical']}",
        f"high_findings: {risk_counts['High']}",
        f"medium_findings: {risk_counts['Medium']}",
        f"low_findings: {risk_counts['Low']}",
        f"categories: [{', '.join(categories)}]",
        f"tags: [{', '.join(sorted(tags))}]",
        "---",
        "" # For the extra newline after front matter
    ]
    out = "\n".join(front_matter_lines)

    # ── Description Section ──
    out += h(2, "Description")
    out += description + "\n\n"

    # Add sources if available
    if sources:
        for source in sources:
            out += bullet(source)
        out += "\n"

    # ── Overview Table Section ──
    out += h(2, "Overview")
    overview_rows = []
    for sa in sa_data:
        sa_name = sa["serviceAccountName"]
        anchor  = slug(sa_name)
        highest_risk_val = get_highest_risk_for_sa(sa_name)
        risk_display = RISK_DISPLAY_MAP[highest_risk_val]
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

    # ── Per-identity Sections ──
    out += h(2, "Identities")

    def sort_sa_identities_key(sa: Dict[str, Any]) -> tuple:
        """
        Sort key for service accounts in the identities section:
        highest risk first, then by descending permission count, then by name.
        """
        top_risk = get_highest_risk_for_sa(sa["serviceAccountName"])
        return (top_risk,
                -perm_counts.get(sa["serviceAccountName"], 0), # Descending by permission count
                sa["serviceAccountName"]) # Ascending by name

    for sa in sorted(sa_data, key=sort_sa_identities_key):
        sa_name = sa["serviceAccountName"]
        anchor  = slug(sa_name)

        # Identity header
        header_parts = [
            f"### 🤖 `{sa_name or '—'}` {{#{anchor}}}\n",
            f"**Namespace:** `{sa['namespace']}`  |  "
            f"**Automount:** {'✅' if sa['automountToken'] else '❌'}"
        ]
        secrets = ", ".join(sa["secrets"] or [])
        if secrets:
            header_parts.append(f"  |  **Secrets:** {secrets}")
        out += " ".join(header_parts) + "\n\n" # Join parts and add final newlines

        # Permissions section
        sa_perms = perms_by_sa[sa_name]
        out += h(4, f"🔑 Permissions ({len(sa_perms)})").rstrip() + "\n"
        if sa_perms:
            # Sort permissions by risk level, then resource, apiGroup, roleType, roleName
            sorted_perms = sorted(sa_perms, key=lambda p: (
                RISK_ORDER.get(p["riskLevel"], DEFAULT_RISK_SORT_VALUE),
                p["resource"],
                p["apiGroup"] or CORE_API_GROUP,
                p["roleType"],
                p["roleName"]
            ))
            perm_rows = [
                [
                    f"{p['roleType']} `{p['roleName']}`",
                    f"{p['apiGroup'] or CORE_API_GROUP}/{p['resource']}",
                    " · ".join(p["verbs"]),
                    f"{{{{< risk {p['riskLevel']} >}}}}",
                    format_tags_for_markdown(p.get("tags"))
                ]
                for p in sorted_perms
            ]
            out += table(["Role", "Resource", "Verbs", "Risk", "Tags"], perm_rows)
        else:
            out += "_No explicit RBAC bindings._\n\n"

        # Potential Abuse section
        if sa_perms:
            # Collect all unique rule IDs from all permissions
            all_risk_rules = set()
            for perm in sa_perms:
                risk_rules = perm.get('riskRules', [])
                all_risk_rules.update(risk_rules)

            if all_risk_rules:
                out += h(4, f"⚠️ Potential Abuse ({len(all_risk_rules)})").rstrip() + "\n"
                out += "The following security risks were found based on the above permissions:\n\n"
                for rule_id in sorted(all_risk_rules):
                    if rule_id in rules_data: # Use passed rules_data
                        rule = rules_data[rule_id]
                        out += f"- [{rule['name']}](/rules/{rule_id})\n"
                out += "\n"

        # Workloads section
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
def write_markdown(markdown_content: str, meta_data: Dict[str, Any], output_dir: str) -> str:
    """
    Writes the generated Markdown content for an application to a file
    and creates an _index.md file in the application's directory.

    Args:
        markdown_content: The main Markdown content for the application page.
        meta_data: The metadata dictionary from the JSON input.
        output_dir: The base output directory (site root).

    Returns:
        The full path to the generated main Markdown file.
    """
    # Path for the main markdown file (e.g., content/app-name/v1.0.0.md)
    file_path = os.path.join(
        output_dir, "charts", meta_data["name"], f"{meta_data['version']}.md"
    )
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, "w", encoding="utf-8") as fh:
        fh.write(markdown_content)

    # Create _index.md file with metadata inside the folder_path
    folder_path = os.path.join(output_dir, "charts", meta_data["name"])
    index_path = os.path.join(folder_path, "_index.md")

    index_description = get_nested_value(meta_data, ['extra', 'helm', 'description'], "")
    index_sources = get_nested_value(meta_data, ['extra', 'helm', 'sources'], [])

    index_front_matter_lines = [
        "---",
        f"title: {meta_data['name']}",
        f"description: {index_description}",
        "---",
        "" # For the extra newline
    ]
    index_content = "\n".join(index_front_matter_lines)

    # Add title and description to the body of _index.md
    index_content += f"## {meta_data['name']}\n\n"
    if index_description:
        index_content += f"{index_description}\n\n"

    # Add sources if available
    if index_sources:
        index_content += "## Sources\n\n"
        for source in index_sources:
            index_content += f"- {source}\n"
        index_content += "\n"

    with open(index_path, "w", encoding="utf-8") as fh:
        fh.write(index_content)

    return file_path


# ──────────────────────────────── CLI ────────────────────────────────────────
def parse_rules_yaml(yaml_path: str) -> Dict[int, Dict[str, Any]]:
    """
    Parses the rules YAML file and returns a dictionary with rule IDs as keys.
    This function is solely responsible for parsing; it does not generate files.

    Args:
        yaml_path: The file path to the rules YAML.

    Returns:
        A dictionary where keys are rule IDs (int) and values are rule dictionaries.

    Raises:
        Exception: If the YAML file cannot be read or parsed.
    """
    try:
        with open(yaml_path, encoding="utf-8") as fh:
            rules_list = yaml.safe_load(fh)
        # Convert list of rules to a dictionary with rule IDs as keys
        return {rule['id']: rule for rule in rules_list}
    except (IOError, yaml.YAMLError) as exc:
        raise Exception(f"Error reading or parsing rules YAML file '{yaml_path}': {exc}")

def generate_rule_markdown_files(rules_data: Dict[int, Dict[str, Any]], output_dir: str) -> None:
    """
    Generates Markdown files for each rule in the provided rules data.
    These files are typically placed under 'content/rules/'.

    Args:
        rules_data: A dictionary of security rules, keyed by rule ID.
        output_dir: The base output directory (site root).
    """
    rules_dir = os.path.join(output_dir, "rules")
    os.makedirs(rules_dir, exist_ok=True)

    for rule_id, rule in rules_data.items():
        # Front matter for the rule page
        front_matter_lines = [
            "---",
            f"id: {rule['id']}",
            f"title: \"{rule['name']}\"",
            f"description: \"{rule['description']}\"",
            f"category: {rule['category']}",
            f"risk_level: {rule['risk_level']}",
            "date: \"\"", # Keep as empty string as per original
            "---",
            "" # For the extra newline
        ]
        content = "\n".join(front_matter_lines)

        # Overview section for the rule
        content += "## Overview\n\n"
        content += "| Field | Value |\n"
        content += "|-------|-------|\n"
        content += f"| ID | {rule['id']} |\n"
        content += f"| Name | {rule['name']} |\n"
        content += f"| Risk Category | {rule['category']} |\n"
        risk_level_display = rule['risk_level'].replace('RiskLevel', '') # Remove 'RiskLevel' prefix
        content += f"| Risk Level | {{{{< risk {risk_level_display} >}}}} |\n"
        content += f"| Role Type | {rule['role_type']} |\n"
        api_groups_formatted = [CORE_API_GROUP if group == '' else group for group in rule['api_groups']]
        content += f"| API Groups | {', '.join(api_groups_formatted)} |\n"
        content += f"| Resources | {', '.join(rule['resources'])} |\n"
        content += f"| Verbs | {', '.join(rule['verbs'])} |\n"
        content += f"| Tags | {format_tags_for_markdown(rule.get('tags'))} |\n\n"

        # Description section for the rule
        content += "## Description\n\n"
        content += f"{rule['description']}\n"

        content += "## Abuse Scenarios\n\n"

        # Add commands section if available
        if 'commands' in rule:
            for i, cmd in enumerate(rule['commands'], 1):
                if 'description' in cmd:
                    content += f"{i}. {cmd['description']}\n\n"
                if 'command' in cmd:
                    # Use Hugo's built-in copy button functionality with ```bash {copy=true}
                    content += f"```bash {{copy=true}}\n{cmd['command']}\n```\n\n"

        # Write the markdown file for the rule
        rule_file_path = os.path.join(rules_dir, f"{rule_id}.md")
        with open(rule_file_path, "w", encoding="utf-8") as f:
            f.write(content)

        print(f"Generated rule file: {rule_file_path}")

def process_json_file(json_file_path: str, output_dir: str, rules_data: Dict[int, Dict[str, Any]]) -> None:
    """
    Processes a single JSON file, generates its markdown content, and writes it to disk.

    Args:
        json_file_path: The full path to the JSON input file.
        output_dir: The base output directory (site root).
        rules_data: A dictionary of security rules, keyed by rule ID.
    """
    try:
        with open(json_file_path, encoding="utf-8") as fh:
            data = json.load(fh)
        markdown_content = build_markdown(data, rules_data)
        destination_path = write_markdown(markdown_content, data["metadata"], output_dir)
        print(f"Wrote application markdown: {destination_path}")
    except (IOError, json.JSONDecodeError) as exc:
        print(f"Warning: Unable to process JSON file '{json_file_path}': {exc}")
    except KeyError as exc:
        print(f"Warning: Missing expected key in JSON data for '{json_file_path}': {exc}")


def main() -> None:
    """
    Main function to parse command-line arguments and orchestrate the
    conversion process from JSON manifests to Hugo Markdown pages.
    """
    ap = argparse.ArgumentParser(
        description="Convert JSON manifests to Hugo markdown pages for a knowledge base."
    )
    ap.add_argument(
        "-f", "--folder", required=True,
        help="Path to the folder containing JSON manifests to convert."
    )
    ap.add_argument(
        "-r", "--rules",
        default="/home/alevsk/Development/rbac-ops/internal/policyevaluation/risks.yaml",
        help="Path to the rules YAML file (e.g., risks.yaml)."
    )
    ap.add_argument(
        "-o", "--output-dir", default="content",
        help="Site root directory (e.g., the directory that contains 'content/')."
    )
    args = ap.parse_args()

    # 1. Parse the rules YAML file
    try:
        rules_data = parse_rules_yaml(args.rules)
        print(f"Parsed {len(rules_data)} rules from '{args.rules}'.")
    except Exception as exc:
        ap.error(str(exc))

    # 2. Generate markdown files for each rule
    try:
        generate_rule_markdown_files(rules_data, args.output_dir)
    except Exception as exc:
        ap.error(f"Error generating rule markdown files: {exc}")

    # 3. Process all JSON files in the specified folder
    if not os.path.isdir(args.folder):
        ap.error(f"Input folder not found: '{args.folder}'")

    json_files = [f for f in os.listdir(args.folder) if f.endswith('.json')]
    if not json_files:
        ap.error(f"No JSON files found in '{args.folder}'.")

    for json_file_name in json_files:
        full_path = os.path.join(args.folder, json_file_name)
        process_json_file(full_path, args.output_dir, rules_data)


if __name__ == "__main__":
    main()
