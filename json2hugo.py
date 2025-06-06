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
from collections import Counter, defaultdict
from datetime import datetime
from typing import Any, Dict, List

# ───────────────────────────── Markdown helpers ──────────────────────────────
def h(level: int, text: str) -> str:
    return f'{"#" * level} {text}\n\n'


def bullet(text: str) -> str:
    return f"* {text}\n"


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
    sa_data   = sorted(data.get("serviceAccountData", []), key=lambda x: x.get("serviceAccountName", ""))
    risk_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    perms     = sorted(data.get("serviceAccountPermissions", []),
                  key=lambda x: (risk_order.get(x.get("riskLevel", ""), 4), x.get("roleName", "")))
    workloads = sorted(data.get("serviceAccountWorkloads", []),
                  key=lambda x: (x.get("workloadType", ""), x.get("workloadName", ""), x.get("containerName", "")))

    # index by SA
    perms_by_sa: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for p in perms:
        perms_by_sa[p["serviceAccountName"]].append(p)

    wl_by_sa: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for w in workloads:
        wl_by_sa[w["serviceAccountName"]].append(w)

    # Overview counts
    perm_counts = Counter(p["serviceAccountName"] for p in perms)
    wl_counts   = Counter(w["serviceAccountName"] for w in workloads)
    risk_counts = Counter(p["riskLevel"] for p in perms)

    # ── page header ──
    out = "---\n"
    out += f"title: {name}\n"
    out += f"description: {description}\n"
    if not version.startswith("v"):
        version = "v" + version
    out += f"version: {version}\n"
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
        categories = meta['extra']['helm']['keywords']
    out += f"categories: [{', '.join(categories)}]\n"

    # Extract and deduplicate tags from all service account permissions
    tags = set()
    for p in perms:
        perm_tags = p.get("tags", [])
        if perm_tags is not None:
            tags.update(perm_tags)

    out += f"tags: [{', '.join(sorted(tags))}]\n"
    out += "---\n\n"

    # ── Overview table ──
    out += h(2, "Overview")
    overview_rows = []
    for sa in sa_data:
        sa_name = sa["serviceAccountName"]
        anchor  = slug(sa_name)
        overview_rows.append([
            f"[`{sa_name or '—'}`](#{anchor})",
            sa["namespace"],
            "✅" if sa["automountToken"] else "❌",
            ", ".join(sa["secrets"] or []) or "—",
            str(perm_counts.get(sa_name, 0)),
            str(wl_counts.get(sa_name, 0)),
        ])
    out += table(
        ["ServiceAccount", "Namespace", "Automount", "Secrets",
         "Permissions", "Workloads"],
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

        header  = f"### `{sa_name or '—'}` {{#{anchor}}}\n"
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
        out += h(4, f"Permissions ({len(sa_perms)})").rstrip() + "\n"
        if sa_perms:
            # Sort permissions by risk level
            sorted_perms = sorted(sa_perms, key=lambda p: (risk_order.get(p["riskLevel"], 4), p["roleType"], p["roleName"]))
            perm_rows = [
                [
                    p["roleType"] + f" `{p['roleName']}`",
                    f"{p['apiGroup'] or 'core'}/{p['resource']}",
                    " · ".join(p["verbs"]),
                    p["riskLevel"],
                ]
                for p in sorted_perms
            ]
            out += table(["Role", "Resource", "Verbs", "Risk"], perm_rows)
        else:
            out += "_No explicit RBAC bindings._\n\n"

        # Workloads
        sa_wl = wl_by_sa[sa_name]
        out += h(4, f"Workloads ({len(sa_wl)})").rstrip() + "\n"
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
        index_content += "## Sources\n\n"
        for source in meta['extra']['helm']['sources']:
            index_content += f"* {source}\n"
        index_content += "\n"

    with open(index_path, "w", encoding="utf-8") as fh:
        fh.write(index_content)

    return path


# ──────────────────────────────── CLI ────────────────────────────────────────
def main() -> None:
    ap = argparse.ArgumentParser(description="Convert JSON to Hugo markdown")
    ap.add_argument("json_file", help="Path to the input JSON file")
    ap.add_argument(
        "-o", "--output-dir", default=".",
        help="Site root (directory that contains 'content/')"
    )
    args = ap.parse_args()

    try:
        with open(args.json_file, encoding="utf-8") as fh:
            data = json.load(fh)
    except (IOError, json.JSONDecodeError) as exc:
        ap.error(f"Unable to read JSON file: {exc}")

    md = build_markdown(data)
    dest = write_markdown(md, data["metadata"], args.output_dir)
    print(f"Wrote {dest}")


if __name__ == "__main__":
    main()
