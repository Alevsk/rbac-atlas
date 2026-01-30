import argparse
import json
import logging
import re
import sys
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import List

# --- Configuration Constants ---
DEFAULT_CHARTS_DIR = "charts"
DEFAULT_MANIFESTS_DIR = "manifests"

# --- Setup Logging ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


def _parse_chart_key(name: str) -> tuple:
    """
    Split a chart directory or manifest stem like 'repo__chart__1.2.3'
    into ('repo__chart', '1.2.3').  The family key is everything up to
    the last '__' separator.
    """
    idx = name.rfind("__")
    if idx == -1:
        return (name, "")
    return (name[:idx], name[idx + 2:])


def _version_sort_key(version: str) -> List:
    """
    Best-effort numeric sort key for semver-like strings so that
    '2.10.0' sorts after '2.9.0'.  Non-numeric segments sort lexically.
    """
    parts = re.split(r'[.\-+]', version)
    key = []
    for p in parts:
        if p.isdigit():
            key.append((0, int(p)))
        else:
            key.append((1, p))
    return key


def _pick_latest_per_family(paths, path_to_name_fn) -> list:
    """
    Group *paths* by chart family (repo__chart) and return only the
    entry with the highest version in each family.

    *path_to_name_fn* converts a path to the name string to parse
    (e.g. Path.stem or str).
    """
    families: dict = defaultdict(list)
    for p in paths:
        family, version = _parse_chart_key(path_to_name_fn(p))
        families[family].append((version, p))

    result = []
    for family in sorted(families):
        entries = families[family]
        entries.sort(key=lambda e: _version_sort_key(e[0]), reverse=True)
        result.append(entries[0][1])
    return result


def _check_manifest(manifest_path: Path) -> dict:
    """
    Validate a single manifest file. Returns a result dict with the path,
    status ('valid', 'invalid', or 'empty'), and an optional error message.
    """
    try:
        content = manifest_path.read_text(encoding="utf-8")
        if not content.strip():
            return {"path": str(manifest_path), "status": "invalid", "error": "file is empty"}
        json.loads(content)
        return {"path": str(manifest_path), "status": "valid"}
    except json.JSONDecodeError as e:
        return {"path": str(manifest_path), "status": "invalid", "error": str(e)}
    except OSError as e:
        return {"path": str(manifest_path), "status": "invalid", "error": str(e)}


def main():
    parser = argparse.ArgumentParser(
        description="Check for missing or invalid JSON manifests relative to pulled Helm charts."
    )
    parser.add_argument(
        "--charts-dir", default=DEFAULT_CHARTS_DIR,
        help=f"Directory containing pulled chart folders (default: {DEFAULT_CHARTS_DIR})."
    )
    parser.add_argument(
        "--manifests-dir", default=DEFAULT_MANIFESTS_DIR,
        help=f"Directory containing JSON manifests (default: {DEFAULT_MANIFESTS_DIR})."
    )
    parser.add_argument(
        "--max-workers", type=int, default=16,
        help="Max concurrent JSON validation workers (default: 16)."
    )
    parser.add_argument(
        "--summary", action="store_true", default=False,
        help="Only print the latest version per chart family for each category."
    )
    args = parser.parse_args()

    charts_dir = Path(args.charts_dir)
    manifests_dir = Path(args.manifests_dir)

    if not charts_dir.is_dir():
        logger.critical(f"Charts directory not found: {charts_dir}")
        sys.exit(1)

    # --- Step 1: Discover chart directories and expected manifests ---
    chart_dirs = sorted(
        p for p in charts_dir.iterdir()
        if p.is_dir() and "__" in p.name
    )
    total_charts = len(chart_dirs)
    logger.info(f"Found {total_charts} chart directories in '{charts_dir}'.")

    # Build expected manifest paths from chart directories
    expected_manifests = {
        d.name: manifests_dir / f"{d.name}.json" for d in chart_dirs
    }

    missing = []
    existing_from_charts = []
    for name, manifest_path in expected_manifests.items():
        if manifest_path.is_file():
            existing_from_charts.append(manifest_path)
        else:
            missing.append(manifest_path)

    # --- Step 2: Discover ALL manifest files on disk (catches orphans) ---
    all_manifest_files = sorted(manifests_dir.glob("*.json")) if manifests_dir.is_dir() else []
    total_manifests = len(all_manifest_files)
    logger.info(f"Found {total_manifests} manifest files in '{manifests_dir}'.")

    # Orphan manifests: exist on disk but have no matching chart directory
    chart_names = {d.name for d in chart_dirs}
    orphan_manifests = [
        m for m in all_manifest_files if m.stem not in chart_names
    ]

    # --- Step 3: Validate all manifest files concurrently ---
    logger.info(f"Validating {total_manifests} manifest files (max workers: {args.max_workers})...")
    invalid = []
    with ThreadPoolExecutor(max_workers=args.max_workers) as executor:
        futures = {
            executor.submit(_check_manifest, m): m for m in all_manifest_files
        }
        for future in as_completed(futures):
            result = future.result()
            if result["status"] == "invalid":
                invalid.append(result)

    # --- Step 4: Report ---
    display_missing = missing
    display_invalid = invalid
    display_orphans = orphan_manifests

    if args.summary:
        display_missing = _pick_latest_per_family(missing, lambda p: p.stem)
        display_invalid = _pick_latest_per_family(
            invalid, lambda r: Path(r["path"]).stem
        )
        display_orphans = _pick_latest_per_family(orphan_manifests, lambda p: p.stem)

    if display_missing:
        label = "families" if args.summary else "manifests"
        logger.info("")
        logger.info(f"--- MISSING {label} ({len(display_missing)}) ---")
        for p in sorted(display_missing):
            print(f"  MISSING: {p}")

    if display_invalid:
        label = "families" if args.summary else "manifests"
        logger.info("")
        logger.info(f"--- INVALID {label} ({len(display_invalid)}) ---")
        for r in sorted(display_invalid, key=lambda r: r["path"] if isinstance(r, dict) else str(r)):
            if isinstance(r, dict):
                print(f"  INVALID: {r['path']}  ({r['error']})")
            else:
                print(f"  INVALID: {r}")

    if display_orphans:
        label = "families" if args.summary else "manifests"
        logger.info("")
        logger.info(f"--- ORPHAN {label} ({len(display_orphans)}) — no matching chart directory ---")
        for p in sorted(display_orphans):
            print(f"  ORPHAN: {p}")

    valid_count = total_manifests - len(invalid)
    print("")
    print("=" * 60)
    print(f"  Total chart directories:    {total_charts}")
    print(f"  Total manifest files:       {total_manifests}")
    print(f"  Valid manifests:            {valid_count}")
    print(f"  Invalid manifests:          {len(invalid)}")
    print(f"  Missing manifests:          {len(missing)}")
    print(f"  Orphan manifests:           {len(orphan_manifests)}")
    print("=" * 60)

    if invalid:
        sys.exit(1)


if __name__ == "__main__":
    main()
