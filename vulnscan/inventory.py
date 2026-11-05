"""Stage 1: inventory container images of the latest version of every chart.

Reads rbac-scope manifests (manifests/<org>__<chart>__<version>.json), picks the latest
version per chart, normalizes every workload image and writes INVENTORY_FILE.

    python -m vulnscan.inventory [--manifests manifests] [--output vulns/out/inventory.json]
"""

from __future__ import annotations

import argparse
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable

from vulnscan.common import INVENTORY_FILE, RBAC_RISK_ORDER, log, read_json, utcnow, write_json
from vulnscan.imageref import normalize

TEST_WORKLOAD_TYPES = {"Pod", "Job"}
_TOKEN_SPLIT_RE = re.compile(r"[^a-z0-9]+")
_VERSION_RE = re.compile(r"^v?(?P<nums>[0-9]+(?:\.[0-9]+)*)(?P<pre>-[^+]*)?(?:\+(?P<build>.*))?$")


def parse_manifest_name(path: Path) -> tuple[str, str, str] | None:
    """Split '<org>__<chart>__<version>.json' into (org, chart, version); None if malformed."""
    if path.suffix != ".json":
        return None
    parts = path.stem.split("__")
    if len(parts) != 3 or not all(parts):
        return None
    return parts[0], parts[1], parts[2]


def is_prerelease(version: str) -> bool:
    """True when a '-' follows the numeric part (1.2.0-rc1); build metadata (+521) is not a prerelease."""
    m = _VERSION_RE.match(version)
    if m:
        return m.group("pre") is not None
    return "-" in version.split("+", 1)[0]


def _ident_key(ident: str) -> tuple[int, int, str]:
    # semver: numeric identifiers sort numerically and before alphanumeric ones
    return (0, int(ident), "") if ident.isdigit() else (1, 0, ident)


def version_key(version: str) -> tuple:
    """Sort key approximating semver precedence; unparseable versions sort lowest."""
    m = _VERSION_RE.match(version)
    if not m:
        return (0, (), 0, (), version)
    nums = tuple(int(n) for n in m.group("nums").split("."))
    # pad so 1.2 == 1.2.0 numerically
    nums = nums + (0,) * max(0, 3 - len(nums))
    pre = m.group("pre")
    pre_key = tuple(_ident_key(i) for i in pre[1:].split(".")) if pre else ()
    return (1, nums, 0 if pre else 1, pre_key, version)


def latest_versions(paths: Iterable[Path]) -> dict[tuple[str, str], tuple[str, Path]]:
    """Map (org, chart) -> (version, path) of the latest non-prerelease version.

    Prereleases are only chosen when a chart has no stable version at all.
    """
    grouped: dict[tuple[str, str], list[tuple[str, Path]]] = defaultdict(list)
    for path in paths:
        parsed = parse_manifest_name(path)
        if parsed:
            org, chart, version = parsed
            grouped[(org, chart)].append((version, path))
    result = {}
    for key, versions in grouped.items():
        stable = [v for v in versions if not is_prerelease(v[0])]
        candidates = stable or versions
        result[key] = max(candidates, key=lambda v: version_key(v[0]))
    return result


def is_test_workload(workload: dict[str, Any]) -> bool:
    """Pod/Job whose workload or container name contains 'test' as a token (e.g. 'x-test-connection')."""
    if workload.get("workloadType") not in TEST_WORKLOAD_TYPES:
        return False
    for field in ("workloadName", "containerName"):
        tokens = _TOKEN_SPLIT_RE.split(str(workload.get(field) or "").lower())
        if "test" in tokens:
            return True
    return False


def sa_risk_index(permissions: Iterable[dict[str, Any]]) -> dict[tuple[str, str], int]:
    """Map (serviceAccountName, namespace) -> most severe RBAC_RISK_ORDER value."""
    index: dict[tuple[str, str], int] = {}
    for perm in permissions or []:
        name = perm.get("serviceAccountName") or ""
        order = RBAC_RISK_ORDER.get(perm.get("riskLevel"))
        if not name or order is None:
            continue
        key = (name, perm.get("namespace") or "")
        index[key] = min(order, index.get(key, order))
    return index


def sa_rbac_risk(index: dict[tuple[str, str], int], name: str, namespace: str) -> str | None:
    """Most severe risk level for a service account; namespaces must match when both are set."""
    if not name:
        return None
    best = None
    for (sa, ns), order in index.items():
        if sa != name or (namespace and ns and ns != namespace):
            continue
        best = order if best is None else min(best, order)
    if best is None:
        return None
    return next(level for level, o in RBAC_RISK_ORDER.items() if o == best)


def chart_images(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    """Group a manifest's workloads by raw image ref, with role and SA risk per workload."""
    index = sa_risk_index(manifest.get("serviceAccountPermissions") or [])
    by_ref: dict[str, dict[str, Any]] = {}
    for wl in manifest.get("serviceAccountWorkloads") or []:
        raw = wl.get("image")
        raw = raw if isinstance(raw, str) else ""
        sa = wl.get("serviceAccountName") or ""
        ns = wl.get("namespace") or ""
        role = "test" if is_test_workload(wl) else "main"
        entry = by_ref.get(raw)
        if entry is None:
            norm = normalize(raw)
            entry = by_ref[raw] = {
                "ref": raw,
                "canonical": norm["canonical"],
                "reason": norm["reason"],
                "role": role,
                "workloads": [],
                "_norm": norm,
            }
        if role == "main":
            entry["role"] = "main"  # an image used by any non-test workload is main
        entry["workloads"].append(
            {
                "serviceAccountName": sa,
                "namespace": ns,
                "workloadType": wl.get("workloadType") or "",
                "workloadName": wl.get("workloadName") or "",
                "containerName": wl.get("containerName") or "",
                "role": role,
                "sa_rbac_risk": sa_rbac_risk(index, sa, ns),
            }
        )
    return list(by_ref.values())


def build_inventory(manifests_dir: Path) -> dict[str, Any]:
    """Build the inventory document for the latest version of every chart in manifests_dir."""
    paths = sorted(manifests_dir.glob("*.json"))
    latest = latest_versions(paths)

    charts: list[dict[str, Any]] = []
    images: dict[str, dict[str, Any]] = {}
    invalid: list[dict[str, Any]] = []
    stats: Counter = Counter()
    unreadable: list[str] = []

    for (org, name), (version, path) in sorted(latest.items()):
        manifest = read_json(path)
        if not isinstance(manifest, dict):
            unreadable.append(path.name)
            continue
        chart_id = f"{org}/{name}"
        chart_ref = f"{chart_id}@{version}"
        if is_prerelease(version):
            stats["prerelease_selected"] += 1
        entries = chart_images(manifest)
        stats["workloads"] += sum(len(e["workloads"]) for e in entries)
        if not entries:
            stats["charts_without_images"] += 1
        for entry in entries:
            norm = entry.pop("_norm")
            reason = entry["reason"]
            if entry["canonical"] is None:
                invalid.append({"ref": entry["ref"], "reason": reason, "chart": chart_ref})
                continue
            img = images.setdefault(
                entry["canonical"],
                {
                    "registry": norm["registry"],
                    "repository": norm["repository"],
                    "tag": norm["tag"],
                    "digest": norm["digest"],
                    "flags": norm["flags"],
                    "charts": [],
                    "roles": [],
                    "refs": [],
                },
            )
            if chart_ref not in img["charts"]:
                img["charts"].append(chart_ref)
            if entry["role"] not in img["roles"]:
                img["roles"].append(entry["role"])
            if entry["ref"] not in img["refs"]:
                img["refs"].append(entry["ref"])
        charts.append(
            {
                "chart": chart_id,
                "org": org,
                "name": name,
                "version": version,
                "manifest": f"{manifests_dir.name}/{path.name}",
                "images": entries,
            }
        )

    for img in images.values():
        img["charts"].sort()
        img["roles"].sort()
        img["refs"].sort()

    flag_counts = Counter(flag for img in images.values() for flag in img["flags"])
    stats_out: dict[str, Any] = {
        "manifests": len(paths),
        "charts": len(charts),
        "unreadable_manifests": unreadable,
        "image_refs": sum(len(c["images"]) for c in charts),
        "unique_images": len(images),
        "test_only_images": sum(1 for img in images.values() if img["roles"] == ["test"]),
        "test_role_refs": sum(1 for c in charts for e in c["images"] if e["role"] == "test"),
        "invalid": len(invalid),
        "invalid_by_reason": dict(sorted(Counter(i["reason"] for i in invalid).items())),
        "flags": dict(sorted(flag_counts.items())),
        "registries": dict(Counter(img["registry"] for img in images.values()).most_common()),
        "workloads": stats["workloads"],
        "charts_without_images": stats["charts_without_images"],
        "prerelease_selected": stats["prerelease_selected"],
    }
    return {
        "generated_at": utcnow(),
        "scope": "latest",
        "charts": charts,
        "images": dict(sorted(images.items())),
        "invalid": invalid,
        "stats": stats_out,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Inventory images of the latest version of every chart.")
    parser.add_argument("--manifests", type=Path, default=Path("manifests"), help="rbac-scope manifests directory")
    parser.add_argument("--output", type=Path, default=INVENTORY_FILE, help="inventory.json path")
    args = parser.parse_args(argv)

    if not args.manifests.is_dir():
        parser.error(f"manifests directory not found: {args.manifests}")
    inventory = build_inventory(args.manifests)
    write_json(args.output, inventory)
    s = inventory["stats"]
    log(
        f"inventory: {s['charts']} charts, {s['image_refs']} image refs, {s['unique_images']} unique images, "
        f"{s['invalid']} invalid {s['invalid_by_reason']}, flags {s['flags']} -> {args.output}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
