"""Stage 1: inventory container images of chart versions.

Reads rbac-scope manifests (manifests/<org>__<chart>__<version>.json), normalizes every workload
image and writes INVENTORY_FILE. Scopes (every entry carries 'latest': true|false):

  latest   only the latest version of every chart
  forward  the latest version of every chart, every version whose manifest metadata.timestamp
           (epoch seconds: when the daily job generated the manifest, i.e. first seen) is on or after
           --since YYYY-MM-DD (UTC), and the version that was the chart's latest at the cutoff (the
           pick_latest of its versions first seen before it). Together that is every version that was
           the latest at any time on/after --since, so a version never drops out of scope (and its
           published data is never pruned) when a newer one replaces it as the latest. Stateless and
           deterministic; adds at most one version per chart. Non-latest versions without a usable
           timestamp are left out.
  all      every version (backfill)

Every image gets a scan 'priority': 0 when a latest version uses it, otherwise 1 + the rank of the
newest selected non-latest version using it (newest first within its chart). Lower is scanned first.

    python -m vulnscan.inventory [--manifests manifests] [--scope latest|forward|all] [--since YYYY-MM-DD]
                                 [--output vulns/out/inventory.json]
"""

from __future__ import annotations

import argparse
import datetime as _dt
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable

from vulnscan.common import INVENTORY_FILE, RBAC_RISK_ORDER, log, read_json, utcnow, write_json
from vulnscan.imageref import normalize

SCOPES = ("latest", "forward", "all")
TEST_WORKLOAD_TYPES = {"Pod", "Job"}
_TOKEN_SPLIT_RE = re.compile(r"[^a-z0-9]+")
_VERSION_RE = re.compile(r"^v?(?P<nums>[0-9]+(?:\.[0-9]+)*)(?P<pre>-[^+]*)?(?:\+(?P<build>.*))?$")


def parse_since(value: str) -> _dt.date:
    """Parse a YYYY-MM-DD cutoff date (argparse type)."""
    if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", value or ""):
        raise argparse.ArgumentTypeError(f"invalid date {value!r} (expected YYYY-MM-DD)")
    try:
        return _dt.date.fromisoformat(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid date {value!r}: {exc}") from None


def manifest_timestamp(manifest: dict[str, Any]) -> float | None:
    """metadata.timestamp as epoch seconds, or None when missing or not a positive number."""
    value = (manifest.get("metadata") or {}).get("timestamp")
    if isinstance(value, bool):
        return None
    try:
        ts = float(value)
    except (TypeError, ValueError):
        return None
    return ts if ts > 0 else None


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


def group_versions(paths: Iterable[Path]) -> dict[tuple[str, str], list[tuple[str, Path]]]:
    """Map (org, chart) -> [(version, path)] sorted newest first."""
    grouped: dict[tuple[str, str], list[tuple[str, Path]]] = defaultdict(list)
    for path in paths:
        parsed = parse_manifest_name(path)
        if parsed:
            org, chart, version = parsed
            grouped[(org, chart)].append((version, path))
    for versions in grouped.values():
        versions.sort(key=lambda v: version_key(v[0]), reverse=True)
    return dict(grouped)


def pick_latest(versions: list[tuple[str, Path]]) -> tuple[str, Path]:
    """Latest non-prerelease version; prereleases are only chosen when there is no stable version."""
    stable = [v for v in versions if not is_prerelease(v[0])]
    return max(stable or versions, key=lambda v: version_key(v[0]))


def latest_versions(paths: Iterable[Path]) -> dict[tuple[str, str], tuple[str, Path]]:
    """Map (org, chart) -> (version, path) of the latest version (see pick_latest)."""
    return {key: pick_latest(versions) for key, versions in group_versions(paths).items()}


def page_version(manifest: dict[str, Any], fallback: str) -> str:
    """Version used in the Hugo page filename (json2hugo: metadata.version without a leading 'v')."""
    version = (manifest.get("metadata") or {}).get("version")
    version = version if isinstance(version, str) and version else fallback
    return version[1:] if version.startswith("v") else version


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
    """Most severe risk level for a service account.

    Prefers permissions whose namespace matches the workload's (or is unset). When none match, falls
    back to every permission of that SA name, as json2hugo groups the page's SA risk by name only.
    """
    if not name:
        return None
    matched = None
    any_ns = None
    for (sa, ns), order in index.items():
        if sa != name:
            continue
        any_ns = order if any_ns is None else min(any_ns, order)
        if namespace and ns and ns != namespace:
            continue
        matched = order if matched is None else min(matched, order)
    best = matched if matched is not None else any_ns
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


def build_inventory(manifests_dir: Path, scope: str = "latest", since: _dt.date | None = None) -> dict[str, Any]:
    """Build the inventory document for the chart versions of a scope (see the module docstring)."""
    if scope not in SCOPES:
        raise ValueError(f"unknown scope: {scope}")
    if scope == "forward" and since is None:
        raise ValueError("scope 'forward' requires a since date")
    since_ts = (_dt.datetime.combine(since, _dt.time(), tzinfo=_dt.timezone.utc).timestamp()
                if scope == "forward" and since is not None else None)
    paths = sorted(manifests_dir.glob("*.json"))
    grouped = group_versions(paths)

    charts: list[dict[str, Any]] = []
    images: dict[str, dict[str, Any]] = {}
    invalid: list[dict[str, Any]] = []
    stats: Counter = Counter()
    unreadable: list[str] = []
    page_owner: dict[str, dict[str, Any]] = {}

    for (org, name), versions in sorted(grouped.items()):
        latest = pick_latest(versions)
        candidates = [latest] if scope == "latest" else [latest] + [v for v in versions if v != latest]
        chart_id = f"{org}/{name}"
        manifests = {}
        anchor = None  # scope forward: the version that was the latest at the cutoff
        if since_ts is not None:
            for version, path in candidates:
                manifests[path] = read_json(path)
            before = [(v, p) for v, p in versions if isinstance(manifests[p], dict)
                      and (ts := manifest_timestamp(manifests[p])) is not None and ts < since_ts]
            anchor = pick_latest(before) if before else None
        rank = 0  # 0 for the latest version, then 1, 2, ... for the selected others, newest first
        for version, path in candidates:
            manifest = manifests[path] if path in manifests else read_json(path)
            if not isinstance(manifest, dict):
                unreadable.append(path.name)
                continue
            is_latest = (version, path) == latest
            is_anchor = not is_latest and (version, path) == anchor
            if not is_latest and not is_anchor and since_ts is not None:
                ts = manifest_timestamp(manifest)
                if ts is None:
                    stats["versions_without_timestamp"] += 1
                    continue
                if ts < since_ts:
                    stats["versions_before_since"] += 1
                    continue
            if not is_latest:
                rank += 1
                stats["versions_latest_at_since" if is_anchor else "versions_since"] += 1
            chart_ref = f"{chart_id}@{version}"
            if is_latest and is_prerelease(version):
                stats["prerelease_selected"] += 1
            pversion = page_version(manifest, version)
            key = f"{chart_id}/{pversion}"
            entries = chart_images(manifest)
            stats["workloads"] += sum(len(e["workloads"]) for e in entries)
            if not entries:
                stats["charts_without_images"] += 1
            for entry in entries:
                norm = entry.pop("_norm")
                if entry["canonical"] is None:
                    invalid.append({"ref": entry["ref"], "reason": entry["reason"], "chart": chart_ref})
                    continue
                img = images.setdefault(
                    entry["canonical"],
                    {
                        "registry": norm["registry"],
                        "repository": norm["repository"],
                        "tag": norm["tag"],
                        "digest": norm["digest"],
                        "flags": norm["flags"],
                        "priority": rank,
                        "charts": [],
                        "roles": [],
                        "refs": [],
                    },
                )
                img["priority"] = min(img["priority"], rank)
                if chart_ref not in img["charts"]:
                    img["charts"].append(chart_ref)
                if entry["role"] not in img["roles"]:
                    img["roles"].append(entry["role"])
                if entry["ref"] not in img["refs"]:
                    img["refs"].append(entry["ref"])
            record = {
                "chart": chart_id,
                "org": org,
                "name": name,
                "version": version,
                "page_version": pversion,
                "key": key,
                "latest": is_latest,
                "manifest": f"{manifests_dir.name}/{path.name}",
                "images": entries,
            }
            # Two manifests can map to one page (metadata.version differs from the filename); the one
            # whose filename version matches the page (or the latest) wins, mirroring a page's content.
            owner = page_owner.get(key)
            if owner is not None:
                stats["page_collisions"] += 1
                mine = is_latest or version.removeprefix("v") == pversion
                theirs = owner["latest"] or owner["version"].removeprefix("v") == pversion
                if theirs or not mine:
                    continue
                charts.remove(owner)
            page_owner[key] = record
            charts.append(record)

    for img in images.values():
        img["charts"].sort()
        img["roles"].sort()
        img["refs"].sort()

    flag_counts = Counter(flag for img in images.values() for flag in img["flags"])
    priorities = Counter(img["priority"] for img in images.values())
    stats_out: dict[str, Any] = {
        "manifests": len(paths),
        "charts": len(grouped),
        "versions": len(charts),
        "unreadable_manifests": unreadable,
        "image_refs": sum(len(c["images"]) for c in charts),
        "unique_images": len(images),
        "latest_images": priorities.get(0, 0),
        "test_only_images": sum(1 for img in images.values() if img["roles"] == ["test"]),
        "test_role_refs": sum(1 for c in charts for e in c["images"] if e["role"] == "test"),
        "invalid": len(invalid),
        "invalid_by_reason": dict(sorted(Counter(i["reason"] for i in invalid).items())),
        "flags": dict(sorted(flag_counts.items())),
        "registries": dict(Counter(img["registry"] for img in images.values()).most_common()),
        "workloads": stats["workloads"],
        "charts_without_images": stats["charts_without_images"],
        "prerelease_selected": stats["prerelease_selected"],
        "page_collisions": stats["page_collisions"],
    }
    if scope == "forward":
        # non-latest versions selected by --since (first seen on/after it, or the latest at the cutoff),
        # those left out, and images only those versions use
        stats_out.update({
            "versions_since": stats["versions_since"],
            "versions_latest_at_since": stats["versions_latest_at_since"],
            "versions_before_since": stats["versions_before_since"],
            "versions_without_timestamp": stats["versions_without_timestamp"],
            "since_only_images": sum(1 for img in images.values() if img["priority"] > 0),
        })
    # JSON objects are written with sorted keys, so consumers must order by 'priority' themselves
    # (see scan.scan_order); the in-memory order matches it.
    ordered = sorted(images.items(), key=lambda kv: (kv[1]["priority"], kv[0]))
    return {
        "generated_at": utcnow(),
        "scope": scope,
        "since": since.isoformat() if since_ts is not None else None,
        "charts": charts,
        "images": dict(ordered),
        "invalid": invalid,
        "stats": stats_out,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Inventory workload images of chart versions.")
    parser.add_argument("--manifests", type=Path, default=Path("manifests"), help="rbac-scope manifests directory")
    parser.add_argument("--scope", choices=SCOPES, default="latest",
                        help="'latest' version of every chart; 'forward' = every version that was the latest on/after "
                             "--since + versions first seen on/after it; 'all' versions (backfill)")
    parser.add_argument("--since", type=parse_since, default=None,
                        help="cutoff date YYYY-MM-DD (UTC) for --scope forward (manifest metadata.timestamp)")
    parser.add_argument("--output", type=Path, default=INVENTORY_FILE, help="inventory.json path")
    args = parser.parse_args(argv)

    if not args.manifests.is_dir():
        parser.error(f"manifests directory not found: {args.manifests}")
    if args.scope == "forward" and args.since is None:
        parser.error("--scope forward requires --since YYYY-MM-DD")
    inventory = build_inventory(args.manifests, args.scope, args.since)
    # scope 'all' is tens of MB; keep it compact
    write_json(args.output, inventory, indent=2 if args.scope == "latest" else None)
    s = inventory["stats"]
    if args.scope == "forward":
        log(f"inventory (forward since {inventory['since']}): {s['versions_since']} non-latest versions on/after the "
            f"cutoff, {s['versions_latest_at_since']} that were the latest at the cutoff, "
            f"{s['versions_before_since']} before it, {s['versions_without_timestamp']} without a timestamp; "
            f"{s['since_only_images']} images used only by them")
    log(
        f"inventory ({args.scope}): {s['charts']} charts, {s['versions']} versions, {s['image_refs']} image refs, "
        f"{s['unique_images']} unique images ({s['latest_images']} in latest versions), "
        f"{s['invalid']} invalid {s['invalid_by_reason']}, flags {s['flags']} -> {args.output}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
