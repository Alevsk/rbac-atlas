#!/usr/bin/env python3
"""Probe cve.now coverage for vulnerabilities found in chart container images.

One-off feasibility check (run by .github/workflows/cvenow-probe.yml):
  1. Collect images from the latest manifest of every chart.
  2. Scan a deterministic sample of them with Trivy.
  3. Look up the unique vulnerability IDs on https://cve.now/api/v1/entries/<id>.
  4. Write probe/report.json, sample entry bodies, and a Markdown summary.
"""

from __future__ import annotations

import argparse
import collections
import json
import os
import re
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path

API = "https://cve.now/api/v1"
USER_AGENT = "rbac-atlas-probe/1.0 (+https://rbac-atlas.github.io)"


def version_key(version: str) -> tuple[int, ...]:
    parts = version.lstrip("v").split("-")[0].split(".")[:3]
    return tuple(int(p) if p.isdigit() else 0 for p in parts)


def latest_images(manifests_dir: Path) -> list[str]:
    latest: dict[str, tuple[tuple[int, ...], Path]] = {}
    for path in manifests_dir.glob("*.json"):
        parts = path.stem.split("__")
        if len(parts) != 3:
            continue
        chart, key = f"{parts[0]}__{parts[1]}", version_key(parts[2])
        if chart not in latest or key > latest[chart][0]:
            latest[chart] = (key, path)
    images = set()
    for _, path in latest.values():
        try:
            data = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        for workload in data.get("serviceAccountWorkloads") or []:
            image = (workload.get("image") or "").strip()
            if image and "{{" not in image:
                images.add(image)
    return sorted(images)


def scan(trivy: str, image: str, out: Path) -> dict:
    started = time.monotonic()
    proc = subprocess.run(
        [trivy, "image", "--image-src", "remote", "--platform", "linux/amd64",
         "--scanners", "vuln", "--list-all-pkgs", "--timeout", "5m",
         "-q", "-f", "json", "-o", str(out), image],
        capture_output=True, text=True, check=False,
    )
    result = {"image": image, "seconds": round(time.monotonic() - started, 1), "ok": proc.returncode == 0}
    if not result["ok"]:
        result["error"] = proc.stderr.strip()[-500:]
        return result
    ids, findings, go_ids, go_pkgs = set(), 0, set(), set()
    for res in json.loads(out.read_text()).get("Results") or []:
        is_go = res.get("Type") == "gobinary"
        for pkg in res.get("Packages") or []:
            if is_go and pkg.get("Name") and pkg.get("Version"):
                go_pkgs.add((pkg["Name"], pkg["Version"]))
        for vuln in res.get("Vulnerabilities") or []:
            findings += 1
            ids.add(vuln["VulnerabilityID"])
            if is_go:
                go_ids.add(vuln["VulnerabilityID"])
    result.update(findings=findings, ids=sorted(ids), go_ids=sorted(go_ids), go_pkgs=sorted(go_pkgs))
    return result


def fetch(url: str, payload: dict | None = None) -> dict:
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    data = None
    if payload is not None:
        data = json.dumps(payload).encode()
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=data, headers=headers)
    started = time.monotonic()
    try:
        with urllib.request.urlopen(request, timeout=30) as resp:
            body = resp.read()
            status, headers, final_url = resp.status, dict(resp.headers), resp.geturl()
    except urllib.error.HTTPError as err:
        body, status, headers, final_url = err.read(), err.code, dict(err.headers), url
    except (urllib.error.URLError, TimeoutError) as err:
        return {"status": None, "error": str(err), "ms": round((time.monotonic() - started) * 1000)}
    return {
        "status": status,
        "ms": round((time.monotonic() - started) * 1000),
        "bytes": len(body),
        "redirected": final_url != url,
        "headers": {k: v for k, v in headers.items() if re.search(r"rate|retry|cache|age", k, re.I)},
        "body": body,
    }


def field_paths(value, prefix: str = "") -> set[str]:
    """Flatten JSON keys to dotted paths (lists collapse to '[]')."""
    paths = set()
    if isinstance(value, dict):
        for key, child in value.items():
            path = f"{prefix}.{key}" if prefix else key
            paths.add(path)
            paths |= field_paths(child, path)
    elif isinstance(value, list):
        for child in value[:5]:
            paths |= field_paths(child, f"{prefix}[]")
    return paths


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--manifests-dir", type=Path, default=Path("manifests"))
    parser.add_argument("--out", type=Path, default=Path("probe"))
    parser.add_argument("--trivy", default=os.environ.get("TRIVY", "trivy"))
    parser.add_argument("--images", type=int, default=40, help="number of images to scan")
    parser.add_argument("--max-ids", type=int, default=500, help="maximum IDs to look up on cve.now")
    parser.add_argument("--delay", type=float, default=1.0, help="seconds between cve.now requests")
    parser.add_argument("--max-403", type=int, default=20, help="stop lookups after this many consecutive 403s")
    parser.add_argument("--check-images", type=int, default=10, help="images whose Go modules are sent to /check")
    args = parser.parse_args()

    scans_dir, entries_dir = args.out / "scans", args.out / "entries"
    scans_dir.mkdir(parents=True, exist_ok=True)
    entries_dir.mkdir(parents=True, exist_ok=True)

    images = latest_images(args.manifests_dir)
    step = max(1, len(images) // args.images)
    sample = images[::step][: args.images]
    print(f"{len(images)} images in latest chart versions; scanning {len(sample)}")

    scans = []
    for i, image in enumerate(sample):
        result = scan(args.trivy, image, scans_dir / f"{i:03d}.json")
        print(f"[{i + 1}/{len(sample)}] {image}: {'ok' if result['ok'] else 'FAILED'} {result['seconds']}s")
        scans.append(result)

    id_counts = collections.Counter(i for s in scans if s["ok"] for i in s["ids"])
    prefixes = collections.Counter(re.match(r"[A-Za-z]+", i).group() for i in id_counts)
    lookup_ids = sorted(i for i in id_counts if not i.startswith("TEMP-"))
    step = max(1, len(lookup_ids) // args.max_ids)
    lookup_ids = lookup_ids[::step][: args.max_ids]
    print(f"{len(id_counts)} unique IDs {dict(prefixes)}; looking up {len(lookup_ids)} on cve.now")

    meta = {}
    for name, url in {"status": f"{API}/status", "llms": "https://cve.now/llms.txt"}.items():
        resp = fetch(url)
        if resp.get("body") is not None:
            (args.out / f"{name}.txt").write_bytes(resp.pop("body"))
        meta[name] = resp

    lookups, fields, streak, blocked_at = [], collections.Counter(), 0, None
    for n, vuln_id in enumerate(lookup_ids):
        if streak >= args.max_403:
            blocked_at = n - streak
            print(f"{streak} consecutive 403s from request {blocked_at + 1}; stopping lookups")
            break
        resp = fetch(f"{API}/entries/{vuln_id}")
        if resp["status"] == 429:
            wait = int(resp["headers"].get("Retry-After", "30") or 30)
            print(f"429 at request {n + 1}; sleeping {wait}s and retrying once")
            time.sleep(min(wait, 120))
            resp = fetch(f"{API}/entries/{vuln_id}")
            resp["retried_after_429"] = True
        body = resp.pop("body", None)
        streak = streak + 1 if resp["status"] == 403 else 0
        if resp["status"] != 200 and body:
            resp["body_snippet"] = body[:300].decode("utf-8", "replace")
        if resp["status"] == 200 and body:
            try:
                fields.update(field_paths(json.loads(body)))
            except json.JSONDecodeError:
                resp["invalid_json"] = True
            if len(list(entries_dir.iterdir())) < 25:
                (entries_dir / f"{vuln_id}.json").write_bytes(body)
        lookups.append({"id": vuln_id, **resp})
        time.sleep(args.delay)

    retry_after_pause = None
    if blocked_at is not None:
        print("Waiting 120s, then retrying one blocked ID")
        time.sleep(120)
        retry = fetch(f"{API}/entries/{lookups[-1]['id']}")
        retry.pop("body", None)
        retry_after_pause = retry

    # Batch-match Go modules with POST /api/v1/check and compare with Trivy's Go findings.
    checks = []
    for s in [s for s in scans if s["ok"] and s["go_pkgs"]][: args.check_images]:
        packages = [{"ecosystem": "go", "name": name, "version": version} for name, version in s["go_pkgs"]]
        resp = fetch(f"{API}/check", {"packages": packages[:10000]})
        body = resp.pop("body", None)
        entry = {"image": s["image"], "packages": len(packages), "trivy_go_ids": len(s["go_ids"]), **resp}
        if body and resp["status"] == 200:
            text = body.decode("utf-8", "replace")
            if not checks:
                (args.out / "check_sample.json").write_text(text)
            found = set(re.findall(r"(?:CVE-\d{4}-\d{4,7}|GHSA-[\w-]{14}|GO-\d{4}-\d{4,})", text))
            entry.update(
                cvenow_ids=len(found),
                both=len(found & set(s["go_ids"])),
                only_trivy=sorted(set(s["go_ids"]) - found)[:20],
                only_cvenow=sorted(found - set(s["go_ids"]))[:20],
            )
        elif body:
            entry["body_snippet"] = body[:300].decode("utf-8", "replace")
        checks.append(entry)
        print(f"/check {s['image']}: {resp['status']} {entry.get('cvenow_ids')} vs trivy {len(s['go_ids'])}")
        time.sleep(args.delay)

    ok_scans = [s for s in scans if s["ok"]]
    statuses = collections.Counter(str(l["status"]) for l in lookups)
    found = statuses.get("200", 0)
    latencies = sorted(l["ms"] for l in lookups if l.get("ms") is not None)
    report = {
        "images_in_latest_versions": len(images),
        "images_scanned": len(sample),
        "scan_failures": [s for s in scans if not s["ok"]],
        "scan_seconds": sorted(s["seconds"] for s in ok_scans),
        "findings_total": sum(s["findings"] for s in ok_scans),
        "unique_ids": len(id_counts),
        "id_prefixes": dict(prefixes),
        "ids_looked_up": len(lookups),
        "cvenow_status_codes": dict(statuses),
        "cvenow_coverage_pct": round(100 * found / len(lookups), 1) if lookups else None,
        "cvenow_by_prefix": {
            p: f"{sum(1 for l in lookups if l['id'].startswith(p) and l['status'] == 200)}"
               f"/{sum(1 for l in lookups if l['id'].startswith(p))}"
            for p in sorted({re.match(r'[A-Za-z]+', l['id']).group() for l in lookups})
        },
        "cvenow_latency_ms": {
            "p50": latencies[len(latencies) // 2] if latencies else None,
            "p95": latencies[int(len(latencies) * 0.95)] if latencies else None,
            "max": latencies[-1] if latencies else None,
        },
        "cvenow_rate_limit_headers": sorted({k for l in lookups for k in l.get("headers", {})}),
        "cvenow_meta": meta,
        "cvenow_entry_fields": {k: v for k, v in sorted(fields.items())},
        "blocked_at_request": blocked_at,
        "retry_after_pause": retry_after_pause,
        "lookups": [{k: l.get(k) for k in ("id", "status", "ms", "body_snippet")} for l in lookups],
        "checks": checks,
        "scans": [{k: v for k, v in s.items() if k not in ("ids", "go_ids", "go_pkgs")} for s in scans],
    }
    (args.out / "report.json").write_text(json.dumps(report, indent=2))

    summary = [
        "## cve.now coverage probe",
        f"- Images scanned: {len(ok_scans)}/{len(sample)} (of {len(images)} in latest chart versions)",
        f"- Findings: {report['findings_total']}, unique IDs: {len(id_counts)} {dict(prefixes)}",
        f"- cve.now lookups: {len(lookups)}, status codes: {dict(statuses)}",
        f"- Coverage: {report['cvenow_coverage_pct']}%, by prefix: {report['cvenow_by_prefix']}",
        f"- Latency ms: {report['cvenow_latency_ms']}",
        f"- Blocked at request: {blocked_at}, retry after pause: {(retry_after_pause or {}).get('status')}",
        f"- /check (Go modules): " + "; ".join(
            f"{c['image']}: {c['status']} cve.now={c.get('cvenow_ids')} trivy={c['trivy_go_ids']} both={c.get('both')}"
            for c in checks),
        f"- Rate-limit headers seen: {report['cvenow_rate_limit_headers'] or 'none'}",
        f"- Entry fields seen ({len(fields)}): {', '.join(sorted(fields)[:80])}",
    ]
    (args.out / "summary.md").write_text("\n".join(summary) + "\n")
    print("\n".join(summary))


if __name__ == "__main__":
    main()
