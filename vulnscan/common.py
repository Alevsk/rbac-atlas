"""Shared paths and helpers for the vulnscan pipeline.

On-disk layout (all under VULNS_DIR, default ./vulns, never committed in this phase):

  vulns/.cache/                 persisted between runs via actions/cache
    resolve.json                {canonical_ref: {"digest": "sha256:..", "resolved_at": iso, "status": "ok"|reason}}
    sbom/<sha256-hex>.cdx.json.gz   CycloneDX SBOM per linux/amd64 image digest
    cvenow/entries/<ID>.json    {"fetched_at": iso, "status": 200|404, "entry": {...raw cve.now entry...} | null}
    cvenow/check/<sha256-of-pkgs>.json  {"fetched_at": iso, "status": int, "response": {...} | null}
  vulns/out/                    produced every run, uploaded as a workflow artifact
    inventory.json              written by vulnscan.inventory
    scan.json                   written by vulnscan.scan
    enrichment.json             written by vulnscan.cvenow
    summary.json, report.md     written by vulnscan.report
"""

from __future__ import annotations

import datetime as _dt
import gzip
import json
import os
import tempfile
from pathlib import Path
from typing import Any

VULNS_DIR = Path(os.environ.get("VULNS_DIR", "vulns"))
CACHE_DIR = VULNS_DIR / ".cache"
OUT_DIR = VULNS_DIR / "out"
SBOM_DIR = CACHE_DIR / "sbom"
RESOLVE_FILE = CACHE_DIR / "resolve.json"
CVENOW_ENTRIES_DIR = CACHE_DIR / "cvenow" / "entries"
CVENOW_CHECK_DIR = CACHE_DIR / "cvenow" / "check"

INVENTORY_FILE = OUT_DIR / "inventory.json"
SCAN_FILE = OUT_DIR / "scan.json"
ENRICHMENT_FILE = OUT_DIR / "enrichment.json"
SUMMARY_FILE = OUT_DIR / "summary.json"
REPORT_FILE = OUT_DIR / "report.md"

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
# RBAC risk levels as used in manifests (serviceAccountPermissions[].riskLevel), most severe first.
RBAC_RISK_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


def utcnow() -> str:
    """Current UTC time as ISO 8601 with a trailing Z (second precision)."""
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_time(value: str) -> _dt.datetime:
    return _dt.datetime.fromisoformat(value.replace("Z", "+00:00"))


def read_json(path: Path, default: Any = None) -> Any:
    """Read JSON (transparently gunzipping *.gz); return default if missing or invalid."""
    try:
        if path.suffix == ".gz":
            with gzip.open(path, "rt", encoding="utf-8") as fh:
                return json.load(fh)
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def write_json(path: Path, data: Any, *, indent: int | None = 2) -> None:
    """Atomically write JSON (gzip when the name ends in .gz)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as fh:
            payload = json.dumps(data, indent=indent, sort_keys=True).encode("utf-8")
            fh.write(gzip.compress(payload, mtime=0) if path.suffix == ".gz" else payload)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def log(message: str) -> None:
    print(message, flush=True)
