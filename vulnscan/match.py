"""Per-digest match cache: the compact, versioned form of one image's Trivy rematch.

scan.json only carries per-image metadata and counts; the per-vulnerability detail that report
(and cvenow's /check) need lives here, one gzipped file per digest in MATCH_DIR:

  {"format_version": 2, "matched_at": iso, "os": {...}|null, "counts": {SEVERITY: n},
   "go": [[module, version], ...],
   "vulns": [[id, severity, fixable, cvss, fixed, pkg, installed, cwes, vendor_ids], ...]}

One 'vulns' row per unique vulnerability ID (sorted by severity, then ID): severity is the worst
of the ID's findings, fixable whether any finding has status 'fixed', cvss the highest numeric
score, cwes the union, vendor_ids the union of the CVE/GHSA/GO vendor IDs. fixed/pkg/installed
come from the ID's representative finding (most severe, fixable first, then package, version),
so report.group_findings over the expanded rows gives the same result as over the raw findings.

Files without the current format_version are never read as such: format 1 ({"matched_at",
"result": summarize_report() output}) is re-derived by migrate(); anything else is treated as
missing (the digest is rematched).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable

from vulnscan import cvenow  # module import: cvenow imports this module too
from vulnscan.common import SEVERITIES, read_json, write_json

FORMAT_VERSION = 2
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}


def scan_format_error(scan: dict[str, Any], scan_path: Any) -> str | None:
    """Why a non-empty scan.json cannot be read by this version (older layout), or None.

    scan.json shares FORMAT_VERSION with the match files; a stale one (e.g. full findings
    inside, no 'ids' map) would otherwise silently yield no IDs and no per-image matches.
    """
    if not scan or scan.get("format_version") == FORMAT_VERSION:
        return None
    return (f"{scan_path} has format_version {scan.get('format_version')!r}, expected {FORMAT_VERSION}; "
            f"re-run the scan stage (make scan-images) to regenerate it")


def path(match_dir: Path, digest: str) -> Path:
    return Path(match_dir) / f"{digest.split(':', 1)[1]}.json.gz"


def _severity(value: Any) -> str:
    sev = str(value or "UNKNOWN").upper()
    return sev if sev in SEV_RANK else "UNKNOWN"


def finding_rank(severity: Any, fixed: Any, pkg: Any, installed: Any) -> tuple[int, bool, str, str]:
    """Representative finding order: most severe, fixable first, then package name and version."""
    return (SEV_RANK[_severity(severity)], not fixed, str(pkg or ""), str(installed or ""))


def compact_findings(findings: Iterable[dict[str, Any]]) -> list[list[Any]]:
    """Reduce findings (summarize_report shape) to one 'vulns' row per unique ID."""
    rows: dict[str, list[Any]] = {}
    best: dict[str, tuple] = {}
    for f in findings:
        if not isinstance(f, dict) or not f.get("id"):
            continue
        vid = f["id"]
        sev = _severity(f.get("severity"))
        score = (f.get("cvss") or {}).get("score")
        score = score if isinstance(score, (int, float)) and not isinstance(score, bool) else None
        rank = finding_rank(sev, f.get("fixed"), f.get("pkg"), f.get("installed"))
        row = rows.get(vid)
        if row is None:
            row = rows[vid] = [vid, sev, False, score, None, None, None, set(), set()]
            best[vid] = rank
            row[4:7] = [f.get("fixed") or None, f.get("pkg") or None, f.get("installed")]
        else:
            if SEV_RANK[sev] < SEV_RANK[row[1]]:
                row[1] = sev
            if score is not None and (row[3] is None or score > row[3]):
                row[3] = score
            if rank < best[vid]:  # strict: the first finding wins ties, as in report.group_findings
                best[vid] = rank
                row[4:7] = [f.get("fixed") or None, f.get("pkg") or None, f.get("installed")]
        if str(f.get("status") or "").lower() == "fixed":
            row[2] = True
        row[7].update(c for c in f.get("cwes") or [] if isinstance(c, str))
        row[8].update(v for v in f.get("vendor_ids") or [] if isinstance(v, str) and cvenow.ID_RE.match(v))
    out = [r[:7] + [sorted(r[7]), sorted(r[8])] for r in rows.values()]
    out.sort(key=lambda r: (SEV_RANK[r[1]], r[0]))
    return out


def compact(result: dict[str, Any], matched_at: str | None) -> dict[str, Any]:
    """Build a match document from summarize_report() output (or a format-1 scan.json image record)."""
    return {
        "format_version": FORMAT_VERSION,
        "matched_at": matched_at,
        "os": result.get("os"),
        "counts": {s: (result.get("counts") or {}).get(s, 0) for s in SEVERITIES},
        "go": [list(m) for m in result.get("go_modules") or []],
        "vulns": compact_findings(result.get("findings") or []),
    }


def expand(doc: dict[str, Any] | None) -> list[dict[str, Any]]:
    """'vulns' rows as finding dicts accepted by report.group_findings (one per unique ID)."""
    out = []
    for vid, sev, fixable, score, fixed, pkg, installed, cwes, vendor_ids in (doc or {}).get("vulns") or []:
        out.append({"id": vid, "severity": sev, "status": "fixed" if fixable else None, "fixed": fixed,
                    "pkg": pkg, "installed": installed, "cvss": {"score": score} if score is not None else None,
                    "cwes": cwes, "vendor_ids": vendor_ids})
    return out


def vuln_ids(doc: dict[str, Any]) -> dict[str, int]:
    """Enrichable IDs of a match (row IDs and vendor IDs, canonical form) → worst severity rank."""
    ids: dict[str, int] = {}
    for row in doc.get("vulns") or []:
        rank = SEV_RANK[row[1]]
        for vid in [row[0], *row[8]]:
            if cvenow.ID_RE.match(vid):
                vid = cvenow.canonical_id(vid)
                ids[vid] = min(rank, ids.get(vid, rank))
    return ids


def migrate(data: Any) -> dict[str, Any] | None:
    """A current-format match document from whatever is on disk, or None if unusable."""
    if not isinstance(data, dict) or not data.get("matched_at"):
        return None
    if data.get("format_version") == FORMAT_VERSION:
        return data if isinstance(data.get("vulns"), list) else None
    if "format_version" not in data and isinstance(data.get("result"), dict) and "error" not in data["result"]:
        return compact(data["result"], data["matched_at"])  # format 1: full summarize_report() output
    return None


def load(match_dir: Path, digest: str) -> dict[str, Any] | None:
    """Read one digest's match (format 1 is converted in memory), or None."""
    return migrate(read_json(path(match_dir, digest)))


def store(match_dir: Path, digest: str, doc: dict[str, Any]) -> None:
    write_json(path(match_dir, digest), doc, indent=None)
