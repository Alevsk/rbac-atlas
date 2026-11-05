# Image vulnerability scan (Phase 1a)

The `vulnscan` package measures the known vulnerabilities in the container images that the
charts in RBAC Atlas deploy. It is used to calibrate an image risk score that may later be
combined with the RBAC risk already shown on the site.

Phase 1a only produces artifacts. Nothing is committed, published, or added to the site.
The workflow `.github/workflows/image-vulns.yml` runs once a day at 06:30 UTC with
`contents: read`. Its outputs go to a workflow artifact (`image-vulns`, kept for 30 days)
and its caches go to `actions/cache`.

## Stages

Each stage is a module you can run as `python -m vulnscan.<stage>`. It reads the file
written by the previous stage and writes its own. Everything is pure standard-library
Python (3.10 or later).

| Stage | Module | Reads | Writes |
|---|---|---|---|
| 1. Inventory | `vulnscan.inventory` | `manifests/*.json` | `out/inventory.json` |
| 2. Scan | `vulnscan.scan` | `inventory.json` | `out/scan.json` |
| 3. Enrich | `vulnscan.cvenow` | `scan.json` | `out/enrichment.json` |
| 4. Report | `vulnscan.report` | all three | `out/summary.json`, `out/report.md` |

1. **Inventory.** Picks the latest version of every chart. This is the highest semver
   version, skipping prereleases unless a chart has only prereleases. It then collects the
   workload images and normalizes each reference with `vulnscan.imageref.normalize`, which
   handles a leading `/`, Docker Hub aliases, `library/`, implicit `latest`, and digests.
   It tags each image with its role (`main`, or `test` for test Pods and Jobs) and records
   the RBAC risk of the service account that runs it.
2. **Scan.** Resolves each tag to its linux/amd64 digest with `crane digest`. Docker Hub
   images are looked up on `mirror.gcr.io` first, and results are cached for 20 hours.
   Trivy then generates one CycloneDX SBOM per digest, which is cached, with at most
   `--max-new-sboms` new SBOMs per run. Every cached SBOM is re-matched against the
   current Trivy DB with `trivy sbom`, so a daily run costs little once the cache is warm.
   An image that fails is marked `unavailable` with a reason (`not_found`, `no_amd64`,
   `unauthorized`, `rate_limited`, `timeout`, `error`), and the rest of the run continues.
3. **Enrich.** Looks up CVE-, GHSA- and GO- IDs on [cve.now](https://cve.now) to get KEV
   status, the date EPSS first reached 10%, public exploits, SSVC, and fixed versions. For
   images that contain Go binaries it also sends their module lists to `POST /api/v1/check`.
   All responses are cached, and `enrichment.json` is always rebuilt from the cache.
4. **Report.** Assigns each image and chart a provisional risk level (Exploited, High,
   Elevated, Moderate, Low, Unknown) and a 0-100 score (`WEIGHTS` in `vulnscan/report.py`,
   `weights_version` 1). It also lists exposures: a workload whose service account has
   Critical or High RBAC risk, running an image with a KEV or likely-exploitable
   vulnerability. `report.md` is appended to the workflow job summary.

## Files

Everything lives under `$VULNS_DIR`, which defaults to `./vulns` and is ignored by git.

```
vulns/
  .cache/                              persisted between runs via actions/cache
    resolve.json                       tag -> digest resolution cache
    sbom/<sha256>.cdx.json.gz          one CycloneDX SBOM per linux/amd64 digest
    cvenow/entries/<ID>.json           cve.now entries (404s cached too)
    cvenow/check/<sha256>.json         /check responses keyed by package list
  out/                                 uploaded as the image-vulns artifact
    inventory.json  scan.json  enrichment.json  summary.json  report.md
```

The schemas are described in the module docstrings and in the stage contract that
`tests/python` exercises.

## Running locally

You need `trivy` (0.76.1 is pinned in CI) and `crane`. Download the Trivy DBs once before
scanning, because the scan stage never updates them:

```bash
trivy image --download-db-only
trivy image --download-java-db-only

make vulns VULN_LIMIT=10            # whole pipeline on the first 10 images
make image-inventory                # or one stage at a time
make scan-images VULN_LIMIT=10 MAX_NEW_SBOMS=10
make enrich-vulns CVENOW_BUDGET=100
make vuln-report
cat vulns/out/report.md

make test-python                    # unit tests: no network, no trivy needed
```

Use `TRIVY=/path/to/trivy CRANE=/path/to/crane` to point at binaries that are not on
`PATH`, and `VULNS_DIR=/tmp/vulns` to keep outputs out of the repository.

## Tunables

| Make variable / workflow input | CLI flag | Default | Meaning |
|---|---|---|---|
| `VULN_LIMIT` / `limit` | `scan --limit` | all | Scan only the first N images (alphabetical) |
| `MAX_NEW_SBOMS` / `max_new_sboms` | `scan --max-new-sboms` | 200 | New SBOMs per run; the rest are `skipped` (`sbom_quota`) |
| `SCAN_WORKERS` | `scan --workers` | 3 | Parallel SBOM generations |
| `CVENOW_BUDGET` / `cvenow_budget` | `cvenow --budget` | 3000 | Maximum cve.now HTTP requests per run, retries included |
| `CVENOW_RPS` | `cvenow --rps` | 1.0 | Maximum cve.now requests per second |
| - | `scan --resolve-max-age-hours` | 20 | Re-resolve tags older than this |
| - | `cvenow --max-age-days` | 7 | Refresh cached entries, and retry cached 404s, after this |

With 641 images, the first runs fill the SBOM cache at 200 images per run, and the cve.now
cache fills at about 3000 IDs per day. After that, a daily run mostly re-matches cached
SBOMs and refreshes stale entries.

In the workflow, each run saves `vulns/.cache` under a new key
(`vulns-cache-<run_id>-<run_attempt>`) and the next run restores the newest one. A run that
restored nothing saves under `vulns-cold-…` instead, which is only restored when no
`vulns-cache-…` entry exists, so a cold snapshot never shadows a fuller one. The Trivy DB is
cached weekly mainly as a fallback: if the DB download fails, the run continues with the
restored DB (with a warning) and `scan.json` records its `db_updated_at`.

## cve.now usage etiquette

cve.now is a free service that needs no API key. Please use it gently:

- **1 request per second** at most (`--rps 1.0`). In testing it started returning 403 after
  about 270 requests at 4 requests per second. At 1 request per second, 400 requests
  produced no blocks.
- **A daily budget** (`--budget 3000`) caps every run, retries included.
- **Back off on 403, 429 or 5xx** for 30 s and then 60 s. The third consecutive blocked
  response stops the run with `stopped_reason: blocked`. If the site cannot be reached at
  all, the run stops after 3 attempts with `unreachable`. Either way the stage exits
  successfully and the report is built from the cache.
- **Cache everything.** Entries are refetched only after 7 days, or sooner when they
  appear in the KEV or critical feeds. `/check` responses are reused for about a day.
- Requests identify themselves with
  `User-Agent: rbac-atlas/1.0 (+https://rbac-atlas.github.io)`.

## Limitations

- **Artifact only.** Levels and scores are provisional and exist only to calibrate the
  weights. Nothing reaches the site or the repository.
- **linux/amd64 only.** Images with no amd64 variant (for example Windows-only images) are
  `unavailable` with reason `no_amd64`.
- **Rendered default manifests only.** Images come from the rbac-scope manifests, which are
  rendered with the chart's default values. Images that only appear with non-default
  values, and images pulled at runtime (operators that launch other images), are missing.
- **Mutable tags.** Tags such as `latest` are resolved at scan time, and `mirror.gcr.io`
  can serve an older digest for them. Pinned digests are exact.
- **`/check` is informational.** It does not match Go stdlib CVEs and gives some false
  positives on an image's own main module. Its matches appear only as `check_only_ids` and
  never change levels or scores.
- **cve.now data.** cve.now has no CWE field and no numeric EPSS. CWEs come from Trivy, and
  "EPSS" here means only the date EPSS first reached 10% (`epss_reached`). DLA, DSA and
  TEMP IDs are not looked up.
- **Cache growth.** Old SBOMs and resolve entries are never pruned.
