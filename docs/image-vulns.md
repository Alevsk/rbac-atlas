# Image vulnerability scan

The `vulnscan` package measures the known vulnerabilities in the container images that the
charts in RBAC Atlas deploy, and cross-references them with the RBAC risk of the service
account that runs each image. The site shows the result on every chart version page (per
workload image), on the home page ("Riskiest combinations" under Threat landscape) and on
the Threat landscape page.

The workflow `.github/workflows/image-vulns.yml` runs once a day at 06:30 UTC in two jobs:

- **scan** (`contents: read`) runs the pipeline below. Its outputs go to a workflow artifact
  (`image-vulns`, kept for 30 days), `inventory.json` and `summary.json` also go to a small
  `image-vulns-publish` artifact, and its caches go to `actions/cache`.
- **publish** (only after a successful scan, only on `master`) downloads `image-vulns-publish`,
  runs `make publish-vulns` and commits `data/vulns/` to master as
  `vulns update YYYY-MM-DD`. See [Publishing](#publishing).

## Stages

Each stage is a module you can run as `python -m vulnscan.<stage>`. It reads the file
written by the previous stage and writes its own. Everything is pure standard-library
Python (3.10 or later).

| Stage | Module | Reads | Writes |
|---|---|---|---|
| 1. Inventory | `vulnscan.inventory` | `manifests/*.json` | `out/inventory.json` |
| 2. Scan | `vulnscan.scan` | `inventory.json` | `out/scan.json`, `.cache/match/` |
| 3. Enrich | `vulnscan.cvenow` | `scan.json` (+ `.cache/match/` for `/check`) | `out/enrichment.json` |
| 4. Report | `vulnscan.report` | all three + `.cache/match/` | `out/summary.json`, `out/report.md` |
| 5. Publish | `vulnscan.publish` | `out/*.json` | `data/vulns/**` (Hugo data) |

1. **Inventory.** With `--scope all` (the default) it inventories every chart version in
   `manifests/`; with `--scope latest` only the latest version of every chart. The latest
   version is the highest semver version, skipping prereleases unless a chart has only
   prereleases, and is flagged `latest: true`. Every image gets a `priority`: 0 when a
   latest version uses it, otherwise its rank by newest version, and images are listed in
   priority order so the scan fills the SBOM cache for the most relevant images first
   (see [Scope and backfill](#scope-and-backfill)). It then collects the workload images
   and normalizes each reference with `vulnscan.imageref.normalize`, which handles a
   leading `/`, Docker Hub aliases, `library/`, implicit `latest`, and digests. It tags
   each image with its role (`main`, or `test` for test Pods and Jobs) and records the
   RBAC risk of the service account that runs it: the most severe risk of that service
   account's permissions in the workload's namespace, or, when it has none there, across all
   namespaces, matching the per-ServiceAccount risk shown on the version page.
2. **Scan.** Resolves each tag to its linux/amd64 digest with `crane digest`. Docker Hub
   images are looked up on `mirror.gcr.io` first. Results are cached for 20 hours for
   images used by a latest version and for 7 days for the others. Trivy then generates one
   CycloneDX SBOM per digest, which is cached, with at most `--max-new-sboms` new SBOMs per
   run. SBOM failures are remembered: `timeout`, `no_amd64`, `unauthorized` and `not_found`
   are retried after 1, 2, 4, ... (at most 30) days and do not use the new-SBOM quota while
   they wait. Cached SBOMs are re-matched against the current Trivy DB with `trivy sbom` and
   each result is cached per digest: digests used by a latest version are re-matched every
   night, the others once their cached match is older than 7 days, at most
   `--max-rematch` per night (never-matched first, then oldest); the rest reuse their cached
   match, and `scanned_at` says when it was made. If a re-match fails, the cached match is
   used. The per-vulnerability detail of each digest lives only in that match cache
   (`.cache/match/`); `scan.json` itself only holds per-image metadata and counts plus one
   global map of vulnerability IDs (see [Memory and size](#memory-and-size)). An image that
   fails is marked `unavailable` with a reason (`not_found`, `no_amd64`, `unauthorized`,
   `rate_limited`, `timeout`, `error`), and the rest of the run
   continues. With `--time-budget-minutes` the stage stops starting new SBOMs and
   re-matches once the budget is spent (those images are `skipped`, reason `time_budget`)
   and still writes its outputs.
3. **Enrich.** Looks up CVE-, GHSA- and GO- IDs on [cve.now](https://cve.now) to get KEV
   status, the date EPSS first reached 10%, public exploits, SSVC, and fixed versions. For
   images used by a latest version that contain Go binaries it also sends their module lists
   to `POST /api/v1/check`.
   All responses are cached, and `enrichment.json` is always rebuilt from the cache.
4. **Report.** Assigns each image, and each chart version, a risk level and a 0-100 score
   (see [Methodology](#methodology), `weights_version` 2) and lists the riskiest
   combinations per workload. Rollups and combinations are computed for every inventoried
   version; landscape aggregates use latest versions only. It reads each image's match from
   the cache one at a time; an `ok` image whose match is missing becomes `unavailable`
   (`match_missing`). `report.md` is appended to the workflow job summary.
5. **Publish.** Writes the compact Hugo data files described in
   [Published data](#published-data). It fails if `data/vulns/` would exceed `--max-mb`,
   and it writes nothing if the scanned images, versions with data or versions would drop
   by more than `--max-drop` (20%) compared with the existing `data/vulns/meta.json`, unless
   `--allow-drop` is given.

## Files

Everything lives under `$VULNS_DIR`, which defaults to `./vulns` and is ignored by git.

```
vulns/
  .cache/                              persisted between runs via actions/cache
    resolve.json                       tag -> digest resolution cache
    sbom/<sha256>.cdx.json.gz          one CycloneDX SBOM per linux/amd64 digest
    match/<sha256>.json.gz             last re-match per digest (compact, format_version 2)
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
make publish-vulns                  # data/vulns/ for `hugo server`; do not commit by hand

make test-python                    # unit tests: no network, no trivy needed
```

Use `TRIVY=/path/to/trivy CRANE=/path/to/crane` to point at binaries that are not on
`PATH`, and `VULNS_DIR=/tmp/vulns` to keep outputs out of the repository.

## Tunables

| Make variable / workflow input | CLI flag | Default | Meaning |
|---|---|---|---|
| `VULN_SCOPE` / `scope` | `inventory --scope` | all | `all` chart versions or only the `latest` ones |
| `VULN_LIMIT` / `limit` | `scan --limit` | all | Scan only the first N images (in priority order) |
| `MAX_NEW_SBOMS` / `max_new_sboms` | `scan --max-new-sboms` | 200 (make), 2500 (workflow) | New SBOMs per run; the rest are `skipped` (`sbom_quota`) |
| `SCAN_WORKERS` | `scan --workers` | 3 | Parallel SBOM generations |
| `MAX_REMATCH` | `scan --max-rematch` | 4000 | Re-matches per run of digests not used by a latest version (`-1` = no limit) |
| `SCAN_BUDGET_MIN` | `scan --time-budget-minutes` | none (make), 165 (workflow) | Stop starting new SBOMs/re-matches after this many minutes |
| `CVENOW_BUDGET` / `cvenow_budget` | `cvenow --budget` | 3000 (make), 5000 (workflow) | Maximum cve.now HTTP requests per run, retries included |
| `CVENOW_RPS` | `cvenow --rps` | 1.0 | Maximum cve.now requests per second |
| `VULN_MAX_MB` | `publish --max-mb` | 80 | Fail the publish if `data/vulns/` exceeds this size |
| `VULN_ALLOW_DROP` / `allow_drop` | `publish --allow-drop` | off | Publish even when the regression guard (`--max-drop` 0.2) trips |
| - / `publish` | - | true | Run the publish job after a successful full scan (master, scope `all`, no `limit`) |
| - | `scan --resolve-max-age-hours` | 20 | Re-resolve tags of latest-version images older than this |
| - | `scan --resolve-max-age-hours-old` | 168 | Re-resolve other tags older than this |
| - | `scan --rematch-max-age-hours` | 168 | Re-match digests not used by a latest version once their match is older than this |
| - | `cvenow --max-age-days` | 7 | Refresh cached entries, and retry cached 404s, after this |

The Make defaults stay small for local runs; the workflow passes the larger values.

In the workflow, each run saves `vulns/.cache` under a new key
(`vulns-cache-<run_id>-<run_attempt>`) and the next run restores the newest one. A run that
restored nothing saves under `vulns-cold-…` instead, which is only restored when no
`vulns-cache-…` entry exists, so a cold snapshot never shadows a fuller one. The Trivy DB is
cached weekly mainly as a fallback: if the DB download fails, the run continues with the
restored DB (with a warning) and `scan.json` records its `db_updated_at`.

## Scope and backfill

`manifests/` holds about 27,900 chart versions; 27,200 of them have workloads, which
reference about 29,300 distinct images (139,500 workload rows). The latest versions alone
reference about 630 images.

A nightly run has four costly parts, all inside the scan job's 300-minute timeout:

| Part | Rate | Nightly cost at the workflow defaults |
|---|---|---|
| Tag resolution | `crane digest` with 6 workers; latest-version tags after 20 h, others after 7 days | about 630 + 29,000/7 calls |
| New SBOMs (`max_new_sboms` 2500) | about 1.5 s wall per SBOM with 3 workers | 60-70 min |
| Re-match | latest-version digests every night, others weekly, at most `MAX_REMATCH` (4000) | bounded; see below |
| cve.now (`cvenow_budget` 5000) | 1 request per second | about 85 min |

Because the inventory lists images in priority order, the first night covers the latest
versions (already mostly cached) and then the images of the newest older versions. At 2500
new SBOMs per night the whole backlog of about 29,000 images takes **about 12 nights**,
assuming Docker Hub credentials are configured and few SBOMs fail (failures back off, so
they cost one attempt per backoff period, but each `timeout` holds a worker for up to 11
minutes).
Until then, version pages whose images are not scanned yet show "pending scan", and their
version rollup is marked partial. Once the backlog is done, a night only generates SBOMs for
new digests (new chart versions, moved tags).

Re-match and resolve work is bounded rather than proportional to the cache: digests used by
a latest version (about 630) are re-matched and re-resolved every night, and the rest of
the cache (up to about 29,000 digests) on a weekly rotation capped at `MAX_REMATCH` per
night, so at steady state a night re-matches roughly 630 + 29,000/7 SBOMs. Older versions'
CVE data can therefore be up to a week behind the Trivy DB (each image shows its scan
date). As a last resort, `SCAN_BUDGET_MIN` (165 in the workflow) stops the scan stage from
starting new work, so the job finishes, uploads its outputs and publishes instead of
hitting the 300-minute timeout. If `time_budget` skips show up in the report, lower
`max_new_sboms` or `MAX_REMATCH`. Registry rate limits mostly hit tag resolution;
rate-limited images are `unavailable` (`rate_limited`) for that night only.

### Memory and size

Per-image vulnerability detail is never held for all images at once:

- `scan.json` has, per image, only status, reason, digest, OS, counts, `scanned_at`, the
  number of Go modules and the inventory priority, plus one global `ids` map
  (`{ID: worst severity}`) that is all `cvenow` needs. About 0.5 KB per image, so roughly
  15 MB for 29,000 images (it used to embed every finding, about 75 KB per image, or about
  2.2 GB).
- The detail lives in `.cache/match/<sha256>.json.gz`, one file per digest with one row per
  unique vulnerability ID holding only what the report uses (severity, fixable, CVSS score,
  fixed version, package, CWEs, CVE/GHSA/GO vendor IDs) and the Go modules for `/check`.
  About 4 KB gzipped per digest, so roughly 115 MB for 29,000 digests, kept by
  `actions/cache` and never uploaded as an artifact.
- Each file has a `format_version`. The scan stage converts entries in the previous format
  (full Trivy summaries) in place without re-running Trivy; any other version is treated as
  missing and re-matched, and the report treats it as `match_missing`, so it is never
  misread. A truncated or corrupt `.json.gz` is handled the same way. `scan.json` carries
  the same `format_version`; `cvenow` and `report` refuse an older `scan.json` (re-run
  `make scan-images`) instead of silently finding no IDs.
- `report` streams: it loads the inventory, `enrichment.json` and the small `scan.json`,
  then reads one match file per image and keeps only the image's summary record and its
  vulnerability groups (deduplicated across images). Measured with every one of the 29,253
  inventoried images scanned (synthetic, from real matches): peak RSS 0.9 GB, against 13 GB
  for the old single-file `scan.json`, with identical `summary.json`. `summary.json` itself
  (about 90 MB then) is the largest object left in memory.
- `/check` only runs for images used by a latest version, so it reads at most a few hundred
  match files.
- The published `data/vulns/` measured about 44 MB with every image scanned (same synthetic
  run), hence the 80 MB `--max-mb` default.

cve.now IDs are cached for 7 days, so the budget must also cover refreshes. With 5000
requests a night, roughly 35,000 IDs can be kept fresh; newly seen IDs are fetched first
and coverage grows over the backfill period (`meta.json` reports `cvenow.coverage_pct`).

## Publishing

The publish job:

1. Checks out `master` with `persist-credentials: false`, so no write credential is on disk
   while repository code runs. The job's `GITHUB_TOKEN` stays `contents: read`.
2. Downloads the `image-vulns-publish` artifact (`inventory.json` and `summary.json`;
   `scan.json` is not needed) into `vulns/out`. The artifact is data only: its
   JSON files are validated and then parsed by `vulnscan.publish` from the master checkout.
   Nothing in the artifact is executed.
3. Runs `make publish-vulns` and validates that every file under `data/vulns/` is JSON and
   that `meta.json` and `landscape.json` exist.
4. Stages `data/vulns` only. If it changed, it commits `vulns update YYYY-MM-DD` and pushes
   to master with `secrets.DAILY_UPDATE_TOKEN`, the same PAT the daily data job uses. A PAT
   push (unlike a `GITHUB_TOKEN` push) triggers `deploy-to-pages.yml`, so the site rebuilds
   with the new data. The token is only given to this final step.
5. If the push is rejected because master moved (for example the daily data job pushed in
   the meantime), it runs `git pull --rebase` and retries, up to 3 attempts in total. The
   daily job never writes `data/vulns/` and this job never writes anything else, so the
   rebase cannot conflict.

The job does not run when the scan failed, when `publish` is `false` on a manual run, when
a manual run used `scope: latest` or a `limit` (publishing rewrites every version shard and
deletes the rest, so a partial run would wipe the data of the other version pages), or when
the workflow was dispatched from a branch other than `master`. `vulnscan.publish` also
refuses to write when scanned images, versions with data or versions would drop by more
than 20% compared with the committed `meta.json` (for example a night where every scan
failed); set the `allow_drop` input to publish anyway.

## Published data

`vulnscan.publish` writes everything under `data/vulns/`, which Hugo reads as
`site.Data.vulns`. Files are sharded so that a page only looks up one small file by key,
the output is deterministic (sorted keys, one record per line) to keep git diffs small,
writes are atomic, and shards that are no longer produced are deleted.

```
data/vulns/
  meta.json                 generated_at, weights_version, trivy {version, db_updated_at},
                            cvenow {coverage_pct, requests}, images_total, images_scanned,
                            images_pending, versions_total, versions_with_data
  images/<s>.json           s = first 2 hex chars of md5(canonical image)
                            {canonical: {lvl, st, rs, os, eosl, n, kev, lk, fx, top, at}}
  versions/<s>.json         s = first 2 hex chars of md5("org/chart/<version>")
                            {key: {lvl, partial, kev, crit, high, imgs, combos, [pending]}}
  landscape.json            latest versions only: generated_at, coverage, distribution
                            {images, charts}, combos (top 25), stats
```

- Image records: `st` is `ok`, `unavailable` (with reason `rs`), `invalid` or `pending`
  (not scanned yet). `n` is `[critical, high, medium, low, unknown]`, `kev` and `lk` count
  KEV and likely-exploitable IDs, `fx` is `[fixable critical, fixable high]`, and `top` holds
  up to 8 `[id, severity, cvss, kev, likely, fixed version, package]` rows.
- Version keys use the same version string as the page file name: `json2hugo.py` strips a
  leading `v` from the chart version, so `org/chart/1.2.3` matches
  `content/charts/org/chart/1.2.3.md`. `imgs` maps each raw image string, exactly as it
  appears in the Workloads table, to its canonical reference. The page template renders
  each raw string with the page's Markdown renderer (`.RenderString`, so typographer and
  linkify changes match) to find its table cell. `pending: true` marks versions none of
  whose main images has been scanned yet; their pages show "Image risk: Pending scan".
- "Latest" means the latest stable version (prereleases are skipped unless a chart has
  only prereleases). The site's project index sorts by version number and can link a
  prerelease, so for a few charts the landscape ranks a different version than the index
  shows.
- The publish fails when `data/vulns/` exceeds `--max-mb` (80 MB by default; a fully scanned `all` scope measured about 44 MB), so the site
  build never silently grows.

## Methodology

**What is scanned.** The images in the rendered default manifests of each chart version
(the same manifests the RBAC analysis uses), linux/amd64 only. Images enabled only by
non-default values, or launched at runtime by operators, are not covered.

**Sources.** [Trivy](https://trivy.dev) (pinned version, DB date in `meta.json`) finds the
vulnerabilities in each image's SBOM. [cve.now](https://cve.now) adds CISA KEV status, the
date EPSS first reached 10% (`epss_reached`), Metasploit modules, Exploit-DB entries and
fixed versions.

**Image risk level** (first match wins):

| Level | Rule |
|---|---|
| Unknown | The image could not be scanned (not `ok`) |
| Exploited | Any vulnerability ID, or alias, is in CISA KEV (per cve.now) |
| High | Any CRITICAL or HIGH finding is *likely exploitable*: its cve.now entry has `epss_reached`, a Metasploit module or an Exploit-DB entry. A GitHub PoC or a nuclei template alone does not count. |
| Elevated | Any CRITICAL finding |
| Moderate | Any HIGH finding |
| Low | Anything else |

**Score** (`weights_version` 2, 0-100):
`min(100, round(30*min(kev,3) + 12*min(likely,3) + 3*min(critical,10) + 0.5*min(high,20)))`,
where the counts are distinct IDs in the image.

**Chart version level.** The worst level among the version's `main` images (test Pods and
Jobs are ignored). A version is `partial` when some of its images are not scanned yet or
unavailable.

**Riskiest combinations.** A combination is one workload, not one CVE: a `main` workload
whose service account has **Critical or High** RBAC risk and whose image level is
**Exploited or High**. Combinations are ranked by RBAC risk (Critical before High), then
image level (Exploited before High), then the number of KEV IDs, likely-exploitable IDs and
critical findings, then chart name.

**Caveats.** A CVE being present in an image does not mean it is exploitable in that
workload: the vulnerable code may never run, or may not be reachable. Treat the levels as a
triage signal that points at where to look first, not as proof of compromise.

## cve.now usage etiquette

cve.now is a free service that needs no API key. Please use it gently:

- **1 request per second** at most (`--rps 1.0`). In testing it started returning 403 after
  about 270 requests at 4 requests per second. At 1 request per second, 400 requests
  produced no blocks.
- **A daily budget** (`--budget`, 5000 in the workflow) caps every run, retries included.
- **Back off on 403, 429 or 5xx** for 30 s and then 60 s. The third consecutive blocked
  response stops the run with `stopped_reason: blocked`. If the site cannot be reached at
  all, the run stops after 3 attempts with `unreachable`. Either way the stage exits
  successfully and the report is built from the cache.
- **Cache everything.** Entries are refetched only after 7 days, or sooner when they
  appear in the KEV or critical feeds. `/check` responses are reused for about a day.
- Requests identify themselves with
  `User-Agent: rbac-atlas/1.0 (+https://rbac-atlas.github.io)`.

## Limitations

- **Backfill.** Until the SBOM cache covers every inventoried image (about 12 nights at
  2500 SBOMs per night), many older versions show "pending scan".
- **Re-match lag.** Images used only by older versions are re-matched weekly, so their
  CVE lists can be up to about a week behind the Trivy DB.
- **linux/amd64 only.** Images with no amd64 variant (for example Windows-only images) are
  `unavailable` with reason `no_amd64`.
- **Rendered default manifests only.** Images come from the rbac-scope manifests, which are
  rendered with the chart's default values. Images that only appear with non-default
  values, and images pulled at runtime (operators that launch other images), are missing.
- **Mutable tags.** Tags such as `latest` are resolved at scan time, and `mirror.gcr.io`
  can serve an older digest for them. Pinned digests are exact.
- **`/check` is informational.** It does not match Go stdlib CVEs and gives some false
  positives on an image's own main module. Its matches appear only as `check_only_ids` and
  never change levels or scores, and only images used by a latest version are checked.
- **cve.now data.** cve.now has no CWE field and no numeric EPSS. CWEs come from Trivy, and
  "EPSS" here means only the date EPSS first reached 10% (`epss_reached`). DLA, DSA and
  TEMP IDs are not looked up.
- **Cache growth.** Old SBOMs, cached matches, SBOM failure records and resolve entries are
  never pruned.
