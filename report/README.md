# RBAC Atlas Report

Generates aggregated security insights from RBAC Atlas manifest data and publishes them as a Hugo page on the RBAC Atlas website.

## How It Works

```
manifests/*.json
       │
       ▼
  report/report.py ──► report/rbac_report.csv   (flat per-manifest data)
       │
       ▼
  reports/YYYY-MM-DD.json   (dated snapshot, accumulates daily)
       │
       ▼
  report2hugo.py ──► content/pages/threat-landscape.md   (Hugo page)
```

The daily GitHub Actions workflow runs `make generate-report`, which:
1. Parses all manifests and writes a dated JSON snapshot to `reports/`
2. Converts the latest snapshot into a Hugo Markdown page

Over time, `reports/` accumulates daily snapshots for time-series analysis.

## Quick Start

```bash
# From the project root
make generate-report

# Or run the steps manually
uv run python report/report.py                    # generates CSV + dated JSON
uv run python report2hugo.py -f reports/ -o content/  # generates Hugo page
```

## CLI Options

### report.py

```bash
uv run python report/report.py --manifests /path    # custom manifests dir
uv run python report/report.py --reports-dir /path   # custom reports output dir
uv run python report/report.py --csv-dir /path       # custom CSV output dir
uv run python report/report.py --date 2026-01-15     # override snapshot date
```

### report2hugo.py

```bash
uv run python report2hugo.py -f reports/ -o content/  # default
uv run python report2hugo.py -f /path/to/reports      # custom reports dir
```

## Output Files

| File | Location | Description |
|------|----------|-------------|
| `rbac_report.csv` | `report/` | One row per manifest version (flat) |
| `YYYY-MM-DD.json` | `reports/` | Dated aggregation snapshot (git-tracked, accumulates) |
| `threat-landscape.md` | `content/pages/` | Hugo page generated from the latest snapshot |

## JSON Snapshot Structure

Each `reports/YYYY-MM-DD.json` contains:

- `date` — snapshot date
- `top_10_risk_tags` — most observed risk tags (latest version per project)
- `top_10_risk_rules` — most triggered detection rules
- `top_10_riskiest_projects` — ranked by weighted score (`critical×10 + high×5 + medium×2 + low×1`)
- `top_10_most_permissions` — projects with most RBAC permission entries
- `summary` — averages across all unique projects (service accounts, permissions, workloads, risk levels)
- `risk_distribution` — total and percentage breakdown by risk level
- `projects_with_no_permissions` — count of projects with zero RBAC permissions
- `projects_with_critical_risks` — count of projects with at least one critical risk

## CSV Columns

| Column | Description |
|--------|-------------|
| `source_file` | Manifest filename |
| `project_name` | Helm chart / project name |
| `version` | Chart version |
| `source` | Source path |
| `helm_description` | Chart description from Helm metadata |
| `helm_home` | Project homepage |
| `service_account_count` | Number of service accounts defined |
| `permission_count` | Number of RBAC permission entries |
| `workload_count` | Number of workloads using those service accounts |
| `risk_critical` | Count of critical-level permissions |
| `risk_high` | Count of high-level permissions |
| `risk_medium` | Count of medium-level permissions |
| `risk_low` | Count of low-level permissions |

## Adding New Metrics

Extend `aggregate()` in `report/report.py` to add new insights. The function receives fully parsed records with access to raw `_tags` and `_rule_names` lists. Then update `build_markdown()` in `report2hugo.py` to render the new data on the Hugo page.
