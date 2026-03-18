# RBAC Atlas Report

Generates aggregated security insights from RBAC Atlas manifest data.

## Quick Start

```bash
# From the report/ directory
uv run report.py
```

This reads all JSON manifests from `../manifests/` and produces two files:

| File | Description |
|------|-------------|
| `rbac_report.csv` | One row per manifest version — flat table of metadata + risk counts |
| `rbac_report.json` | Aggregated insights: top risks, riskiest projects, summary stats |

## CLI Options

```bash
uv run report.py --manifests /path/to/manifests   # custom input directory
uv run report.py --output-dir /path/to/output      # custom output directory
```

## JSON Report Structure

### `top_10_risk_tags`

Most frequently observed risk tags across all scanned manifest versions (e.g. `InformationDisclosure`, `PrivilegeEscalation`, `SecretAccess`).

```json
{ "tag_name": occurrence_count }
```

### `top_10_risk_rules`

Most frequently triggered `rbac-scope` detection rules.

```json
{ "rule_name": occurrence_count }
```

### `top_10_riskiest_projects`

Projects ranked by a weighted risk score (`critical*10 + high*5 + medium*2 + low*1`), using only the latest version of each project.

```json
{
  "project_name": {
    "version": "x.y.z",
    "critical": N,
    "high": N,
    "medium": N,
    "low": N,
    "risk_score": N
  }
}
```

### `top_10_most_permissions`

Projects with the highest number of RBAC permission entries (latest version).

```json
{ "project_name": permission_count }
```

### `summary`

Averages computed across the latest version of each unique project:

- `total_manifest_versions` — total JSON files processed
- `unique_projects` — distinct project names
- `avg_service_accounts` — average service accounts per project
- `avg_permissions` — average permission bindings per project
- `avg_workloads` — average workloads per project
- `avg_critical_risks` / `avg_high_risks` / `avg_medium_risks` / `avg_low_risks`

### `risk_distribution`

Total and percentage breakdown of risk levels across all unique projects (latest version).

### Other Fields

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

The report is built in layers — extend `aggregate()` in `report.py` to add new insights. The function receives fully parsed records with access to raw `_tags` and `_rule_names` lists, so you can compute any aggregation without re-reading the manifests.
