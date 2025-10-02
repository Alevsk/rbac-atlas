# RBAC ATLAS

_A curated index of RBAC policies in Kubernetes_

## Overview

RBAC Atlas is a curated database of identities and the Role Based Access Control (RBAC) policies associated with them across popular Kubernetes open-source projects. Each entry includes security annotations that highlight granted permissions, potential risks, and possible abuse scenarios.

Why this matters: RBAC is the final layer of defense in Kubernetes. If a workload is compromised and an identity is stolen, a misconfigured or overly permissive RBAC policy (common with operators and controllers) can enable lateral movement and, in the worst case, a full cluster takeover. RBAC Atlas helps practitioners quickly understand these risks before deploying.

- Website: https://rbac-atlas.github.io/
- Browse by categories: https://rbac-atlas.github.io/categories/
- Browse by risks/tags: https://rbac-atlas.github.io/tags/

## Who It's For

- Platform/SRE teams evaluating third-party charts and operators
- Security engineers performing RBAC reviews and threat modeling
- Developers who need clear, actionable summaries of granted permissions

## Risk Annotations

Each entry includes:

- A severity snapshot (Critical/High/Medium/Low)
- A short description of the chart/component
- Tags that summarize key capabilities and potential abuse paths (e.g., `ClusterWideAccess`, `SecretAccess`, `PodExec`)

## Add/Update Tracked Projects

RBAC Atlas analyzes Helm charts and OCI artifacts defined in `projects.yaml`. To propose a new project or update an existing one, open a Pull Request modifying `projects.yaml` with the appropriate section:

1) Helm repositories (`helm_repos`):

```yaml
helm_repos:
  - name: example
    url: https://charts.example.com
    charts:
      - name: example-operator            # required
        version: 1.2.3                    # optional, latest used if omitted
        values: charts/custom-values/example-operator.yaml  # optional
        keywords: [operator, example]     # optional, used for search/labels
```

2) OCI Helm repositories (`oci_repos`):

```yaml
oci_repos:
  - name: my-oci
    url: oci://ghcr.io/org/charts
    charts:
      - name: my-operator
```

3) Direct OCI chart references (`oci_charts`):

```yaml
oci_charts:
  - name: pulumi-kubernetes-operator
    uri: oci://ghcr.io/pulumi/helm-charts/pulumi-kubernetes-operator
```

Notes:
- `values` is optional and lets you provide a custom values file that will be copied into the chart folder as `custom-values.yaml` and used during analysis.
- If `version` is omitted, the latest version found in the repo index is used.
- After a PR is merged, the site will be regenerated and the new/updated project will appear on the next publish.

## How It Works

Automation keeps the catalog fresh via GitHub Actions:

- Daily scan: a scheduled workflow runs every day at 00:00 UTC and regenerates content from the projects listed in `projects.yaml`. It:
  - Checks out this repo and the latest `rbac-scope` sources (copies `risks.yaml`).
  - Sets up Python/Node/Helm and builds the `rbac-scope` binary.
  - Executes the pipeline: `make pull-projects`, `make get-manifests`, `make generate-pages`.
  - Commits and pushes changes back to `master` if anything changed.
  - Workflow file: `.github/workflows/daily-update.yml`.

- Publish site: on push to `master`, another workflow builds the Hugo site and deploys it to the `rbac-atlas/rbac-atlas.github.io` repository (GitHub Pages).
  - Workflow file: `.github/workflows/deploy-to-pages.yml`.

- CI checks: a CI workflow lints and builds on pushes and pull requests.
  - Workflow file: `.github/workflows/ci.yml`.

## Contributing

Because the public website is statically generated, please contribute in the following places:

- rbac-scope (main tool and policy analyzer): send improvements via Pull Request at https://github.com/alevsk/rbac-scope. Submit new or updated detection rules, parsers, annotations, and fixes there. Changes will be reflected here on the next site publish.
- Propose new Kubernetes open-source projects to be tracked: open an issue or PR editing `projects.yaml` in this repository.
- If you spot a small issue in these generated pages (e.g., a typo), you can also open an issue here.

See also: [CONTRIBUTING.md](CONTRIBUTING.md).

## Development

For local setup, data pipeline, and running the site, see [DEVELOPMENT.md](DEVELOPMENT.md).

## Security

For security concerns, please see our [Security Policy](SECURITY.md).

## Contact

RBAC Atlas is a collaborative project created by Lenin Alevski.

- LinkedIn: https://www.linkedin.com/in/alevsk/
- X/Twitter: https://twitter.com/alevsk

## Disclaimer

RBAC Atlas is provided for educational and operational awareness purposes. Always validate RBAC configurations against your organization's security requirements and test them in your environment before deploying to production.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
