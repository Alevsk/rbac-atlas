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

## Contributing

Because this is a statically generated website, please contribute changes in the upstream repositories:

- rbac-scope (main tool and policy analyzer): send improvements via Pull Request at https://github.com/alevsk/rbac-scope. Submit new or updated detection rules, parsers, annotations, and fixes there. Changes will be reflected here on the next site publish.
- Propose new Kubernetes open-source projects to be tracked: open an issue or PR at https://github.com/alevsk/rbac-atlas.

If you spot a small issue in these generated pages (e.g., a typo), you can also open an issue in this repository.

## Contact

RBAC Atlas is a collaborative project created by Lenin Alevski.

- LinkedIn: https://www.linkedin.com/in/alevsk/
- X/Twitter: https://twitter.com/alevsk

## Disclaimer

RBAC Atlas is provided for educational and operational awareness purposes. Always validate RBAC configurations against your organization's security requirements and test them in your environment before deploying to production.
