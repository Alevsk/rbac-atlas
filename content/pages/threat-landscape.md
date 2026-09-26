---
title: "Cloud-Native Threat Landscape"
description: "RBAC risk analysis across 257 Kubernetes open-source projects"
date: "2026-09-26"
---

This report is auto-generated from the latest RBAC Atlas scan (**2026-09-26**). It analyzes the RBAC permissions of **257** Kubernetes open-source projects across **27635** manifest versions to provide a snapshot of the current cloud-native threat landscape.

## At a Glance

| Metric | Value |
|--------|-------|
| Projects analyzed | 257 |
| Total manifest versions | 27635 |
| Avg service accounts per project | 2.09 |
| Avg permission bindings per project | 31.12 |
| Avg workloads per project | 3.48 |
| Avg critical risks per project | 3.44 |
| Avg high risks per project | 3.99 |
| Avg medium risks per project | 2.03 |
| Avg low risks per project | 21.67 |
| Projects with critical risks | 170 |
| Projects with no RBAC permissions | 54 |

## Risk Distribution

| Risk Level | Count | Percentage |
|------------|-------|------------|
| {{< risk "Critical" >}} | 883 | 11.04% |
| {{< risk "High" >}} | 1025 | 12.82% |
| {{< risk "Medium" >}} | 521 | 6.51% |
| {{< risk "Low" >}} | 5569 | 69.63% |
| **Total** | **7998** | |

## Top 10 RBAC Risk Tags

| Risk Tag | Occurrences |
|----------|-------------|
| {{< tag "InformationDisclosure" >}} | 1107 |
| {{< tag "WildcardPermission" >}} | 1022 |
| {{< tag "ClusterWideAccess" >}} | 904 |
| {{< tag "Tampering" >}} | 826 |
| {{< tag "PotentialPrivilegeEscalation" >}} | 568 |
| {{< tag "DataExposure" >}} | 528 |
| {{< tag "Reconnaissance" >}} | 519 |
| {{< tag "PrivilegeEscalation" >}} | 445 |
| {{< tag "ResourceNameRestricted" >}} | 417 |
| {{< tag "DenialOfService" >}} | 319 |

## Top 10 Triggered Risk Rules

| Rule | Occurrences |
|------|-------------|
| Base Risk Level - Low | 6976 |
| Base Risk Level - High | 902 |
| Read ConfigMaps in a namespace | 252 |
| Read secrets in a namespace | 240 |
| Read secrets cluster-wide | 186 |
| Read ConfigMaps cluster-wide | 161 |
| Modify ConfigMaps in a namespace | 146 |
| List Namespaces (Cluster Reconnaissance) | 140 |
| Read RBAC configuration cluster-wide | 135 |
| Base Risk Level - Medium | 118 |

## Top 10 Riskiest Projects

Ranked by weighted risk score (`critical×10 + high×5 + medium×2 + low×1`), using only the latest version of each project.

| Project | Version | Critical | High | Medium | Low | Score |
|---------|---------|----------|------|--------|-----|-------|
| [openebs](/charts/openebs/openebs/) | 3.9.0 | 90 | 73 | 30 | 170 | **1495** |
| [victoria-metrics-k8s-stack](/charts/victoriametrics/victoria-metrics-k8s-stack/) | 0.93.0 | 14 | 173 | 5 | 38 | **1053** |
| [victoria-metrics-distributed](/charts/victoriametrics/victoria-metrics-distributed/) | 0.9.0 | 13 | 117 | 5 | 39 | **764** |
| [longhorn](/charts/longhorn/longhorn/) | 1.9.2 | 20 | 56 | 3 | 7 | **493** |
| [gitlab](/charts/gitlab/gitlab/) | 9.9.3 | 18 | 10 | 9 | 199 | **447** |
| [gitlab-operator](/charts/gitlab/gitlab-operator/) | 3.4.1 | 20 | 5 | 7 | 126 | **365** |
| [eg-universal-agent-operator](/charts/eg-universal-agent-operator/eg-universal-agent-operator/) | 0.0.5 | 16 | 24 | 8 | 64 | **360** |
| [flux2](/charts/fluxcd/flux2/) | 2.9.2 | 18 | 30 | 0 | 24 | **354** |
| [opentelemetry-kube-stack](/charts/opentelemetry-helm/opentelemetry-kube-stack/) | 0.9.4 | 13 | 9 | 13 | 111 | **312** |
| [stackgres-operator](/charts/stackgres-charts/stackgres-operator/) | 1.9.0 | 12 | 5 | 2 | 162 | **311** |

## Top 10 Projects by Permission Count

| Project | Permissions |
|---------|-------------|
| [openebs](/charts/openebs/openebs/) | 363 |
| [gitlab](/charts/gitlab/gitlab/) | 236 |
| [victoria-metrics-k8s-stack](/charts/victoriametrics/victoria-metrics-k8s-stack/) | 230 |
| [rook-ceph](/charts/rook-release/rook-ceph/) | 185 |
| [stackgres-operator](/charts/stackgres-charts/stackgres-operator/) | 181 |
| [victoria-metrics-distributed](/charts/victoriametrics/victoria-metrics-distributed/) | 174 |
| [tigera-operator](/charts/stevehipwell/tigera-operator/) | 169 |
| [gateway-operator](/charts/kong/gateway-operator/) | 162 |
| [gitlab-operator](/charts/gitlab/gitlab-operator/) | 158 |
| [opentelemetry-kube-stack](/charts/opentelemetry-helm/opentelemetry-kube-stack/) | 146 |

