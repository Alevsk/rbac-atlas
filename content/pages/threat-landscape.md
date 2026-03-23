---
title: "Cloud-Native Threat Landscape"
description: "RBAC risk analysis across 257 Kubernetes open-source projects"
date: "2026-03-23"
---

This report is auto-generated from the latest RBAC Atlas scan (**2026-03-23**). It analyzes the RBAC permissions of **257** Kubernetes open-source projects across **25520** manifest versions to provide a snapshot of the current cloud-native threat landscape.

## At a Glance

| Metric | Value |
|--------|-------|
| Projects analyzed | 257 |
| Total manifest versions | 25520 |
| Avg service accounts per project | 2.11 |
| Avg permission bindings per project | 30.19 |
| Avg workloads per project | 3.5 |
| Avg critical risks per project | 3.52 |
| Avg high risks per project | 3.49 |
| Avg medium risks per project | 2.21 |
| Avg low risks per project | 20.97 |
| Projects with critical risks | 171 |
| Projects with no RBAC permissions | 54 |

## Risk Distribution

| Risk Level | Count | Percentage |
|------------|-------|------------|
| {{< risk "Critical" >}} | 905 | 11.66% |
| {{< risk "High" >}} | 898 | 11.57% |
| {{< risk "Medium" >}} | 568 | 7.32% |
| {{< risk "Low" >}} | 5389 | 69.45% |
| **Total** | **7760** | |

## Top 10 RBAC Risk Tags

| Risk Tag | Occurrences |
|----------|-------------|
| {{< tag "InformationDisclosure" >}} | 1107 |
| {{< tag "WildcardPermission" >}} | 938 |
| {{< tag "Tampering" >}} | 863 |
| {{< tag "ClusterWideAccess" >}} | 761 |
| {{< tag "PotentialPrivilegeEscalation" >}} | 593 |
| {{< tag "DataExposure" >}} | 528 |
| {{< tag "Reconnaissance" >}} | 525 |
| {{< tag "PrivilegeEscalation" >}} | 452 |
| {{< tag "ResourceNameRestricted" >}} | 375 |
| {{< tag "DenialOfService" >}} | 329 |

## Top 10 Triggered Risk Rules

| Rule | Occurrences |
|------|-------------|
| Base Risk Level - Low | 6822 |
| Base Risk Level - High | 758 |
| Read ConfigMaps in a namespace | 256 |
| Read secrets in a namespace | 239 |
| Read secrets cluster-wide | 191 |
| Base Risk Level - Medium | 177 |
| Read ConfigMaps cluster-wide | 162 |
| Modify ConfigMaps in a namespace | 158 |
| List Namespaces (Cluster Reconnaissance) | 143 |
| Read RBAC configuration cluster-wide | 138 |

## Top 10 Riskiest Projects

Ranked by weighted risk score (`critical×10 + high×5 + medium×2 + low×1`), using only the latest version of each project.

| Project | Version | Critical | High | Medium | Low | Score |
|---------|---------|----------|------|--------|-----|-------|
| [openebs](/charts/openebs/openebs/) | 3.9.0 | 90 | 73 | 30 | 170 | **1495** |
| [victoria-metrics-distributed](/charts/victoriametrics/victoria-metrics-distributed/) | 0.9.0 | 13 | 117 | 5 | 39 | **764** |
| [longhorn](/charts/longhorn/longhorn/) | 1.9.2 | 20 | 56 | 3 | 7 | **493** |
| [gitlab](/charts/gitlab/gitlab/) | 9.9.3 | 18 | 10 | 9 | 199 | **447** |
| [eg-universal-agent-operator](/charts/eg-universal-agent-operator/eg-universal-agent-operator/) | 0.0.5 | 16 | 24 | 8 | 64 | **360** |
| [gitlab-operator](/charts/gitlab/gitlab-operator/) | 2.9.2 | 20 | 6 | 7 | 115 | **359** |
| [kuadrant-operator](/charts/kuadrant/kuadrant-operator/) | 1.4.2 | 21 | 9 | 4 | 94 | **357** |
| [flux2](/charts/fluxcd/flux2/) | 2.9.2 | 18 | 30 | 0 | 24 | **354** |
| [victoria-metrics-k8s-stack](/charts/victoriametrics/victoria-metrics-k8s-stack/) | 0.9.8 | 13 | 17 | 5 | 98 | **323** |
| [opentelemetry-kube-stack](/charts/opentelemetry-helm/opentelemetry-kube-stack/) | 0.9.4 | 13 | 9 | 13 | 111 | **312** |

## Top 10 Projects by Permission Count

| Project | Permissions |
|---------|-------------|
| [openebs](/charts/openebs/openebs/) | 363 |
| [gitlab](/charts/gitlab/gitlab/) | 236 |
| [rook-ceph](/charts/rook-release/rook-ceph/) | 185 |
| [stackgres-operator](/charts/stackgres-charts/stackgres-operator/) | 181 |
| [victoria-metrics-distributed](/charts/victoriametrics/victoria-metrics-distributed/) | 174 |
| [gateway-operator](/charts/kong/gateway-operator/) | 162 |
| [gitlab-operator](/charts/gitlab/gitlab-operator/) | 148 |
| [opentelemetry-kube-stack](/charts/opentelemetry-helm/opentelemetry-kube-stack/) | 146 |
| [edp-install](/charts/epmdedp-dev/edp-install/) | 142 |
| [victoria-metrics-k8s-stack](/charts/victoriametrics/victoria-metrics-k8s-stack/) | 133 |

