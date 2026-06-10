---
title: "Cloud-Native Threat Landscape"
description: "RBAC risk analysis across 257 Kubernetes open-source projects"
date: "2026-06-10"
---

This report is auto-generated from the latest RBAC Atlas scan (**2026-06-10**). It analyzes the RBAC permissions of **257** Kubernetes open-source projects across **26410** manifest versions to provide a snapshot of the current cloud-native threat landscape.

## At a Glance

| Metric | Value |
|--------|-------|
| Projects analyzed | 257 |
| Total manifest versions | 26410 |
| Avg service accounts per project | 2.11 |
| Avg permission bindings per project | 30.79 |
| Avg workloads per project | 3.47 |
| Avg critical risks per project | 3.56 |
| Avg high risks per project | 3.47 |
| Avg medium risks per project | 2.26 |
| Avg low risks per project | 21.5 |
| Projects with critical risks | 171 |
| Projects with no RBAC permissions | 54 |

## Risk Distribution

| Risk Level | Count | Percentage |
|------------|-------|------------|
| {{< risk "Critical" >}} | 916 | 11.57% |
| {{< risk "High" >}} | 892 | 11.27% |
| {{< risk "Medium" >}} | 580 | 7.33% |
| {{< risk "Low" >}} | 5526 | 69.83% |
| **Total** | **7914** | |

## Top 10 RBAC Risk Tags

| Risk Tag | Occurrences |
|----------|-------------|
| {{< tag "InformationDisclosure" >}} | 1126 |
| {{< tag "WildcardPermission" >}} | 927 |
| {{< tag "Tampering" >}} | 872 |
| {{< tag "ClusterWideAccess" >}} | 750 |
| {{< tag "PotentialPrivilegeEscalation" >}} | 599 |
| {{< tag "Reconnaissance" >}} | 537 |
| {{< tag "DataExposure" >}} | 532 |
| {{< tag "PrivilegeEscalation" >}} | 457 |
| {{< tag "ResourceNameRestricted" >}} | 395 |
| {{< tag "DenialOfService" >}} | 332 |

## Top 10 Triggered Risk Rules

| Rule | Occurrences |
|------|-------------|
| Base Risk Level - Low | 6987 |
| Base Risk Level - High | 748 |
| Read ConfigMaps in a namespace | 257 |
| Read secrets in a namespace | 240 |
| Read secrets cluster-wide | 190 |
| Base Risk Level - Medium | 177 |
| Read ConfigMaps cluster-wide | 163 |
| Modify ConfigMaps in a namespace | 159 |
| List Namespaces (Cluster Reconnaissance) | 145 |
| Read RBAC configuration cluster-wide | 143 |

## Top 10 Riskiest Projects

Ranked by weighted risk score (`critical×10 + high×5 + medium×2 + low×1`), using only the latest version of each project.

| Project | Version | Critical | High | Medium | Low | Score |
|---------|---------|----------|------|--------|-----|-------|
| [openebs](/charts/openebs/openebs/) | 3.9.0 | 90 | 73 | 30 | 170 | **1495** |
| [victoria-metrics-distributed](/charts/victoriametrics/victoria-metrics-distributed/) | 0.9.0 | 13 | 117 | 5 | 39 | **764** |
| [longhorn](/charts/longhorn/longhorn/) | 1.9.2 | 20 | 56 | 3 | 7 | **493** |
| [gitlab](/charts/gitlab/gitlab/) | 9.9.3 | 18 | 10 | 9 | 199 | **447** |
| [gitlab-operator](/charts/gitlab/gitlab-operator/) | 3.0.1 | 20 | 6 | 7 | 123 | **367** |
| [eg-universal-agent-operator](/charts/eg-universal-agent-operator/eg-universal-agent-operator/) | 0.0.5 | 16 | 24 | 8 | 64 | **360** |
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
| [tigera-operator](/charts/stevehipwell/tigera-operator/) | 167 |
| [gateway-operator](/charts/kong/gateway-operator/) | 162 |
| [gitlab-operator](/charts/gitlab/gitlab-operator/) | 156 |
| [opentelemetry-kube-stack](/charts/opentelemetry-helm/opentelemetry-kube-stack/) | 146 |
| [edp-install](/charts/epmdedp-dev/edp-install/) | 142 |

