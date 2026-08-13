---
title: "Cloud-Native Threat Landscape"
description: "RBAC risk analysis across 257 Kubernetes open-source projects"
date: "2026-08-13"
---

This report is auto-generated from the latest RBAC Atlas scan (**2026-08-13**). It analyzes the RBAC permissions of **257** Kubernetes open-source projects across **27149** manifest versions to provide a snapshot of the current cloud-native threat landscape.

## At a Glance

| Metric | Value |
|--------|-------|
| Projects analyzed | 257 |
| Total manifest versions | 27149 |
| Avg service accounts per project | 2.11 |
| Avg permission bindings per project | 31.19 |
| Avg workloads per project | 3.47 |
| Avg critical risks per project | 3.5 |
| Avg high risks per project | 4.0 |
| Avg medium risks per project | 2.23 |
| Avg low risks per project | 21.46 |
| Projects with critical risks | 171 |
| Projects with no RBAC permissions | 54 |

## Risk Distribution

| Risk Level | Count | Percentage |
|------------|-------|------------|
| {{< risk "Critical" >}} | 899 | 11.22% |
| {{< risk "High" >}} | 1028 | 12.83% |
| {{< risk "Medium" >}} | 572 | 7.14% |
| {{< risk "Low" >}} | 5516 | 68.82% |
| **Total** | **8015** | |

## Top 10 RBAC Risk Tags

| Risk Tag | Occurrences |
|----------|-------------|
| {{< tag "InformationDisclosure" >}} | 1121 |
| {{< tag "WildcardPermission" >}} | 1072 |
| {{< tag "ClusterWideAccess" >}} | 902 |
| {{< tag "Tampering" >}} | 845 |
| {{< tag "PotentialPrivilegeEscalation" >}} | 580 |
| {{< tag "DataExposure" >}} | 538 |
| {{< tag "Reconnaissance" >}} | 523 |
| {{< tag "PrivilegeEscalation" >}} | 436 |
| {{< tag "ResourceNameRestricted" >}} | 385 |
| {{< tag "DenialOfService" >}} | 325 |

## Top 10 Triggered Risk Rules

| Rule | Occurrences |
|------|-------------|
| Base Risk Level - Low | 6943 |
| Base Risk Level - High | 900 |
| Read ConfigMaps in a namespace | 259 |
| Read secrets in a namespace | 244 |
| Read secrets cluster-wide | 190 |
| Base Risk Level - Medium | 170 |
| Read ConfigMaps cluster-wide | 162 |
| Modify ConfigMaps in a namespace | 154 |
| List Namespaces (Cluster Reconnaissance) | 142 |
| Read RBAC configuration cluster-wide | 137 |

## Top 10 Riskiest Projects

Ranked by weighted risk score (`critical×10 + high×5 + medium×2 + low×1`), using only the latest version of each project.

| Project | Version | Critical | High | Medium | Low | Score |
|---------|---------|----------|------|--------|-----|-------|
| [openebs](/charts/openebs/openebs/) | 3.9.0 | 90 | 73 | 30 | 170 | **1495** |
| [victoria-metrics-k8s-stack](/charts/victoriametrics/victoria-metrics-k8s-stack/) | 0.90.2 | 14 | 173 | 5 | 38 | **1053** |
| [victoria-metrics-distributed](/charts/victoriametrics/victoria-metrics-distributed/) | 0.9.0 | 13 | 117 | 5 | 39 | **764** |
| [longhorn](/charts/longhorn/longhorn/) | 1.9.2 | 20 | 56 | 3 | 7 | **493** |
| [gitlab](/charts/gitlab/gitlab/) | 9.9.3 | 18 | 10 | 9 | 199 | **447** |
| [kuadrant-operator](/charts/kuadrant/kuadrant-operator/) | 1.5.2-rc1 | 21 | 9 | 4 | 103 | **366** |
| [gitlab-operator](/charts/gitlab/gitlab-operator/) | 3.2.2 | 20 | 5 | 7 | 124 | **363** |
| [eg-universal-agent-operator](/charts/eg-universal-agent-operator/eg-universal-agent-operator/) | 0.0.5 | 16 | 24 | 8 | 64 | **360** |
| [flux2](/charts/fluxcd/flux2/) | 2.9.2 | 18 | 30 | 0 | 24 | **354** |
| [opentelemetry-kube-stack](/charts/opentelemetry-helm/opentelemetry-kube-stack/) | 0.9.4 | 13 | 9 | 13 | 111 | **312** |

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
| [gitlab-operator](/charts/gitlab/gitlab-operator/) | 156 |
| [opentelemetry-kube-stack](/charts/opentelemetry-helm/opentelemetry-kube-stack/) | 146 |

