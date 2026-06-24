---
title: "Cloud-Native Threat Landscape"
description: "RBAC risk analysis across 257 Kubernetes open-source projects"
date: "2026-06-24"
---

This report is auto-generated from the latest RBAC Atlas scan (**2026-06-24**). It analyzes the RBAC permissions of **257** Kubernetes open-source projects across **26567** manifest versions to provide a snapshot of the current cloud-native threat landscape.

## At a Glance

| Metric | Value |
|--------|-------|
| Projects analyzed | 257 |
| Total manifest versions | 26567 |
| Avg service accounts per project | 2.11 |
| Avg permission bindings per project | 30.72 |
| Avg workloads per project | 3.47 |
| Avg critical risks per project | 3.5 |
| Avg high risks per project | 3.39 |
| Avg medium risks per project | 2.24 |
| Avg low risks per project | 21.59 |
| Projects with critical risks | 171 |
| Projects with no RBAC permissions | 54 |

## Risk Distribution

| Risk Level | Count | Percentage |
|------------|-------|------------|
| {{< risk "Critical" >}} | 900 | 11.4% |
| {{< risk "High" >}} | 871 | 11.03% |
| {{< risk "Medium" >}} | 576 | 7.3% |
| {{< risk "Low" >}} | 5548 | 70.27% |
| **Total** | **7895** | |

## Top 10 RBAC Risk Tags

| Risk Tag | Occurrences |
|----------|-------------|
| {{< tag "InformationDisclosure" >}} | 1119 |
| {{< tag "WildcardPermission" >}} | 914 |
| {{< tag "Tampering" >}} | 846 |
| {{< tag "ClusterWideAccess" >}} | 737 |
| {{< tag "PotentialPrivilegeEscalation" >}} | 582 |
| {{< tag "DataExposure" >}} | 539 |
| {{< tag "Reconnaissance" >}} | 523 |
| {{< tag "PrivilegeEscalation" >}} | 438 |
| {{< tag "ResourceNameRestricted" >}} | 385 |
| {{< tag "DenialOfService" >}} | 325 |

## Top 10 Triggered Risk Rules

| Rule | Occurrences |
|------|-------------|
| Base Risk Level - Low | 6981 |
| Base Risk Level - High | 735 |
| Read ConfigMaps in a namespace | 260 |
| Read secrets in a namespace | 244 |
| Read secrets cluster-wide | 190 |
| Base Risk Level - Medium | 177 |
| Read ConfigMaps cluster-wide | 162 |
| Modify ConfigMaps in a namespace | 156 |
| List Namespaces (Cluster Reconnaissance) | 142 |
| Read RBAC configuration cluster-wide | 137 |

## Top 10 Riskiest Projects

Ranked by weighted risk score (`critical×10 + high×5 + medium×2 + low×1`), using only the latest version of each project.

| Project | Version | Critical | High | Medium | Low | Score |
|---------|---------|----------|------|--------|-----|-------|
| [openebs](/charts/openebs/openebs/) | 3.9.0 | 90 | 73 | 30 | 170 | **1495** |
| [victoria-metrics-distributed](/charts/victoriametrics/victoria-metrics-distributed/) | 0.9.0 | 13 | 117 | 5 | 39 | **764** |
| [longhorn](/charts/longhorn/longhorn/) | 1.9.2 | 20 | 56 | 3 | 7 | **493** |
| [gitlab](/charts/gitlab/gitlab/) | 9.9.3 | 18 | 10 | 9 | 199 | **447** |
| [gitlab-operator](/charts/gitlab/gitlab-operator/) | 3.1.0 | 20 | 5 | 7 | 124 | **363** |
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

