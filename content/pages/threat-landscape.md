---
title: "Cloud-Native Threat Landscape"
description: "RBAC risk analysis across 257 Kubernetes open-source projects"
date: "2026-05-15"
---

This report is auto-generated from the latest RBAC Atlas scan (**2026-05-15**). It analyzes the RBAC permissions of **257** Kubernetes open-source projects across **26123** manifest versions to provide a snapshot of the current cloud-native threat landscape.

## At a Glance

| Metric | Value |
|--------|-------|
| Projects analyzed | 257 |
| Total manifest versions | 26123 |
| Avg service accounts per project | 2.11 |
| Avg permission bindings per project | 30.66 |
| Avg workloads per project | 3.49 |
| Avg critical risks per project | 3.54 |
| Avg high risks per project | 3.46 |
| Avg medium risks per project | 2.24 |
| Avg low risks per project | 21.42 |
| Projects with critical risks | 171 |
| Projects with no RBAC permissions | 54 |

## Risk Distribution

| Risk Level | Count | Percentage |
|------------|-------|------------|
| {{< risk "Critical" >}} | 911 | 11.56% |
| {{< risk "High" >}} | 888 | 11.27% |
| {{< risk "Medium" >}} | 575 | 7.3% |
| {{< risk "Low" >}} | 5506 | 69.87% |
| **Total** | **7880** | |

## Top 10 RBAC Risk Tags

| Risk Tag | Occurrences |
|----------|-------------|
| {{< tag "InformationDisclosure" >}} | 1118 |
| {{< tag "WildcardPermission" >}} | 928 |
| {{< tag "Tampering" >}} | 867 |
| {{< tag "ClusterWideAccess" >}} | 751 |
| {{< tag "PotentialPrivilegeEscalation" >}} | 595 |
| {{< tag "Reconnaissance" >}} | 536 |
| {{< tag "DataExposure" >}} | 530 |
| {{< tag "PrivilegeEscalation" >}} | 453 |
| {{< tag "ResourceNameRestricted" >}} | 395 |
| {{< tag "DenialOfService" >}} | 331 |

## Top 10 Triggered Risk Rules

| Rule | Occurrences |
|------|-------------|
| Base Risk Level - Low | 6952 |
| Base Risk Level - High | 748 |
| Read ConfigMaps in a namespace | 257 |
| Read secrets in a namespace | 240 |
| Read secrets cluster-wide | 190 |
| Base Risk Level - Medium | 177 |
| Read ConfigMaps cluster-wide | 163 |
| Modify ConfigMaps in a namespace | 159 |
| List Namespaces (Cluster Reconnaissance) | 146 |
| Read RBAC configuration cluster-wide | 142 |

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
| [tigera-operator](/charts/stevehipwell/tigera-operator/) | 167 |
| [gateway-operator](/charts/kong/gateway-operator/) | 162 |
| [gitlab-operator](/charts/gitlab/gitlab-operator/) | 148 |
| [opentelemetry-kube-stack](/charts/opentelemetry-helm/opentelemetry-kube-stack/) | 146 |
| [edp-install](/charts/epmdedp-dev/edp-install/) | 142 |

