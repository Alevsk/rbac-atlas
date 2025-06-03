---
title: "Token Automount"
description: "Token automount is a feature that allows a ServiceAccount to automatically mount a token into a pod."
---

## Why is token automount a security risk?

Token automount on service accounts presents a security risk primarily because, by default, every pod automatically receives a service account token that grants it certain permissions within the cluster. If a pod is compromised, an attacker can leverage this automounted token to escalate privileges, access sensitive information, or interact with other Kubernetes API objects, even if the pod itself doesn't explicitly require API access. This broad default access increases the attack surface and makes it easier for an attacker to move laterally within the cluster, highlighting the importance of disabling automount for pods that don't need API access and implementing fine-grained RBAC policies.

## References

- [Opt out of API credential automounting](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/#opt-out-of-api-credential-automounting)
