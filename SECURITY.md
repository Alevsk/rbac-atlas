# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in RBAC Atlas (this repository, its build and data
pipelines, or the website), please report it privately through
[GitHub private vulnerability reporting](https://github.com/Alevsk/rbac-atlas/security/advisories/new)
(Security tab, "Report a vulnerability"). Please do not open a public issue for it.

Please include the following information:

- A description of the vulnerability
- Steps to reproduce the issue
- Potential impact
- Suggestions for remediation if any

Out of scope here:

- RBAC risks or CVEs reported for the third-party Helm charts and images that RBAC Atlas
  catalogs. Report those to the upstream project.
- Bugs in the analyzer itself. Report those to
  [rbac-scope](https://github.com/alevsk/rbac-scope).

## Response Timeline

- Initial Response: Within 48 hours
- Status Update: Within 5 business days
- Security Fix: Timeline will be communicated based on severity

## Security Updates

RBAC Atlas has no versioned releases: fixes land on the `master` branch and the website is
redeployed from it automatically. Confirmed vulnerabilities are disclosed through a GitHub
security advisory.

## Supported Versions

Only the current `master` branch and the live website receive security fixes.
