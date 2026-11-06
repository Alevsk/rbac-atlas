# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial project setup
- Basic Hugo configuration
- Docker deployment support
- CI/CD pipeline with GitHub Actions
- Documentation framework
- Daily threat landscape report and time-series data
- Container image vulnerability scan (Trivy + cve.now) shown on chart version pages, the
  home page and the threat landscape page

### Changed
- CI no longer builds or pushes a Docker image; the `Dockerfile` is kept for local use and
  the dev container. Base images are pinned by version and digest, the runtime runs on
  unprivileged nginx, and the build context is an allowlist.
