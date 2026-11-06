# Contributing to RBAC Atlas

We love your input! We want to make contributing to RBAC Atlas as easy and transparent as possible.

Most of the site is generated: chart pages under `content/charts/`, `manifests/`, `reports/`
and `data/` are rewritten by the scheduled workflows, so please do not edit them by hand.
To track a new project, edit `projects.yaml` (see the [README](README.md#addupdate-tracked-projects)).
Analyzer and rule changes belong in [rbac-scope](https://github.com/alevsk/rbac-scope).

## Development Process

1. Fork the repo and create your branch from `master`.
2. If you've added code that should be tested, add tests.
3. If you've changed behavior, update the documentation.
4. Ensure the test suite passes: `make test-python` (and `make test` for site changes,
   with `make serve` running).
5. Make sure your code lints: `make lint`.
6. Issue that pull request!

See [DEVELOPMENT.md](DEVELOPMENT.md) for the local setup.

## Pull Request Process

1. Update the README.md with details of changes if applicable.
2. Add notable changes to CHANGELOG.md under `Unreleased`, following the Keep a Changelog format.
3. The PR will be merged once you have the sign-off of at least one maintainer.

## Any contributions you make will be under the MIT Software License

In short, when you submit code changes, your submissions are understood to be under the same [MIT License](LICENSE) that covers the project. Feel free to contact the maintainers if that's a concern.
