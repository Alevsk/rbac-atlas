# Development Guide

## Prerequisites

- [uv](https://docs.astral.sh/uv/) (Python package manager)
- Make
- Helm
- Docker (optional)

## Python Environment Setup

1. Install uv:

   ```bash
   curl -LsSf https://astral.sh/uv/install.sh | sh
   ```

2. Install dependencies:

   ```bash
   uv sync
   ```

   Or using make:

   ```bash
   make install
   ```

## Development Workflow

1. Trigger update workflow to generate new findings:

   ```bash
   make update
   ```

2. Build static site:

   ```bash
   make build      # Development build
   make build-prod # Production build
   ```

3. Start development server:

   ```bash
   make serve
   ```

4. Run tests:

   ```bash
   make test
   ```

## Docker Development

```bash
make docker        # Build container
docker run -it --rm --name rbac-atlas -p 8080:8080 rbac-atlas:latest
```

## Project Structure

- `content/`: Hugo content files
- `layouts/`: Hugo templates
- `static/`: Static assets
- `scripts/`: Python scripts for data processing
- `manifests/`: Generated RBAC manifests
