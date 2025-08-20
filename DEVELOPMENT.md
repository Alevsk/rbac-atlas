# Development Guide

## Prerequisites

- Python 3.x
- Make
- Helm
- Docker (optional)

## Python Environment Setup

1. Create a virtual environment:

   ```bash
   python -m venv .venv
   ```

2. Activate the virtual environment:
   - Linux/macOS:

     ```bash
     source .venv/bin/activate
     ```

   - Windows:

     ```bash
     .venv\Scripts\activate
     ```

3. Install dependencies:

   ```bash
   pip install -r requirements.txt
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
