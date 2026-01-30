# Makefile for the RBAC Atlas Website
#
# This Makefile automates common development tasks such as building the site,
# running tests, formatting code, and managing project-specific data pipelines.
# It is designed to be clear, maintainable, and easy to use.

# ==============================================================================
# Help Target - Provides self-documentation for the Makefile.
#
# By default, running "make" will display this help message.
# The help text is generated automatically from the double-commented (##@) lines.
# ==============================================================================
.DEFAULT_GOAL := help

.PHONY: help
help: ##@ Help
	@awk 'BEGIN {FS = ":.*?##@ "} /^[a-zA-Z_0-9-]+:.*?##@ / {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# ==============================================================================
# Variables & Configuration
#
# Centralize configuration here. Avoid hardcoding values in the recipes.
# ==============================================================================

# --- Application Configuration ---
DOCKER_IMAGE   := rbac-atlas
DOCKER_TAG     := latest
HUGO_PORT      := 1313

# --- Tooling ---
# Use variables for commands to allow for easy overrides and environment flexibility.
SHELL          := /bin/bash
UV             := uv
HUGO           := hugo
PYTHON         := $(UV) run python
NPM            := npm
NPX            := npx
DOCKER         := docker
DJLINT         := $(UV) run djlint
PAGEFIND       := $(UV) run python -m pagefind

# --- Directories & Paths ---
# Define paths to avoid repetition and make cleaning more precise.
PUBLIC_DIR     := public
RESOURCES_DIR  := resources
NODE_MODULES   := node_modules
MANIFESTS_DIR  := manifests
CONTENT_DIR    := content
PLAYWRIGHT_REPORT := playwright-report

# --- Flags & Arguments ---
# Use variables for flags to centralize logic.
# HUGO_ARGS can be overridden from the command line, e.g., `make build HUGO_ARGS="..."`
HUGO_ARGS      ?=

# Parameter for forcing regeneration of pages. Usage: `make generate-pages FORCE=true`
J2H_SCRIPT     := json2hugo.py
J2H_FLAGS      := -f $(MANIFESTS_DIR)/ -o $(CONTENT_DIR)/
ifeq ($(FORCE),true)
	J2H_FLAGS += --force
endif
ifdef J2H_WORKERS
	J2H_FLAGS += --max-workers $(J2H_WORKERS)
endif
ifeq ($(VERBOSE),true)
	J2H_FLAGS += --verbose
endif


# ==============================================================================
# Primary Targets
# ==============================================================================
.PHONY: all build build-prod serve

all: build ##@ Build the site for development (alias for 'build')

build: fmt lint pre-build ##@ Build the static site for development (formats, lints, then builds)

build-prod: ##@ Build the static site for production
	@echo "INFO: Building site for production..."
	$(MAKE) build HUGO_ARGS="--config config.toml,config.production.toml"

serve: ##@ Start the Hugo development server with live reload
	@echo "INFO: Starting Hugo server on http://localhost:$(HUGO_PORT)"
	$(HUGO) server -D --bind 0.0.0.0 -p $(HUGO_PORT)


# ==============================================================================
# Sub-Targets & Steps
#
# These are the building blocks for the primary targets.
# ==============================================================================
.PHONY: pre-build
pre-build:
	@echo "INFO: Generating static site with Hugo..."
	$(HUGO) --minify $(HUGO_ARGS)
	@echo "INFO: Building Pagefind search index..."
	$(PAGEFIND) --site $(PUBLIC_DIR)


# ==============================================================================
# Code Quality & Testing
# ==============================================================================
.PHONY: fmt fmt-all lint lint-all test cover

fmt: ##@ Format changed source files (use 'fmt-all' for everything)
	@echo "INFO: Formatting changed Markdown files..."
	@$(NPM) run fmt:changed --silent
	@echo "INFO: Formatting HTML layout files..."
	@$(DJLINT) --reformat --quiet layouts/**/*.html

fmt-all: ##@ Format all source files (Markdown, Go Templates, HTML)
	@echo "INFO: Formatting all Markdown files..."
	@$(NPM) run fmt --silent
	@echo "INFO: Formatting HTML layout files..."
	@$(DJLINT) --reformat layouts/**/*.html

lint: ##@ Lint changed source files (use 'lint-all' for everything)
	@echo "INFO: Linting changed Markdown files..."
	@$(NPM) run lint:changed --silent
	@echo "INFO: Linting HTML layout files..."
	@$(DJLINT) --check --quiet layouts/**/*.html

lint-all: ##@ Lint all source files for formatting issues
	@echo "INFO: Linting all Markdown files..."
	@$(NPM) run lint --silent
	@echo "INFO: Linting HTML layout files..."
	@$(DJLINT) --check layouts/**/*.html

test: ##@ Run Playwright end-to-end tests
	@echo "INFO: Running Playwright tests..."
	@$(NPM) run test

cover: ##@ Run tests and generate an HTML coverage report
	@echo "INFO: Running tests and generating HTML report..."
	@$(NPX) playwright test --reporter=html
	@echo "INFO: Report available at $(PLAYWRIGHT_REPORT)/index.html"


# ==============================================================================
# Project-Specific Data Pipeline
#
# These targets manage fetching Helm charts and generating content from them.
# ==============================================================================
.PHONY: update pull-projects get-manifests generate-pages check-manifests

update: pull-projects get-manifests generate-pages ##@ Full data pipeline: pull projects, analyze manifests, generate pages

pull-projects: ##@ Pull remote project sources defined in projects.yaml
	@echo "INFO: Pulling project sources..."
	@$(UV) run pull_projects.py -c projects.yaml $(PULL_ARGS)

get-manifests: ##@ Analyze Helm charts to generate JSON manifests (use FORCE=true to regenerate all)
	@echo "INFO: Fetching and analyzing manifests from Helm charts..."
	@# Complex shell logic is moved to an external script for clarity.
	@# This makes the Makefile cleaner and the script more maintainable and testable.
	@FORCE=$(FORCE) scripts/get_manifests.sh

check-manifests: ##@ Report charts with missing or invalid JSON manifests
	@$(UV) run check_manifests.py --charts-dir charts --manifests-dir $(MANIFESTS_DIR)

generate-pages: json-to-markdown fmt lint ##@ Generate Hugo content from JSON manifests (use FORCE=true to overwrite)
	@echo "SUCCESS: Pages generated successfully."

# Internal target for generating markdown. Called by `generate-pages`.
.PHONY: json-to-markdown
json-to-markdown:
	@echo "INFO: Generating Hugo content pages from JSON manifests..."
	@$(UV) run python $(J2H_SCRIPT) $(J2H_FLAGS)


# ==============================================================================
# Dependency Management & Cleanup
# ==============================================================================
.PHONY: install clean docker

install: ##@ Install all required dependencies (npm, uv)
	@echo "INFO: Installing Node.js dependencies..."
	@$(NPM) install --include=dev
	@echo "INFO: Installing global Node.js tools (Playwright)..."
	@$(NPM) install -g playwright
	@echo "INFO: Installing Python dependencies..."
	@$(UV) sync

clean: ##@ Remove all generated files and build artifacts
	@echo "INFO: Cleaning up generated files and directories..."
	@rm -rf $(PUBLIC_DIR) $(RESOURCES_DIR) $(NODE_MODULES) $(PLAYWRIGHT_REPORT) .venv

docker: ##@ Build the Docker image for the application
	@echo "INFO: Building Docker image [$(DOCKER_IMAGE):$(DOCKER_TAG)]..."
	@$(DOCKER) build -t $(DOCKER_IMAGE):$(DOCKER_TAG) .
