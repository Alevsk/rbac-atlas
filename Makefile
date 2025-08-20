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

# --- Python Environment ---
VENV_DIR       := .venv
VENV_BIN       := $(VENV_DIR)/bin
VENV_PYTHON    := $(VENV_BIN)/python
VENV_PIP       := $(VENV_BIN)/pip

# --- Application Configuration ---
DOCKER_IMAGE   := rbac-atlas
DOCKER_TAG     := latest
HUGO_PORT      := 1313

# --- Tooling ---
# Use variables for commands to allow for easy overrides and environment flexibility.
SHELL          := /bin/bash
HUGO           := hugo
PYTHON         := python3
NPM            := npm
NPX            := npx
DOCKER         := docker
DJLINT         := $(VENV_BIN)/djlint
PAGEFIND       := $(VENV_PYTHON) -m pagefind

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
.PHONY: fmt lint test cover

fmt: ##@ Format all source files (Markdown, Go Templates, HTML)
	@echo "INFO: Formatting Markdown and Go template files..."
	@$(NPM) run fmt
	@echo "INFO: Formatting HTML layout files..."
	@$(DJLINT) --reformat layouts/**/*.html

lint: ##@ Check all source files for formatting issues
	@echo "INFO: Linting Markdown and Go template files..."
	@$(NPM) run lint
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
.PHONY: update pull-projects get-manifests generate-pages

update: pull-projects get-manifests generate-pages ##@ Full data pipeline: pull projects, analyze manifests, generate pages

pull-projects: ##@ Pull remote project sources defined in projects.yaml
	@echo "INFO: Pulling project sources..."
	@$(PYTHON) pull_projects.py -c projects.yaml

get-manifests: ##@ Analyze Helm charts to generate JSON manifests (use FORCE=true to regenerate all)
	@echo "INFO: Fetching and analyzing manifests from Helm charts..."
	@# Complex shell logic is moved to an external script for clarity.
	@# This makes the Makefile cleaner and the script more maintainable and testable.
	@FORCE=$(FORCE) scripts/get_manifests.sh

generate-pages: json-to-markdown fmt ##@ Generate Hugo content from JSON manifests (use FORCE=true to overwrite)
	@echo "SUCCESS: Pages generated successfully."

# Internal target for generating markdown. Called by `generate-pages`.
.PHONY: json-to-markdown
json-to-markdown:
	@echo "INFO: Generating Hugo content pages from JSON manifests..."
	@$(PYTHON) $(J2H_SCRIPT) $(J2H_FLAGS)


# ==============================================================================
# Dependency Management & Cleanup
# ==============================================================================
.PHONY: install clean docker

venv: ##@ Create Python virtual environment
	@echo "INFO: Creating Python virtual environment..."
	@$(PYTHON) -m venv $(VENV_DIR)

activate: ##@ Print commands to activate virtual environment
	@echo "To activate the virtual environment, run:"
	@echo "source $(VENV_DIR)/bin/activate"

install: venv ##@ Install all required dependencies (npm, pip)
	@echo "INFO: Installing Node.js dependencies..."
	@$(NPM) install
	@echo "INFO: Installing global Node.js tools (Playwright)..."
	@$(NPM) install -g playwright
	@echo "INFO: Installing Python dependencies..."
	@$(VENV_PIP) install -r requirements.txt

clean: ##@ Remove all generated files and build artifacts
	@echo "INFO: Cleaning up generated files and directories..."
	@rm -rf $(PUBLIC_DIR) $(RESOURCES_DIR) $(NODE_MODULES) $(PLAYWRIGHT_REPORT) $(VENV_DIR)

docker: ##@ Build the Docker image for the application
	@echo "INFO: Building Docker image [$(DOCKER_IMAGE):$(DOCKER_TAG)]..."
	@$(DOCKER) build -t $(DOCKER_IMAGE):$(DOCKER_TAG) .
