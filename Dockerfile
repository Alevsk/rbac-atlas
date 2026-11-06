# syntax=docker/dockerfile:1
#
# Builds the RBAC Atlas static site and serves it with an unprivileged nginx.
# The `toolchain` stage doubles as the dev container image (devcontainer/.devcontainer.json).
# Note: a full site build renders ~28k pages and needs a lot of memory (~16 GB) and time.
#
# Base images are pinned by version and digest; bump tag and digest together.
ARG HUGO_IMAGE=hugomods/hugo:0.164.0@sha256:8e0437ccd0ba94f484a935edecb669678effcd558bb25d5cf21f851019bbbd29
ARG UV_IMAGE=ghcr.io/astral-sh/uv:0.12.0@sha256:606e70c71c852d03f611b1e56a195d08648507018a7057fab82c4974c4eae105
ARG NGINX_IMAGE=nginxinc/nginx-unprivileged:1.29-alpine@sha256:0c79d56aee561a1d81c63f00eee5fb5fe29279560cdc55e91425133104c7fbe6

FROM ${UV_IMAGE} AS uv

# Toolchain: Hugo extended, Node.js/npm and git come from the base image.
FROM ${HUGO_IMAGE} AS toolchain
# Packages follow the base image's Alpine release branch; exact apk pins break on repo updates.
# hadolint ignore=DL3018
RUN apk add --no-cache bash make python3
COPY --from=uv /uv /uvx /usr/local/bin/
ENV UV_PROJECT_ENVIRONMENT=/opt/venv \
    UV_PYTHON_DOWNLOADS=never \
    UV_LINK_MODE=copy \
    UV_COMPILE_BYTECODE=1 \
    PATH="/opt/venv/bin:$PATH"
WORKDIR /src

# Dependencies first to leverage the layer cache; versions come from the lockfiles.
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY pyproject.toml uv.lock ./
COPY report/pyproject.toml report/
RUN uv sync --frozen --no-install-project

# Build: check templates (no reformatting), render the site with the production
# baseURL (Hugo does not auto-merge a root config.production.toml), build the search index.
FROM toolchain AS builder
COPY . .
RUN djlint --check layouts
ENV HUGO_ENV=production
RUN hugo --gc --minify --config config.toml,config.production.toml && python -m pagefind --site public

# Runtime: static files only, served as a non-root user on port 8080.
FROM ${NGINX_IMAGE} AS runtime
LABEL org.opencontainers.image.title="RBAC Atlas" \
      org.opencontainers.image.description="A curated index of RBAC policies in Kubernetes" \
      org.opencontainers.image.url="https://rbac-atlas.github.io/" \
      org.opencontainers.image.source="https://github.com/Alevsk/rbac-atlas" \
      org.opencontainers.image.licenses="MIT"
COPY nginx.conf /etc/nginx/nginx.conf
COPY --from=builder /src/public /usr/share/nginx/html
USER 101
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD ["wget", "-q", "--spider", "http://127.0.0.1:8080/"]
CMD ["nginx", "-g", "daemon off;"]
