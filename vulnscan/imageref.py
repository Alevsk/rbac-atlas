"""Container image reference normalization.

normalize() turns the raw ``image`` strings found in rbac-scope manifests into a canonical
``registry/repository[:tag][@digest]`` form so the same image referenced in different ways
(``redis``, ``docker.io/library/redis:latest``, ``registry-1.docker.io/library/redis``) is
scanned once.
"""

from __future__ import annotations

import re
from typing import Any

DOCKER_HUB = "docker.io"
DOCKER_HUB_ALIASES = {"docker.io", "registry-1.docker.io", "index.docker.io"}

# Repository path component (OCI distribution spec, applied after lowercasing).
_COMPONENT_RE = re.compile(r"^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*$")
# Registry host with optional port.
_REGISTRY_RE = re.compile(r"^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?(?::[0-9]+)?$")
_TAG_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$")
_DIGEST_RE = re.compile(r"^[a-z0-9]+(?:[.+_-][a-z0-9]+)*:[a-f0-9]{32,}$")
_WHITESPACE_RE = re.compile(r"\s")

FLAG_IMPLICIT_LATEST = "implicit_latest"
FLAG_MUTABLE_TAG = "mutable_tag"
FLAG_DIGEST_PINNED = "digest_pinned"
FLAG_DEPRECATED_REGISTRY = "deprecated_registry"


def _invalid(ref: Any, reason: str) -> dict[str, Any]:
    return {"ref": ref, "canonical": None, "reason": reason}


def normalize(ref: Any) -> dict[str, Any]:
    """Normalize a raw image reference.

    Always returns a dict. On success it has ``canonical`` (str), ``registry``, ``repository``,
    ``tag`` (str|None), ``digest`` (str|None), ``flags`` (sorted list) and ``reason`` None.
    On failure ``canonical`` is None and ``reason`` is one of: ``empty``, ``templated``,
    ``whitespace``, ``invalid_digest``, ``invalid_tag``, ``invalid_registry``,
    ``invalid_repository``.
    """
    if not isinstance(ref, str):
        return _invalid(ref, "empty")
    value = ref.strip().lstrip("/")
    if not value:
        return _invalid(ref, "empty")
    if "{{" in value or "}}" in value:
        return _invalid(ref, "templated")
    if _WHITESPACE_RE.search(value):
        return _invalid(ref, "whitespace")

    flags: set[str] = set()

    digest: str | None = None
    if "@" in value:
        value, digest = value.split("@", 1)
        digest = digest.lower()
        if not _DIGEST_RE.match(digest):
            return _invalid(ref, "invalid_digest")
        flags.add(FLAG_DIGEST_PINNED)

    tag: str | None = None
    last_slash = value.rfind("/")
    colon = value.rfind(":")
    if colon > last_slash:
        value, tag = value[:colon], value[colon + 1 :]
        if not _TAG_RE.match(tag):
            return _invalid(ref, "invalid_tag")

    parts = value.split("/")
    first = parts[0]
    if len(parts) > 1 and ("." in first or ":" in first or first.lower() == "localhost"):
        registry = first.lower()
        repo_parts = parts[1:]
    else:
        registry = DOCKER_HUB
        repo_parts = parts
    if registry in DOCKER_HUB_ALIASES:
        registry = DOCKER_HUB
    if not _REGISTRY_RE.match(registry):
        return _invalid(ref, "invalid_registry")

    repo_parts = [p.lower() for p in repo_parts]
    if not repo_parts or not all(_COMPONENT_RE.match(p) for p in repo_parts):
        return _invalid(ref, "invalid_repository")
    if registry == DOCKER_HUB and len(repo_parts) == 1:
        repo_parts.insert(0, "library")
    repository = "/".join(repo_parts)

    if tag is None and digest is None:
        tag = "latest"
        flags.add(FLAG_IMPLICIT_LATEST)
    if tag == "latest":
        flags.add(FLAG_MUTABLE_TAG)
    if registry == "k8s.gcr.io" or (registry == "gcr.io" and repo_parts[0] == "google_containers"):
        flags.add(FLAG_DEPRECATED_REGISTRY)

    canonical = f"{registry}/{repository}"
    if tag is not None:
        canonical += f":{tag}"
    if digest is not None:
        canonical += f"@{digest}"

    return {
        "ref": ref,
        "canonical": canonical,
        "registry": registry,
        "repository": repository,
        "tag": tag,
        "digest": digest,
        "flags": sorted(flags),
        "reason": None,
    }
