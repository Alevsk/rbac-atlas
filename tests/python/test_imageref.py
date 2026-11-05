"""Tests for vulnscan.imageref.normalize."""

from __future__ import annotations

import unittest

from vulnscan.imageref import normalize

DIGEST = "sha256:" + "0123456789abcdef" * 4


class NormalizeValidTest(unittest.TestCase):
    def assertCanonical(self, ref: str, canonical: str, flags: list[str] | None = None) -> dict:
        result = normalize(ref)
        self.assertIsNone(result["reason"], ref)
        self.assertEqual(result["canonical"], canonical)
        if flags is not None:
            self.assertEqual(result["flags"], sorted(flags))
        return result

    def test_docker_hub_official_image(self) -> None:
        r = self.assertCanonical("redis:7.2", "docker.io/library/redis:7.2", [])
        self.assertEqual((r["registry"], r["repository"], r["tag"], r["digest"]), ("docker.io", "library/redis", "7.2", None))

    def test_implicit_latest(self) -> None:
        self.assertCanonical("busybox", "docker.io/library/busybox:latest", ["implicit_latest", "mutable_tag"])

    def test_explicit_latest_is_mutable(self) -> None:
        self.assertCanonical("bitnami/redis:latest", "docker.io/bitnami/redis:latest", ["mutable_tag"])

    def test_docker_hub_aliases(self) -> None:
        for ref in (
            "registry-1.docker.io/bitnami/redis:latest",
            "index.docker.io/bitnami/redis:latest",
            "docker.io/bitnami/redis:latest",
            "Docker.IO/Bitnami/Redis:latest",
        ):
            self.assertCanonical(ref, "docker.io/bitnami/redis:latest")
        self.assertCanonical("docker.io/busybox:1.38.0", "docker.io/library/busybox:1.38.0")

    def test_leading_slash_and_whitespace_stripped(self) -> None:
        self.assertCanonical(" /grafana/grafana:10.3.3\n", "docker.io/grafana/grafana:10.3.3")

    def test_tag_case_preserved(self) -> None:
        self.assertCanonical("quay.io/Org/App:V1.0-RC", "quay.io/org/app:V1.0-RC")

    def test_digest_with_tag(self) -> None:
        r = self.assertCanonical(
            f"registry.k8s.io/ingress-nginx/controller:v1.9.6@{DIGEST}",
            f"registry.k8s.io/ingress-nginx/controller:v1.9.6@{DIGEST}",
            ["digest_pinned"],
        )
        self.assertEqual(r["tag"], "v1.9.6")
        self.assertEqual(r["digest"], DIGEST)

    def test_digest_only_has_no_implicit_tag(self) -> None:
        r = self.assertCanonical(f"ghcr.io/org/app@{DIGEST}", f"ghcr.io/org/app@{DIGEST}", ["digest_pinned"])
        self.assertIsNone(r["tag"])

    def test_registry_with_port_and_localhost(self) -> None:
        self.assertCanonical("myreg:5000/team/app:1", "myreg:5000/team/app:1")
        self.assertCanonical("localhost/app:1", "localhost/app:1")

    def test_non_hub_single_component_not_prefixed(self) -> None:
        self.assertCanonical("quay.io/prometheus:v1", "quay.io/prometheus:v1")

    def test_deprecated_registries(self) -> None:
        self.assertIn("deprecated_registry", normalize("k8s.gcr.io/pause:3.2")["flags"])
        self.assertIn("deprecated_registry", normalize("gcr.io/google_containers/pause:3.2")["flags"])
        self.assertNotIn("deprecated_registry", normalize("gcr.io/distroless/static:nonroot")["flags"])


class NormalizeInvalidTest(unittest.TestCase):
    def assertInvalid(self, ref: object, reason: str) -> None:
        result = normalize(ref)
        self.assertIsNone(result["canonical"], ref)
        self.assertEqual(result["reason"], reason, ref)

    def test_invalid_refs(self) -> None:
        self.assertInvalid("", "empty")
        self.assertInvalid("   ", "empty")
        self.assertInvalid("/", "empty")
        self.assertInvalid(None, "empty")
        self.assertInvalid("{{ .Values.image.repository }}:1.0", "templated")
        self.assertInvalid("repo/app:{{ .Chart.AppVersion }}", "templated")
        self.assertInvalid("repo/app :1.0", "whitespace")
        self.assertInvalid("sonarqube:", "invalid_tag")
        self.assertInvalid("app:bad$tag", "invalid_tag")
        self.assertInvalid(":no-image-tag-could-be-found", "invalid_repository")
        self.assertInvalid("repo/app$:1", "invalid_repository")
        self.assertInvalid("repo//app:1", "invalid_repository")
        self.assertInvalid("app@sha256:xyz", "invalid_digest")
        self.assertInvalid("bad_host.io:port/app:1", "invalid_registry")


if __name__ == "__main__":
    unittest.main()
