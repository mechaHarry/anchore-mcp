"""Version-aware Anchore API paths.

Query parameters intentionally remain outside these helpers so callers can use
an actual URL/query encoder instead of concatenating untrusted values.
"""

from typing import Literal
from urllib.parse import quote

from anchore_mcp.models.common import ApiVersion


SbomFormat = Literal["native-json", "spdx-json", "cyclonedx-json"]

_API_VERSIONS: frozenset[str] = frozenset({"v1", "v2"})
_SBOM_FORMATS: frozenset[str] = frozenset({"native-json", "spdx-json", "cyclonedx-json"})


def _version_prefix(version: ApiVersion) -> str:
    if version not in _API_VERSIONS:
        raise ValueError("unsupported Anchore API version")
    return f"/{version}"


def _digest_segment(digest: str) -> str:
    if digest in {"", ".", ".."}:
        raise ValueError("image digest must not be empty or a dot segment")
    return quote(digest, safe="")


def images_list_route(version: ApiVersion) -> str:
    return f"{_version_prefix(version)}/images"


def image_tag_summaries_route(version: ApiVersion) -> str:
    return f"{_version_prefix(version)}/summaries/image-tags"


def image_vulnerabilities_route(version: ApiVersion, digest: str) -> str:
    image_route = image_by_digest_route(version, digest)
    if version == "v1":
        return f"{image_route}/vulnerabilities"
    return f"{image_route}/vuln/all"


def image_sbom_route(version: ApiVersion, digest: str, format_name: SbomFormat) -> str:
    image_route = image_by_digest_route(version, digest)
    if format_name not in _SBOM_FORMATS:
        raise ValueError("unsupported image SBOM format")
    sbom_segment = "sbom" if version == "v1" else "sboms"
    return f"{image_route}/{sbom_segment}/{format_name}"


def image_by_digest_route(version: ApiVersion, digest: str) -> str:
    return f"{images_list_route(version)}/{_digest_segment(digest)}"


def image_policy_check_route(version: ApiVersion, digest: str) -> str:
    return f"{image_by_digest_route(version, digest)}/check"


def openapi_route(version: ApiVersion) -> str:
    return f"{_version_prefix(version)}/openapi.json"


def image_full_tag_query_key(version: ApiVersion) -> Literal["fulltag", "full_tag"]:
    _version_prefix(version)
    return "fulltag" if version == "v1" else "full_tag"
