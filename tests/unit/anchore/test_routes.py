from collections.abc import Callable
from typing import cast

import httpx
import pytest

from anchore_mcp.anchore.routes import (
    ApiVersion,
    SbomFormat,
    image_by_digest_route,
    image_full_tag_query_key,
    image_policy_check_route,
    image_sbom_route,
    image_tag_summaries_route,
    image_vulnerabilities_route,
    images_list_route,
    openapi_route,
)


@pytest.mark.parametrize("version", ["v1", "v2"])
def test_collection_routes_are_versioned_paths_without_queries(version: ApiVersion) -> None:
    assert images_list_route(version) == f"/{version}/images"
    assert image_tag_summaries_route(version) == f"/{version}/summaries/image-tags"
    assert openapi_route(version) == f"/{version}/openapi.json"

    assert "?" not in images_list_route(version)
    assert "?" not in image_tag_summaries_route(version)


@pytest.mark.parametrize(
    ("version", "expected"),
    [("v1", "fulltag"), ("v2", "full_tag")],
)
def test_full_tag_query_key_is_version_specific(version: ApiVersion, expected: str) -> None:
    assert image_full_tag_query_key(version) == expected


@pytest.mark.parametrize(
    ("version", "vulnerability_suffix", "sbom_segment"),
    [("v1", "vulnerabilities", "sbom"), ("v2", "vuln/all", "sboms")],
)
def test_image_routes_preserve_version_specific_wire_paths(
    version: ApiVersion, vulnerability_suffix: str, sbom_segment: str
) -> None:
    digest = "sha256:abc"
    encoded = "sha256%3Aabc"

    assert image_vulnerabilities_route(version, digest) == (
        f"/{version}/images/{encoded}/{vulnerability_suffix}"
    )
    assert image_sbom_route(version, digest, "native-json") == (
        f"/{version}/images/{encoded}/{sbom_segment}/native-json"
    )
    assert image_by_digest_route(version, digest) == f"/{version}/images/{encoded}"
    assert image_policy_check_route(version, digest) == f"/{version}/images/{encoded}/check"


@pytest.mark.parametrize("format_name", ["native-json", "spdx-json", "cyclonedx-json"])
def test_all_typed_sbom_formats_are_wire_literals(format_name: SbomFormat) -> None:
    assert image_sbom_route("v2", "sha256:abc", format_name).endswith(f"/{format_name}")


@pytest.mark.parametrize(
    ("digest", "encoded"),
    [
        ("sha/256", "sha%2F256"),
        ("sha?256", "sha%3F256"),
        ("sha%256", "sha%25256"),
        ("sha256:abc", "sha256%3Aabc"),
        ("哈希:值", "%E5%93%88%E5%B8%8C%3A%E5%80%BC"),
    ],
)
def test_digest_is_encoded_as_exactly_one_path_segment(digest: str, encoded: str) -> None:
    assert image_by_digest_route("v2", digest) == f"/v2/images/{encoded}"


@pytest.mark.parametrize("digest", ["", ".", ".."])
def test_all_digest_routes_reject_empty_and_dot_segments(digest: str) -> None:
    route_builders: tuple[Callable[[str], str], ...] = (
        lambda value: image_vulnerabilities_route("v2", value),
        lambda value: image_sbom_route("v2", value, "native-json"),
        lambda value: image_by_digest_route("v2", value),
        lambda value: image_policy_check_route("v2", value),
    )

    for build_route in route_builders:
        with pytest.raises(ValueError, match="digest"):
            build_route(digest)


def test_legitimate_dot_digest_routes_do_not_escape_when_joined_to_httpx_base() -> None:
    digest = "sha256:abc..def.json"
    routes = (
        image_vulnerabilities_route("v2", digest),
        image_sbom_route("v2", digest, "spdx-json"),
        image_by_digest_route("v2", digest),
        image_policy_check_route("v2", digest),
    )

    for route in routes:
        composed = httpx.URL("https://anchore.example").join(route)
        assert str(composed) == f"https://anchore.example{route}"
        assert composed.path.startswith("/v2/images/sha256:abc..def.json")


@pytest.mark.parametrize(
    "route",
    [
        image_vulnerabilities_route,
        image_by_digest_route,
        image_policy_check_route,
    ],
)
def test_unknown_api_version_fails_closed(route: object) -> None:
    invalid = cast(ApiVersion, "v3")
    with pytest.raises(ValueError, match="API version"):
        cast(object, route)(invalid, "sha256:abc")  # type: ignore[operator]


def test_unknown_api_version_fails_closed_for_collection_routes() -> None:
    invalid = cast(ApiVersion, "v3")
    for route in (images_list_route, image_tag_summaries_route, openapi_route):
        with pytest.raises(ValueError, match="API version"):
            route(invalid)
    with pytest.raises(ValueError, match="API version"):
        image_full_tag_query_key(invalid)


def test_unknown_sbom_format_fails_closed() -> None:
    with pytest.raises(ValueError, match="SBOM format"):
        image_sbom_route("v2", "sha256:abc", cast(SbomFormat, "xml"))
