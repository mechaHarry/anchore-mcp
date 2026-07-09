from collections.abc import Sequence
from datetime import UTC, datetime
from typing import cast

import httpx
from pydantic import JsonValue, SecretStr
import pytest

from anchore_mcp.anchore.http import JsonResponse
from anchore_mcp.anchore.openapi import OpenApiCache
from anchore_mcp.anchore.pagination import PageCaps
from anchore_mcp.config import AnchoreConnection
from anchore_mcp.domain.selection import normalize_timestamp, select_image_for_policy
from anchore_mcp.errors import EnumerationIncompleteError, TrustEvidenceError
from anchore_mcp.models.locators import DigestLocator, ReferenceLocator, RepositoryLocator


REFERENCE = "registry.example/team/app:1"


class StubHttp:
    def __init__(self, responses: dict[str, Sequence[object]]) -> None:
        self.responses = {path: list(values) for path, values in responses.items()}
        self.calls: list[tuple[str, httpx.QueryParams]] = []

    async def get_json(
        self,
        connection: AnchoreConnection,
        path: str,
        *,
        params: httpx.QueryParams | None = None,
        max_response_bytes: int,
        timeout: httpx.Timeout | float | None = None,
    ) -> JsonResponse:
        del connection, max_response_bytes, timeout
        self.calls.append((path, params or httpx.QueryParams()))
        value = self.responses[path].pop(0)
        if isinstance(value, BaseException):
            raise value
        if isinstance(value, JsonResponse):
            return value
        return JsonResponse(data=cast(JsonValue, value), byte_length=2, headers=httpx.Headers())


def connection(version: str = "v2") -> AnchoreConnection:
    return AnchoreConnection(
        base_url="https://anchore.example",
        token=SecretStr("test-token"),
        api_version=version,  # type: ignore[arg-type]
    )


def openapi_document() -> JsonValue:
    return {
        "paths": {
            "/v1/summaries/image-tags": {
                "get": {
                    "parameters": [
                        {"name": "registry", "in": "query"},
                        {"name": "repository", "in": "query"},
                    ]
                }
            }
        }
    }


@pytest.mark.asyncio
async def test_digest_locator_returns_without_http_or_openapi() -> None:
    http = StubHttp({})

    selected = await select_image_for_policy(
        http,
        connection(),
        DigestLocator(kind="digest", digest=" sha256:direct "),
        OpenApiCache(http),
    )

    assert selected.digest == "sha256:direct"
    assert selected.reference is None
    assert selected.timestamp is None
    assert http.calls == []


@pytest.mark.asyncio
async def test_reference_selects_newest_exact_digest_and_uses_versioned_query() -> None:
    http = StubHttp(
        {
            "/v2/images": [
                {
                    "items": [
                        {
                            "image_digest": "sha256:old",
                            "full_tag": REFERENCE,
                            "analyzed_at": "2026-04-01T00:00:00Z",
                        },
                        {
                            "image_digest": "sha256:new",
                            "fulltag": REFERENCE,
                            "analyzedAt": 1_775_174_400_000,
                        },
                        {
                            "image_digest": "sha256:unrelated",
                            "full_tag": "registry.example/team/app:other",
                            "analyzed_at": "2027-01-01T00:00:00Z",
                        },
                    ]
                }
            ]
        }
    )

    selected = await select_image_for_policy(
        http,
        connection(),
        ReferenceLocator(kind="reference", reference=REFERENCE),
        OpenApiCache(http),
    )

    assert selected.digest == "sha256:new"
    assert selected.reference == REFERENCE
    assert selected.repository == "registry.example/team/app"
    assert selected.timestamp == datetime(2026, 4, 3, tzinfo=UTC)
    assert http.calls == [("/v2/images", httpx.QueryParams({"full_tag": REFERENCE}))]


@pytest.mark.asyncio
async def test_missing_timestamp_on_digest_candidate_fails_closed() -> None:
    http = StubHttp(
        {
            "/v2/images": [
                {
                    "items": [
                        {
                            "image_digest": "sha256:known",
                            "full_tag": REFERENCE,
                            "analyzed_at": "2026-04-01T00:00:00Z",
                        },
                        {"image_digest": "sha256:unknown", "full_tag": REFERENCE},
                        {"full_tag": REFERENCE},
                    ]
                }
            ]
        }
    )

    with pytest.raises(TrustEvidenceError, match="timestamp evidence"):
        await select_image_for_policy(
            http,
            connection(),
            ReferenceLocator(kind="reference", reference=REFERENCE),
            OpenApiCache(http),
        )


@pytest.mark.asyncio
async def test_reference_evidence_or_page_incompleteness_dominates_match() -> None:
    evidence_http = StubHttp(
        {
            "/v2/images": [
                {
                    "items": [
                        {
                            "image_digest": "sha256:exact",
                            "full_tag": REFERENCE,
                            "analyzed_at": "2026-04-01T00:00:00Z",
                            "tags": [f"registry.example/team/app:{index}" for index in range(65)],
                        }
                    ]
                }
            ]
        }
    )
    with pytest.raises(EnumerationIncompleteError, match="evidence"):
        await select_image_for_policy(
            evidence_http,
            connection(),
            ReferenceLocator(kind="reference", reference=REFERENCE),
            OpenApiCache(evidence_http),
        )

    response = JsonResponse(
        data={
            "items": [
                {
                    "image_digest": "sha256:exact",
                    "full_tag": REFERENCE,
                    "analyzed_at": "2026-04-01T00:00:00Z",
                }
            ]
        },
        byte_length=2,
        headers=httpx.Headers({"Link": "</v2/images?page=2>; rel=next"}),
    )
    page_http = StubHttp({"/v2/images": [response]})
    with pytest.raises(EnumerationIncompleteError, match="max_pages"):
        await select_image_for_policy(
            page_http,
            connection(),
            ReferenceLocator(kind="reference", reference=REFERENCE),
            OpenApiCache(page_http),
            caps=PageCaps(1, 100),
        )


@pytest.mark.asyncio
async def test_repository_v2_uses_direct_exact_summary_filters() -> None:
    http = StubHttp(
        {
            "/v2/summaries/image-tags": [
                {
                    "items": [
                        {
                            "image_digest": "sha256:old",
                            "full_tag": "registry.example/team/app:1",
                            "analyzed_at": 1_775_001_600,
                        },
                        {
                            "image_digest": "sha256:new",
                            "full_tag": "registry.example/team/app:2",
                            "analysis_timestamp": "2026-04-03T00:00:00+00:00",
                        },
                        {
                            "image_digest": "sha256:wrong",
                            "full_tag": "other.example/team/app:9",
                            "analyzed_at": "2027-01-01T00:00:00Z",
                        },
                    ],
                    "total_rows": 3,
                }
            ]
        }
    )

    selected = await select_image_for_policy(
        http,
        connection(),
        RepositoryLocator(kind="repository", registry="registry.example", repository="team/app"),
        OpenApiCache(http),
    )

    assert selected.digest == "sha256:new"
    assert selected.reference == "registry.example/team/app:2"
    assert selected.repository == "registry.example/team/app"
    assert http.calls[0][0] == "/v2/summaries/image-tags"
    assert http.calls[0][1].get("registry") == "registry.example"
    assert http.calls[0][1].get("repository") == "team/app"
    assert http.calls[0][1].get("analysis_status") == "analyzed"
    assert all(path != "/v2/openapi.json" for path, _params in http.calls)


@pytest.mark.asyncio
async def test_v1_repository_requires_bounded_direct_openapi_capability() -> None:
    unsupported = StubHttp({"/v1/openapi.json": [{"paths": {}}]})
    with pytest.raises(TrustEvidenceError, match="unavailable for this v1 deployment"):
        await select_image_for_policy(
            unsupported,
            connection("v1"),
            RepositoryLocator(
                kind="repository", registry="registry.example", repository="team/app"
            ),
            OpenApiCache(unsupported),
        )
    assert [path for path, _params in unsupported.calls] == ["/v1/openapi.json"]

    supported = StubHttp(
        {
            "/v1/openapi.json": [openapi_document()],
            "/v1/summaries/image-tags": [
                {
                    "items": [
                        {
                            "image_digest": "sha256:v1",
                            "full_tag": "registry.example/team/app:1",
                            "createdAt": "2026-04-03T00:00:00Z",
                        }
                    ],
                    "total_rows": 1,
                }
            ],
        }
    )
    selected = await select_image_for_policy(
        supported,
        connection("v1"),
        RepositoryLocator(kind="repository", registry="registry.example", repository="team/app"),
        OpenApiCache(supported),
    )
    assert selected.digest == "sha256:v1"
    assert [path for path, _params in supported.calls] == [
        "/v1/openapi.json",
        "/v1/summaries/image-tags",
    ]


@pytest.mark.asyncio
async def test_v1_openapi_failure_is_static_and_does_not_call_summary() -> None:
    http = StubHttp({"/v1/openapi.json": [RuntimeError("PRIVATE_BACKEND_MARKER")]})

    with pytest.raises(TrustEvidenceError) as caught:
        await select_image_for_policy(
            http,
            connection("v1"),
            RepositoryLocator(
                kind="repository", registry="registry.example", repository="team/app"
            ),
            OpenApiCache(http),
        )

    assert "PRIVATE_BACKEND_MARKER" not in str(caught.value)
    assert [path for path, _params in http.calls] == ["/v1/openapi.json"]


@pytest.mark.asyncio
async def test_tied_newest_digests_fail_closed() -> None:
    http = StubHttp(
        {
            "/v2/summaries/image-tags": [
                {
                    "items": [
                        {
                            "image_digest": "sha256:a",
                            "full_tag": "registry.example/team/app:1",
                            "analyzed_at": "2026-04-02T00:00:00Z",
                        },
                        {
                            "image_digest": "sha256:b",
                            "full_tag": "registry.example/team/app:2",
                            "analyzed_at": "2026-04-02T00:00:00+00:00",
                        },
                    ],
                    "total_rows": 2,
                }
            ]
        }
    )

    with pytest.raises(TrustEvidenceError, match="newest image is ambiguous"):
        await select_image_for_policy(
            http,
            connection(),
            RepositoryLocator(
                kind="repository", registry="registry.example", repository="team/app"
            ),
            OpenApiCache(http),
        )


@pytest.mark.parametrize(
    "value",
    [
        True,
        False,
        float("nan"),
        float("inf"),
        float("-inf"),
        1e300,
        pytest.param(10**10_000, id="huge-integer"),
        "not-a-date",
        "",
    ],
)
def test_invalid_timestamp_values_are_rejected(value: object) -> None:
    with pytest.raises(TrustEvidenceError, match="timestamp"):
        normalize_timestamp(value)


def test_timestamp_normalizes_iso_epoch_seconds_and_milliseconds() -> None:
    expected = datetime(2000, 1, 1, tzinfo=UTC)

    assert normalize_timestamp("2000-01-01T00:00:00Z") == expected
    assert normalize_timestamp(946_684_800) == expected
    assert normalize_timestamp(946_684_800_000) == expected
