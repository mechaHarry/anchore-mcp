from collections.abc import Sequence
from typing import cast

import httpx
from pydantic import JsonValue, SecretStr
import pytest

from anchore_mcp.anchore.http import JsonResponse
from anchore_mcp.anchore.pagination import PageCaps
from anchore_mcp.config import AnchoreConnection
from anchore_mcp.domain.resolution import (
    Disambiguation,
    Incomplete,
    NoMatch,
    Resolved,
    resolve_image_reference,
)


REFERENCE = "docker.io/library/nginx:1.21"


class StubHttp:
    def __init__(self, responses: Sequence[object]) -> None:
        self.responses = list(responses)
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
        response = self.responses.pop(0)
        if isinstance(response, JsonResponse):
            return response
        return JsonResponse(data=cast(JsonValue, response), byte_length=2, headers=httpx.Headers())


def connection(version: str = "v2") -> AnchoreConnection:
    return AnchoreConnection(
        base_url="https://anchore.example",
        token=SecretStr("test-token"),
        api_version=version,  # type: ignore[arg-type]
    )


@pytest.mark.asyncio
async def test_backend_filter_is_hint_and_only_exact_local_evidence_resolves() -> None:
    http = StubHttp(
        [
            {
                "items": [
                    {"image_digest": "sha256:exact", "full_tag": REFERENCE},
                    {
                        "image_digest": "sha256:unrelated",
                        "full_tag": "docker.io/library/redis:7",
                    },
                ]
            }
        ]
    )

    result = await resolve_image_reference(http, connection(), REFERENCE)

    assert result == Resolved(digest="sha256:exact")
    assert http.calls == [("/v2/images", httpx.QueryParams({"full_tag": REFERENCE}))]


@pytest.mark.asyncio
async def test_v1_uses_legacy_fulltag_query_key() -> None:
    http = StubHttp([{"images": [{"image_digest": "sha256:v1", "fulltag": REFERENCE}]}])

    result = await resolve_image_reference(http, connection("v1"), REFERENCE)

    assert result == Resolved(digest="sha256:v1")
    assert http.calls == [("/v1/images", httpx.QueryParams({"fulltag": REFERENCE}))]


@pytest.mark.asyncio
async def test_unrelated_or_unproven_rows_are_no_match() -> None:
    http = StubHttp(
        [
            {
                "items": [
                    {"image_digest": "sha256:unrelated", "full_tag": "docker.io/x/y:1"},
                    {"image_digest": "sha256:unproven"},
                ]
            }
        ]
    )

    result = await resolve_image_reference(http, connection(), REFERENCE)

    assert result == NoMatch()


@pytest.mark.asyncio
async def test_exact_match_plus_incomplete_page_fails_closed() -> None:
    response = JsonResponse(
        data={"items": [{"image_digest": "sha256:exact", "full_tag": REFERENCE}]},
        byte_length=2,
        headers=httpx.Headers({"Link": "</v2/images?page=2>; rel=next"}),
    )

    result = await resolve_image_reference(
        StubHttp([response]), connection(), REFERENCE, caps=PageCaps(1, 100)
    )

    assert isinstance(result, Incomplete)
    assert result.kind == "incomplete"
    assert "full_tag" in result.reason


@pytest.mark.asyncio
async def test_exact_match_plus_incomplete_row_evidence_fails_closed() -> None:
    row = {
        "image_digest": "sha256:exact",
        "full_tag": REFERENCE,
        "tags": [f"docker.io/library/nginx:extra-{index}" for index in range(65)],
    }

    result = await resolve_image_reference(StubHttp([{"items": [row]}]), connection(), REFERENCE)

    assert result == Incomplete(reason="Image reference evidence exceeded safety limits.")


@pytest.mark.asyncio
async def test_dedupes_digest_and_bounds_disambiguation_hints() -> None:
    rows: list[JsonValue] = []
    for digest_index in range(10):
        digest = f"sha256:{digest_index:064x}"
        rows.extend(
            [
                {
                    "image_digest": digest,
                    "full_tag": REFERENCE,
                    "tags": [
                        f"docker.io/library/nginx:d{digest_index}-hint-{hint_index}"
                        for hint_index in range(20)
                    ],
                },
                {"image_digest": digest, "fulltag": REFERENCE},
            ]
        )

    result = await resolve_image_reference(StubHttp([{"items": rows}]), connection(), REFERENCE)

    assert isinstance(result, Disambiguation)
    assert result.kind == "disambiguation"
    assert result.truncated is False
    assert len(result.candidates) == 10
    assert all(candidate.hints[0] == REFERENCE for candidate in result.candidates)
    assert all(len(candidate.hints) <= 8 for candidate in result.candidates)
    assert sum(len(candidate.hints) for candidate in result.candidates) <= 64


@pytest.mark.asyncio
async def test_disambiguation_is_sorted_and_truncated_to_fifty_candidates() -> None:
    rows: list[JsonValue] = [
        {"image_digest": f"sha256:{index:064x}", "full_tag": REFERENCE}
        for index in reversed(range(51))
    ]

    result = await resolve_image_reference(StubHttp([{"items": rows}]), connection(), REFERENCE)

    assert isinstance(result, Disambiguation)
    assert result.truncated is True
    assert len(result.candidates) == 50
    assert [candidate.digest for candidate in result.candidates] == sorted(
        candidate.digest for candidate in result.candidates
    )


@pytest.mark.asyncio
async def test_invalid_reference_fails_before_http() -> None:
    http = StubHttp([])

    with pytest.raises(ValueError, match="fully qualified"):
        await resolve_image_reference(http, connection(), "nginx:latest")

    assert http.calls == []
