from collections.abc import Sequence
from datetime import UTC
import math
from typing import cast

import httpx
from hypothesis import given, settings, strategies as st
from pydantic import JsonValue, SecretStr
import pytest

from anchore_mcp.anchore.http import JsonResponse
from anchore_mcp.anchore.openapi import OpenApiCache
from anchore_mcp.config import AnchoreConnection
from anchore_mcp.domain.selection import normalize_timestamp, select_image_for_policy
from anchore_mcp.errors import TrustEvidenceError
from anchore_mcp.models.locators import ReferenceLocator


REFERENCE = "registry.example/team/app:1"


class StubHttp:
    def __init__(self, responses: Sequence[object]) -> None:
        self.responses = list(responses)

    async def get_json(
        self,
        connection: AnchoreConnection,
        path: str,
        *,
        params: httpx.QueryParams | None = None,
        max_response_bytes: int,
        timeout: httpx.Timeout | float | None = None,
    ) -> JsonResponse:
        del connection, path, params, max_response_bytes, timeout
        return JsonResponse(
            data=cast(JsonValue, self.responses.pop(0)),
            byte_length=2,
            headers=httpx.Headers(),
        )


def connection() -> AnchoreConnection:
    return AnchoreConnection(
        base_url="https://anchore.example",
        token=SecretStr("test-token"),
    )


timestamp_values = st.one_of(
    st.booleans(),
    st.integers(),
    st.floats(allow_nan=True, allow_infinity=True),
    st.text(max_size=80),
)


@given(value=timestamp_values)
@settings(max_examples=100, deadline=None)
def test_timestamp_inputs_normalize_deterministically_or_reject(value: object) -> None:
    try:
        first = normalize_timestamp(value)
    except TrustEvidenceError:
        return

    assert first == normalize_timestamp(value)
    assert first.tzinfo is UTC
    assert math.isfinite(first.timestamp())


@given(value=timestamp_values)
@settings(max_examples=100, deadline=None)
@pytest.mark.asyncio
async def test_invalid_matching_timestamp_never_falls_back_to_older_digest(value: object) -> None:
    try:
        normalize_timestamp(value)
    except TrustEvidenceError:
        http = StubHttp(
            [
                {
                    "items": [
                        {
                            "image_digest": "sha256:older",
                            "full_tag": REFERENCE,
                            "analyzed_at": "2000-01-01T00:00:00Z",
                        },
                        {
                            "image_digest": "sha256:invalid",
                            "full_tag": REFERENCE,
                            "analyzed_at": value,
                        },
                    ]
                }
            ]
        )
        with pytest.raises(TrustEvidenceError):
            await select_image_for_policy(
                http,
                connection(),
                ReferenceLocator(kind="reference", reference=REFERENCE),
                OpenApiCache(http),
            )
