import asyncio
import base64
from collections.abc import AsyncIterator
from datetime import UTC, datetime
import gzip
from typing import cast

import httpx
from pydantic import SecretStr
import pytest

from anchore_mcp.anchore.http import (
    MAX_PATH_LENGTH,
    MAX_RESPONSE_BYTES,
    AnchoreHttpClient,
    JsonResponse,
)
from anchore_mcp.config import AnchoreConnection, RetryPolicy
from anchore_mcp.errors import (
    AnchoreHttpError,
    AnchoreInvalidResponseError,
    AnchoreNetworkError,
    AnchoreResponseTooLargeError,
    AnchoreTimeoutError,
)


TOKEN_MARKER = "synthetic-secret-token"
BODY_MARKER = "synthetic-private-body"
EXCEPTION_MARKER = "synthetic-httpx-detail"


def connection(
    *,
    base_url: str = "https://anchore.example/anchore",
    account: str | None = None,
    max_retries: int = 0,
) -> AnchoreConnection:
    return AnchoreConnection(
        base_url=base_url,
        token=SecretStr(TOKEN_MARKER),
        account=account,
        retry=RetryPolicy(max_retries=max_retries, base_delay_ms=1000, max_delay_ms=8000),
    )


def basic_credentials(request: httpx.Request) -> tuple[str, str]:
    scheme, encoded = request.headers["authorization"].split(" ", 1)
    assert scheme == "Basic"
    decoded = base64.b64decode(encoded).decode("utf-8")
    username, password = decoded.split(":", 1)
    return username, password


class ChunkStream(httpx.AsyncByteStream):
    def __init__(self, chunks: list[bytes]) -> None:
        self.chunks = chunks
        self.consumed = 0
        self.closed = False

    async def __aiter__(self) -> AsyncIterator[bytes]:
        for chunk in self.chunks:
            self.consumed += 1
            yield chunk

    async def aclose(self) -> None:
        self.closed = True


class CancellingStream(httpx.AsyncByteStream):
    def __init__(self) -> None:
        self.closed = False

    async def __aiter__(self) -> AsyncIterator[bytes]:
        yield b'{"partial":'
        raise asyncio.CancelledError

    async def aclose(self) -> None:
        self.closed = True


@pytest.mark.asyncio
async def test_get_sends_exact_auth_headers_params_and_preserves_base_path() -> None:
    observed: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        observed.append(request)
        return httpx.Response(200, json={"ok": True})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as shared:
        response = await AnchoreHttpClient(shared).get_json(
            connection(account="security"),
            "/v2/images",
            params={"full_tag": "registry.example/team/image:1", "page": 2},
            max_response_bytes=1024,
        )

    request = observed[0]
    assert request.method == "GET"
    assert request.url.path == "/anchore/v2/images"
    assert request.url.params == httpx.QueryParams(
        {"full_tag": "registry.example/team/image:1", "page": "2"}
    )
    assert basic_credentials(request) == ("_api_key", TOKEN_MARKER)
    assert request.headers["accept"] == "application/json"
    assert request.headers["accept-encoding"] == "identity"
    assert request.headers["x-anchore-account"] == "security"
    assert response.data == {"ok": True}


@pytest.mark.asyncio
async def test_account_header_is_omitted_when_not_configured() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        assert "x-anchore-account" not in request.headers
        return httpx.Response(200, json={})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as shared:
        await AnchoreHttpClient(shared).get_json(connection(), "/v2/images", max_response_bytes=100)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "path",
    [
        "v2/images",
        "https://other.example/v2/images",
        "//other.example/v2/images",
        "/../private",
        "/v2/./images",
        "/v2/%2e%2e/private",
        "/v2/%2525252e%2525252e/private",
        "/v2/%2525252e%2525252e%2525252fprivate",
        "/v2/images?secret=value",
        "/v2/images#fragment",
        "/v2\\..\\private",
    ],
)
async def test_unsafe_route_paths_are_rejected_before_request(path: str) -> None:
    calls = 0

    async def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json={})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as shared:
        with pytest.raises(ValueError, match="path"):
            await AnchoreHttpClient(shared).get_json(connection(), path, max_response_bytes=100)

    assert calls == 0


@pytest.mark.asyncio
async def test_excessive_percent_encoding_depth_is_rejected_before_request() -> None:
    calls = 0
    path = f"/v2/%{'25' * 17}2e/private"

    async def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json={})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as shared:
        with pytest.raises(ValueError, match="encoding"):
            await AnchoreHttpClient(shared).get_json(connection(), path, max_response_bytes=100)

    assert calls == 0


@pytest.mark.asyncio
async def test_overlong_path_is_rejected_before_percent_processing_or_request() -> None:
    calls = 0
    path = "/" + ("a" * MAX_PATH_LENGTH)

    async def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json={})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as shared:
        with pytest.raises(ValueError, match="length"):
            await AnchoreHttpClient(shared).get_json(connection(), path, max_response_bytes=100)

    assert calls == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("path", "expected_path"),
    [
        ("/v2/images/sha256%3Aabc", "/anchore/v2/images/sha256:abc"),
        ("/v2/images/sha%2F256", "/anchore/v2/images/sha/256"),
        ("/v2/images/value%2525literal", "/anchore/v2/images/value%25literal"),
    ],
)
async def test_nested_path_inspection_preserves_legitimate_route_encodings(
    path: str, expected_path: str
) -> None:
    observed: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        observed.append(request)
        return httpx.Response(200, json={})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as shared:
        await AnchoreHttpClient(shared).get_json(connection(), path, max_response_bytes=100)

    assert observed[0].url.path == expected_path


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("content", "expected"),
    [
        (b'{"ok":true}', {"ok": True}),
        (b"[1,2,3]", [1, 2, 3]),
        (b'"value"', "value"),
        (b"42", 42),
        (b"true", True),
        (b"null", None),
        (b"", {}),
    ],
)
async def test_valid_json_values_and_empty_body_are_returned(
    content: bytes, expected: object
) -> None:
    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=content)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as shared:
        response = await AnchoreHttpClient(shared).get_json(
            connection(), "/v2/images", max_response_bytes=100
        )

    assert isinstance(response, JsonResponse)
    assert response.data == expected
    assert response.byte_length == len(content)
    assert isinstance(response.headers, httpx.Headers)


@pytest.mark.asyncio
async def test_unicode_byte_length_is_utf8_length_not_character_count() -> None:
    content = '"漏洞"'.encode()

    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=content, headers={"x-result": "safe"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as shared:
        response = await AnchoreHttpClient(shared).get_json(
            connection(), "/v2/images", max_response_bytes=100
        )

    assert response.data == "漏洞"
    assert response.byte_length == len(content)
    assert response.headers["x-result"] == "safe"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "content",
    [
        b"\xff",
        b"{broken",
        b"NaN",
        b"Infinity",
        b"-Infinity",
        b"1e999",
        b"-1e999",
        b'{"nested":[1e999]}',
    ],
)
async def test_invalid_utf8_json_and_nonfinite_numbers_are_rejected(content: bytes) -> None:
    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=content)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as shared:
        with pytest.raises(AnchoreInvalidResponseError) as caught:
            await AnchoreHttpClient(shared).get_json(
                connection(), "/v2/images", max_response_bytes=100
            )

    decoded_marker = content.decode("utf-8", errors="ignore")
    if decoded_marker:
        assert decoded_marker not in str(caught.value)


@pytest.mark.asyncio
@pytest.mark.parametrize("encoding", ["gzip", "br", "deflate", "x-private-encoding"])
async def test_unexpected_content_encoding_is_rejected_before_stream_iteration(
    encoding: str,
) -> None:
    stream = ChunkStream([BODY_MARKER.encode()])

    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            stream=stream,
            headers={"content-encoding": encoding},
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as shared:
        with pytest.raises(AnchoreInvalidResponseError) as caught:
            await AnchoreHttpClient(shared).get_json(
                connection(), "/v2/images", max_response_bytes=100
            )

    assert encoding not in str(caught.value)
    assert BODY_MARKER not in str(caught.value)
    assert stream.consumed == 0
    assert stream.closed


@pytest.mark.asyncio
@pytest.mark.parametrize("encoding", ["identity", " Identity "])
async def test_identity_content_encoding_is_accepted(encoding: str) -> None:
    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            content=b"null",
            headers={"content-encoding": encoding},
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as shared:
        response = await AnchoreHttpClient(shared).get_json(
            connection(), "/v2/images", max_response_bytes=100
        )

    assert response.data is None


@pytest.mark.asyncio
async def test_deeply_nested_json_is_a_safe_invalid_response() -> None:
    content = (b"[" * 10_000) + b"null" + (b"]" * 10_000)
    stream = ChunkStream([content])

    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, stream=stream)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as shared:
        with pytest.raises(AnchoreInvalidResponseError) as caught:
            await AnchoreHttpClient(shared).get_json(
                connection(), "/v2/images", max_response_bytes=len(content)
            )

    assert "recursion" not in str(caught.value).casefold()
    assert stream.closed


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "content_type",
    [
        "application/json",
        "Application/Problem+Json",
        "application/vnd.anchore.result+json; charset=utf-8",
    ],
)
async def test_json_content_types_are_accepted_case_insensitively(
    content_type: str,
) -> None:
    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"null", headers={"content-type": content_type})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as shared:
        response = await AnchoreHttpClient(shared).get_json(
            connection(), "/v2/images", max_response_bytes=100
        )

    assert response.data is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "content_type",
    [
        f"text/html; marker={BODY_MARKER}",
        "text/json",
        "application/jsonp",
        "application/foo+jsonx",
        "application/foo/bar+json",
        "",
    ],
)
async def test_non_json_content_type_is_rejected_before_json_parse(
    content_type: str,
) -> None:
    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            content=b"null",
            headers={"content-type": content_type},
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as shared:
        with pytest.raises(AnchoreInvalidResponseError) as caught:
            await AnchoreHttpClient(shared).get_json(
                connection(), "/v2/images", max_response_bytes=100
            )

    assert BODY_MARKER not in str(caught.value)


@pytest.mark.asyncio
async def test_empty_body_allows_non_json_content_type_for_compatibility() -> None:
    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"", headers={"content-type": "text/html"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as shared:
        response = await AnchoreHttpClient(shared).get_json(
            connection(), "/v2/images", max_response_bytes=100
        )

    assert response.data == {}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status", "message"),
    [
        (302, "redirected"),
        (401, "authentication"),
        (403, "forbidden"),
        (404, "not found"),
        (500, "500"),
    ],
)
async def test_http_failures_have_safe_status_specific_messages(status: int, message: str) -> None:
    requests: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            status,
            content=BODY_MARKER.encode(),
            headers={"x-private": "private-header-marker", "location": "https://other.example"},
        )

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(handler), follow_redirects=True
    ) as shared:
        with pytest.raises(AnchoreHttpError) as caught:
            await AnchoreHttpClient(shared).get_json(
                connection(), "/v2/images", max_response_bytes=100
            )

    assert caught.value.status == status
    assert message in str(caught.value)
    assert len(requests) == 1
    assert BODY_MARKER not in str(caught.value)
    assert "private-header-marker" not in str(caught.value)
    assert TOKEN_MARKER not in str(caught.value)


@pytest.mark.asyncio
async def test_stream_limit_stops_before_consuming_later_chunks() -> None:
    stream = ChunkStream([b'{"value":"', b"0123456789", b'"}', b"later-private-chunk"])

    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, stream=stream)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as shared:
        with pytest.raises(AnchoreResponseTooLargeError) as caught:
            await AnchoreHttpClient(shared).get_json(
                connection(), "/v2/images", max_response_bytes=15
            )

    assert stream.consumed == 2
    assert stream.closed
    assert caught.value.observed == 20
    assert caught.value.max == 15
    assert "later-private-chunk" not in str(caught.value)


@pytest.mark.asyncio
async def test_gzip_expansion_is_rejected_without_decompression() -> None:
    expanded = b'{"value":"' + (b"x" * 1000) + b'"}'
    compressed = gzip.compress(expanded)
    assert len(compressed) < 100
    stream = ChunkStream([compressed])

    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, stream=stream, headers={"content-encoding": "gzip"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as shared:
        with pytest.raises(AnchoreInvalidResponseError):
            await AnchoreHttpClient(shared).get_json(
                connection(), "/v2/images", max_response_bytes=100
            )

    assert stream.consumed == 0
    assert stream.closed


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [429, 502, 503, 504])
async def test_every_transient_status_retries_then_succeeds_and_honors_retry_after(
    status: int,
) -> None:
    attempts = 0
    delays: list[float] = []

    async def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            return httpx.Response(status, headers={"retry-after": "3"})
        return httpx.Response(200, json={"attempts": attempts})

    async def sleep(delay: float) -> None:
        delays.append(delay)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as shared:
        response = await AnchoreHttpClient(shared, sleep=sleep, random_value=lambda: 0.0).get_json(
            connection(max_retries=1), "/v2/images", max_response_bytes=100
        )

    assert response.data == {"attempts": 2}
    assert attempts == 2
    assert delays == [3.0]


@pytest.mark.asyncio
async def test_retry_after_http_date_uses_injected_clock() -> None:
    attempts = 0
    delays: list[float] = []

    async def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            return httpx.Response(503, headers={"retry-after": "Thu, 09 Jul 2026 12:00:05 GMT"})
        return httpx.Response(200, json={})

    async def sleep(delay: float) -> None:
        delays.append(delay)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as shared:
        await AnchoreHttpClient(
            shared,
            sleep=sleep,
            random_value=lambda: 0.0,
            clock=lambda: datetime(2026, 7, 9, 12, 0, tzinfo=UTC),
        ).get_json(connection(max_retries=1), "/v2/images", max_response_bytes=100)

    assert delays == [5.0]


@pytest.mark.asyncio
async def test_transient_status_attempts_are_bounded_and_last_status_is_safe() -> None:
    attempts = 0

    async def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        return httpx.Response(503, content=BODY_MARKER.encode())

    async def no_sleep(_delay: float) -> None:
        return None

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as shared:
        with pytest.raises(AnchoreHttpError) as caught:
            await AnchoreHttpClient(shared, sleep=no_sleep).get_json(
                connection(max_retries=2), "/v2/images", max_response_bytes=100
            )

    assert attempts == 3
    assert caught.value.status == 503
    assert BODY_MARKER not in str(caught.value)


@pytest.mark.asyncio
@pytest.mark.parametrize("exception_type", [httpx.ConnectError, httpx.ConnectTimeout])
async def test_connect_failures_retry_then_succeed(
    exception_type: type[httpx.RequestError],
) -> None:
    attempts = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise exception_type(EXCEPTION_MARKER, request=request)
        return httpx.Response(200, json={"ok": True})

    async def no_sleep(_delay: float) -> None:
        return None

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as shared:
        response = await AnchoreHttpClient(shared, sleep=no_sleep).get_json(
            connection(max_retries=1), "/v2/images", max_response_bytes=100
        )

    assert attempts == 2
    assert response.data == {"ok": True}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("exception_type", "safe_type"),
    [
        (httpx.ReadTimeout, AnchoreTimeoutError),
        (httpx.PoolTimeout, AnchoreTimeoutError),
    ],
)
async def test_read_and_pool_timeouts_do_not_retry(
    exception_type: type[httpx.RequestError], safe_type: type[Exception]
) -> None:
    attempts = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        raise exception_type(EXCEPTION_MARKER, request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as shared:
        with pytest.raises(safe_type) as caught:
            await AnchoreHttpClient(shared).get_json(
                connection(max_retries=2), "/v2/images", max_response_bytes=100
            )

    assert attempts == 1
    assert EXCEPTION_MARKER not in str(caught.value)


@pytest.mark.asyncio
async def test_exhausted_connect_error_is_safe() -> None:
    attempts = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        raise httpx.ConnectError(EXCEPTION_MARKER, request=request)

    async def no_sleep(_delay: float) -> None:
        return None

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as shared:
        with pytest.raises(AnchoreNetworkError) as caught:
            await AnchoreHttpClient(shared, sleep=no_sleep).get_json(
                connection(max_retries=1), "/v2/images", max_response_bytes=100
            )

    assert attempts == 2
    assert EXCEPTION_MARKER not in str(caught.value)
    assert TOKEN_MARKER not in str(caught.value)


@pytest.mark.asyncio
async def test_request_cancellation_propagates_without_retry() -> None:
    attempts = 0

    async def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        raise asyncio.CancelledError

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as shared:
        with pytest.raises(asyncio.CancelledError):
            await AnchoreHttpClient(shared).get_json(
                connection(max_retries=2), "/v2/images", max_response_bytes=100
            )

    assert attempts == 1


@pytest.mark.asyncio
async def test_sleep_cancellation_propagates_without_another_attempt() -> None:
    attempts = 0

    async def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        return httpx.Response(503)

    async def cancelled_sleep(_delay: float) -> None:
        raise asyncio.CancelledError

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as shared:
        with pytest.raises(asyncio.CancelledError):
            await AnchoreHttpClient(shared, sleep=cancelled_sleep).get_json(
                connection(max_retries=2), "/v2/images", max_response_bytes=100
            )

    assert attempts == 1


@pytest.mark.asyncio
async def test_transient_response_closes_before_retry_sleep() -> None:
    stream = ChunkStream([BODY_MARKER.encode()])
    attempts = 0

    async def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            return httpx.Response(503, stream=stream)
        return httpx.Response(200, json={})

    async def assert_closed(_delay: float) -> None:
        assert stream.closed

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as shared:
        await AnchoreHttpClient(shared, sleep=assert_closed).get_json(
            connection(max_retries=1), "/v2/images", max_response_bytes=100
        )

    assert stream.consumed == 0
    assert stream.closed


@pytest.mark.asyncio
@pytest.mark.parametrize(("status", "content"), [(200, b"{broken"), (500, BODY_MARKER.encode())])
async def test_failed_response_streams_are_closed(status: int, content: bytes) -> None:
    stream = ChunkStream([content])

    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, stream=stream)

    expected_error = AnchoreInvalidResponseError if status == 200 else AnchoreHttpError
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as shared:
        with pytest.raises(expected_error):
            await AnchoreHttpClient(shared).get_json(
                connection(), "/v2/images", max_response_bytes=100
            )

    assert stream.closed
    assert stream.consumed == (1 if status == 200 else 0)


@pytest.mark.asyncio
async def test_body_stream_cancellation_closes_response() -> None:
    stream = CancellingStream()

    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, stream=stream)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as shared:
        with pytest.raises(asyncio.CancelledError):
            await AnchoreHttpClient(shared).get_json(
                connection(), "/v2/images", max_response_bytes=100
            )

    assert stream.closed


@pytest.mark.asyncio
@pytest.mark.parametrize("limit", [0, -1, True, 1.5, MAX_RESPONSE_BYTES + 1])
async def test_response_size_limit_must_be_a_positive_bounded_integer(limit: object) -> None:
    calls = 0

    async def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json={})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as shared:
        with pytest.raises(ValueError, match="max_response_bytes"):
            await AnchoreHttpClient(shared).get_json(
                connection(), "/v2/images", max_response_bytes=cast(int, limit)
            )

    assert calls == 0


@pytest.mark.asyncio
async def test_default_and_override_timeouts_are_passed_to_request() -> None:
    observed: list[dict[str, object]] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        observed.append(cast(dict[str, object], request.extensions["timeout"]))
        return httpx.Response(200, json={})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as shared:
        client = AnchoreHttpClient(shared)
        await client.get_json(connection(), "/v2/images", max_response_bytes=100)
        await client.get_json(connection(), "/v2/images", max_response_bytes=100, timeout=2.5)

    assert observed[0] == {"connect": 10.0, "read": 60.0, "write": 10.0, "pool": 10.0}
    assert observed[1] == {"connect": 2.5, "read": 2.5, "write": 2.5, "pool": 2.5}


def test_json_response_is_frozen_and_slotted() -> None:
    response = JsonResponse(data={}, byte_length=0, headers=httpx.Headers())

    assert not hasattr(response, "__dict__")
    with pytest.raises((AttributeError, TypeError)):
        response.byte_length = 1  # type: ignore[misc]
