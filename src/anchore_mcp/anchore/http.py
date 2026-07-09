"""Bounded asynchronous HTTP reads for the Anchore API."""

from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
import json
import math
import random
import re
from typing import NoReturn, cast
from urllib.parse import unquote, urlsplit

import httpx
from pydantic import JsonValue, TypeAdapter, ValidationError

from anchore_mcp.anchore.retry import (
    backoff_seconds,
    is_transient_status,
    parse_retry_after,
    sleep_with_cancellation,
)
from anchore_mcp.config import AnchoreConnection
from anchore_mcp.errors import (
    AnchoreHttpError,
    AnchoreInvalidResponseError,
    AnchoreNetworkError,
    AnchoreResponseTooLargeError,
    AnchoreTimeoutError,
)


MAX_RESPONSE_BYTES = 100 * 1024 * 1024
DEFAULT_TIMEOUT = httpx.Timeout(connect=10.0, read=60.0, write=10.0, pool=10.0)

_JSON_ADAPTER: TypeAdapter[JsonValue] = TypeAdapter(JsonValue)
_INVALID_PERCENT_ESCAPE = re.compile(r"%(?![0-9A-Fa-f]{2})")

type QueryScalar = str | int | float | bool | None
type StructuredQueryParams = Mapping[str, QueryScalar] | httpx.QueryParams


@dataclass(frozen=True, slots=True)
class JsonResponse:
    data: JsonValue
    byte_length: int
    headers: httpx.Headers


class AnchoreHttpClient:
    """Perform request-scoped, idempotent Anchore GET requests."""

    def __init__(
        self,
        client: httpx.AsyncClient,
        *,
        sleep: Callable[[float], Awaitable[None]] | None = None,
        random_value: Callable[[], float] | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._client = client
        self._sleep = sleep
        self._random_value = random.random if random_value is None else random_value
        self._clock = _utc_now if clock is None else clock

    async def get_json(
        self,
        connection: AnchoreConnection,
        path: str,
        *,
        params: StructuredQueryParams | None = None,
        max_response_bytes: int,
        timeout: httpx.Timeout | float | None = None,
    ) -> JsonResponse:
        """GET and strictly decode one size-bounded JSON response."""

        _validate_response_limit(max_response_bytes)
        url = _compose_url(connection.base_url, path)
        headers = {"accept": "application/json"}
        if connection.account is not None:
            headers["x-anchore-account"] = connection.account
        auth = httpx.BasicAuth(connection.username, connection.token.get_secret_value())
        request_timeout = DEFAULT_TIMEOUT if timeout is None else timeout

        max_attempts = connection.retry.max_retries + 1
        for attempt in range(max_attempts):
            retry_after: float | None = None
            try:
                async with self._client.stream(
                    "GET",
                    url,
                    params=params,
                    headers=headers,
                    auth=auth,
                    timeout=request_timeout,
                    follow_redirects=False,
                ) as response:
                    status = response.status_code
                    if is_transient_status(status) and attempt + 1 < max_attempts:
                        retry_after = parse_retry_after(
                            response.headers.get("retry-after"),
                            now=self._clock(),
                            max_delay_s=connection.retry.max_delay_ms / 1000,
                        )
                    elif not 200 <= status < 300:
                        raise _http_error(status)
                    else:
                        return await _read_json_response(response, max_response_bytes)
            except httpx.ConnectTimeout as error:
                if attempt + 1 >= max_attempts:
                    raise AnchoreTimeoutError("connect") from error
            except httpx.ConnectError as error:
                if attempt + 1 >= max_attempts:
                    raise AnchoreNetworkError("Unable to connect to Anchore") from error
            except httpx.ReadTimeout as error:
                raise AnchoreTimeoutError("read") from error
            except httpx.PoolTimeout as error:
                raise AnchoreTimeoutError("pool") from error
            except httpx.WriteTimeout as error:
                raise AnchoreTimeoutError("write") from error
            except httpx.TimeoutException as error:
                raise AnchoreTimeoutError("request") from error
            except httpx.DecodingError as error:
                raise AnchoreInvalidResponseError("Anchore returned an invalid response") from error
            except httpx.RequestError as error:
                raise AnchoreNetworkError("Unable to complete Anchore request") from error

            delay = backoff_seconds(
                attempt,
                connection.retry,
                random_value=self._random_value(),
                retry_after=retry_after,
            )
            await sleep_with_cancellation(delay, sleep=self._sleep)

        raise RuntimeError("retry loop exhausted without a result")


async def _read_json_response(response: httpx.Response, max_response_bytes: int) -> JsonResponse:
    body = bytearray()
    async for chunk in response.aiter_bytes():
        observed = len(body) + len(chunk)
        if observed > max_response_bytes:
            raise AnchoreResponseTooLargeError(observed, max_response_bytes)
        body.extend(chunk)

    headers = httpx.Headers(response.headers)
    if not body:
        return JsonResponse(data={}, byte_length=0, headers=headers)

    try:
        text = bytes(body).decode("utf-8", errors="strict")
        parsed = cast(
            object,
            json.loads(
                text,
                parse_constant=_reject_nonfinite,
                parse_float=_parse_finite_float,
            ),
        )
        data = _JSON_ADAPTER.validate_python(parsed)
    except (UnicodeDecodeError, json.JSONDecodeError, ValidationError, ValueError) as error:
        raise AnchoreInvalidResponseError("Anchore returned an invalid JSON response") from error
    return JsonResponse(data=data, byte_length=len(body), headers=headers)


def _reject_nonfinite(_value: str) -> NoReturn:
    raise ValueError("non-finite JSON number")


def _parse_finite_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError("non-finite JSON number")
    return parsed


def _validate_response_limit(value: int) -> None:
    if type(value) is not int or not 1 <= value <= MAX_RESPONSE_BYTES:
        raise ValueError(
            f"max_response_bytes must be an integer between 1 and {MAX_RESPONSE_BYTES}"
        )


def _compose_url(base_url: str, path: str) -> httpx.URL:
    if not path.startswith("/") or path.startswith("//"):
        raise ValueError("path must be an absolute-origin path beginning with one slash")
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in path):
        raise ValueError("path must not contain control characters")
    if "\\" in path or _INVALID_PERCENT_ESCAPE.search(path):
        raise ValueError("path contains an unsafe escape")

    parsed = urlsplit(path)
    if parsed.scheme or parsed.netloc or parsed.query or parsed.fragment or parsed.path != path:
        raise ValueError("path must not contain an origin, query, or fragment")

    decoded = path
    for _ in range(3):
        decoded_next = unquote(decoded)
        if decoded_next == decoded:
            break
        decoded = decoded_next
    if "\\" in decoded or any(segment in {".", ".."} for segment in decoded.split("/")):
        raise ValueError("path must not contain dot traversal segments")

    return httpx.URL(f"{base_url.rstrip('/')}{path}")


def _http_error(status: int) -> AnchoreHttpError:
    if 300 <= status < 400:
        message = "Anchore redirected the request unexpectedly"
    elif status == 401:
        message = "Anchore authentication failed"
    elif status == 403:
        message = "Anchore request was forbidden"
    elif status == 404:
        message = "Anchore resource was not found"
    else:
        message = f"Anchore request failed with HTTP status {status}"
    return AnchoreHttpError(status, message)


def _utc_now() -> datetime:
    return datetime.now(UTC)
