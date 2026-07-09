from collections.abc import Sequence
from types import SimpleNamespace
from typing import cast

from fastmcp import Context
import httpx
from pydantic import JsonValue, SecretStr

from anchore_mcp.anchore.http import JsonResponse
from anchore_mcp.anchore.openapi import OpenApiCache
from anchore_mcp.config import AnchoreConnection
from anchore_mcp.runtime import Runtime


class RoutingHttp:
    def __init__(self, responses: dict[str, Sequence[tuple[object, int] | Exception]]) -> None:
        self.responses = {path: list(values) for path, values in responses.items()}
        self.calls: list[tuple[str, httpx.QueryParams, int]] = []

    async def get_json(
        self,
        connection: AnchoreConnection,
        path: str,
        *,
        params: httpx.QueryParams | None = None,
        max_response_bytes: int,
        timeout: httpx.Timeout | float | None = None,
    ) -> JsonResponse:
        del connection, timeout
        self.calls.append((path, params or httpx.QueryParams(), max_response_bytes))
        response = self.responses[path].pop(0)
        if isinstance(response, Exception):
            raise response
        data, size = response
        return JsonResponse(data=cast(JsonValue, data), byte_length=size, headers=httpx.Headers())


def connection() -> AnchoreConnection:
    return AnchoreConnection(
        base_url="https://anchore.example/root",
        token=SecretStr("private-token"),
        account="team",
        api_version="v2",
    )


def context(http: RoutingHttp) -> Context:
    runtime = Runtime(
        http_client=cast(httpx.AsyncClient, SimpleNamespace()),
        anchore_http=cast(object, http),  # type: ignore[arg-type]
        openapi_cache=OpenApiCache(http),
    )
    return cast(Context, SimpleNamespace(lifespan_context=runtime))
