from collections.abc import Mapping, Sequence
import json
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import httpx
from pydantic import JsonValue

from anchore_mcp.anchore.http import JsonResponse
from anchore_mcp.anchore.openapi import OpenApiCache
from anchore_mcp.config import AnchoreConnection
from anchore_mcp.runtime import Runtime


FIXTURES = Path(__file__).parents[1] / "fixtures" / "semantic"


def fixture(name: str) -> dict[str, JsonValue]:
    value = json.loads((FIXTURES / name).read_text(encoding="utf-8"))
    return cast(dict[str, JsonValue], value)


class FixtureHttp:
    def __init__(self, responses: Mapping[str, Sequence[JsonValue]]) -> None:
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
        data = self.responses[path].pop(0)
        return JsonResponse(data=data, byte_length=len(json.dumps(data)), headers=httpx.Headers())


class RuntimeFactory:
    def __init__(self, http: FixtureHttp) -> None:
        self.http = http
        self.runtimes: list[Runtime] = []

    def __call__(self) -> Runtime:
        client = httpx.AsyncClient(transport=httpx.MockTransport(lambda _: httpx.Response(500)))
        runtime = Runtime(
            http_client=client,
            anchore_http=cast(object, self.http),  # type: ignore[arg-type]
            openapi_cache=OpenApiCache(self.http),
        )
        self.runtimes.append(runtime)
        return runtime


def configured_env(monkeypatch: object, *, version: str = "v2") -> None:
    setter = cast(SimpleNamespace, monkeypatch)
    setter.setenv("ANCHORE_URL", "https://anchore.example/api")
    setter.setenv("ANCHORE_TOKEN", "synthetic-test-token")
    setter.setenv("ANCHORE_API_VERSION", version)
