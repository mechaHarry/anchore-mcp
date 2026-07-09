import asyncio
from collections.abc import Callable

import httpx
from pydantic import SecretStr
import pytest

from anchore_mcp.anchore.http import JsonResponse
from anchore_mcp.anchore.openapi import (
    FALLBACK_LIST_IMAGES_QUERY_KEYS,
    MAX_LIST_QUERY_KEYS,
    MAX_LIST_QUERY_VALUE_LENGTH,
    MAX_OPENAPI_BYTES,
    OpenApiCache,
    extract_list_images_query_parameter_names,
    fallback_list_images_query_keys,
    merge_list_images_query,
    openapi_advertises_v1_image_tag_summary_filters,
)
from anchore_mcp.config import AnchoreConnection


class StubHttp:
    def __init__(self, handler: Callable[[AnchoreConnection, str, int], object]) -> None:
        self.handler = handler
        self.calls: list[tuple[AnchoreConnection, str, int]] = []

    async def get_json(
        self,
        connection: AnchoreConnection,
        path: str,
        *,
        params: httpx.QueryParams | None = None,
        max_response_bytes: int,
        timeout: httpx.Timeout | float | None = None,
    ) -> JsonResponse:
        del params, timeout
        self.calls.append((connection, path, max_response_bytes))
        value = self.handler(connection, path, max_response_bytes)
        if isinstance(value, BaseException):
            raise value
        if asyncio.isfuture(value):
            value = await value
        return JsonResponse(data=value, byte_length=2, headers=httpx.Headers())  # type: ignore[arg-type]


def connection(
    *,
    token: str = "one",
    account: str | None = None,
    version: str = "v2",
    base: str = "https://AE.example:443/root",
) -> AnchoreConnection:
    return AnchoreConnection(
        base_url=base,
        token=SecretStr(token),
        account=account,
        api_version=version,  # type: ignore[arg-type]
    )


@pytest.mark.asyncio
async def test_cache_uses_version_route_ttl_and_token_independent_key() -> None:
    now = [10.0]
    http = StubHttp(lambda _c, path, size: {"path": path, "size": size, "n": len(http.calls)})
    cache = OpenApiCache(http, clock=lambda: now[0])
    first = await cache.fetch(connection(token="one"))
    second = await cache.fetch(connection(token="two"))
    assert first == second
    assert len(http.calls) == 1
    assert http.calls[0][1:] == ("/v2/openapi.json", MAX_OPENAPI_BYTES)
    assert cache.size == 1
    now[0] += 601
    assert await cache.fetch(connection(token="two")) != first
    assert len(http.calls) == 2


@pytest.mark.asyncio
async def test_account_or_version_replaces_the_single_entry() -> None:
    http = StubHttp(lambda c, path, _size: {"account": c.account, "path": path})
    cache = OpenApiCache(http)
    await cache.fetch(connection(account="a"))
    await cache.fetch(connection(account="b", version="v1"))
    assert cache.size == 1
    assert http.calls[-1][1] == "/v1/openapi.json"
    await cache.fetch(connection(account="a"))
    assert len(http.calls) == 3


@pytest.mark.asyncio
async def test_concurrent_fetches_are_coalesced() -> None:
    future: asyncio.Future[object] = asyncio.get_running_loop().create_future()
    http = StubHttp(lambda _c, _p, _s: future)
    cache = OpenApiCache(http)
    tasks = [asyncio.create_task(cache.fetch(connection())) for _ in range(8)]
    await asyncio.sleep(0)
    future.set_result({"ok": True})
    assert await asyncio.gather(*tasks) == [{"ok": True}] * 8
    assert len(http.calls) == 1


@pytest.mark.asyncio
async def test_failures_and_cancellation_are_not_cached() -> None:
    http = StubHttp(lambda _c, _p, _s: RuntimeError("no"))
    cache = OpenApiCache(http)
    with pytest.raises(RuntimeError):
        await cache.fetch(connection())
    assert cache.size == 0

    future: asyncio.Future[object] = asyncio.get_running_loop().create_future()
    cancelled_http = StubHttp(lambda _c, _p, _s: future)
    cancelled_cache = OpenApiCache(cancelled_http)
    task = asyncio.create_task(cancelled_cache.fetch(connection()))
    await asyncio.sleep(0)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert cancelled_cache.size == 0


@pytest.mark.asyncio
async def test_expired_entry_is_removed_before_failed_refresh() -> None:
    now = [0.0]
    fail = [False]

    def handler(_connection: AnchoreConnection, _path: str, _size: int) -> object:
        return RuntimeError("refresh failed") if fail[0] else {"ok": True}

    cache = OpenApiCache(StubHttp(handler), clock=lambda: now[0])
    await cache.fetch(connection())
    now[0] = 601
    fail[0] = True
    with pytest.raises(RuntimeError):
        await cache.fetch(connection())
    assert cache.size == 0


@pytest.mark.asyncio
async def test_clear_and_invalidate_remove_entry() -> None:
    cache = OpenApiCache(StubHttp(lambda _c, _p, _s: {}))
    conn = connection()
    await cache.fetch(conn)
    assert cache.invalidate(conn)
    assert cache.size == 0
    await cache.fetch(conn)
    cache.clear()
    assert cache.size == 0


def document(path: str, parameters: object) -> dict[str, object]:
    return {"paths": {path: {"get": {"parameters": parameters}}}}


def test_extracts_only_bounded_direct_query_parameters_from_exact_images_path() -> None:
    doc = document(
        "/v2/images",
        [
            {"name": "full_tag", "in": "query"},
            {"name": "header", "in": "header"},
            {"$ref": "#/components/x", "name": "bad", "in": "query"},
            {"name": "x" * 300, "in": "query"},
        ],
    )
    assert extract_list_images_query_parameter_names(doc, "v2") == frozenset({"full_tag"})
    assert extract_list_images_query_parameter_names(doc, "v1") == frozenset()


def test_v1_summary_capability_requires_direct_registry_and_repository() -> None:
    for path in ("/v1/summaries/image-tags", "/summaries/image-tags"):
        assert openapi_advertises_v1_image_tag_summary_filters(
            document(
                path,
                [{"name": "registry", "in": "query"}, {"name": "repository", "in": "query"}],
            )
        )
    assert not openapi_advertises_v1_image_tag_summary_filters(
        document(
            "/v1/summaries/image-tags",
            [{"$ref": "#/r"}, {"name": "repository", "in": "query"}],
        )
    )
    hostile_paths: dict[str, object] = {f"/{n}": {} for n in range(3000)}
    assert not openapi_advertises_v1_image_tag_summary_filters({"paths": hostile_paths})


def test_fallback_and_query_merge_are_bounded_with_explicit_precedence() -> None:
    assert {"full_tag", "fulltag", "vulnerability_id", "limit"} <= FALLBACK_LIST_IMAGES_QUERY_KEYS
    extras = {f"k{n}": str(n) for n in range(MAX_LIST_QUERY_KEYS + 3)}
    extras |= {
        "full_tag": "attacker",
        "vulnerability_id": "attacker",
        "huge": "x" * (MAX_LIST_QUERY_VALUE_LENGTH + 1),
    }
    merged = merge_list_images_query(
        version="v2",
        full_tag=" registry/team:tag ",
        vulnerability_id=" CVE-1 ",
        list_query=extras,
        allowlist=FALLBACK_LIST_IMAGES_QUERY_KEYS | frozenset(extras),
    )
    assert merged.params.get("full_tag") == "registry/team:tag"
    assert merged.params.get("vulnerability_id") == "CVE-1"
    assert "huge" in merged.rejected_keys
    assert len(merged.params) <= MAX_LIST_QUERY_KEYS + 2
    assert "fulltag" in fallback_list_images_query_keys("v1")
    assert "full_tag" not in fallback_list_images_query_keys("v1")
    assert "full_tag" in fallback_list_images_query_keys("v2")
    assert "fulltag" not in fallback_list_images_query_keys("v2")
