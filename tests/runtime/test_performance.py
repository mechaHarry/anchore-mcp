import time
from typing import cast

from fastmcp import Client
from fastmcp.client.transports import StdioTransport
from pydantic import SecretStr
import pytest

from anchore_mcp.anchore.http import MAX_RESPONSE_BYTES
from anchore_mcp.anchore.openapi import OpenApiCache
from anchore_mcp.anchore.pagination import JsonHttpClient
from anchore_mcp.config import AnchoreConnection, RetryPolicy
from anchore_mcp.domain.resolution import MAX_DISAMBIGUATION_CANDIDATES
from anchore_mcp.runtime import create_runtime
from tests.mcp.test_stdio import ROOT, clean_environment
from tests.support.anchore_server import synthetic_anchore_server


@pytest.mark.performance
@pytest.mark.asyncio
async def test_warm_stdio_discovery_is_under_generous_three_second_ceiling() -> None:
    transport = StdioTransport(
        command="uv",
        args=["run", "--frozen", "anchore-mcp"],
        env=clean_environment(),
        cwd=str(ROOT),
        keep_alive=True,
    )
    try:
        async with Client(transport) as client:
            await client.list_tools()
        started = time.perf_counter()
        async with Client(transport) as client:
            await client.list_tools()
        elapsed = time.perf_counter() - started
    finally:
        await transport.close()

    assert elapsed < 3


@pytest.mark.performance
@pytest.mark.asyncio
async def test_sequential_loopback_requests_reuse_one_connection() -> None:
    with synthetic_anchore_server({"/v2/images": {"items": []}}) as server:
        connection = AnchoreConnection.model_construct(
            base_url=server.base_url,
            token=SecretStr("synthetic-test-token"),
            account=None,
            api_version="v2",
            retry=RetryPolicy(max_retries=0),
        )
        runtime = create_runtime()
        async with runtime:
            for _ in range(5):
                response = await runtime.anchore_http.get_json(
                    connection,
                    "/v2/images",
                    max_response_bytes=MAX_RESPONSE_BYTES,
                )
                assert response.data == {"items": []}

    assert server.requests == ["/v2/images"] * 5
    assert len(set(server.connection_ids)) == 1
    assert runtime.closed is True


@pytest.mark.performance
def test_bounded_container_cardinality_constants_are_small() -> None:
    cache = OpenApiCache(cast(JsonHttpClient, object()))
    assert MAX_DISAMBIGUATION_CANDIDATES <= 50
    assert cache.size <= 1
