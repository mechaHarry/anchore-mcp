import asyncio
import os
from typing import Protocol, cast

import httpx
import pytest
from pytest import MonkeyPatch

from anchore_mcp.runtime import Runtime, create_runtime, runtime_lifespan


class _PoolView(Protocol):
    _max_connections: int
    _max_keepalive_connections: int
    _keepalive_expiry: float


class _TransportView(Protocol):
    _pool: _PoolView


def test_factory_has_exact_transport_policy_and_does_not_read_environment(
    monkeypatch: MonkeyPatch,
) -> None:
    def fail_getenv(*_args: object) -> None:
        raise AssertionError("env read")

    monkeypatch.setattr(os, "getenv", fail_getenv)
    runtime = create_runtime()
    transport = cast(
        _TransportView,
        cast(object, runtime.http_client._transport),  # pyright: ignore[reportPrivateUsage]
    )
    assert transport._pool._max_connections == 20  # pyright: ignore[reportPrivateUsage]
    assert transport._pool._max_keepalive_connections == 10  # pyright: ignore[reportPrivateUsage]
    assert transport._pool._keepalive_expiry == 30.0  # pyright: ignore[reportPrivateUsage]
    assert runtime.http_client.follow_redirects is False
    assert runtime.http_client.timeout == httpx.Timeout(connect=10, read=60, write=10, pool=10)
    assert runtime.http_client.headers["user-agent"].startswith("anchore-mcp/")


@pytest.mark.asyncio
async def test_context_lifespan_creates_and_closes_fresh_runtime_repeatedly() -> None:
    seen: list[Runtime] = []
    for _ in range(2):
        async with runtime_lifespan() as runtime:
            seen.append(runtime)
            assert not runtime.closed
        assert runtime.closed
        assert runtime.http_client.is_closed
    assert seen[0] is not seen[1]


@pytest.mark.asyncio
async def test_owned_tasks_are_removed_and_exceptions_retrieved() -> None:
    runtime = create_runtime()

    async def fail() -> None:
        raise RuntimeError("expected")

    task = runtime.create_task(fail(), name="failure")
    await asyncio.sleep(0)
    await asyncio.sleep(0)
    assert task.done()
    assert runtime.owned_tasks == set()
    assert isinstance(task.exception(), RuntimeError)
    await runtime.close()


@pytest.mark.asyncio
async def test_close_cancels_tasks_clears_cache_and_is_idempotent() -> None:
    runtime = create_runtime()
    started = asyncio.Event()

    async def wait() -> None:
        started.set()
        await asyncio.Event().wait()

    task = runtime.create_task(wait())
    await started.wait()
    await runtime.close()
    await runtime.close()
    assert task.cancelled()
    assert runtime.owned_tasks == set()
    assert runtime.openapi_cache.size == 0
    assert runtime.http_client.is_closed
    with pytest.raises(RuntimeError, match="closed"):
        runtime.create_task(asyncio.sleep(0))


@pytest.mark.asyncio
async def test_caller_cancellation_still_finishes_close_cleanup() -> None:
    runtime = create_runtime()
    task = runtime.create_task(asyncio.Event().wait())
    close_task = asyncio.create_task(runtime.close())
    await asyncio.sleep(0)
    close_task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await close_task
    assert runtime.closed
    assert task.cancelled()
    assert runtime.owned_tasks == set()
    assert runtime.openapi_cache.size == 0
    assert runtime.http_client.is_closed
