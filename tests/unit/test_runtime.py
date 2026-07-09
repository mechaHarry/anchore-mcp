import asyncio
from typing import Any

import httpx
import pytest
from pytest import MonkeyPatch

from anchore_mcp.runtime import Runtime, create_runtime, runtime_lifespan


@pytest.mark.asyncio
async def test_factory_has_exact_transport_policy_and_does_not_read_environment(
    monkeypatch: MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    def client_factory(**kwargs: Any) -> httpx.AsyncClient:
        captured.update(kwargs)
        return httpx.AsyncClient(**kwargs)

    def fail_load(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("connection config loaded")

    monkeypatch.setattr("anchore_mcp.config.load_connection", fail_load)
    runtime = create_runtime(client_factory=client_factory)
    limits = captured["limits"]
    assert isinstance(limits, httpx.Limits)
    assert limits == httpx.Limits(
        max_connections=20,
        max_keepalive_connections=10,
        keepalive_expiry=30,
    )
    assert runtime.http_client.follow_redirects is False
    assert runtime.http_client.timeout == httpx.Timeout(connect=10, read=60, write=10, pool=10)
    assert runtime.http_client.headers["user-agent"].startswith("anchore-mcp/")
    await runtime.close()


@pytest.mark.asyncio
async def test_owned_task_can_close_runtime_without_cancelling_or_deadlocking_itself() -> None:
    runtime = create_runtime()

    async def close_from_owner() -> str:
        await runtime.close()
        return "closed"

    task = runtime.create_task(close_from_owner())
    assert await asyncio.wait_for(task, timeout=1) == "closed"
    assert runtime.closed
    assert runtime.http_client.is_closed


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
