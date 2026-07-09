"""Shared asynchronous runtime resources for the future FastMCP lifespan."""

import asyncio
from collections.abc import AsyncGenerator, Callable, Coroutine
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
import inspect
from types import TracebackType
from typing import Any, Self, TypeVar, cast

import httpx

from anchore_mcp import __version__
from anchore_mcp.anchore.http import AnchoreHttpClient
from anchore_mcp.anchore.openapi import OpenApiCache


_T = TypeVar("_T")
_LIMITS = httpx.Limits(
    max_connections=20,
    max_keepalive_connections=10,
    keepalive_expiry=30.0,
)
_TIMEOUT = httpx.Timeout(connect=10.0, read=60.0, write=10.0, pool=10.0)


@dataclass(slots=True)
class Runtime:
    http_client: httpx.AsyncClient
    anchore_http: AnchoreHttpClient
    openapi_cache: OpenApiCache
    owned_tasks: set[asyncio.Task[object]] = field(
        default_factory=lambda: set[asyncio.Task[object]]()
    )
    _closed: bool = False
    _cleanup_task: asyncio.Task[None] | None = None
    _joining_tasks: set[asyncio.Task[object]] = field(
        default_factory=lambda: set[asyncio.Task[object]]()
    )

    @property
    def closed(self) -> bool:
        return self._closed

    def create_task(
        self,
        coroutine: Coroutine[Any, Any, _T],
        *,
        name: str | None = None,
    ) -> asyncio.Task[_T]:
        if self._closed or self._cleanup_task is not None:
            if inspect.iscoroutine(coroutine):
                coroutine.close()
            raise RuntimeError("runtime is closed")
        task = asyncio.create_task(coroutine, name=name)
        owned = cast(asyncio.Task[object], task)
        self.owned_tasks.add(owned)
        task.add_done_callback(self._task_finished)
        return task

    def _task_finished(self, task: asyncio.Task[object]) -> None:
        self.owned_tasks.discard(task)
        if not task.cancelled():
            task.exception()

    async def close(self) -> None:
        if self._closed:
            return
        current = cast(asyncio.Task[object] | None, asyncio.current_task())
        if current is not None:
            self.owned_tasks.discard(current)
            if current in self._joining_tasks:
                return
        if self._cleanup_task is None:
            self._cleanup_task = asyncio.create_task(self._close_resources())
        cleanup = self._cleanup_task
        try:
            await asyncio.shield(cleanup)
        except asyncio.CancelledError:
            await cleanup
            raise

    async def _close_resources(self) -> None:
        try:
            await asyncio.sleep(0)
            pending = tuple(task for task in self.owned_tasks if not task.done())
            self._joining_tasks.update(pending)
            try:
                for task in pending:
                    task.cancel()
                if pending:
                    await asyncio.gather(*pending, return_exceptions=True)
            finally:
                self._joining_tasks.difference_update(pending)
            self.owned_tasks.clear()
            self.openapi_cache.clear()
            await self.http_client.aclose()
        finally:
            self._closed = True

    async def __aenter__(self) -> Self:
        if self._closed:
            raise RuntimeError("runtime is closed")
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exc_type, exc_value, traceback
        await self.close()


def create_runtime(
    *,
    client_factory: Callable[..., httpx.AsyncClient] = httpx.AsyncClient,
) -> Runtime:
    """Create transport resources without reading connection configuration or environment."""

    client = client_factory(
        http2=True,
        follow_redirects=False,
        limits=_LIMITS,
        timeout=_TIMEOUT,
        headers={
            "User-Agent": f"anchore-mcp/{__version__}",
            "Accept": "application/json",
            "Accept-Encoding": "identity",
        },
    )
    anchore_http = AnchoreHttpClient(client)
    return Runtime(
        http_client=client,
        anchore_http=anchore_http,
        openapi_cache=OpenApiCache(anchore_http),
    )


@asynccontextmanager
async def runtime_lifespan() -> AsyncGenerator[Runtime]:
    runtime = create_runtime()
    try:
        yield runtime
    finally:
        await runtime.close()
