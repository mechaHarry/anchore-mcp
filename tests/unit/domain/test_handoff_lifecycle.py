import asyncio

import httpx
from pydantic import SecretStr
import pytest

from anchore_mcp.anchore.http import JsonResponse
from anchore_mcp.config import AnchoreConnection
from anchore_mcp.domain.handoff import build_remediation_handoff
from anchore_mcp.errors import AnchoreHttpError
from anchore_mcp.models.locators import DigestLocator


class ConcurrentHttp:
    def __init__(
        self,
        expected: int,
        *,
        fail_path: str | None = None,
        cancel_path: str | None = None,
        hold_success: bool = False,
    ) -> None:
        self.expected = expected
        self.fail_path = fail_path
        self.cancel_path = cancel_path
        self.hold_success = hold_success
        self.running_requests = 0
        self.max_running_requests = 0
        self.entered: set[str] = set()
        self.tasks: list[asyncio.Task[object]] = []
        self.all_entered = asyncio.Event()

    async def get_json(
        self,
        connection: AnchoreConnection,
        path: str,
        *,
        params: httpx.QueryParams | None = None,
        max_response_bytes: int,
        timeout: httpx.Timeout | float | None = None,
    ) -> JsonResponse:
        del connection, params, max_response_bytes, timeout
        task = asyncio.current_task()
        assert task is not None
        self.tasks.append(task)
        self.running_requests += 1
        self.max_running_requests = max(self.max_running_requests, self.running_requests)
        self.entered.add(path)
        if len(self.entered) == self.expected:
            self.all_entered.set()
        try:
            await self.all_entered.wait()
            if path == self.cancel_path:
                raise asyncio.CancelledError
            if path == self.fail_path:
                raise AnchoreHttpError(503, "Anchore request failed with HTTP status 503")
            if self.hold_success:
                await asyncio.Event().wait()
            else:
                await asyncio.sleep(0)
            return JsonResponse(data={"path": path}, byte_length=len(path), headers=httpx.Headers())
        finally:
            self.running_requests -= 1


def connection() -> AnchoreConnection:
    return AnchoreConnection(
        base_url="https://anchore.example",
        token=SecretStr("test-token"),
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(("include_policy", "expected"), [(False, 2), (True, 3)])
async def test_handoff_requests_overlap_without_survivors(
    include_policy: bool, expected: int
) -> None:
    client = ConcurrentHttp(expected)

    await build_remediation_handoff(
        client,
        connection(),
        DigestLocator(kind="digest", digest="sha256:abc"),
        include_policy_check=include_policy,
    )

    assert client.max_running_requests == expected
    assert client.running_requests == 0
    assert all(task.done() for task in client.tasks)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "fail_path",
    [
        "/v2/images/sha256%3Aabc",
        "/v2/images/sha256%3Aabc/vuln/all",
        "/v2/images/sha256%3Aabc/check",
    ],
)
async def test_handoff_failure_cancels_siblings_and_unwraps_single_leaf(
    fail_path: str,
) -> None:
    client = ConcurrentHttp(3, fail_path=fail_path)

    with pytest.raises(AnchoreHttpError) as caught:
        await build_remediation_handoff(
            client,
            connection(),
            DigestLocator(kind="digest", digest="sha256:abc"),
            include_policy_check=True,
        )

    assert caught.value.status == 503
    assert client.running_requests == 0
    assert all(task.done() for task in client.tasks)


@pytest.mark.asyncio
async def test_handoff_child_self_cancellation_cancels_and_joins_siblings() -> None:
    policy_path = "/v2/images/sha256%3Aabc/check"
    client = ConcurrentHttp(3, cancel_path=policy_path, hold_success=True)

    with pytest.raises(asyncio.CancelledError):
        await build_remediation_handoff(
            client,
            connection(),
            DigestLocator(kind="digest", digest="sha256:abc"),
            include_policy_check=True,
        )

    assert client.running_requests == 0
    assert all(task.done() for task in client.tasks)


@pytest.mark.asyncio
async def test_handoff_parent_cancellation_joins_all_children() -> None:
    client = ConcurrentHttp(3, hold_success=True)
    parent = asyncio.create_task(
        build_remediation_handoff(
            client,
            connection(),
            DigestLocator(kind="digest", digest="sha256:abc"),
            include_policy_check=True,
        )
    )
    await client.all_entered.wait()
    parent.cancel()

    with pytest.raises(asyncio.CancelledError):
        await parent

    assert client.running_requests == 0
    assert all(task.done() for task in client.tasks)
