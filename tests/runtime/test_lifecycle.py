import asyncio
from typing import cast

import httpx
from pydantic import JsonValue, SecretStr
import pytest

from anchore_mcp.anchore.http import JsonResponse
from anchore_mcp.anchore.openapi import OpenApiCache
from anchore_mcp.config import AnchoreConnection
from anchore_mcp.domain.handoff import build_remediation_handoff
from anchore_mcp.domain.policy_report import build_policy_blocking_report
from anchore_mcp.models.locators import DigestLocator
from anchore_mcp.runtime import Runtime, create_runtime


def connection() -> AnchoreConnection:
    return AnchoreConnection(
        base_url="https://anchore.example/api",
        token=SecretStr("synthetic-test-token"),
    )


@pytest.mark.asyncio
async def test_runtime_enter_use_exit_25_times_leaves_no_resources_or_named_tasks() -> None:
    runtimes: list[Runtime] = []
    for _ in range(25):
        runtime = create_runtime()
        runtimes.append(runtime)
        async with runtime:
            task = runtime.create_task(asyncio.sleep(0), name="anchore-mcp-lifecycle")
            await task

    assert all(runtime.closed for runtime in runtimes)
    assert all(runtime.http_client.is_closed for runtime in runtimes)
    assert all(runtime.openapi_cache.size == 0 for runtime in runtimes)
    assert all(runtime.owned_tasks == set() for runtime in runtimes)
    assert not any(
        task.get_name().startswith("anchore-mcp") and not task.done()
        for task in asyncio.all_tasks()
    )


class BarrierHttp:
    def __init__(self) -> None:
        self.started: set[str] = set()
        self.all_started = asyncio.Event()
        self.release = asyncio.Event()

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
        self.started.add(path)
        if len(self.started) == 3:
            self.all_started.set()
        await self.release.wait()
        data: JsonValue = {"status": "green"} if path.endswith("/check") else {"items": []}
        return JsonResponse(data=data, byte_length=2, headers=httpx.Headers())


@pytest.mark.asyncio
async def test_handoff_three_evidence_requests_overlap() -> None:
    client = BarrierHttp()
    operation = asyncio.create_task(
        build_remediation_handoff(
            client,
            connection(),
            DigestLocator(kind="digest", digest="sha256:abc"),
        )
    )
    await asyncio.wait_for(client.all_started.wait(), timeout=1)
    client.release.set()
    await operation

    assert client.started == {
        "/v2/images/sha256%3Aabc",
        "/v2/images/sha256%3Aabc/vuln/all",
        "/v2/images/sha256%3Aabc/check",
    }


class SequencedHttp:
    def __init__(self) -> None:
        self.calls: list[str] = []
        self.policy_finished = False

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
        self.calls.append(path)
        if path.endswith("/check"):
            await asyncio.sleep(0)
            self.policy_finished = True
            data: JsonValue = {
                "status": "red",
                "findings": [
                    {
                        "gate": "vulnerabilities",
                        "action": "stop",
                        "vulnerability_id": "CVE-2099-0001",
                    }
                ],
            }
        else:
            assert self.policy_finished
            data = {"items": [{"vuln": "CVE-2099-0001"}]}
        return JsonResponse(data=data, byte_length=2, headers=httpx.Headers())


@pytest.mark.asyncio
async def test_policy_blocker_waits_for_policy_before_vulnerabilities() -> None:
    client = SequencedHttp()
    await build_policy_blocking_report(
        client,
        connection(),
        DigestLocator(kind="digest", digest="sha256:abc"),
        OpenApiCache(cast(object, client)),  # type: ignore[arg-type]
    )

    assert client.calls == [
        "/v2/images/sha256%3Aabc/check",
        "/v2/images/sha256%3Aabc/vuln/all",
    ]
