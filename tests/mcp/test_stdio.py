import asyncio
import os
from pathlib import Path

from fastmcp import Client
from fastmcp.client.transports import StdioTransport
import pytest


ROOT = Path(__file__).parents[2]
EXPECTED_TOOLS = {
    "anchore_connection_info",
    "anchore_list_images",
    "anchore_image_vulnerabilities",
    "anchore_image_sbom",
    "anchore_image_policy_check",
    "anchore_policy_blocking_vulnerabilities",
    "anchore_image_detail",
    "anchore_remediation_handoff",
}


def clean_environment() -> dict[str, str]:
    return {key: value for key, value in os.environ.items() if not key.startswith("ANCHORE_")}


def active_stdio_transport_tasks() -> list[asyncio.Task[object]]:
    return [
        task
        for task in asyncio.all_tasks()
        if not task.done() and "_stdio_transport_connect_task" in repr(task.get_coro())
    ]


@pytest.mark.asyncio
async def test_stdio_discovers_without_credentials_and_exits_cleanly() -> None:
    transport = StdioTransport(
        command="uv",
        args=["run", "--frozen", "anchore-mcp"],
        env=clean_environment(),
        cwd=str(ROOT),
        keep_alive=False,
    )

    async with Client(transport) as client:
        tools = await client.list_tools()

    assert {tool.name for tool in tools} == EXPECTED_TOOLS
    assert active_stdio_transport_tasks() == []


@pytest.mark.asyncio
async def test_stdio_eof_exits_within_two_seconds() -> None:
    process = await asyncio.create_subprocess_exec(
        "uv",
        "run",
        "--frozen",
        "anchore-mcp",
        cwd=ROOT,
        env=clean_environment(),
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    assert process.stdin is not None
    process.stdin.close()

    return_code = await asyncio.wait_for(process.wait(), timeout=2)
    stdout, _stderr = await process.communicate()

    assert return_code == 0
    assert stdout == b""


@pytest.mark.asyncio
async def test_cancelled_stdio_request_leaves_no_transport_process() -> None:
    environment = clean_environment()
    environment.update(
        {
            "ANCHORE_URL": "https://127.0.0.1:9",
            "ANCHORE_TOKEN": "synthetic-test-token",
            "ANCHORE_HTTP_MAX_RETRIES": "0",
        }
    )
    transport = StdioTransport(
        command="uv",
        args=["run", "--frozen", "anchore-mcp"],
        env=environment,
        cwd=str(ROOT),
        keep_alive=False,
    )
    async with Client(transport) as client:
        request = asyncio.create_task(client.call_tool("anchore_list_images", {}))
        await asyncio.sleep(0)
        request.cancel()
        with pytest.raises(asyncio.CancelledError):
            await request

    assert active_stdio_transport_tasks() == []
