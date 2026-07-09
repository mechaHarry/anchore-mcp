import asyncio
import json
import os
import sys

import pytest


@pytest.mark.asyncio
async def test_stdio_suppresses_framework_payload_logging_and_banner() -> None:
    secret = "TOPSECRET-INPUT"
    messages: tuple[dict[str, object], ...] = (
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "logging-test", "version": "1"},
            },
        },
        {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "anchore_image_detail",
                "arguments": {
                    "locator": {
                        "kind": "digest",
                        "digest": 123,
                        "token": secret,
                    }
                },
            },
        },
    )
    environment = os.environ.copy()
    environment.pop("ANCHORE_URL", None)
    environment.pop("ANCHORE_TOKEN", None)

    process = await asyncio.create_subprocess_exec(
        sys.executable,
        "-m",
        "anchore_mcp",
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=environment,
    )
    assert process.stdin is not None
    assert process.stdout is not None
    assert process.stderr is not None

    process.stdin.write(f"{json.dumps(messages[0])}\n".encode())
    await process.stdin.drain()
    initialize_response = await asyncio.wait_for(process.stdout.readline(), timeout=5)

    for message in messages[1:]:
        process.stdin.write(f"{json.dumps(message)}\n".encode())
    await process.stdin.drain()
    call_response = await asyncio.wait_for(process.stdout.readline(), timeout=5)

    process.stdin.close()
    await process.stdin.wait_closed()
    return_code = await asyncio.wait_for(process.wait(), timeout=5)
    remaining_stdout = await process.stdout.read()
    stderr = (await process.stderr.read()).decode()

    responses = [json.loads(initialize_response), json.loads(call_response)]
    assert [response["id"] for response in responses] == [1, 2]
    assert return_code == 0
    assert remaining_stdout == b""
    assert stderr == ""
