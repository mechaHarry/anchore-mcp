"""Verify the built wheel's stdio entry point in an isolated uvx environment."""

import asyncio
import os
from pathlib import Path
import sys

from fastmcp import Client
from fastmcp.client.transports import StdioTransport


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


async def verify(wheel: str | Path) -> None:
    wheel_path = Path(wheel).resolve(strict=True)
    if wheel_path.suffix != ".whl":
        raise ValueError("wheel path must end in .whl")
    clean_environment = {
        key: value for key, value in os.environ.items() if not key.startswith("ANCHORE_")
    }
    transport = StdioTransport(
        command="uvx",
        args=["--from", str(wheel_path), "anchore-mcp"],
        env=clean_environment,
        keep_alive=False,
    )
    async with Client(transport) as client:
        tools = await client.list_tools()
    observed = {tool.name for tool in tools}
    if observed != EXPECTED_TOOLS:
        raise RuntimeError("installed wheel advertised an unexpected tool contract")


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: smoke_wheel.py <wheel>")
    asyncio.run(verify(sys.argv[1]))


if __name__ == "__main__":
    main()
