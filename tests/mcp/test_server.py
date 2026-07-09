from fastmcp import Client
import pytest

from anchore_mcp.runtime import Runtime
from anchore_mcp.server import create_server, run


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


def _unused_runtime_factory() -> Runtime:
    raise AssertionError("credential-free discovery must not enter the runtime lifespan")


@pytest.mark.asyncio
async def test_server_advertises_exact_native_contract_without_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ANCHORE_URL", raising=False)
    monkeypatch.delenv("ANCHORE_TOKEN", raising=False)
    server = create_server(runtime_factory=_unused_runtime_factory)

    tools = await server.list_tools()

    assert {tool.name for tool in tools} == EXPECTED_TOOLS
    for tool in tools:
        assert tool.annotations is not None
        assert tool.annotations.readOnlyHint is True
        assert tool.annotations.idempotentHint is True
        assert tool.annotations.destructiveHint is False
        assert tool.annotations.openWorldHint is True


@pytest.mark.asyncio
async def test_in_memory_client_discovers_without_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ANCHORE_URL", raising=False)
    monkeypatch.delenv("ANCHORE_TOKEN", raising=False)
    server = create_server()

    async with Client(server) as client:
        tools = await client.list_tools()

    assert {tool.name for tool in tools} == EXPECTED_TOOLS


def test_run_uses_stdio_transport_only(monkeypatch: pytest.MonkeyPatch) -> None:
    run_calls: list[tuple[str, bool]] = []

    class _Server:
        def run(self, *, transport: str, show_banner: bool) -> None:
            run_calls.append((transport, show_banner))

    monkeypatch.setattr("anchore_mcp.server.create_server", _Server)

    run()

    assert run_calls == [("stdio", False)]
