from types import SimpleNamespace
from typing import cast

from fastmcp import Context
from fastmcp.exceptions import ToolError
from mcp.types import TextContent
from pydantic import SecretStr
import pytest

from anchore_mcp.config import AnchoreConnection
from anchore_mcp.errors import AnchoreConfigurationError
from anchore_mcp.tools.connection_info import anchore_connection_info


def fake_context() -> Context:
    return cast(Context, SimpleNamespace(lifespan_context={}))


@pytest.mark.asyncio
async def test_connection_info_missing_env_is_normal_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def missing_connection() -> AnchoreConnection:
        raise AnchoreConfigurationError("ANCHORE_TOKEN is required")

    monkeypatch.setattr("anchore_mcp.tools.connection_info.load_connection", missing_connection)

    result = await anchore_connection_info(fake_context())

    assert result.is_error is False
    assert result.structured_content is not None
    assert result.structured_content["configured"] is False
    encoded = str(result.structured_content).casefold()
    assert "anchore_token" not in encoded
    assert "required" not in encoded


@pytest.mark.asyncio
async def test_connection_info_loads_current_snapshot_lazily_without_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0

    def configured_connection() -> AnchoreConnection:
        nonlocal calls
        calls += 1
        return AnchoreConnection(
            base_url="https://anchore.example",
            token=SecretStr("private-token"),
            account="team",
            api_version="v1",
        )

    monkeypatch.setattr("anchore_mcp.tools.connection_info.load_connection", configured_connection)
    assert calls == 0

    result = await anchore_connection_info(fake_context())

    assert calls == 1
    assert result.structured_content is not None
    assert result.structured_content["configured"] is True
    assert result.structured_content["context"] == {
        "base_url": "https://anchore.example",
        "account": "team",
        "api_version": "v1",
        "action": "connection info",
    }
    assert "private-token" not in str(result.structured_content)
    assert isinstance(result.content[0], TextContent)


@pytest.mark.asyncio
async def test_connection_info_unknown_failure_is_generic_without_cause(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail() -> AnchoreConnection:
        raise RuntimeError("private-token")

    monkeypatch.setattr("anchore_mcp.tools.connection_info.load_connection", fail)

    with pytest.raises(ToolError, match="failed safely") as raised:
        await anchore_connection_info(fake_context())

    assert raised.value.__cause__ is None
