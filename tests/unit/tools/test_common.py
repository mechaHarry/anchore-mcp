from typing import cast

from fastmcp.exceptions import ToolError
from mcp.types import TextContent
from pydantic import Field
import pytest

from anchore_mcp.errors import AnchoreConfigurationError, AnchoreHttpError
from anchore_mcp.models.common import DeploymentContext
from anchore_mcp.models.results import CapabilityResult, ConnectionInfoResult
from anchore_mcp.tools.common import success_result, tool_error


def connection_info_result(*, warnings: list[str] | None = None) -> ConnectionInfoResult:
    return ConnectionInfoResult(
        context=DeploymentContext(
            base_url="https://anchore.example",
            account=None,
            api_version="v2",
            action="connection info",
        ),
        warnings=[] if warnings is None else warnings,
        configured=True,
    )


class AliasedCapability(CapabilityResult):
    aliased_value: str = Field(alias="aliasedValue")


def test_success_result_contains_masked_text_and_json_structured_content() -> None:
    result = success_result(
        "Listed images for person@example.test",
        connection_info_result(warnings=["existing warning", "existing warning"]),
    )

    assert isinstance(result.content[0], TextContent)
    assert result.content[0].text == "Listed images for [email redacted]"
    assert result.structured_content is not None
    assert result.structured_content["configured"] is True
    assert result.structured_content["context"]["api_version"] == "v2"
    assert result.structured_content["warnings"][0] == "existing warning"
    assert len(result.structured_content["warnings"]) == 2
    assert "heuristic" in cast(str, result.structured_content["warnings"][1]).casefold()


def test_success_result_uses_json_mode_and_field_aliases() -> None:
    structured = AliasedCapability.model_validate(
        {
            "context": connection_info_result().context,
            "warnings": [],
            "aliasedValue": "wire-value",
        }
    )

    result = success_result("Alias check", structured)

    assert result.structured_content is not None
    assert result.structured_content["aliasedValue"] == "wire-value"
    assert "aliased_value" not in result.structured_content


def test_tool_error_exposes_only_allowlisted_domain_messages() -> None:
    mapped = tool_error(AnchoreConfigurationError("Anchore is not configured"))

    assert isinstance(mapped, ToolError)
    assert str(mapped) == "Anchore is not configured"
    assert str(tool_error(AnchoreHttpError(403, "Anchore request was forbidden"))) == (
        "Anchore request was forbidden"
    )


def test_unknown_error_logs_only_type_and_returns_generic(
    capsys: pytest.CaptureFixture[str],
) -> None:
    class InternalFailure(Exception):
        pass

    mapped = tool_error(InternalFailure("Bearer private-token customer@example.test"))
    captured = capsys.readouterr()

    assert str(mapped) == "Anchore operation failed safely"
    assert "InternalFailure" in captured.err
    assert "private-token" not in captured.err
    assert "customer@example.test" not in captured.err
    assert captured.out == ""
