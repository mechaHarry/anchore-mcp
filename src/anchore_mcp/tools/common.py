"""Safe FastMCP result serialization and exception translation."""

from collections.abc import Mapping
from typing import cast

from fastmcp import Context
from fastmcp.exceptions import ToolError
from fastmcp.tools import ToolResult
from mcp.types import TextContent

from anchore_mcp.errors import AnchoreConfigurationError, AnchoreError
from anchore_mcp.models.results import CapabilityResult
from anchore_mcp.runtime import Runtime
from anchore_mcp.security.logging import log_stderr_line
from anchore_mcp.security.pii import mask_pii_text


def _append_once(values: list[str], value: str) -> None:
    if value not in values:
        values.append(value)


def success_result(text: str, result: CapabilityResult) -> ToolResult:
    """Return masked concise text and JSON-mode, alias-aware structured content."""

    structured = result.model_dump(mode="json", by_alias=True)
    warnings: list[str] = []
    raw_warnings = structured.get("warnings")
    if isinstance(raw_warnings, list):
        for raw_warning in cast(list[object], raw_warnings):
            if not isinstance(raw_warning, str):
                continue
            masked_warning = mask_pii_text(raw_warning)
            _append_once(warnings, masked_warning.text)
            for warning in masked_warning.warnings:
                _append_once(warnings, warning)

    masked_text = mask_pii_text(text)
    for warning in masked_text.warnings:
        _append_once(warnings, warning)
    structured["warnings"] = warnings
    return ToolResult(
        content=[TextContent(type="text", text=masked_text.text)],
        structured_content=structured,
    )


def tool_error(error: Exception) -> ToolError:
    """Translate only explicitly safe domain errors; hide all unknown details."""

    if isinstance(error, AnchoreConfigurationError):
        return ToolError("Anchore is not configured")
    if isinstance(error, AnchoreError):
        return ToolError(error.user_message)
    log_stderr_line(f"[anchore-mcp] unexpected tool error: {type(error).__name__}")
    return ToolError("Anchore operation failed safely")


def runtime_from_context(context: Context) -> Runtime:
    """Read the lifespan-owned runtime without constructing fallback resources."""

    lifespan = cast(object, context.lifespan_context)
    if isinstance(lifespan, Runtime):
        return lifespan
    if isinstance(lifespan, Mapping):
        runtime = cast(Mapping[object, object], lifespan).get("runtime")
        if isinstance(runtime, Runtime):
            return runtime
    raise RuntimeError("FastMCP runtime is unavailable")
