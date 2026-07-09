"""Exact policy-blocking vulnerability adapter."""

from typing import Annotated

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field

from anchore_mcp.config import load_connection
from anchore_mcp.domain.policy_report import build_policy_blocking_report
from anchore_mcp.models.locators import PolicyImageLocator
from anchore_mcp.tools.common import runtime_from_context, success_result, tool_error


type PolicyContextValue = Annotated[str, Field(max_length=1_024)]


async def anchore_policy_blocking_vulnerabilities(
    context: Context,
    locator: PolicyImageLocator,
    tag: PolicyContextValue | None = None,
    base_digest: PolicyContextValue | None = None,
) -> ToolResult:
    try:
        connection = load_connection()
        runtime = runtime_from_context(context)
        result = await build_policy_blocking_report(
            runtime.anchore_http,
            connection,
            locator,
            runtime.openapi_cache,
            tag=tag,
            base_digest=base_digest,
        )
        if result.outcome == "already_green":
            summary = "Policy evaluation is already green; no vulnerability remediation is proven."
        else:
            summary = (
                f"Found {len(result.blockers)} proven policy-blocking vulnerability record(s)."
            )
        return success_result(summary, result)
    except Exception as error:
        raise tool_error(error) from None
