"""Remediation handoff v2 adapter."""

from typing import Annotated

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field

from anchore_mcp.config import load_connection
from anchore_mcp.domain.handoff import build_remediation_handoff
from anchore_mcp.models.locators import ImageLocator
from anchore_mcp.tools.common import runtime_from_context, success_result, tool_error


type PolicyContextValue = Annotated[str, Field(max_length=1_024)]


async def anchore_remediation_handoff(
    context: Context,
    locator: ImageLocator,
    include_policy_check: bool = True,
    tag: PolicyContextValue | None = None,
    base_digest: PolicyContextValue | None = None,
) -> ToolResult:
    try:
        connection = load_connection()
        runtime = runtime_from_context(context)
        result = await build_remediation_handoff(
            runtime.anchore_http,
            connection,
            locator,
            include_policy_check=include_policy_check,
            tag=tag,
            base_digest=base_digest,
        )
        return success_result("Prepared remediation evidence handoff version 2.0.0.", result)
    except Exception as error:
        raise tool_error(error) from None
