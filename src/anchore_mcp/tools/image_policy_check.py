"""Image policy-check evidence adapter."""

from typing import Annotated

from fastmcp import Context
from fastmcp.tools import ToolResult
import httpx
from pydantic import Field

from anchore_mcp.anchore.http import MAX_RESPONSE_BYTES
from anchore_mcp.anchore.routes import image_policy_check_route
from anchore_mcp.config import load_connection
from anchore_mcp.models.common import DeploymentContext
from anchore_mcp.models.locators import ImageLocator
from anchore_mcp.models.results import ImagePolicyCheckResult
from anchore_mcp.tools.common import runtime_from_context, success_result, tool_error
from anchore_mcp.tools.image_common import resolve_image_locator


type PolicyContextValue = Annotated[str, Field(max_length=1_024)]


def _policy_params(tag: str | None, base_digest: str | None) -> httpx.QueryParams:
    values: dict[str, str] = {}
    normalized_tag = tag.strip() if tag is not None else ""
    normalized_base = base_digest.strip() if base_digest is not None else ""
    if normalized_tag:
        values["tag"] = normalized_tag
    if normalized_base:
        values["base_digest"] = normalized_base
    return httpx.QueryParams(values)


async def anchore_image_policy_check(
    context: Context,
    locator: ImageLocator,
    tag: PolicyContextValue | None = None,
    base_digest: PolicyContextValue | None = None,
) -> ToolResult:
    try:
        connection = load_connection()
        runtime = runtime_from_context(context)
        selected, selection = await resolve_image_locator(runtime.anchore_http, connection, locator)
        response = await runtime.anchore_http.get_json(
            connection,
            image_policy_check_route(connection.api_version, selected.digest),
            params=_policy_params(tag, base_digest),
            max_response_bytes=MAX_RESPONSE_BYTES,
        )
        result = ImagePolicyCheckResult(
            context=DeploymentContext(
                base_url=connection.base_url,
                account=connection.account,
                api_version=connection.api_version,
                action="image policy check",
            ),
            warnings=[],
            selected_image=selected,
            selection=selection,
            policy=response.data,
            size_bytes=response.byte_length,
        )
        return success_result("Fetched policy-check evidence for the selected image.", result)
    except Exception as error:
        raise tool_error(error) from None
