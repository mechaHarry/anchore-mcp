"""Image vulnerability evidence adapter."""

from fastmcp import Context
from fastmcp.tools import ToolResult

from anchore_mcp.anchore.http import MAX_RESPONSE_BYTES
from anchore_mcp.anchore.routes import image_vulnerabilities_route
from anchore_mcp.config import load_connection
from anchore_mcp.models.common import DeploymentContext
from anchore_mcp.models.locators import ImageLocator
from anchore_mcp.models.results import ImageVulnerabilitiesResult
from anchore_mcp.tools.common import runtime_from_context, success_result, tool_error
from anchore_mcp.tools.image_common import resolve_image_locator


async def anchore_image_vulnerabilities(context: Context, locator: ImageLocator) -> ToolResult:
    try:
        connection = load_connection()
        runtime = runtime_from_context(context)
        selected, selection = await resolve_image_locator(runtime.anchore_http, connection, locator)
        response = await runtime.anchore_http.get_json(
            connection,
            image_vulnerabilities_route(connection.api_version, selected.digest),
            max_response_bytes=MAX_RESPONSE_BYTES,
        )
        result = ImageVulnerabilitiesResult(
            context=DeploymentContext(
                base_url=connection.base_url,
                account=connection.account,
                api_version=connection.api_version,
                action="image vulnerabilities",
            ),
            warnings=[],
            selected_image=selected,
            selection=selection,
            vulnerabilities=response.data,
            size_bytes=response.byte_length,
        )
        return success_result("Fetched vulnerability evidence for the selected image.", result)
    except Exception as error:
        raise tool_error(error) from None
