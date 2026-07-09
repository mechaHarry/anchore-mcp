"""Credential-free connection status capability."""

from fastmcp import Context
from fastmcp.tools import ToolResult

from anchore_mcp.config import load_connection
from anchore_mcp.errors import AnchoreConfigurationError
from anchore_mcp.models.common import DeploymentContext
from anchore_mcp.models.results import ConnectionInfoResult
from anchore_mcp.tools.common import success_result, tool_error


async def anchore_connection_info(context: Context) -> ToolResult:
    """Load a fresh non-secret connection snapshot, or report unconfigured normally."""

    del context
    try:
        connection = load_connection()
    except AnchoreConfigurationError:
        result = ConnectionInfoResult(
            context=DeploymentContext(
                base_url="not configured",
                account=None,
                api_version="v2",
                action="connection info",
            ),
            configured=False,
            warnings=["Anchore is not configured; add the documented MCP environment variables."],
        )
        return success_result("Anchore is not configured.", result)
    except Exception as error:
        raise tool_error(error) from None

    result = ConnectionInfoResult(
        context=DeploymentContext(
            base_url=connection.base_url,
            account=connection.account,
            api_version=connection.api_version,
            action="connection info",
        ),
        configured=True,
        warnings=[],
    )
    return success_result(f"Anchore is configured at {connection.base_url}.", result)
