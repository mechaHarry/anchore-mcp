"""Image SBOM evidence adapter."""

from typing import Annotated, Literal

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field

from anchore_mcp.anchore.routes import image_sbom_route
from anchore_mcp.config import load_connection
from anchore_mcp.errors import TrustEvidenceError
from anchore_mcp.models.common import DeploymentContext
from anchore_mcp.models.locators import ImageLocator
from anchore_mcp.models.results import ImageSbomResult
from anchore_mcp.tools.common import runtime_from_context, success_result, tool_error
from anchore_mcp.tools.image_common import resolve_image_locator


DEFAULT_SBOM_MAX_RESPONSE_BYTES = 20_000_000
MAX_SBOM_RESPONSE_BYTES = 100_000_000

type SbomFormat = Literal["normal", "spdx", "cyclonedx"]
type SbomResponseLimit = Annotated[int, Field(ge=1, le=MAX_SBOM_RESPONSE_BYTES)]

_WIRE_FORMAT: dict[SbomFormat, Literal["native-json", "spdx-json", "cyclonedx-json"]] = {
    "normal": "native-json",
    "spdx": "spdx-json",
    "cyclonedx": "cyclonedx-json",
}


async def anchore_image_sbom(
    context: Context,
    locator: ImageLocator,
    format: SbomFormat,
    max_response_bytes: SbomResponseLimit = DEFAULT_SBOM_MAX_RESPONSE_BYTES,
) -> ToolResult:
    try:
        if (
            type(max_response_bytes) is not int
            or not 1 <= max_response_bytes <= MAX_SBOM_RESPONSE_BYTES
        ):
            raise TrustEvidenceError(
                f"max_response_bytes must be between 1 and {MAX_SBOM_RESPONSE_BYTES}"
            )
        connection = load_connection()
        runtime = runtime_from_context(context)
        selected, selection = await resolve_image_locator(runtime.anchore_http, connection, locator)
        response = await runtime.anchore_http.get_json(
            connection,
            image_sbom_route(connection.api_version, selected.digest, _WIRE_FORMAT[format]),
            max_response_bytes=max_response_bytes,
        )
        result = ImageSbomResult(
            context=DeploymentContext(
                base_url=connection.base_url,
                account=connection.account,
                api_version=connection.api_version,
                action="image SBOM",
            ),
            warnings=[],
            selected_image=selected,
            selection=selection,
            format=format,
            sbom=response.data,
            size_bytes=response.byte_length,
        )
        return success_result(f"Fetched {format} SBOM evidence for the selected image.", result)
    except Exception as error:
        raise tool_error(error) from None
