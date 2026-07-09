"""FastMCP stdio server with an explicitly bounded native tool contract."""

from collections.abc import AsyncGenerator, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager
import logging
from typing import Any

from fastmcp import FastMCP
from mcp.types import ToolAnnotations

from anchore_mcp import __version__
from anchore_mcp.runtime import Runtime, create_runtime
from anchore_mcp.tools.connection_info import anchore_connection_info
from anchore_mcp.tools.image_detail import anchore_image_detail
from anchore_mcp.tools.image_policy_check import anchore_image_policy_check
from anchore_mcp.tools.image_sbom import anchore_image_sbom
from anchore_mcp.tools.image_vulnerabilities import anchore_image_vulnerabilities
from anchore_mcp.tools.list_images import anchore_list_images
from anchore_mcp.tools.policy_blocking_vulnerabilities import (
    anchore_policy_blocking_vulnerabilities,
)
from anchore_mcp.tools.remediation_handoff import anchore_remediation_handoff


type RuntimeFactory = Callable[[], Runtime]

_FRAMEWORK_LOG_LEVEL = logging.CRITICAL + 1
_READ_ONLY_ANNOTATIONS = ToolAnnotations(
    readOnlyHint=True,
    idempotentHint=True,
    destructiveHint=False,
    openWorldHint=True,
)


def _disable_framework_logging() -> None:
    for logger_name in ("fastmcp", "mcp"):
        logging.getLogger(logger_name).setLevel(_FRAMEWORK_LOG_LEVEL)


def make_lifespan(
    runtime_factory: RuntimeFactory,
) -> Callable[[FastMCP[Any]], AbstractAsyncContextManager[dict[str, Runtime]]]:
    @asynccontextmanager
    async def lifespan(_: FastMCP[Any]) -> AsyncGenerator[dict[str, Runtime]]:
        runtime = runtime_factory()
        try:
            yield {"runtime": runtime}
        finally:
            await runtime.close()

    return lifespan


def create_server(*, runtime_factory: RuntimeFactory = create_runtime) -> FastMCP:
    _disable_framework_logging()
    app = FastMCP(
        name="anchore-mcp",
        version=__version__,
        lifespan=make_lifespan(runtime_factory),
    )
    for tool in (
        anchore_connection_info,
        anchore_list_images,
        anchore_image_vulnerabilities,
        anchore_image_sbom,
        anchore_image_policy_check,
        anchore_policy_blocking_vulnerabilities,
        anchore_image_detail,
        anchore_remediation_handoff,
    ):
        app.tool(tool, annotations=_READ_ONLY_ANNOTATIONS)
    return app


def run() -> None:
    create_server().run(transport="stdio", show_banner=False)
