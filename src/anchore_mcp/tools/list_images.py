"""Bounded Anchore image-list tool adapter."""

from typing import Annotated

from fastmcp import Context
from fastmcp.tools import ToolResult
import httpx
from pydantic import Field

from anchore_mcp.anchore.http import MAX_RESPONSE_BYTES, JsonResponse
from anchore_mcp.anchore.openapi import (
    MAX_LIST_QUERY_ENTRIES_EXAMINED,
    MAX_LIST_QUERY_KEY_LENGTH,
    MAX_LIST_QUERY_VALUE_LENGTH,
    list_images_query_allowlist,
    merge_list_images_query,
)
from anchore_mcp.anchore.pagination import JsonHttpClient, fetch_image_pages
from anchore_mcp.config import AnchoreConnection, load_connection
from anchore_mcp.errors import AnchoreResponseTooLargeError
from anchore_mcp.models.common import DeploymentContext, EnumerationState
from anchore_mcp.models.results import ListImagesResult
from anchore_mcp.tools.common import runtime_from_context, success_result, tool_error


type QueryKey = Annotated[str, Field(min_length=1, max_length=MAX_LIST_QUERY_KEY_LENGTH)]
type QueryValue = Annotated[str, Field(max_length=MAX_LIST_QUERY_VALUE_LENGTH)]
type ListQuery = Annotated[
    dict[QueryKey, QueryValue], Field(max_length=MAX_LIST_QUERY_ENTRIES_EXAMINED)
]
MAX_LIST_TOTAL_BYTES = MAX_RESPONSE_BYTES


class _CountingClient:
    def __init__(self, client: JsonHttpClient) -> None:
        self._client = client
        self.total_bytes = 0

    async def get_json(
        self,
        connection: AnchoreConnection,
        path: str,
        *,
        params: httpx.QueryParams | None = None,
        max_response_bytes: int,
        timeout: httpx.Timeout | float | None = None,
    ) -> JsonResponse:
        response = await self._client.get_json(
            connection,
            path,
            params=params,
            max_response_bytes=max_response_bytes,
            timeout=timeout,
        )
        observed = self.total_bytes + response.byte_length
        if observed > MAX_LIST_TOTAL_BYTES:
            raise AnchoreResponseTooLargeError(observed=observed, max=MAX_LIST_TOTAL_BYTES)
        self.total_bytes = observed
        return response


def _rejection_warning(rejected_keys: tuple[str, ...], rejected_count: int) -> str:
    sample = ", ".join(repr(key) for key in rejected_keys[:8])
    suffix = "" if rejected_count <= len(rejected_keys[:8]) else " (additional keys omitted)"
    return f"Dropped {rejected_count} rejected list_query key(s): {sample}{suffix}."


async def anchore_list_images(
    context: Context,
    fulltag: QueryValue | None = None,
    vulnerability_id: QueryValue | None = None,
    list_query: ListQuery | None = None,
) -> ToolResult:
    """List bounded image rows with explicit completeness and query diagnostics."""

    try:
        connection = load_connection()
        runtime = runtime_from_context(context)
        allowlist = None
        if list_query:
            allowlist = await list_images_query_allowlist(runtime.openapi_cache, connection)
        merged = merge_list_images_query(
            version=connection.api_version,
            full_tag=fulltag,
            vulnerability_id=vulnerability_id,
            list_query=list_query,
            allowlist=allowlist,
        )
        counting_client = _CountingClient(runtime.anchore_http)
        pages = await fetch_image_pages(counting_client, connection, merged.params)

        warnings: list[str] = []
        if merged.rejected_count:
            warnings.append(_rejection_warning(merged.rejected_keys, merged.rejected_count))
        if merged.truncated:
            warnings.append("Additional list_query entries were not examined after the safety cap.")
        if not pages.complete and pages.incomplete_reason is not None:
            warnings.append(f"Image enumeration is incomplete: {pages.incomplete_reason}")

        result = ListImagesResult(
            context=DeploymentContext(
                base_url=connection.base_url,
                account=connection.account,
                api_version=connection.api_version,
                action="list images",
            ),
            warnings=warnings,
            images=list(pages.rows),
            enumeration=EnumerationState(
                complete=pages.complete,
                pages_fetched=pages.pages_fetched,
                reason=pages.incomplete_reason,
            ),
            size_bytes=counting_client.total_bytes,
        )
        count = len(pages.rows)
        summary = (
            "No images matched the query."
            if count == 0
            else f"Found {count} image record(s) in Anchore."
        )
        if not pages.complete:
            summary = f"{summary} Enumeration is incomplete."
        return success_result(summary, result)
    except Exception as error:
        raise tool_error(error) from None
