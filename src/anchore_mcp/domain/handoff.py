"""Structured-concurrency remediation evidence handoff assembly."""

import asyncio
from collections.abc import Callable
from datetime import UTC, datetime
from typing import cast

import httpx

from anchore_mcp.anchore.http import MAX_RESPONSE_BYTES, JsonResponse
from anchore_mcp.anchore.pagination import RESOLUTION_CAPS, JsonHttpClient, PageCaps
from anchore_mcp.anchore.routes import (
    image_by_digest_route,
    image_policy_check_route,
    image_vulnerabilities_route,
)
from anchore_mcp.config import AnchoreConnection
from anchore_mcp.domain.images import validate_full_image_reference
from anchore_mcp.domain.resolution import (
    Disambiguation,
    Incomplete,
    Resolved,
    resolve_image_reference,
)
from anchore_mcp.errors import EnumerationIncompleteError, TrustEvidenceError
from anchore_mcp.models.common import DeploymentContext, EnumerationState
from anchore_mcp.models.locators import DigestLocator, ImageLocator
from anchore_mcp.models.results import (
    HandoffDeployment,
    HandoffEvidenceEntry,
    HandoffEvidenceKey,
    RemediationHandoffResult,
)


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _policy_params(tag: str | None, base_digest: str | None) -> httpx.QueryParams:
    values: dict[str, str] = {}
    normalized_tag = tag.strip() if tag is not None else ""
    normalized_base = base_digest.strip() if base_digest is not None else ""
    if normalized_tag:
        values["tag"] = normalized_tag
    if normalized_base:
        values["base_digest"] = normalized_base
    return httpx.QueryParams(values)


async def _resolve_once(
    client: JsonHttpClient,
    connection: AnchoreConnection,
    locator: ImageLocator,
    caps: PageCaps,
) -> tuple[str, EnumerationState]:
    if isinstance(locator, DigestLocator):
        return locator.digest.strip(), EnumerationState(complete=True, pages_fetched=0)
    try:
        reference = validate_full_image_reference(locator.reference)
    except ValueError as error:
        raise TrustEvidenceError(str(error)) from None
    result = await resolve_image_reference(client, connection, reference, caps=caps)
    if isinstance(result, Resolved):
        return result.digest, EnumerationState(
            complete=True,
            pages_fetched=result.pages_fetched,
        )
    if isinstance(result, Incomplete):
        raise EnumerationIncompleteError(result.reason)
    if isinstance(result, Disambiguation):
        raise TrustEvidenceError("Image reference matched multiple analyzed image digests")
    raise TrustEvidenceError("No analyzed image matched the requested image reference")


def _single_leaf(error: BaseExceptionGroup[BaseException]) -> BaseException | None:
    if len(error.exceptions) != 1:
        return None
    child = error.exceptions[0]
    if isinstance(child, BaseExceptionGroup):
        return _single_leaf(cast(BaseExceptionGroup[BaseException], child))
    return child


async def build_remediation_handoff(
    client: JsonHttpClient,
    connection: AnchoreConnection,
    locator: ImageLocator,
    *,
    include_policy_check: bool = True,
    tag: str | None = None,
    base_digest: str | None = None,
    clock: Callable[[], datetime] = _utc_now,
    caps: PageCaps = RESOLUTION_CAPS,
) -> RemediationHandoffResult:
    """Resolve once, then fetch independent evidence with structured concurrency."""

    digest, selection = await _resolve_once(client, connection, locator, caps)
    detail_path = image_by_digest_route(connection.api_version, digest)
    vulnerability_path = image_vulnerabilities_route(connection.api_version, digest)
    policy_path = image_policy_check_route(connection.api_version, digest)

    detail_task: asyncio.Task[JsonResponse]
    vulnerability_task: asyncio.Task[JsonResponse]
    policy_task: asyncio.Task[JsonResponse] | None = None
    try:
        async with asyncio.TaskGroup() as group:
            detail_task = group.create_task(
                client.get_json(
                    connection,
                    detail_path,
                    max_response_bytes=MAX_RESPONSE_BYTES,
                ),
                name="anchore-mcp-handoff-detail",
            )
            vulnerability_task = group.create_task(
                client.get_json(
                    connection,
                    vulnerability_path,
                    max_response_bytes=MAX_RESPONSE_BYTES,
                ),
                name="anchore-mcp-handoff-vulnerabilities",
            )
            if include_policy_check:
                policy_task = group.create_task(
                    client.get_json(
                        connection,
                        policy_path,
                        params=_policy_params(tag, base_digest),
                        max_response_bytes=MAX_RESPONSE_BYTES,
                    ),
                    name="anchore-mcp-handoff-policy",
                )
    except BaseExceptionGroup as caught:
        leaf = _single_leaf(caught)
        if leaf is not None:
            raise leaf
        raise

    detail = detail_task.result()
    vulnerabilities = vulnerability_task.result()
    evidence: dict[HandoffEvidenceKey, HandoffEvidenceEntry] = {
        "detail": HandoffEvidenceEntry(data=detail.data, sizeBytes=detail.byte_length),
        "vulnerabilities": HandoffEvidenceEntry(
            data=vulnerabilities.data,
            sizeBytes=vulnerabilities.byte_length,
        ),
    }
    total_size = detail.byte_length + vulnerabilities.byte_length
    if policy_task is not None:
        policy = policy_task.result()
        evidence["policy"] = HandoffEvidenceEntry(
            data=policy.data,
            sizeBytes=policy.byte_length,
        )
        total_size += policy.byte_length

    generated_at = clock()
    if generated_at.tzinfo is None or generated_at.utcoffset() is None:
        raise ValueError("handoff clock must return a timezone-aware datetime")
    generated_at = generated_at.astimezone(UTC)
    context = DeploymentContext(
        base_url=connection.base_url,
        account=connection.account,
        api_version=connection.api_version,
        action="remediation handoff",
    )
    return RemediationHandoffResult(
        context=context,
        handoffVersion="2.0.0",
        generatedAt=generated_at,
        deployment=HandoffDeployment(
            baseUrl=connection.base_url,
            account=connection.account,
            apiVersion=connection.api_version,
        ),
        imageDigest=digest,
        selection=selection,
        evidence=evidence,
        totalSizeBytes=total_size,
    )
