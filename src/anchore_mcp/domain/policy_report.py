"""Trust-sensitive policy remediation report orchestration."""

from dataclasses import asdict
from typing import cast
import httpx
from pydantic import JsonValue

from anchore_mcp.anchore.http import MAX_RESPONSE_BYTES
from anchore_mcp.anchore.openapi import OpenApiCache
from anchore_mcp.anchore.pagination import RESOLUTION_CAPS, JsonHttpClient, PageCaps
from anchore_mcp.anchore.routes import image_policy_check_route, image_vulnerabilities_route
from anchore_mcp.config import AnchoreConnection
from anchore_mcp.domain.policy import interpret_policy
from anchore_mcp.domain.selection import select_image_for_policy_with_state
from anchore_mcp.domain.vulnerabilities import correlate_blockers, extract_vulnerability_records
from anchore_mcp.errors import TrustEvidenceError
from anchore_mcp.models.common import DeploymentContext
from anchore_mcp.models.locators import PolicyImageLocator
from anchore_mcp.models.results import PolicyBlockingVulnerabilitiesResult


POLICY_VULNERABILITY_MAX_RESPONSE_BYTES = 20 * 1024 * 1024


def _json_value(value: object) -> JsonValue:
    if value is None or isinstance(value, str | bool | int | float):
        return value
    if isinstance(value, dict):
        mapping = cast(dict[object, object], value)
        return {str(key): _json_value(item) for key, item in mapping.items()}
    if isinstance(value, list | tuple):
        sequence = cast(list[object] | tuple[object, ...], value)
        return [_json_value(item) for item in sequence]
    raise TypeError(f"unsupported blocker value: {type(value).__name__}")


def _policy_params(
    explicit_tag: str | None,
    base_digest: str | None,
    selected_reference: str | None,
) -> httpx.QueryParams:
    values: dict[str, str] = {}
    tag = explicit_tag.strip() if explicit_tag is not None else ""
    if not tag and selected_reference is not None:
        tag = selected_reference.strip()
    if tag:
        values["tag"] = tag
    normalized_base = base_digest.strip() if base_digest is not None else ""
    if normalized_base:
        values["base_digest"] = normalized_base
    return httpx.QueryParams(values)


async def build_policy_blocking_report(
    client: JsonHttpClient,
    connection: AnchoreConnection,
    locator: PolicyImageLocator,
    openapi_cache: OpenApiCache,
    *,
    tag: str | None = None,
    base_digest: str | None = None,
    caps: PageCaps = RESOLUTION_CAPS,
) -> PolicyBlockingVulnerabilitiesResult:
    """Evaluate policy first and fetch vulnerability evidence only when required."""

    selection = await select_image_for_policy_with_state(
        client,
        connection,
        locator,
        openapi_cache,
        caps=caps,
    )
    selected = selection.selected_image
    policy = await client.get_json(
        connection,
        image_policy_check_route(connection.api_version, selected.digest),
        params=_policy_params(tag, base_digest, selected.reference),
        max_response_bytes=MAX_RESPONSE_BYTES,
    )
    interpretation = interpret_policy(policy.data)
    context = DeploymentContext(
        base_url=connection.base_url,
        account=connection.account,
        api_version=connection.api_version,
        action="policy blocking vulnerabilities",
    )
    if interpretation.status == "green" or (
        interpretation.status == "unknown" and not interpretation.has_blocking_action
    ):
        return PolicyBlockingVulnerabilitiesResult(
            context=context,
            selected_image=selected,
            selection=selection.enumeration,
            outcome="already_green",
            blockers=[],
        )

    vulnerabilities = await client.get_json(
        connection,
        image_vulnerabilities_route(connection.api_version, selected.digest),
        max_response_bytes=POLICY_VULNERABILITY_MAX_RESPONSE_BYTES,
    )
    blockers = correlate_blockers(
        interpretation.findings,
        extract_vulnerability_records(vulnerabilities.data),
    )
    if not blockers:
        raise TrustEvidenceError("red policy has no proven vulnerability remediation")
    serialized = [_json_value(asdict(blocker)) for blocker in blockers]
    return PolicyBlockingVulnerabilitiesResult(
        context=context,
        selected_image=selected,
        selection=selection.enumeration,
        outcome="blocked",
        blockers=serialized,
    )
