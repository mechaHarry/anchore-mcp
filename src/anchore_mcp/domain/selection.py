"""Fail-closed image selection for policy reporting."""

from dataclasses import dataclass
from datetime import UTC, datetime
import math
import re
from typing import cast

import httpx

from anchore_mcp.anchore.openapi import (
    OpenApiCache,
    openapi_advertises_v1_image_tag_summary_filters,
)
from anchore_mcp.anchore.pagination import (
    RESOLUTION_CAPS,
    JsonHttpClient,
    PageCaps,
    fetch_image_pages,
    fetch_image_tag_summary_pages,
)
from anchore_mcp.anchore.routes import image_full_tag_query_key
from anchore_mcp.config import AnchoreConnection
from anchore_mcp.domain.images import (
    digest_from_image_row,
    extract_reference_evidence,
    validate_full_image_reference,
)
from anchore_mcp.errors import EnumerationIncompleteError, TrustEvidenceError
from anchore_mcp.models.common import SelectedImage
from anchore_mcp.models.locators import DigestLocator, PolicyImageLocator, ReferenceLocator


TIMESTAMP_KEYS = (
    "analyzed_at",
    "analyzedAt",
    "analysis_timestamp",
    "analysisTimestamp",
    "last_updated",
    "lastUpdated",
    "created_at",
    "createdAt",
)
MAX_PLAUSIBLE_EPOCH_SECONDS = 10_000_000_000
_ISO_TIMESTAMP = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]+)?(?:Z|[+-][0-9]{2}:[0-9]{2})$"
)
_MISSING_TIMESTAMP = (
    "Cannot prove newest image because a matching digest-bearing row lacked reliable "
    "timestamp evidence."
)
_V1_REPOSITORY_UNAVAILABLE = (
    "Repository selection is unavailable for this v1 deployment because its OpenAPI does not "
    "advertise registry and repository filters on image tag summaries."
)


@dataclass(frozen=True, slots=True)
class _TimestampedCandidate:
    digest: str
    reference: str
    repository: str
    timestamp: datetime


def _millisecond_precision(value: datetime) -> datetime:
    return value.replace(microsecond=(value.microsecond // 1_000) * 1_000)


def normalize_timestamp(value: object) -> datetime:
    """Normalize one trusted ISO or epoch seconds/milliseconds timestamp to UTC."""

    if isinstance(value, bool):
        raise TrustEvidenceError("Analysis timestamp evidence was invalid")
    if isinstance(value, int | float):
        try:
            numeric = float(value)
        except OverflowError:
            raise TrustEvidenceError("Analysis timestamp evidence was out of range") from None
        if not math.isfinite(numeric):
            raise TrustEvidenceError("Analysis timestamp evidence was invalid")
        seconds = numeric if abs(numeric) <= MAX_PLAUSIBLE_EPOCH_SECONDS else numeric / 1_000
        try:
            return _millisecond_precision(datetime.fromtimestamp(seconds, tz=UTC))
        except (OverflowError, OSError, ValueError):
            raise TrustEvidenceError("Analysis timestamp evidence was out of range") from None
    if isinstance(value, str):
        normalized = value.strip()
        if not _ISO_TIMESTAMP.fullmatch(normalized):
            raise TrustEvidenceError("Analysis timestamp evidence was invalid")
        try:
            parsed = datetime.fromisoformat(normalized.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                raise ValueError
            return _millisecond_precision(parsed.astimezone(UTC))
        except (OverflowError, ValueError):
            raise TrustEvidenceError("Analysis timestamp evidence was invalid") from None
    raise TrustEvidenceError("Analysis timestamp evidence was invalid")


def _timestamp_from_row(row: dict[object, object]) -> datetime | None:
    for key in TIMESTAMP_KEYS:
        if key not in row:
            continue
        try:
            return normalize_timestamp(row[key])
        except TrustEvidenceError:
            continue
    return None


def _repository_from_reference(reference: str) -> str:
    return reference.rpartition(":")[0]


def _selected(candidate: _TimestampedCandidate) -> SelectedImage:
    try:
        return SelectedImage(
            digest=candidate.digest,
            reference=candidate.reference,
            repository=candidate.repository,
            timestamp=candidate.timestamp,
        )
    except ValueError:
        raise TrustEvidenceError("Selected image evidence was invalid") from None


def _select_newest(candidates: list[_TimestampedCandidate]) -> SelectedImage:
    if not candidates:
        raise TrustEvidenceError(
            "No matching image row had both a digest and reliable timestamp evidence."
        )
    newest_timestamp = max(candidate.timestamp for candidate in candidates)
    newest = [candidate for candidate in candidates if candidate.timestamp == newest_timestamp]
    tied_digests = {candidate.digest for candidate in newest}
    if len(tied_digests) > 1:
        raise TrustEvidenceError(
            f"The newest image is ambiguous: {len(tied_digests)} digests share the same timestamp."
        )
    return _selected(newest[0])


def _validate_repository_locator(registry: str, repository: str) -> tuple[str, str]:
    normalized_registry = registry.strip()
    normalized_repository = repository.strip()
    if not normalized_registry or "/" in normalized_registry:
        raise TrustEvidenceError("image_registry must be a non-empty registry component")
    if (
        not normalized_repository
        or normalized_repository.startswith("/")
        or normalized_repository.endswith("/")
        or "//" in normalized_repository
        or "\\" in normalized_repository
        or any(character.isspace() for character in normalized_repository)
    ):
        raise TrustEvidenceError("image_repository must be a non-empty repository path")
    last_slash = normalized_repository.rfind("/")
    if normalized_repository.rfind(":") > last_slash:
        raise TrustEvidenceError("image_repository must not include an image tag")
    return normalized_registry, normalized_repository


def _matching_summary_reference(value: object, qualified_repository: str) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    reference = value.strip()
    try:
        validate_full_image_reference(reference)
    except ValueError:
        return None
    return reference if _repository_from_reference(reference) == qualified_repository else None


async def _select_reference(
    client: JsonHttpClient,
    connection: AnchoreConnection,
    locator: ReferenceLocator,
    caps: PageCaps,
) -> SelectedImage:
    try:
        reference = validate_full_image_reference(locator.reference)
    except ValueError as error:
        raise TrustEvidenceError(str(error)) from None
    query_key = image_full_tag_query_key(connection.api_version)
    pages = await fetch_image_pages(
        client,
        connection,
        httpx.QueryParams({query_key: reference}),
        caps,
    )
    if not pages.complete:
        raise EnumerationIncompleteError(
            pages.incomplete_reason or "Image list enumeration was incomplete."
        )

    repository = _repository_from_reference(reference)
    candidates: list[_TimestampedCandidate] = []
    for row in pages.rows:
        evidence = extract_reference_evidence(row)
        if not evidence.complete:
            raise EnumerationIncompleteError("Image reference evidence exceeded safety limits.")
        if reference not in evidence.references or not isinstance(row, dict):
            continue
        row_map = cast(dict[object, object], row)
        digest = digest_from_image_row(row_map)
        if digest is None:
            continue
        timestamp = _timestamp_from_row(row_map)
        if timestamp is None:
            raise TrustEvidenceError(_MISSING_TIMESTAMP)
        candidates.append(_TimestampedCandidate(digest, reference, repository, timestamp))
    return _select_newest(candidates)


async def _v1_summary_supported(
    cache: OpenApiCache,
    connection: AnchoreConnection,
) -> bool:
    try:
        document = await cache.fetch(connection)
    except Exception:
        return False
    return openapi_advertises_v1_image_tag_summary_filters(document)


async def _select_repository(
    client: JsonHttpClient,
    connection: AnchoreConnection,
    locator: object,
    cache: OpenApiCache,
    caps: PageCaps,
) -> SelectedImage:
    registry = cast(str, getattr(locator, "registry"))
    repository = cast(str, getattr(locator, "repository"))
    registry, repository = _validate_repository_locator(registry, repository)
    if connection.api_version == "v1" and not await _v1_summary_supported(cache, connection):
        raise TrustEvidenceError(_V1_REPOSITORY_UNAVAILABLE)

    pages = await fetch_image_tag_summary_pages(
        client,
        connection,
        httpx.QueryParams(
            {
                "registry": registry,
                "repository": repository,
                "analysis_status": "analyzed",
            }
        ),
        caps,
    )
    if not pages.complete:
        raise EnumerationIncompleteError(
            pages.incomplete_reason or "Image tag summary enumeration was incomplete."
        )

    qualified_repository = f"{registry}/{repository}"
    candidates: list[_TimestampedCandidate] = []
    for row in pages.rows:
        if not isinstance(row, dict):
            continue
        row_map = cast(dict[object, object], row)
        reference = _matching_summary_reference(row_map.get("full_tag"), qualified_repository)
        if reference is None:
            continue
        digest = digest_from_image_row(row_map)
        if digest is None:
            continue
        timestamp = _timestamp_from_row(row_map)
        if timestamp is None:
            raise TrustEvidenceError(_MISSING_TIMESTAMP)
        candidates.append(_TimestampedCandidate(digest, reference, qualified_repository, timestamp))
    return _select_newest(candidates)


async def select_image_for_policy(
    client: JsonHttpClient,
    connection: AnchoreConnection,
    locator: PolicyImageLocator,
    openapi_cache: OpenApiCache,
    *,
    caps: PageCaps = RESOLUTION_CAPS,
) -> SelectedImage:
    """Select a policy image only when the requested locator is fully proven."""

    if isinstance(locator, DigestLocator):
        try:
            return SelectedImage(digest=locator.digest.strip())
        except ValueError:
            raise TrustEvidenceError("image_digest was invalid") from None
    if isinstance(locator, ReferenceLocator):
        return await _select_reference(client, connection, locator, caps)
    return await _select_repository(client, connection, locator, openapi_cache, caps)
