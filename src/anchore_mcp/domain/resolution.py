"""Exact, bounded image-reference resolution over Anchore list evidence."""

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Literal

import httpx

from anchore_mcp.anchore.pagination import (
    RESOLUTION_CAPS,
    JsonHttpClient,
    PageCaps,
    fetch_image_pages,
)
from anchore_mcp.anchore.routes import image_full_tag_query_key
from anchore_mcp.config import AnchoreConnection
from anchore_mcp.domain.images import (
    digest_from_image_row,
    extract_reference_evidence,
    validate_full_image_reference,
)


MAX_DISAMBIGUATION_CANDIDATES = 50
MAX_HINTS_PER_DIGEST = 8
MAX_TOTAL_DISAMBIGUATION_HINTS = 64
EVIDENCE_INCOMPLETE_REASON = "Image reference evidence exceeded safety limits."


@dataclass(frozen=True, slots=True)
class ResolveCandidate:
    digest: str
    hints: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class Resolved:
    digest: str
    pages_fetched: int = field(default=0, compare=False)
    kind: Literal["resolved"] = field(init=False, default="resolved")


@dataclass(frozen=True, slots=True)
class NoMatch:
    kind: Literal["no_match"] = field(init=False, default="no_match")


@dataclass(frozen=True, slots=True)
class Disambiguation:
    candidates: tuple[ResolveCandidate, ...]
    truncated: bool
    kind: Literal["disambiguation"] = field(init=False, default="disambiguation")


@dataclass(frozen=True, slots=True)
class Incomplete:
    reason: str
    kind: Literal["incomplete"] = field(init=False, default="incomplete")


type ResolutionResult = Resolved | NoMatch | Disambiguation | Incomplete


def resolve_image_rows(rows: Iterable[object], image_reference: str) -> ResolutionResult:
    """Resolve only from exact local row evidence; any evidence overflow wins."""

    requested = validate_full_image_reference(image_reference)
    by_digest: dict[str, list[str]] = {}
    for row in rows:
        evidence = extract_reference_evidence(row)
        if not evidence.complete:
            return Incomplete(EVIDENCE_INCOMPLETE_REASON)
        if requested not in evidence.references:
            continue
        digest = digest_from_image_row(row)
        if digest is None:
            continue
        hints = [
            requested,
            *(reference for reference in evidence.references if reference != requested),
        ]
        existing = by_digest.setdefault(digest, [])
        for hint in hints:
            if hint not in existing and len(existing) < MAX_HINTS_PER_DIGEST:
                existing.append(hint)

    if not by_digest:
        return NoMatch()
    if len(by_digest) == 1:
        return Resolved(next(iter(by_digest)))

    ordered = sorted(by_digest.items())
    truncated = len(ordered) > MAX_DISAMBIGUATION_CANDIDATES
    ordered = ordered[:MAX_DISAMBIGUATION_CANDIDATES]
    remaining_optional = MAX_TOTAL_DISAMBIGUATION_HINTS - len(ordered)
    candidates: list[ResolveCandidate] = []
    for digest, hints in ordered:
        optional = [hint for hint in hints if hint != requested][
            : min(MAX_HINTS_PER_DIGEST - 1, remaining_optional)
        ]
        remaining_optional -= len(optional)
        candidates.append(ResolveCandidate(digest, (requested, *optional)))
    return Disambiguation(tuple(candidates), truncated)


async def resolve_image_reference(
    client: JsonHttpClient,
    connection: AnchoreConnection,
    image_reference: str,
    *,
    caps: PageCaps = RESOLUTION_CAPS,
) -> ResolutionResult:
    """Query with the versioned exact-tag hint, then prove the match locally."""

    requested = validate_full_image_reference(image_reference)
    query_key = image_full_tag_query_key(connection.api_version)
    pages = await fetch_image_pages(
        client,
        connection,
        httpx.QueryParams({query_key: requested}),
        caps,
    )
    if not pages.complete:
        reason = pages.incomplete_reason or "Image list enumeration was incomplete."
        return Incomplete(f"{reason} Narrow {query_key} or raise caps.")
    result = resolve_image_rows(pages.rows, requested)
    if isinstance(result, Resolved):
        return Resolved(result.digest, pages_fetched=pages.pages_fetched)
    return result
