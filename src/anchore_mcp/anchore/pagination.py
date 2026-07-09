"""Fail-closed, memory-bounded Anchore collection pagination."""

from collections.abc import Mapping
from dataclasses import dataclass
import re
from typing import Literal, Protocol, cast
from urllib.parse import SplitResult, urljoin, urlsplit

import httpx
from pydantic import JsonValue

from anchore_mcp.anchore.http import MAX_RESPONSE_BYTES, JsonResponse
from anchore_mcp.anchore.routes import images_list_route, image_tag_summaries_route
from anchore_mcp.config import AnchoreConnection


SUMMARY_PAGE_LIMIT = 1_000
_MAX_CONTINUATION_LENGTH = 16 * 1024
_LINK_VALUE = re.compile(r"^\s*<([^<>]+)>\s*(.*)$")
_LINK_PARAMETER_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_TOKEN_KEYS = ("next_page_token", "nextPageToken", "continuation_token", "page_token")
_PAGINATION_QUERY_KEYS = frozenset(
    {"page", "limit", "offset", "page_size", "page_token", *_TOKEN_KEYS}
)

type QueryValue = str | int | float | bool | None
type Query = Mapping[str, QueryValue] | httpx.QueryParams
type Wrapper = Literal["images", "items", "array"]


class JsonHttpClient(Protocol):
    async def get_json(
        self,
        connection: AnchoreConnection,
        path: str,
        *,
        params: httpx.QueryParams | None = None,
        max_response_bytes: int,
        timeout: httpx.Timeout | float | None = None,
    ) -> JsonResponse: ...


@dataclass(frozen=True, slots=True)
class PageCaps:
    max_pages: int
    max_items: int
    max_bytes: int = MAX_RESPONSE_BYTES

    def __post_init__(self) -> None:
        if type(self.max_pages) is not int or self.max_pages <= 0:
            raise ValueError("max_pages must be a positive integer")
        if type(self.max_items) is not int or self.max_items <= 0:
            raise ValueError("max_items must be a positive integer")
        if type(self.max_bytes) is not int or not 1 <= self.max_bytes <= MAX_RESPONSE_BYTES:
            raise ValueError(f"max_bytes must be in [1, {MAX_RESPONSE_BYTES}]")


LIST_CAPS = PageCaps(max_pages=200, max_items=50_000)
RESOLUTION_CAPS = PageCaps(max_pages=100, max_items=20_000)


@dataclass(frozen=True, slots=True)
class PaginatedRows:
    rows: tuple[JsonValue, ...]
    pages_fetched: int
    complete: bool
    incomplete_reason: str | None
    wrapper: Wrapper = "items"

    def __post_init__(self) -> None:
        if self.pages_fetched < 0:
            raise ValueError("pages_fetched must not be negative")
        if self.complete == (self.incomplete_reason is not None):
            raise ValueError("complete results must omit a reason; incomplete results require one")


@dataclass(frozen=True, slots=True)
class _Continuation:
    path: str
    params: httpx.QueryParams


def validate_next_link(
    base_url: str,
    current_path: str,
    link: str,
) -> tuple[str, httpx.QueryParams] | None:
    """Validate one RFC Link next target and return deployment-relative request parts."""

    parsed = _parse_link_next(base_url, current_path, link)
    if parsed is None:
        return None
    found, continuation = parsed
    if not found or continuation is None:
        return None
    return continuation.path, continuation.params


def _parse_link_next(
    base_url: str, current_path: str, link: str
) -> tuple[bool, _Continuation | None] | None:
    if not 0 < len(link) <= _MAX_CONTINUATION_LENGTH:
        return None
    parts = _split_link_values(link)
    if parts is None:
        return None
    next_hrefs: list[str] = []
    for part in parts:
        match = _LINK_VALUE.fullmatch(part)
        if match is None:
            return None
        href, attributes = match.groups()
        relations: list[str] = []
        if attributes.strip():
            if not attributes.lstrip().startswith(";"):
                return None
            for raw_attribute in attributes.split(";")[1:]:
                name, separator, raw_value = raw_attribute.strip().partition("=")
                if not separator or _LINK_PARAMETER_NAME.fullmatch(name) is None:
                    return None
                value = raw_value.strip()
                if value.startswith('"'):
                    if len(value) < 2 or not value.endswith('"'):
                        return None
                    value = value[1:-1]
                elif not value or any(character.isspace() for character in value):
                    return None
                if name.casefold() == "rel":
                    relations.extend(value.casefold().split())
        if "next" in relations:
            next_hrefs.append(href.strip())
    if not next_hrefs:
        return False, None
    if len(next_hrefs) != 1:
        return None
    continuation = _validate_href(base_url, current_path, next_hrefs[0])
    if continuation is None:
        return None
    return True, continuation


def _split_link_values(link: str) -> list[str] | None:
    parts: list[str] = []
    start = 0
    in_angle = False
    in_quote = False
    escaped = False
    for index, character in enumerate(link):
        if escaped:
            escaped = False
        elif in_quote and character == "\\":
            escaped = True
        elif character == '"':
            in_quote = not in_quote
        elif not in_quote and character == "<":
            if in_angle:
                return None
            in_angle = True
        elif not in_quote and character == ">":
            if not in_angle:
                return None
            in_angle = False
        elif not in_quote and not in_angle and character == ",":
            parts.append(link[start:index])
            start = index + 1
    if in_angle or in_quote or escaped:
        return None
    parts.append(link[start:])
    return parts if all(part.strip() for part in parts) else None


def _validate_href(base_url: str, current_path: str, href: str) -> _Continuation | None:
    if not href or len(href) > _MAX_CONTINUATION_LENGTH or "\\" in href:
        return None
    try:
        base = urlsplit(base_url)
        current = f"{base_url.rstrip('/')}{current_path}"
        target = urlsplit(urljoin(current, href))
        base_origin = _origin(base)
        target_origin = _origin(target)
    except (UnicodeError, ValueError):
        return None
    if base_origin is None or target_origin != base_origin:
        return None
    if target.username is not None or target.password is not None or target.fragment:
        return None
    prefix = base.path.rstrip("/")
    if prefix and target.path != prefix and not target.path.startswith(f"{prefix}/"):
        return None
    route = target.path[len(prefix) :] if prefix else target.path
    if not route.startswith("/") or route.startswith("//"):
        return None
    return _Continuation(route, httpx.QueryParams(target.query))


def _origin(parsed: SplitResult) -> tuple[str, str, int] | None:
    scheme = parsed.scheme.casefold()
    host = parsed.hostname
    if scheme != "https" or not host:
        return None
    normalized_host = host.rstrip(".").encode("idna").decode("ascii").casefold()
    try:
        port = parsed.port
    except ValueError:
        return None
    return scheme, normalized_host, 443 if port is None else port


def _rows_and_wrapper(data: JsonValue) -> tuple[list[JsonValue], Wrapper] | None:
    if isinstance(data, list):
        rows = data
        wrapper: Wrapper = "array"
    elif isinstance(data, dict):
        if isinstance(data.get("images"), list):
            rows = cast(list[JsonValue], data["images"])
            wrapper = "images"
        elif isinstance(data.get("items"), list):
            rows = cast(list[JsonValue], data["items"])
            wrapper = "items"
        else:
            return None
    else:
        return None
    if any(not isinstance(row, dict) for row in rows):
        return None
    return rows, wrapper


def _incomplete(
    rows: list[JsonValue], pages: int, reason: str, wrapper: Wrapper = "items"
) -> PaginatedRows:
    return PaginatedRows(tuple(rows), pages, False, reason, wrapper)


def _request_key(path: str, params: httpx.QueryParams) -> tuple[str, tuple[tuple[str, str], ...]]:
    return path, tuple(sorted(params.multi_items()))


def _normalize_continuation(
    continuation: _Continuation,
    canonical_path: str,
    base_params: httpx.QueryParams,
) -> _Continuation | None:
    if continuation.path != canonical_path:
        return None
    original = {key: base_params.get_list(key) for key in base_params.keys()}
    candidate = {key: continuation.params.get_list(key) for key in continuation.params.keys()}
    for key, values in candidate.items():
        if key in _PAGINATION_QUERY_KEYS:
            continue
        if key not in original or values != original[key]:
            return None
    normalized = list(continuation.params.multi_items())
    for key, values in original.items():
        if key in _PAGINATION_QUERY_KEYS or key in candidate:
            continue
        normalized.extend((key, value) for value in values)
    return _Continuation(canonical_path, httpx.QueryParams(tuple(normalized)))


async def fetch_image_pages(
    client: JsonHttpClient,
    connection: AnchoreConnection,
    params: Query,
    caps: PageCaps = LIST_CAPS,
) -> PaginatedRows:
    """Fetch every advertised image page, or return explicit incomplete evidence."""

    path = images_list_route(connection.api_version)
    base_params = httpx.QueryParams(params)
    request_params = base_params
    seen = {_request_key(path, request_params)}
    rows: list[JsonValue] = []
    wrapper: Wrapper | None = None
    expected_total: int | None = None
    total_bytes = 0

    for page_number in range(1, caps.max_pages + 1):
        response = await client.get_json(
            connection,
            path,
            params=request_params,
            max_response_bytes=MAX_RESPONSE_BYTES,
        )
        observed_bytes = total_bytes + response.byte_length
        if observed_bytes > caps.max_bytes:
            return _incomplete(
                rows,
                page_number,
                "Stopped at the aggregate max_bytes cap.",
                wrapper or "items",
            )
        total_bytes = observed_bytes
        extracted = _rows_and_wrapper(response.data)
        if extracted is None:
            return _incomplete(
                rows, page_number, "Image page wrapper or rows were malformed.", wrapper or "items"
            )
        page_rows, page_wrapper = extracted
        if wrapper is None:
            wrapper = page_wrapper
        elif page_wrapper != wrapper:
            return _incomplete(
                rows, page_number, "Image page wrapper changed during enumeration.", wrapper
            )
        data = response.data
        if isinstance(data, dict) and "total_rows" in data:
            reported = data["total_rows"]
            if type(reported) is not int or reported < 0:
                return _incomplete(rows, page_number, "Image total_rows was invalid.", wrapper)
            if expected_total is None:
                expected_total = reported
            elif reported != expected_total:
                return _incomplete(rows, page_number, "Image total_rows was inconsistent.", wrapper)
        if expected_total is not None and len(rows) + len(page_rows) > expected_total:
            return _incomplete(rows, page_number, "Image total_rows was inconsistent.", wrapper)
        remaining = caps.max_items - len(rows)
        rows.extend(page_rows[:remaining])
        truncated = len(page_rows) > remaining

        advertised, continuation, invalid_reason = _next_image_continuation(
            response, connection.base_url, path, base_params
        )
        if invalid_reason is not None:
            return _incomplete(rows, page_number, invalid_reason, wrapper)
        if truncated:
            return _incomplete(rows, page_number, "Stopped at the max_items cap.", wrapper)
        if continuation is None:
            if expected_total is not None and len(rows) != expected_total:
                return _incomplete(
                    rows,
                    page_number,
                    "Enumeration ended before image total_rows was reached.",
                    wrapper,
                )
            return PaginatedRows(tuple(rows), page_number, True, None, wrapper)
        if expected_total is not None:
            if len(rows) == expected_total:
                return _incomplete(
                    rows,
                    page_number,
                    "Pagination continued after image total_rows was reached.",
                    wrapper,
                )
            if not page_rows:
                return _incomplete(
                    rows,
                    page_number,
                    "Enumeration ended before image total_rows was reached.",
                    wrapper,
                )
        if len(rows) >= caps.max_items and advertised:
            return _incomplete(rows, page_number, "Stopped at the max_items cap.", wrapper)
        key = _request_key(continuation.path, continuation.params)
        if key in seen:
            return _incomplete(
                rows, page_number, "Pagination advertised a repeated continuation.", wrapper
            )
        seen.add(key)
        if page_number >= caps.max_pages:
            return _incomplete(rows, page_number, "Stopped at the max_pages cap.", wrapper)
        path, request_params = continuation.path, continuation.params

    return _incomplete(rows, caps.max_pages, "Stopped at the max_pages cap.", wrapper or "items")


def _next_image_continuation(
    response: JsonResponse,
    base_url: str,
    current_path: str,
    base_params: httpx.QueryParams,
) -> tuple[bool, _Continuation | None, str | None]:
    link_continuation: _Continuation | None = None
    link_advertised = False
    link = response.headers.get("link")
    if link is not None:
        parsed_link = _parse_link_next(base_url, current_path, link)
        if parsed_link is None:
            return True, None, "Pagination advertised an invalid Link continuation."
        link_advertised, link_continuation = parsed_link
        if link_continuation is not None:
            link_continuation = _normalize_continuation(
                link_continuation, current_path, base_params
            )
            if link_continuation is None:
                return True, None, "Pagination advertised an invalid Link continuation."

    data = response.data
    if not isinstance(data, dict):
        return link_advertised, link_continuation, None
    body_candidates: list[_Continuation] = []
    body_advertised = False
    if "next" in data:
        body_advertised = True
        href = data["next"]
        if not isinstance(href, str):
            return True, None, "Pagination advertised an invalid JSON continuation."
        body_continuation = _validate_href(base_url, current_path, href)
        if body_continuation is None:
            return True, None, "Pagination advertised an invalid JSON continuation."
        normalized = _normalize_continuation(body_continuation, current_path, base_params)
        if normalized is None:
            return True, None, "Pagination advertised an invalid JSON continuation."
        body_candidates.append(normalized)
    present_tokens = [key for key in _TOKEN_KEYS if key in data]
    if present_tokens:
        body_advertised = True
        if len(present_tokens) != 1:
            return True, None, "Pagination advertised ambiguous continuation tokens."
        value = data[present_tokens[0]]
        if not isinstance(value, str) or not value or len(value) > _MAX_CONTINUATION_LENGTH:
            return True, None, "Pagination advertised an invalid continuation token."
        next_params = base_params.set("page_token", value)
        body_candidates.append(_Continuation(current_path, next_params))
    candidates = [
        candidate for candidate in (link_continuation, *body_candidates) if candidate is not None
    ]
    if len({_request_key(candidate.path, candidate.params) for candidate in candidates}) > 1:
        return True, None, "Pagination advertised conflicting continuations."
    return (
        link_advertised or body_advertised,
        candidates[0] if candidates else None,
        None,
    )


async def fetch_image_tag_summary_pages(
    client: JsonHttpClient,
    connection: AnchoreConnection,
    params: Query,
    caps: PageCaps = RESOLUTION_CAPS,
) -> PaginatedRows:
    """Walk the documented page/limit summary API with stable total_rows checks."""

    base_params = httpx.QueryParams(params)
    requested_limit = _positive_integer(base_params.get("limit"))
    page_limit = max(
        1, min(requested_limit or SUMMARY_PAGE_LIMIT, SUMMARY_PAGE_LIMIT, caps.max_items)
    )
    rows: list[JsonValue] = []
    expected_total: int | None = None
    total_bytes = 0

    for page_number in range(1, caps.max_pages + 1):
        page_params = base_params.set("page", page_number).set("limit", page_limit)
        response = await client.get_json(
            connection,
            image_tag_summaries_route(connection.api_version),
            params=page_params,
            max_response_bytes=MAX_RESPONSE_BYTES,
        )
        observed_bytes = total_bytes + response.byte_length
        if observed_bytes > caps.max_bytes:
            return _incomplete(rows, page_number, "Stopped at the aggregate max_bytes cap.")
        total_bytes = observed_bytes
        data = response.data
        if not isinstance(data, dict) or not isinstance(data.get("items"), list):
            return _incomplete(rows, page_number, "Image tag summary wrapper was malformed.")
        page_rows = cast(list[JsonValue], data["items"])
        if any(not isinstance(row, dict) for row in page_rows):
            return _incomplete(rows, page_number, "Image tag summary rows were malformed.")

        if "total_rows" in data:
            reported = data["total_rows"]
            if type(reported) is not int or reported < 0:
                return _incomplete(rows, page_number, "Image tag summary total_rows was invalid.")
            if expected_total is None:
                expected_total = reported
            elif reported != expected_total:
                return _incomplete(
                    rows, page_number, "Image tag summary total_rows was inconsistent."
                )
        if expected_total is not None and len(rows) + len(page_rows) > expected_total:
            return _incomplete(rows, page_number, "Image tag summary total_rows was inconsistent.")

        remaining = caps.max_items - len(rows)
        rows.extend(page_rows[:remaining])
        if len(page_rows) > remaining:
            return _incomplete(rows, page_number, "Stopped at the max_items cap.")

        if expected_total is not None:
            if len(rows) == expected_total:
                return PaginatedRows(tuple(rows), page_number, True, None)
            if not page_rows:
                return _incomplete(
                    rows, page_number, "Enumeration ended before total_rows was reached."
                )
            if len(rows) >= caps.max_items:
                return _incomplete(rows, page_number, "Stopped at the max_items cap.")
        elif len(page_rows) < page_limit:
            return PaginatedRows(tuple(rows), page_number, True, None)

        if page_number >= caps.max_pages:
            return _incomplete(rows, page_number, "Stopped at the max_pages cap.")

    return _incomplete(rows, caps.max_pages, "Stopped at the max_pages cap.")


def _positive_integer(value: str | None) -> int | None:
    if value is None or not value.isascii() or not value.isdecimal():
        return None
    parsed = int(value)
    return parsed if parsed > 0 else None
