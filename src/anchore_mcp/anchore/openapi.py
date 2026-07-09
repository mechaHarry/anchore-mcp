"""Bounded deployment capability discovery for Anchore OpenAPI documents."""

import asyncio
from collections.abc import Callable, Mapping
from dataclasses import dataclass
import time
from typing import cast

import httpx
from pydantic import JsonValue

from anchore_mcp.anchore.pagination import JsonHttpClient
from anchore_mcp.anchore.routes import image_full_tag_query_key, openapi_route
from anchore_mcp.config import AnchoreConnection
from anchore_mcp.models.common import ApiVersion


OPENAPI_TTL_SECONDS = 600.0
MAX_OPENAPI_BYTES = 6_000_000
MAX_OPENAPI_NODES = 10_000
MAX_OPENAPI_PATHS = 2_048
MAX_OPENAPI_PARAMETERS = 256
MAX_PARAMETER_NAME_LENGTH = 256
MAX_LIST_QUERY_KEYS = 32
MAX_LIST_QUERY_ENTRIES_EXAMINED = 64
MAX_LIST_QUERY_KEY_LENGTH = 256
MAX_LIST_QUERY_VALUE_LENGTH = 4_096
MAX_REJECTED_QUERY_KEYS = 32

_COMMON_FALLBACK_LIST_IMAGES_QUERY_KEYS = frozenset(
    {
        "vulnerability_id",
        "limit",
        "page",
        "page_size",
        "page_token",
        "name",
        "image_digest",
        "tag",
    }
)
FALLBACK_LIST_IMAGES_QUERY_KEYS = _COMMON_FALLBACK_LIST_IMAGES_QUERY_KEYS | {
    "full_tag",
    "fulltag",
}
_V1_SUMMARY_PATHS = ("/v1/summaries/image-tags", "/summaries/image-tags")


@dataclass(frozen=True, slots=True)
class _Entry:
    key: tuple[str, ApiVersion, str | None]
    document: JsonValue
    expires_at: float


class OpenApiCache:
    """One-entry, account-aware OpenAPI cache with stampede prevention."""

    def __init__(
        self,
        client: JsonHttpClient,
        *,
        clock: Callable[[], float] = time.monotonic,
        ttl_seconds: float = OPENAPI_TTL_SECONDS,
    ) -> None:
        if not 0 < ttl_seconds <= OPENAPI_TTL_SECONDS:
            raise ValueError(f"ttl_seconds must be in (0, {OPENAPI_TTL_SECONDS}]")
        self._client = client
        self._clock = clock
        self._ttl_seconds = ttl_seconds
        self._entry: _Entry | None = None
        self._lock = asyncio.Lock()
        self._generation = 0

    @property
    def size(self) -> int:
        return int(self._entry is not None)

    async def fetch(self, connection: AnchoreConnection) -> JsonValue:
        key = _cache_key(connection)
        now = self._clock()
        entry = self._entry
        if entry is not None and entry.key == key and entry.expires_at > now:
            return entry.document

        async with self._lock:
            now = self._clock()
            entry = self._entry
            if entry is not None and entry.key == key and entry.expires_at > now:
                return entry.document
            self._entry = None
            generation = self._generation
            response = await self._client.get_json(
                connection,
                openapi_route(connection.api_version),
                max_response_bytes=MAX_OPENAPI_BYTES,
            )
            document = response.data
            if generation == self._generation:
                self._entry = _Entry(key, document, self._clock() + self._ttl_seconds)
            return document

    def invalidate(self, connection: AnchoreConnection) -> bool:
        self._generation += 1
        matched = self._entry is not None and self._entry.key == _cache_key(connection)
        if matched:
            self._entry = None
        return matched

    def clear(self) -> None:
        self._generation += 1
        self._entry = None


def _cache_key(connection: AnchoreConnection) -> tuple[str, ApiVersion, str | None]:
    return connection.base_url, connection.api_version, connection.account


def fallback_list_images_query_keys(version: ApiVersion) -> frozenset[str]:
    return _COMMON_FALLBACK_LIST_IMAGES_QUERY_KEYS | {image_full_tag_query_key(version)}


def _bounded_document(document: object) -> bool:
    pending: list[object] = [document]
    visited = 0
    while pending:
        node = pending.pop()
        visited += 1
        if visited > MAX_OPENAPI_NODES:
            return False
        if isinstance(node, dict):
            mapping = cast(dict[object, object], node)
            if len(mapping) * 2 > MAX_OPENAPI_NODES - visited - len(pending):
                return False
            pending.extend(mapping.keys())
            pending.extend(mapping.values())
        elif isinstance(node, list):
            values = cast(list[object], node)
            if len(values) > MAX_OPENAPI_NODES - visited - len(pending):
                return False
            pending.extend(values)
    return True


def _direct_query_parameter_names(operation: object) -> frozenset[str]:
    if not isinstance(operation, dict):
        return frozenset()
    operation_map = cast(dict[str, object], operation)
    parameters = operation_map.get("parameters")
    if not isinstance(parameters, list):
        return frozenset()
    parameter_list = cast(list[object], parameters)
    if len(parameter_list) > MAX_OPENAPI_PARAMETERS:
        return frozenset()
    names: set[str] = set()
    for parameter in parameter_list:
        if not isinstance(parameter, dict) or "$ref" in parameter:
            continue
        parameter_map = cast(dict[str, object], parameter)
        name = parameter_map.get("name")
        if (
            parameter_map.get("in") == "query"
            and isinstance(name, str)
            and 0 < len(name) <= MAX_PARAMETER_NAME_LENGTH
        ):
            names.add(name)
    return frozenset(names)


def extract_list_images_query_parameter_names(
    document: object, version: ApiVersion
) -> frozenset[str]:
    if not _bounded_document(document) or not isinstance(document, dict):
        return frozenset()
    document_map = cast(dict[str, object], document)
    paths = document_map.get("paths")
    if not isinstance(paths, dict):
        return frozenset()
    paths_map = cast(dict[str, object], paths)
    if len(paths_map) > MAX_OPENAPI_PATHS:
        return frozenset()
    path_item = paths_map.get(f"/{version}/images")
    if not isinstance(path_item, dict):
        return frozenset()
    return _direct_query_parameter_names(cast(dict[str, object], path_item).get("get"))


def openapi_advertises_v1_image_tag_summary_filters(document: object) -> bool:
    if not _bounded_document(document) or not isinstance(document, dict):
        return False
    document_map = cast(dict[str, object], document)
    paths = document_map.get("paths")
    if not isinstance(paths, dict):
        return False
    paths_map = cast(dict[str, object], paths)
    if len(paths_map) > MAX_OPENAPI_PATHS:
        return False
    for path in _V1_SUMMARY_PATHS:
        path_item = paths_map.get(path)
        if not isinstance(path_item, dict):
            continue
        names = _direct_query_parameter_names(cast(dict[str, object], path_item).get("get"))
        if {"registry", "repository"} <= names:
            return True
    return False


async def list_images_query_allowlist(
    cache: OpenApiCache, connection: AnchoreConnection
) -> frozenset[str]:
    """Return conservative built-ins unioned with bounded deployment evidence."""

    try:
        document = await cache.fetch(connection)
    except Exception:
        return fallback_list_images_query_keys(connection.api_version)
    return fallback_list_images_query_keys(
        connection.api_version
    ) | extract_list_images_query_parameter_names(document, connection.api_version)


@dataclass(frozen=True, slots=True)
class MergedListQuery:
    params: httpx.QueryParams
    rejected_keys: tuple[str, ...]
    applied_keys: tuple[str, ...]
    rejected_count: int
    truncated: bool


def merge_list_images_query(
    *,
    version: ApiVersion,
    full_tag: str | None = None,
    vulnerability_id: str | None = None,
    list_query: Mapping[str, str] | None = None,
    allowlist: frozenset[str] | None = None,
) -> MergedListQuery:
    """Merge public filters with a bounded allowlisted map; explicit filters win."""

    allowed = fallback_list_images_query_keys(version) if allowlist is None else allowlist
    values: dict[str, str] = {}
    explicit_full_tag = full_tag.strip() if full_tag is not None else ""
    explicit_vulnerability = vulnerability_id.strip() if vulnerability_id is not None else ""
    if explicit_full_tag:
        values[image_full_tag_query_key(version)] = explicit_full_tag
    if explicit_vulnerability:
        values["vulnerability_id"] = explicit_vulnerability

    rejected: list[str] = []
    rejected_count = 0
    applied_keys: list[str] = []
    applied = 0
    entries: list[tuple[str, str]] = []
    truncated = False
    for index, entry in enumerate((list_query or {}).items()):
        if index >= MAX_LIST_QUERY_ENTRIES_EXAMINED:
            truncated = True
            break
        entries.append(entry)
    for key, raw_value in sorted(entries):
        if (
            len(key) > MAX_LIST_QUERY_KEY_LENGTH
            or applied >= MAX_LIST_QUERY_KEYS
            or key not in allowed
        ):
            rejected_count += 1
            if len(rejected) < MAX_REJECTED_QUERY_KEYS:
                rejected.append(key[:MAX_LIST_QUERY_KEY_LENGTH])
            continue
        if explicit_full_tag and key in {"full_tag", "fulltag"}:
            continue
        if explicit_vulnerability and key == "vulnerability_id":
            continue
        value = raw_value.strip()
        if len(value) > MAX_LIST_QUERY_VALUE_LENGTH:
            rejected_count += 1
            if len(rejected) < MAX_REJECTED_QUERY_KEYS:
                rejected.append(key)
            continue
        if not value:
            continue
        values[key] = value
        applied += 1
        applied_keys.append(key)
    return MergedListQuery(
        httpx.QueryParams(values),
        tuple(rejected),
        tuple(applied_keys),
        rejected_count,
        truncated,
    )
