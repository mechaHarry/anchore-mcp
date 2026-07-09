"""Bounded image-row normalization and exact reference evidence extraction."""

from dataclasses import dataclass
import ipaddress
import re
from typing import Literal, cast


MAX_IMAGE_REFERENCE_STRING_LENGTH = 1_024
MAX_IMAGE_DETAIL_ENTRIES_PER_ROW = 64
MAX_IMAGE_TAG_ENTRIES_PER_OBJECT = 64
MAX_NORMALIZED_IMAGE_REFERENCES_PER_ROW = 32
MAX_IMAGE_REFERENCE_EVIDENCE_SCANS_PER_ROW = 256
MAX_REGISTRY_COMPONENT_LENGTH = 255
MAX_REPOSITORY_COMPONENT_LENGTH = 1_024

type EvidenceIncompleteReason = Literal[
    "detail_entry_limit",
    "tag_entry_limit",
    "reference_limit",
    "scan_limit",
    "string_length_limit",
]

_TOP_LEVEL_REFERENCE_KEYS = ("full_tag", "fulltag", "image_tag", "imageTag", "tag")
_DETAIL_REFERENCE_KEYS = ("full_tag", "fulltag", "image_tag", "imageTag")
_DETAIL_KEYS = ("image_detail", "imageDetail")
_TAG = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$")
_HOST = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$")
_BRACKETED_REGISTRY = re.compile(r"^\[([^\]]+)\](?::([0-9]{1,5}))?$")
_SHA256 = re.compile(r"^sha256:[a-fA-F0-9]+$")


@dataclass(frozen=True, slots=True)
class ReferenceEvidence:
    references: tuple[str, ...]
    complete: bool
    reason: EvidenceIncompleteReason | None = None

    def __post_init__(self) -> None:
        if self.complete == (self.reason is not None):
            raise ValueError("complete evidence omits a reason; incomplete evidence requires one")


@dataclass(slots=True)
class _EvidenceState:
    references: dict[str, None]
    scans: int = 0
    reason: EvidenceIncompleteReason | None = None

    def consume(self) -> bool:
        self.scans += 1
        if self.scans > MAX_IMAGE_REFERENCE_EVIDENCE_SCANS_PER_ROW:
            self.reason = self.reason or "scan_limit"
            return False
        return True

    def fail(self, reason: EvidenceIncompleteReason) -> None:
        self.reason = self.reason or reason

    def result(self) -> ReferenceEvidence:
        return ReferenceEvidence(
            references=tuple(self.references),
            complete=self.reason is None,
            reason=self.reason,
        )


def extract_image_list_rows(data: object) -> tuple[object, ...]:
    """Normalize root-array and v1/v2 wrapped image list payloads."""

    if isinstance(data, list):
        return tuple(cast(list[object], data))
    if isinstance(data, dict):
        mapping = cast(dict[object, object], data)
        images = mapping.get("images")
        if isinstance(images, list):
            return tuple(cast(list[object], images))
        items = mapping.get("items")
        if isinstance(items, list):
            return tuple(cast(list[object], items))
    return ()


def digest_from_image_row(row: object) -> str | None:
    """Return the first non-empty documented digest alias."""

    if not isinstance(row, dict):
        return None
    mapping = cast(dict[object, object], row)
    for key in ("imageDigest", "image_digest", "digest", "imageId", "image_id"):
        candidate = mapping.get(key)
        if isinstance(candidate, str) and candidate.strip():
            return candidate.strip()
    return None


def is_canonical_image_digest(value: str) -> bool:
    normalized = value.strip()
    return 12 <= len(normalized) <= 512 and _SHA256.fullmatch(normalized) is not None


def _valid_registry(registry: str) -> bool:
    if (
        not registry
        or len(registry) > MAX_REGISTRY_COMPONENT_LENGTH
        or any(character.isspace() or character in "/\\" for character in registry)
        or any(ord(character) < 32 or ord(character) == 127 for character in registry)
    ):
        return False
    bracketed = _BRACKETED_REGISTRY.fullmatch(registry)
    if bracketed is not None:
        try:
            ipaddress.IPv6Address(bracketed.group(1))
        except ipaddress.AddressValueError:
            return False
        port = bracketed.group(2)
        return port is None or 0 < int(port) <= 65_535
    parts = registry.split(":")
    if len(parts) > 2 or _HOST.fullmatch(parts[0]) is None:
        return False
    if len(parts) == 2:
        return parts[1].isdigit() and 1 <= len(parts[1]) <= 5 and 0 < int(parts[1]) <= 65_535
    return True


def _valid_repository(repository: str) -> bool:
    return (
        0 < len(repository) <= MAX_REPOSITORY_COMPONENT_LENGTH
        and not repository.startswith("/")
        and not repository.endswith("/")
        and "//" not in repository
        and not any(character.isspace() or character in ":\\" for character in repository)
        and not any(ord(character) < 32 or ord(character) == 127 for character in repository)
    )


def validate_full_image_reference(reference: str) -> str:
    """Normalize and validate one registry-qualified ``repository:tag`` reference."""

    normalized = reference.strip()
    if not normalized:
        raise ValueError("image_reference is empty")
    if len(normalized) > MAX_IMAGE_REFERENCE_STRING_LENGTH:
        raise ValueError("image_reference is too long")
    if any(ord(character) < 32 or ord(character) == 127 for character in normalized):
        raise ValueError("image_reference contains invalid control characters")
    registry, separator, remainder = normalized.partition("/")
    if not separator or not _valid_registry(registry):
        raise ValueError("image_reference must be a fully qualified registry/repository:tag")
    repository, tag_separator, tag = remainder.rpartition(":")
    if not tag_separator or not _valid_repository(repository) or _TAG.fullmatch(tag) is None:
        raise ValueError("image_reference must include a valid repository:tag")
    return normalized


def _bounded_string(
    state: _EvidenceState,
    value: object,
    max_length: int,
) -> str | None:
    if value is None or state.reason is not None:
        return None
    if not state.consume() or not isinstance(value, str):
        return None
    if len(value) > max_length:
        state.fail("string_length_limit")
        return None
    normalized = value.strip()
    return normalized or None


def _add_reference(state: _EvidenceState, value: object) -> None:
    reference = _bounded_string(state, value, MAX_IMAGE_REFERENCE_STRING_LENGTH)
    if reference is None or state.reason is not None:
        return
    try:
        normalized = validate_full_image_reference(reference)
    except ValueError:
        return
    if normalized not in state.references:
        if len(state.references) >= MAX_NORMALIZED_IMAGE_REFERENCES_PER_ROW:
            state.fail("reference_limit")
            return
        state.references[normalized] = None


def _add_direct_references(
    state: _EvidenceState,
    row: dict[object, object],
    keys: tuple[str, ...],
) -> None:
    for key in keys:
        _add_reference(state, row.get(key))
        if state.reason is not None:
            return
    tags = row.get("tags")
    if not isinstance(tags, list):
        return
    tag_values = cast(list[object], tags)
    if len(tag_values) > MAX_IMAGE_TAG_ENTRIES_PER_OBJECT:
        state.fail("tag_entry_limit")
        return
    for tag in tag_values:
        _add_reference(state, tag)
        if state.reason is not None:
            return


def _add_coherent_reference(state: _EvidenceState, detail: dict[object, object]) -> None:
    registry = _bounded_string(state, detail.get("registry"), MAX_REGISTRY_COMPONENT_LENGTH)
    repo = _bounded_string(state, detail.get("repo"), MAX_REPOSITORY_COMPONENT_LENGTH)
    repository = _bounded_string(state, detail.get("repository"), MAX_REPOSITORY_COMPONENT_LENGTH)
    tag = _bounded_string(state, detail.get("tag"), 128)
    if state.reason is not None:
        return
    if (
        registry is None
        or not _valid_registry(registry)
        or tag is None
        or _TAG.fullmatch(tag) is None
        or (repo is not None and repository is not None and repo != repository)
    ):
        return
    coherent_repository = repo if repo is not None else repository
    if coherent_repository is not None and _valid_repository(coherent_repository):
        _add_reference(state, f"{registry}/{coherent_repository}:{tag}")


def extract_reference_evidence(row: object) -> ReferenceEvidence:
    """Extract bounded exact references without combining evidence across objects."""

    if not isinstance(row, dict):
        return ReferenceEvidence((), True)
    mapping = cast(dict[object, object], row)
    state = _EvidenceState(references={})
    _add_direct_references(state, mapping, _TOP_LEVEL_REFERENCE_KEYS)
    if state.reason is not None:
        return state.result()

    detail_count = 0
    for key in _DETAIL_KEYS:
        raw = mapping.get(key)
        details: list[object]
        if isinstance(raw, list):
            details = cast(list[object], raw)
        elif isinstance(raw, dict):
            details = [raw]
        else:
            details = []
        detail_count += len(details)
        if detail_count > MAX_IMAGE_DETAIL_ENTRIES_PER_ROW:
            state.fail("detail_entry_limit")
            return state.result()
        for detail in details:
            if not isinstance(detail, dict):
                continue
            detail_mapping = cast(dict[object, object], detail)
            if not state.consume():
                return state.result()
            _add_direct_references(state, detail_mapping, _DETAIL_REFERENCE_KEYS)
            if state.reason is not None:
                return state.result()
            _add_coherent_reference(state, detail_mapping)
            if state.reason is not None:
                return state.result()
    return state.result()
