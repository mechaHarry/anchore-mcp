"""Bounded vulnerability normalization and exact policy correlation."""

from dataclasses import dataclass, replace
from typing import Literal, cast

from anchore_mcp.domain.policy import (
    MAX_JSON_STRING_LENGTH,
    PolicyBlockingFinding,
    json_within_limits,
    normalize_vulnerability_id,
)


MAX_VULNERABILITY_ROWS = 1_000
MAX_LOCATIONS_PER_VULNERABILITY = 256
MAX_FIX_VERSIONS = 64

type LocationKind = Literal["file", "directory", "unknown"]
type CorrelationKind = Literal["vulnerability_id", "package_identity"]

_WRAPPER_KEYS = ("vulnerabilities", "items", "results")
_ID_KEYS = ("vuln", "vulnerability_id", "vulnerabilityId", "vuln_id", "id", "cve")
_PACKAGE_NAME_KEYS = ("package_name", "packageName", "pkg_name", "pkgName", "package")
_PACKAGE_VERSION_KEYS = (
    "package_version",
    "packageVersion",
    "pkg_version",
    "pkgVersion",
    "installed_version",
    "installedVersion",
    "version",
)
_PACKAGE_TYPE_KEYS = ("package_type", "packageType", "pkg_type", "pkgType")
_FIXED_VERSION_KEYS = ("fix", "fixed_version", "fixedVersion", "fix_version")
_DIRECT_LOCATION_KEYS = ("path", "file_path", "filePath", "location")
_LOCATION_KIND_KEYS = ("kind", "type")


@dataclass(frozen=True, slots=True)
class ImageLocation:
    path: str
    kind: LocationKind = "unknown"
    source: Literal["vulnerability"] = "vulnerability"


@dataclass(frozen=True, slots=True)
class NormalizedVulnerability:
    vulnerability_id: str | None
    severity: str | None = None
    package_name: str | None = None
    package_version: str | None = None
    package_type: str | None = None
    fixed_version: str | None = None
    image_locations: tuple[ImageLocation, ...] = ()


@dataclass(frozen=True, slots=True)
class PolicyMetadata:
    gate: str | None = None
    trigger: str | None = None
    reason: str | None = None


@dataclass(frozen=True, slots=True)
class CorrelationEvidence:
    matched_by: tuple[CorrelationKind, ...]
    policy_finding_ref: str


@dataclass(frozen=True, slots=True)
class BlockingVulnerability:
    vulnerability: NormalizedVulnerability
    policy: PolicyMetadata
    evidence: CorrelationEvidence


def _string_value(value: object) -> str | None:
    if isinstance(value, str):
        normalized = value.strip()
        return normalized or None
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        try:
            candidate = str(value)
        except ValueError:
            return None
        return candidate if len(candidate) <= MAX_JSON_STRING_LENGTH else None
    if isinstance(value, float) and value == value and value not in (float("inf"), float("-inf")):
        candidate = str(int(value)) if value.is_integer() else str(value)
        return candidate if len(candidate) <= MAX_JSON_STRING_LENGTH else None
    return None


def _first_string(value: dict[str, object], keys: tuple[str, ...]) -> str | None:
    for key in keys:
        candidate = _string_value(value.get(key))
        if candidate is not None:
            return candidate
    return None


def _rows(payload: object) -> tuple[dict[str, object], ...] | None:
    raw_rows: object = payload
    if isinstance(payload, dict):
        mapping = cast(dict[object, object], payload)
        raw_rows = None
        for key in _WRAPPER_KEYS:
            candidate = mapping.get(key)
            if isinstance(candidate, list):
                raw_rows = cast(list[object], candidate)
                break
    if not isinstance(raw_rows, list):
        return None
    sequence = cast(list[object], raw_rows)
    if len(sequence) > MAX_VULNERABILITY_ROWS:
        return None
    return tuple(
        cast(dict[str, object], cast(dict[object, object], row))
        for row in sequence
        if isinstance(row, dict)
    )


def _fixed_version(row: dict[str, object]) -> str | None:
    for key in _FIXED_VERSION_KEYS:
        value = row.get(key)
        direct = _string_value(value)
        if direct is not None:
            return direct
        if isinstance(value, list):
            sequence = cast(list[object], value)
            if len(sequence) > MAX_FIX_VERSIONS:
                raise ValueError("fix version limit exceeded")
            versions = tuple(
                candidate
                for item in sequence
                if isinstance(item, str) and (candidate := item.strip())
            )
            return ", ".join(versions) or None
    return None


def _location_kind(value: object) -> LocationKind:
    candidate = _string_value(value)
    if candidate is not None and candidate.casefold() in {"file", "directory"}:
        return candidate.casefold()  # type: ignore[return-value]
    return "unknown"


def _locations(row: dict[str, object]) -> tuple[ImageLocation, ...]:
    locations: list[ImageLocation] = []
    seen: set[ImageLocation] = set()

    def add(location: ImageLocation) -> None:
        if location not in seen:
            seen.add(location)
            locations.append(location)

    for key in _DIRECT_LOCATION_KEYS:
        path = _string_value(row.get(key))
        if path is not None:
            add(ImageLocation(path))
    raw_locations = row.get("locations")
    if raw_locations is None:
        return tuple(locations)
    if not isinstance(raw_locations, list):
        raise ValueError("location limit exceeded")
    sequence = cast(list[object], raw_locations)
    if len(sequence) > MAX_LOCATIONS_PER_VULNERABILITY:
        raise ValueError("location limit exceeded")
    for raw_location in sequence:
        direct = _string_value(raw_location)
        if direct is not None:
            add(ImageLocation(direct))
            continue
        if not isinstance(raw_location, dict):
            continue
        mapping = cast(dict[str, object], cast(dict[object, object], raw_location))
        path = _first_string(mapping, _DIRECT_LOCATION_KEYS)
        if path is not None:
            kind = _first_string(mapping, _LOCATION_KIND_KEYS)
            add(ImageLocation(path, kind=_location_kind(kind)))
    return tuple(locations)


def extract_vulnerability_records(payload: object) -> tuple[NormalizedVulnerability, ...]:
    if not json_within_limits(payload):
        return ()
    rows = _rows(payload)
    if rows is None:
        return ()
    records: list[NormalizedVulnerability] = []
    seen: set[NormalizedVulnerability] = set()
    try:
        for row in rows:
            vulnerability_id = normalize_vulnerability_id(_first_string(row, _ID_KEYS))
            if vulnerability_id is None:
                continue
            record = NormalizedVulnerability(
                vulnerability_id=vulnerability_id,
                severity=_string_value(row.get("severity")),
                package_name=_first_string(row, _PACKAGE_NAME_KEYS),
                package_version=_first_string(row, _PACKAGE_VERSION_KEYS),
                package_type=_first_string(row, _PACKAGE_TYPE_KEYS),
                fixed_version=_fixed_version(row),
                image_locations=_locations(row),
            )
            if record not in seen:
                seen.add(record)
                records.append(record)
    except ValueError:
        return ()
    return tuple(records)


def correlate_blockers(
    findings: tuple[PolicyBlockingFinding, ...],
    vulnerabilities: tuple[NormalizedVulnerability, ...],
) -> tuple[BlockingVulnerability, ...]:
    by_id: dict[str, list[NormalizedVulnerability]] = {}
    by_package: dict[tuple[str, str], list[NormalizedVulnerability]] = {}
    record_order: dict[NormalizedVulnerability, int] = {}
    for index, vulnerability in enumerate(vulnerabilities):
        record_order.setdefault(vulnerability, index)
        vulnerability_id = normalize_vulnerability_id(vulnerability.vulnerability_id)
        if vulnerability_id is not None:
            by_id.setdefault(vulnerability_id, []).append(vulnerability)
        if vulnerability.package_name is not None and vulnerability.package_version is not None:
            by_package.setdefault(
                (vulnerability.package_name, vulnerability.package_version), []
            ).append(vulnerability)

    correlated: list[BlockingVulnerability] = []
    index_by_record: dict[NormalizedVulnerability, int] = {}
    expanded_ids: set[str] = set()
    expanded_packages: set[tuple[str, str]] = set()
    for finding in findings:
        matched_records: dict[NormalizedVulnerability, list[CorrelationKind]] = {}
        finding_id = normalize_vulnerability_id(finding.vulnerability_id)
        if finding_id is not None and finding_id not in expanded_ids:
            expanded_ids.add(finding_id)
            for vulnerability in by_id.get(finding_id, ()):
                matched_records.setdefault(vulnerability, []).append("vulnerability_id")
        if finding.package_name is not None and finding.package_version is not None:
            package_key = (finding.package_name, finding.package_version)
            if package_key not in expanded_packages:
                expanded_packages.add(package_key)
                for vulnerability in by_package.get(package_key, ()):
                    kinds = matched_records.setdefault(vulnerability, [])
                    if "package_identity" not in kinds:
                        kinds.append("package_identity")
        for vulnerability in sorted(matched_records, key=record_order.__getitem__):
            matched_by = tuple(matched_records[vulnerability])
            existing_index = index_by_record.get(vulnerability)
            if existing_index is not None:
                existing = correlated[existing_index]
                merged = tuple(dict.fromkeys((*existing.evidence.matched_by, *matched_by)))
                correlated[existing_index] = replace(
                    existing,
                    evidence=replace(existing.evidence, matched_by=merged),
                )
                continue
            index_by_record[vulnerability] = len(correlated)
            correlated.append(
                BlockingVulnerability(
                    vulnerability=vulnerability,
                    policy=PolicyMetadata(finding.gate, finding.trigger, finding.reason),
                    evidence=CorrelationEvidence(matched_by, finding.source_ref),
                )
            )
    return tuple(correlated)
