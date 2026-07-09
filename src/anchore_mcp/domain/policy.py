"""Bounded policy interpretation over untrusted Anchore JSON evidence."""

from dataclasses import dataclass
import math
import re
from typing import Literal, cast


MAX_JSON_NODES = 10_000
MAX_JSON_DEPTH = 32
MAX_JSON_COLLECTION_ENTRIES = 1_024
MAX_JSON_STRING_LENGTH = 4_096
MAX_SOURCE_REF_LENGTH = 8_192

type PolicyStatus = Literal["green", "red", "unknown"]

_GREEN_STATUSES = frozenset({"pass", "passed", "green", "allow", "allowed", "ok"})
_RED_STATUSES = frozenset({"fail", "failed", "red", "deny", "denied", "stop", "stopped"})
_BLOCK_ACTIONS = frozenset({"stop", "fail", "failed", "deny", "denied", "block", "blocked"})
_VULNERABILITY_GATES = frozenset({"vulnerability", "vulnerabilities", "vuln", "vulns"})
_BLOCK_ACTION_KEYS = ("action", "status", "result")
_SPECIFIC_ID_KEYS = ("vulnerability_id", "vulnerabilityId", "vuln_id", "vulnId", "vuln", "cve")
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
_REASON_KEYS = ("reason", "message", "description")
_TRIGGER_ID_KEYS = ("trigger_id", "triggerId")
_VULNERABILITY_ID = re.compile(
    r"(?i)\b(?:CVE-[0-9]{4}-[0-9]{4,}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}|"
    r"(?:RHSA|ELSA|ALAS|DLA)-[0-9]{4}:[0-9]+)\b"
)


@dataclass(frozen=True, slots=True)
class PolicyBlockingFinding:
    source_ref: str
    vulnerability_id: str | None = None
    package_name: str | None = None
    package_version: str | None = None
    gate: str | None = None
    trigger: str | None = None
    reason: str | None = None


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
    if isinstance(value, float) and math.isfinite(value):
        candidate = str(int(value)) if value.is_integer() else str(value)
        return candidate if len(candidate) <= MAX_JSON_STRING_LENGTH else None
    return None


def _first_string(value: dict[str, object], keys: tuple[str, ...]) -> str | None:
    for key in keys:
        candidate = _string_value(value.get(key))
        if candidate is not None:
            return candidate
    return None


def normalize_vulnerability_id(value: str | None, *, search: bool = False) -> str | None:
    """Return one supported identifier in canonical uppercase form."""

    if value is None or len(value) > MAX_JSON_STRING_LENGTH:
        return None
    candidate = value.strip()
    match = (
        _VULNERABILITY_ID.search(candidate) if search else _VULNERABILITY_ID.fullmatch(candidate)
    )
    return match.group(0).upper() if match is not None else None


def _child_path(parent: str, key: str) -> str:
    path = key if parent == "$" else f"{parent}.{key}"
    return path


def _bounded_objects(payload: object) -> tuple[tuple[tuple[dict[str, object], str], ...], bool]:
    objects: list[tuple[dict[str, object], str]] = []
    stack: list[tuple[object, str, int]] = [(payload, "$", 0)]
    seen: set[int] = set()
    nodes = 0

    while stack:
        value, source_ref, depth = stack.pop()
        nodes += 1
        if (
            nodes > MAX_JSON_NODES
            or depth > MAX_JSON_DEPTH
            or len(source_ref) > MAX_SOURCE_REF_LENGTH
        ):
            return (), False
        if isinstance(value, str) and len(value) > MAX_JSON_STRING_LENGTH:
            return (), False
        if isinstance(value, list):
            sequence = cast(list[object], value)
            if len(sequence) > MAX_JSON_COLLECTION_ENTRIES:
                return (), False
            identity = id(sequence)
            if identity in seen:
                continue
            seen.add(identity)
            for index in range(len(sequence) - 1, -1, -1):
                child_ref = f"[{index}]" if source_ref == "$" else f"{source_ref}[{index}]"
                stack.append((sequence[index], child_ref, depth + 1))
            continue
        if not isinstance(value, dict):
            continue
        mapping = cast(dict[object, object], value)
        if len(mapping) > MAX_JSON_COLLECTION_ENTRIES:
            return (), False
        identity = id(mapping)
        if identity in seen:
            continue
        seen.add(identity)
        if any(not isinstance(key, str) or len(key) > MAX_JSON_STRING_LENGTH for key in mapping):
            return (), False
        typed_value = cast(dict[str, object], mapping)
        objects.append((typed_value, source_ref))
        entries = list(typed_value.items())
        for key, child in reversed(entries):
            stack.append((child, _child_path(source_ref, key), depth + 1))

    return tuple(objects), True


def json_within_limits(payload: object) -> bool:
    """Validate the shared hostile-JSON traversal limits without recursion."""

    _, complete = _bounded_objects(payload)
    return complete


def policy_status_from_payload(payload: object) -> PolicyStatus:
    objects, complete = _bounded_objects(payload)
    if not complete:
        return "unknown"
    for value, _ in objects:
        for key in ("status", "result"):
            candidate = _string_value(value.get(key))
            if candidate is None:
                continue
            normalized = candidate.casefold()
            if normalized in _GREEN_STATUSES:
                return "green"
            if normalized in _RED_STATUSES:
                return "red"
    return "unknown"


def _has_blocking_action(value: dict[str, object]) -> bool:
    return any(
        (candidate := _string_value(value.get(key))) is not None
        and candidate.casefold() in _BLOCK_ACTIONS
        for key in _BLOCK_ACTION_KEYS
    )


def has_policy_blocking_action(payload: object) -> bool:
    objects, complete = _bounded_objects(payload)
    return complete and any(_has_blocking_action(value) for value, _ in objects)


def extract_policy_blocking_findings(payload: object) -> tuple[PolicyBlockingFinding, ...]:
    objects, complete = _bounded_objects(payload)
    if not complete:
        return ()
    findings: list[PolicyBlockingFinding] = []
    for value, source_ref in objects:
        if not _has_blocking_action(value):
            continue
        gate = _first_string(value, ("gate",))
        vulnerability_gate = gate is not None and gate.casefold() in _VULNERABILITY_GATES
        if gate is not None and not vulnerability_gate:
            continue
        id_keys = (*_SPECIFIC_ID_KEYS, "id") if vulnerability_gate else _SPECIFIC_ID_KEYS
        vulnerability_id = normalize_vulnerability_id(_first_string(value, id_keys))
        if vulnerability_id is None:
            vulnerability_id = normalize_vulnerability_id(
                _first_string(value, _TRIGGER_ID_KEYS), search=True
            )
        package_name = _first_string(value, _PACKAGE_NAME_KEYS)
        package_version = _first_string(value, _PACKAGE_VERSION_KEYS)
        if vulnerability_id is None and (package_name is None or package_version is None):
            continue
        findings.append(
            PolicyBlockingFinding(
                source_ref=source_ref,
                vulnerability_id=vulnerability_id,
                package_name=package_name,
                package_version=package_version,
                gate=gate,
                trigger=_first_string(value, ("trigger",)),
                reason=_first_string(value, _REASON_KEYS),
            )
        )
    return tuple(findings)
