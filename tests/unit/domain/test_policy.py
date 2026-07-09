import pytest

from anchore_mcp.domain.policy import (
    MAX_JSON_COLLECTION_ENTRIES,
    MAX_JSON_DEPTH,
    MAX_JSON_NODES,
    MAX_JSON_STRING_LENGTH,
    PolicyBlockingFinding,
    extract_policy_blocking_findings,
    has_policy_blocking_action,
    policy_status_from_payload,
)
from anchore_mcp.errors import EnumerationIncompleteError


def test_generic_id_is_not_vulnerability_evidence() -> None:
    payload = {"gate": "dockerfile", "id": "CVE-2099-0001", "action": "STOP"}

    assert extract_policy_blocking_findings(payload) == ()


def test_extracts_normalized_blocker_and_supported_trigger_identifier() -> None:
    payload = {
        "status": "failed",
        "findings": [
            {
                "gate": " Vulnerabilities ",
                "action": "STOP",
                "trigger_id": "prefix ghsa-abcd-1234-efgh+package",
                "package_name": " openssl ",
                "installed_version": " 1.0.1 ",
                "message": " blocked by policy ",
            }
        ],
    }

    assert policy_status_from_payload(payload) == "red"
    assert has_policy_blocking_action(payload) is True
    assert extract_policy_blocking_findings(payload) == (
        PolicyBlockingFinding(
            vulnerability_id="GHSA-ABCD-1234-EFGH",
            package_name="openssl",
            package_version="1.0.1",
            gate="Vulnerabilities",
            reason="blocked by policy",
            source_ref="findings[0]",
        ),
    )


def test_generic_id_requires_vulnerability_gate_and_supported_identifier() -> None:
    assert extract_policy_blocking_findings(
        {"gate": "vuln", "id": "cve-2099-0001", "result": "blocked"}
    ) == (PolicyBlockingFinding(vulnerability_id="CVE-2099-0001", gate="vuln", source_ref="$"),)
    assert (
        extract_policy_blocking_findings(
            {"gate": "vuln", "id": "policy-row-1", "result": "blocked"}
        )
        == ()
    )


def test_only_actual_blocking_fields_and_supported_states_count() -> None:
    assert extract_policy_blocking_findings({"policy_action": "stop", "cve": "CVE-2099-0002"}) == ()
    assert policy_status_from_payload({"outcome": "red"}) == "unknown"
    assert policy_status_from_payload({"result": {"status": "allowed"}}) == "green"
    assert has_policy_blocking_action({"nested": {"status": "denied"}}) is True


def test_policy_findings_at_distinct_paths_preserve_source_evidence() -> None:
    row = {"action": "stop", "cve": "CVE-2099-0003"}

    assert extract_policy_blocking_findings([row, row.copy()]) == (
        PolicyBlockingFinding(vulnerability_id="CVE-2099-0003", source_ref="[0]"),
        PolicyBlockingFinding(vulnerability_id="CVE-2099-0003", source_ref="[1]"),
    )


def test_hostile_policy_json_limits_fail_closed_without_recursion() -> None:
    too_deep: object = {"action": "stop", "cve": "CVE-2099-0004"}
    for _ in range(MAX_JSON_DEPTH + 1):
        too_deep = {"nested": too_deep}

    for function in (
        policy_status_from_payload,
        extract_policy_blocking_findings,
        has_policy_blocking_action,
    ):
        with pytest.raises(EnumerationIncompleteError):
            function(too_deep)
    with pytest.raises(EnumerationIncompleteError):
        extract_policy_blocking_findings([None] * (MAX_JSON_COLLECTION_ENTRIES + 1))
    node_heavy = [[None] * 10 for _ in range((MAX_JSON_NODES // 11) + 1)]
    with pytest.raises(EnumerationIncompleteError):
        extract_policy_blocking_findings(node_heavy)
    oversized_red = {
        "status": "fail",
        "action": "stop",
        "cve": "CVE-2099-0005",
        "noise": "x" * (MAX_JSON_STRING_LENGTH + 1),
    }
    for function in (
        policy_status_from_payload,
        extract_policy_blocking_findings,
        has_policy_blocking_action,
    ):
        with pytest.raises(EnumerationIncompleteError):
            function(oversized_red)


def test_cycles_are_bounded_and_supported_advisories_are_normalized() -> None:
    payload: dict[str, object] = {
        "action": "blocked",
        "vulnerability_id": "rhsa-2099:42",
    }
    payload["cycle"] = payload

    assert extract_policy_blocking_findings(payload) == (
        PolicyBlockingFinding(vulnerability_id="RHSA-2099:42", source_ref="$"),
    )


def test_unsupported_or_partial_vulnerability_identifiers_are_not_evidence() -> None:
    payload = [
        {"action": "stop", "cve": "CVE-2099-12"},
        {"action": "stop", "vulnerability_id": "prefix-CVE-2099-1234"},
        {"action": "stop", "trigger_id": "not-an-advisory"},
        {"action": "stop", "trigger_id": "fakeCVE-2099-1234suffix"},
        {"action": "stop", "trigger_id": "prefix_GHSA-abcd-1234-efgh_suffix"},
    ]

    assert extract_policy_blocking_findings(payload) == ()


def test_source_reference_length_limit_fails_closed_before_depth_limit() -> None:
    payload: object = {"action": "stop", "cve": "CVE-2099-1234"}
    for index in range(28):
        payload = {f"key-{index}-{'x' * 294}": payload}

    with pytest.raises(EnumerationIncompleteError):
        extract_policy_blocking_findings(payload)


def test_boolean_fields_are_not_strings_but_finite_numeric_package_versions_are_exact() -> None:
    assert policy_status_from_payload({"status": True}) == "unknown"
    assert extract_policy_blocking_findings(
        {
            "action": "stop",
            "vulnerability_id": "CVE-2099-1234",
            "package_name": "sample",
            "package_version": 2.0,
        }
    ) == (
        PolicyBlockingFinding(
            vulnerability_id="CVE-2099-1234",
            package_name="sample",
            package_version="2",
            source_ref="$",
        ),
    )
