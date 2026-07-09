from pytest import MonkeyPatch

from anchore_mcp.domain.policy import PolicyBlockingFinding
from anchore_mcp.domain.vulnerabilities import (
    MAX_VULNERABILITY_ROWS,
    BlockingVulnerability,
    CorrelationEvidence,
    ImageLocation,
    NormalizedVulnerability,
    PolicyMetadata,
    correlate_blockers,
    extract_vulnerability_records,
)


def test_package_name_without_version_does_not_correlate() -> None:
    finding = PolicyBlockingFinding(
        package_name="openssl", package_version=None, source_ref="finding-1"
    )
    vulnerability = NormalizedVulnerability(
        vulnerability_id=None, package_name="openssl", package_version="1.0"
    )

    assert correlate_blockers((finding,), (vulnerability,)) == ()


def test_normalizes_wrappers_fix_versions_and_exact_path_evidence() -> None:
    payload = {
        "vulnerabilities": [
            {
                "vuln": " cve-2099-1234 ",
                "severity": " Critical ",
                "package_name": " openssl ",
                "package_version": " 1.0.1 ",
                "package_type": " deb ",
                "fix": [" 1.0.2 ", "", "1.0.3"],
                "path": "/direct/path",
                "locations": [
                    {"path": "/usr/lib/libssl.so", "type": "file"},
                    {"path": "/usr/lib/libssl.so", "type": "file"},
                    "/opt/openssl",
                ],
            }
        ]
    }

    assert extract_vulnerability_records(payload) == (
        NormalizedVulnerability(
            vulnerability_id="CVE-2099-1234",
            severity="Critical",
            package_name="openssl",
            package_version="1.0.1",
            package_type="deb",
            fixed_version="1.0.2, 1.0.3",
            image_locations=(
                ImageLocation("/direct/path"),
                ImageLocation("/usr/lib/libssl.so", kind="file"),
                ImageLocation("/opt/openssl"),
            ),
        ),
    )


def test_deduplicates_only_exact_records_and_preserves_distinct_paths() -> None:
    first = {
        "vuln": "CVE-2099-1234",
        "package_name": "openssl",
        "package_version": "1.0.1",
        "locations": [{"path": "/one", "type": "file"}],
    }
    second = {**first, "locations": [{"path": "/two", "type": "file"}]}

    assert extract_vulnerability_records([first, first.copy(), second]) == (
        NormalizedVulnerability(
            vulnerability_id="CVE-2099-1234",
            package_name="openssl",
            package_version="1.0.1",
            image_locations=(ImageLocation("/one", kind="file"),),
        ),
        NormalizedVulnerability(
            vulnerability_id="CVE-2099-1234",
            package_name="openssl",
            package_version="1.0.1",
            image_locations=(ImageLocation("/two", kind="file"),),
        ),
    )


def test_correlates_only_case_normalized_id_or_exact_package_identity() -> None:
    vulnerability = NormalizedVulnerability(
        vulnerability_id="CVE-2099-1234",
        severity="High",
        package_name="openssl",
        package_version="1.0.1",
        image_locations=(ImageLocation("/one", kind="file"),),
    )
    finding = PolicyBlockingFinding(
        vulnerability_id="cve-2099-1234",
        package_name="openssl",
        package_version="1.0.1",
        gate="vulnerabilities",
        trigger="package",
        reason="blocked",
        source_ref="findings[0]",
    )

    assert correlate_blockers((finding,), (vulnerability,)) == (
        BlockingVulnerability(
            vulnerability=vulnerability,
            policy=PolicyMetadata("vulnerabilities", "package", "blocked"),
            evidence=CorrelationEvidence(
                matched_by=("vulnerability_id", "package_identity"),
                policy_finding_ref="findings[0]",
            ),
        ),
    )
    assert (
        correlate_blockers(
            (
                PolicyBlockingFinding(vulnerability_id="CVE-2099-123", source_ref="prefix"),
                PolicyBlockingFinding(
                    package_name="OpenSSL", package_version="1.0.1", source_ref="case"
                ),
                PolicyBlockingFinding(
                    package_name="openssl", package_version="1.0", source_ref="version"
                ),
            ),
            (vulnerability,),
        )
        == ()
    )


def test_correlation_preserves_path_distinct_records() -> None:
    finding = PolicyBlockingFinding(vulnerability_id="CVE-2099-1234", source_ref="finding")
    records = (
        NormalizedVulnerability(
            vulnerability_id="CVE-2099-1234",
            image_locations=(ImageLocation("/one"),),
        ),
        NormalizedVulnerability(
            vulnerability_id="CVE-2099-1234",
            image_locations=(ImageLocation("/two"),),
        ),
    )

    correlated = correlate_blockers((finding,), records)

    assert len(correlated) == 2
    assert [item.vulnerability.image_locations[0].path for item in correlated] == ["/one", "/two"]


def test_hostile_vulnerability_collections_fail_closed() -> None:
    assert (
        extract_vulnerability_records(
            {
                "items": [
                    {"vuln": f"CVE-2099-{index:04d}"} for index in range(MAX_VULNERABILITY_ROWS + 1)
                ]
            }
        )
        == ()
    )
    assert (
        extract_vulnerability_records(
            {"items": [{"vuln": "CVE-2099-0001", "locations": ["/x"] * 257}]}
        )
        == ()
    )


def test_unsupported_ids_and_oversized_irrelevant_strings_fail_closed() -> None:
    assert extract_vulnerability_records({"results": [{"id": "scanner-row-1"}]}) == ()
    assert (
        extract_vulnerability_records(
            {"results": [{"id": "CVE-2099-0001", "ignored": "x" * 4_097}]}
        )
        == ()
    )


def test_severity_package_prefix_and_substring_never_correlate() -> None:
    vulnerability = NormalizedVulnerability(
        vulnerability_id="CVE-2099-1234",
        severity="Critical",
        package_name="libssl3",
        package_version="3.0.1",
    )
    findings = (
        PolicyBlockingFinding(vulnerability_id="CVE-2099-12345", source_ref="id"),
        PolicyBlockingFinding(
            package_name="libssl", package_version="3.0.1", source_ref="package-prefix"
        ),
        PolicyBlockingFinding(
            package_name="libssl3", package_version="3.0", source_ref="version-prefix"
        ),
    )

    assert correlate_blockers(findings, (vulnerability,)) == ()


def test_invalid_location_shape_fails_closed_and_unknown_kind_is_preserved_safely() -> None:
    assert (
        extract_vulnerability_records(
            {"items": [{"vuln": "CVE-2099-0001", "locations": {"path": "/x"}}]}
        )
        == ()
    )
    assert extract_vulnerability_records(
        {
            "items": [
                {
                    "vuln": "CVE-2099-0001",
                    "fix": "1.2.3",
                    "locations": [{"path": "/x", "kind": "symlink"}],
                }
            ]
        }
    ) == (
        NormalizedVulnerability(
            vulnerability_id="CVE-2099-0001",
            fixed_version="1.2.3",
            image_locations=(ImageLocation("/x"),),
        ),
    )


def test_duplicate_matches_merge_exact_evidence_without_duplicating_record() -> None:
    vulnerability = NormalizedVulnerability(
        vulnerability_id="CVE-2099-1234",
        package_name="openssl",
        package_version="1.0.1",
    )
    findings = (
        PolicyBlockingFinding(vulnerability_id="CVE-2099-1234", source_ref="first"),
        PolicyBlockingFinding(package_name="openssl", package_version="1.0.1", source_ref="second"),
    )

    correlated = correlate_blockers(findings, (vulnerability, vulnerability))

    assert len(correlated) == 1
    assert correlated[0].evidence == CorrelationEvidence(
        matched_by=("vulnerability_id", "package_identity"),
        policy_finding_ref="first",
    )


def test_correlation_normalizes_each_identifier_once_and_uses_exact_indexes(
    monkeypatch: MonkeyPatch,
) -> None:
    from anchore_mcp.domain import vulnerabilities as module

    original = module.normalize_vulnerability_id
    calls = 0

    def counted(value: str | None, *, search: bool = False) -> str | None:
        nonlocal calls
        calls += 1
        return original(value, search=search)

    monkeypatch.setattr(module, "normalize_vulnerability_id", counted)
    findings = tuple(
        PolicyBlockingFinding(vulnerability_id=f"CVE-2099-{index + 10_000}", source_ref=str(index))
        for index in range(2_000)
    )
    records = tuple(
        NormalizedVulnerability(vulnerability_id=f"CVE-2098-{index + 10_000}")
        for index in range(1_000)
    )

    assert correlate_blockers(findings, records) == ()
    assert calls <= len(findings) + len(records)


def test_skewed_duplicate_matches_expand_each_index_bucket_once(
    monkeypatch: MonkeyPatch,
) -> None:
    original_hash = NormalizedVulnerability.__hash__
    assert original_hash is not None
    hash_calls = 0

    def counted_hash(value: NormalizedVulnerability) -> int:
        nonlocal hash_calls
        hash_calls += 1
        return original_hash(value)

    monkeypatch.setattr(NormalizedVulnerability, "__hash__", counted_hash)
    findings = tuple(
        PolicyBlockingFinding(vulnerability_id="CVE-2099-1234", source_ref=str(index))
        for index in range(2_000)
    )
    records = tuple(
        NormalizedVulnerability(
            vulnerability_id="CVE-2099-1234",
            image_locations=(ImageLocation(f"/path/{index}"),),
        )
        for index in range(1_000)
    )

    correlated = correlate_blockers(findings, records)

    assert len(correlated) == len(records)
    assert all(item.evidence.policy_finding_ref == "0" for item in correlated)
    assert hash_calls < 50_000
