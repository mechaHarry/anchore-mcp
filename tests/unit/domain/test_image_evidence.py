import pytest

from anchore_mcp.domain.images import (
    MAX_NORMALIZED_IMAGE_REFERENCES_PER_ROW,
    digest_from_image_row,
    extract_reference_evidence,
    validate_full_image_reference,
)


def test_validates_registry_qualified_references_with_ports_and_ipv6() -> None:
    assert validate_full_image_reference("registry.example:5000/team/app:release") == (
        "registry.example:5000/team/app:release"
    )
    assert validate_full_image_reference("[2001:db8::1]:5000/team/app:release") == (
        "[2001:db8::1]:5000/team/app:release"
    )
    for invalid in (
        "nginx:latest",
        "registry.example:5000/team/app",
        "registry.example/team/app:",
        "[::::]/team/app:1",
        "registry.example/bad:repo:1",
        "registry.example//team/app:1",
    ):
        with pytest.raises(ValueError):
            validate_full_image_reference(invalid)


def test_extracts_direct_and_coherent_nested_reference_evidence() -> None:
    evidence = extract_reference_evidence(
        {
            "full_tag": "registry.example/team/app:1",
            "imageTag": "registry.example/team/app:2",
            "tag": "latest",
            "tags": ["registry.example/team/app:3", "not-qualified"],
            "image_detail": [
                {"fulltag": "registry.example/team/app:4"},
                {
                    "registry": "registry.example:5000",
                    "repo": "team/app",
                    "tag": "release",
                },
            ],
            "imageDetail": {
                "registry": "[2001:db8::1]:5000",
                "repository": "team/other",
                "tag": "2",
            },
        }
    )

    assert evidence.complete is True
    assert evidence.reason is None
    assert evidence.references == (
        "registry.example/team/app:1",
        "registry.example/team/app:2",
        "registry.example/team/app:3",
        "registry.example/team/app:4",
        "registry.example:5000/team/app:release",
        "[2001:db8::1]:5000/team/other:2",
    )


def test_never_synthesizes_across_objects_or_conflicting_aliases() -> None:
    evidence = extract_reference_evidence(
        {
            "image_detail": [
                {"registry": "registry.example", "repo": "team/app"},
                {"tag": "1"},
                {
                    "registry": "registry.example",
                    "repo": "team/one",
                    "repository": "team/two",
                    "tag": "1",
                },
                {
                    "registry": "registry.example/library",
                    "repository": "nginx",
                    "tag": "1",
                },
            ]
        }
    )

    assert evidence.references == ()
    assert evidence.complete is True


def test_evidence_overflow_never_becomes_no_match() -> None:
    row = {
        "image_detail": [{"fulltag": f"registry.example/team/app:{index}"} for index in range(65)]
    }

    evidence = extract_reference_evidence(row)

    assert evidence.complete is False
    assert evidence.reason == "detail_entry_limit"


@pytest.mark.parametrize(
    ("row", "reason"),
    [
        (
            {"tags": [f"registry.example/team/app:{index}" for index in range(65)]},
            "tag_entry_limit",
        ),
        (
            {
                "tags": [
                    f"registry.example/team/app:{index}"
                    for index in range(MAX_NORMALIZED_IMAGE_REFERENCES_PER_ROW + 1)
                ]
            },
            "reference_limit",
        ),
        (
            {"full_tag": f"registry.example/team/app:{'x' * 1024}"},
            "string_length_limit",
        ),
        (
            {
                "full_tag": "registry.example/team/app:exact",
                "image_detail": [
                    {"tags": [{"ignored": True} for _ in range(64)]} for _ in range(4)
                ],
            },
            "scan_limit",
        ),
    ],
)
def test_reports_exact_evidence_limit_reason(row: object, reason: str) -> None:
    evidence = extract_reference_evidence(row)

    assert evidence.complete is False
    assert evidence.reason == reason
    assert len(evidence.references) <= MAX_NORMALIZED_IMAGE_REFERENCES_PER_ROW


def test_digest_aliases_are_trimmed_in_precedence_order() -> None:
    assert digest_from_image_row({"imageDigest": " ", "image_digest": " sha256:a "}) == "sha256:a"
    assert digest_from_image_row({"digest": "sha256:b"}) == "sha256:b"
    assert digest_from_image_row(None) is None
