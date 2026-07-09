import json
import math
from datetime import UTC, datetime

from pydantic import JsonValue, ValidationError
import pytest

from anchore_mcp.models.common import DeploymentContext, EnumerationState, SelectedImage
from anchore_mcp.models.results import (
    ConnectionInfoResult,
    ImageDetailResult,
    ImagePolicyCheckResult,
    ImageSbomResult,
    ImageVulnerabilitiesResult,
    ListImagesResult,
    PolicyBlockingVulnerabilitiesResult,
    RemediationHandoffResult,
)


def context() -> DeploymentContext:
    return DeploymentContext(
        base_url="https://anchore.example", account="team", api_version="v2", action="list"
    )


def selected() -> SelectedImage:
    return SelectedImage(digest="sha256:abc", reference="registry.example/team/app:latest")


def complete() -> EnumerationState:
    return EnumerationState(complete=True, pages_fetched=1)


def test_common_models_validate_and_serialize_without_secret_fields() -> None:
    deployment = context()
    enumeration = complete()
    image = SelectedImage(
        digest="sha256:abc",
        reference="registry.example/team/app:latest",
        repository="team/app",
        timestamp=datetime(2026, 7, 9, tzinfo=UTC),
    )

    payload = {
        "deployment": deployment.model_dump(mode="json"),
        "enumeration": enumeration.model_dump(mode="json"),
        "image": image.model_dump(mode="json"),
    }
    encoded = json.dumps(payload)

    assert payload["deployment"]["api_version"] == "v2"
    assert payload["enumeration"] == {"complete": True, "pages_fetched": 1, "reason": None}
    assert "token" not in encoded.casefold()
    assert "password" not in encoded.casefold()
    assert "authorization" not in encoded.casefold()


def test_all_capability_results_have_context_and_warnings() -> None:
    evidence: JsonValue = {"items": []}
    results = [
        ConnectionInfoResult(context=context(), warnings=[], configured=True),
        ListImagesResult(
            context=context(), warnings=[], images=[], enumeration=complete(), size_bytes=12
        ),
        ImageVulnerabilitiesResult(
            context=context(),
            warnings=[],
            selected_image=selected(),
            selection=complete(),
            vulnerabilities=evidence,
            size_bytes=12,
        ),
        ImageSbomResult(
            context=context(),
            warnings=[],
            selected_image=selected(),
            selection=complete(),
            format="spdx",
            sbom=evidence,
            size_bytes=12,
        ),
        ImagePolicyCheckResult(
            context=context(),
            warnings=[],
            selected_image=selected(),
            selection=complete(),
            policy=evidence,
            size_bytes=12,
        ),
        PolicyBlockingVulnerabilitiesResult(
            context=context(),
            warnings=[],
            selected_image=selected(),
            selection=complete(),
            outcome="blocked",
            blockers=[],
        ),
        ImageDetailResult(
            context=context(),
            warnings=[],
            selected_image=selected(),
            selection=complete(),
            detail=evidence,
            size_bytes=12,
        ),
        RemediationHandoffResult(
            context=context(),
            warnings=[],
            handoffVersion="2.0.0",
            generatedAt=datetime(2026, 7, 9, tzinfo=UTC),
            imageDigest="sha256:abc",
            selection=complete(),
            evidence={"detail": evidence},
            evidence_size_bytes={"detail": 12},
            totalSizeBytes=12,
        ),
    ]

    for result in results:
        dumped = result.model_dump(mode="json", by_alias=True)
        assert dumped["context"]["base_url"] == "https://anchore.example"
        assert dumped["warnings"] == []
        json.dumps(dumped)


def test_handoff_uses_public_camel_case_aliases() -> None:
    result = RemediationHandoffResult(
        context=context(),
        warnings=[],
        handoffVersion="2.0.0",
        generatedAt=datetime(2026, 7, 9, tzinfo=UTC),
        imageDigest="sha256:abc",
        selection=complete(),
        evidence={},
        evidence_size_bytes={},
        totalSizeBytes=0,
    )

    dumped = result.model_dump(mode="json", by_alias=True)
    schema = RemediationHandoffResult.model_json_schema(by_alias=True)

    assert dumped["handoffVersion"] == "2.0.0"
    assert dumped["generatedAt"] == "2026-07-09T00:00:00Z"
    assert dumped["imageDigest"] == "sha256:abc"
    assert dumped["totalSizeBytes"] == 0
    assert {"handoffVersion", "generatedAt", "imageDigest", "totalSizeBytes"} <= set(
        schema["properties"]
    )


def test_result_schema_contains_no_secret_bearing_field_names() -> None:
    models = (
        ConnectionInfoResult,
        ListImagesResult,
        ImageVulnerabilitiesResult,
        ImageSbomResult,
        ImagePolicyCheckResult,
        PolicyBlockingVulnerabilitiesResult,
        ImageDetailResult,
        RemediationHandoffResult,
    )

    schemas = json.dumps(
        [model.model_json_schema(by_alias=True, mode="serialization") for model in models]
    ).casefold()

    assert "token" not in schemas
    assert "password" not in schemas
    assert "authorization" not in schemas


def test_list_schema_reports_payload_size_and_enumeration_completeness() -> None:
    schema = ListImagesResult.model_json_schema()

    assert {"images", "enumeration", "size_bytes"} <= set(schema["properties"])
    assert {"complete", "pages_fetched"} <= set(schema["$defs"]["EnumerationState"]["properties"])


@pytest.mark.parametrize("field", ["digest", "reference", "repository"])
@pytest.mark.parametrize("invalid", [" ", "line\nbreak", "nul\x00byte"])
def test_selected_image_identifiers_reject_blank_or_control_text(field: str, invalid: str) -> None:
    values = {
        "digest": "sha256:abc",
        "reference": "registry.example/team/app:tag",
        "repository": "team/app",
    }
    values[field] = invalid

    with pytest.raises(ValidationError):
        SelectedImage.model_validate(values)


@pytest.mark.parametrize("invalid", [" ", "line\nbreak", "nul\x00byte"])
def test_handoff_image_digest_rejects_blank_or_control_text(invalid: str) -> None:
    with pytest.raises(ValidationError):
        RemediationHandoffResult(
            context=context(),
            warnings=[],
            handoffVersion="2.0.0",
            generatedAt=datetime(2026, 7, 9, tzinfo=UTC),
            imageDigest=invalid,
            selection=complete(),
            evidence={},
            evidence_size_bytes={},
            totalSizeBytes=0,
        )


@pytest.mark.parametrize("non_finite", [math.nan, math.inf, -math.inf])
def test_nested_raw_json_rejects_non_finite_floats(non_finite: float) -> None:
    with pytest.raises(ValidationError):
        ImageDetailResult(
            context=context(),
            warnings=[],
            selected_image=selected(),
            selection=complete(),
            detail={"nested": [non_finite]},
            size_bytes=12,
        )
