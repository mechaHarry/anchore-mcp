from datetime import datetime
from typing import Annotated, Literal

from pydantic import ConfigDict, Field, JsonValue

from anchore_mcp.models.common import (
    ContractModel,
    DeploymentContext,
    EnumerationState,
    SelectedImage,
)


ByteCount = Annotated[int, Field(ge=0)]


class CapabilityResult(ContractModel):
    context: DeploymentContext
    warnings: list[str] = Field(default_factory=list)


class SelectedCapabilityResult(CapabilityResult):
    selected_image: SelectedImage
    selection: EnumerationState


class ConnectionInfoResult(CapabilityResult):
    configured: bool


class ListImagesResult(CapabilityResult):
    images: list[JsonValue]
    enumeration: EnumerationState
    size_bytes: ByteCount


class ImageVulnerabilitiesResult(SelectedCapabilityResult):
    vulnerabilities: JsonValue
    size_bytes: ByteCount


class ImageSbomResult(SelectedCapabilityResult):
    format: Literal["normal", "spdx", "cyclonedx"]
    sbom: JsonValue
    size_bytes: ByteCount


class ImagePolicyCheckResult(SelectedCapabilityResult):
    policy: JsonValue
    size_bytes: ByteCount


class PolicyBlockingVulnerabilitiesResult(SelectedCapabilityResult):
    outcome: Literal["already_green", "blocked"]
    blockers: list[JsonValue]


class ImageDetailResult(SelectedCapabilityResult):
    detail: JsonValue
    size_bytes: ByteCount


class RemediationHandoffResult(CapabilityResult):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    handoff_version: Literal["2.0.0"] = Field(alias="handoffVersion")
    generated_at: datetime = Field(alias="generatedAt")
    image_digest: str = Field(alias="imageDigest", min_length=1)
    selection: EnumerationState
    evidence: dict[str, JsonValue]
    evidence_size_bytes: dict[str, ByteCount]
    total_size_bytes: ByteCount = Field(alias="totalSizeBytes")
