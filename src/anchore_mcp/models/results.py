from datetime import datetime
from typing import Annotated, Literal, cast

from pydantic import (
    ConfigDict,
    Field,
    JsonValue,
    SerializerFunctionWrapHandler,
    model_serializer,
)

from anchore_mcp.models.common import (
    ContractModel,
    DeploymentContext,
    EnumerationState,
    IdentifierText,
    SelectedImage,
    ApiVersion,
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


class HandoffEvidenceEntry(ContractModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    data: JsonValue
    size_bytes: ByteCount = Field(alias="sizeBytes")


class HandoffDeployment(ContractModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    base_url: str = Field(alias="baseUrl")
    account: str | None = None
    api_version: ApiVersion = Field(alias="apiVersion")


type HandoffEvidenceKey = Literal["detail", "vulnerabilities", "policy"]


class HandoffEvidence(ContractModel):
    detail: HandoffEvidenceEntry
    vulnerabilities: HandoffEvidenceEntry
    policy: HandoffEvidenceEntry | None = None

    @model_serializer(mode="wrap")
    def serialize_without_absent_policy(
        self, handler: SerializerFunctionWrapHandler
    ) -> dict[str, object]:
        serialized = cast(dict[str, object], handler(self))
        if self.policy is None:
            serialized.pop("policy", None)
        return serialized


class RemediationHandoffResult(CapabilityResult):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    handoff_version: Literal["2.0.0"] = Field(alias="handoffVersion")
    generated_at: datetime = Field(alias="generatedAt")
    deployment: HandoffDeployment
    image_digest: IdentifierText = Field(alias="imageDigest")
    selection: EnumerationState
    evidence: HandoffEvidence
    total_size_bytes: ByteCount = Field(alias="totalSizeBytes")
