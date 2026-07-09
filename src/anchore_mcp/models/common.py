from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field


ApiVersion = Literal["v1", "v2"]
NonEmptyText = Annotated[str, Field(min_length=1)]


class ContractModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class DeploymentContext(ContractModel):
    base_url: NonEmptyText
    account: NonEmptyText | None = None
    api_version: ApiVersion
    action: NonEmptyText


class EnumerationState(ContractModel):
    complete: bool
    pages_fetched: Annotated[int, Field(ge=0)]
    reason: NonEmptyText | None = None


class SelectedImage(ContractModel):
    digest: NonEmptyText
    reference: NonEmptyText | None = None
    repository: NonEmptyText | None = None
    timestamp: datetime | None = None
