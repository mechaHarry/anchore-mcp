from datetime import datetime
from typing import Annotated, Literal
import unicodedata

from pydantic import AfterValidator, BaseModel, ConfigDict, Field


ApiVersion = Literal["v1", "v2"]
NonEmptyText = Annotated[str, Field(min_length=1)]


def validate_identifier_text(value: str) -> str:
    if not value.strip():
        raise ValueError("identifier must contain a non-whitespace character")
    if any(
        unicodedata.category(character) in {"Cc", "Cf", "Cs", "Zl", "Zp"} for character in value
    ):
        raise ValueError("identifier must not contain control characters")
    return value


IdentifierText = Annotated[
    str,
    Field(min_length=1, max_length=1024),
    AfterValidator(validate_identifier_text),
]


class ContractModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        allow_inf_nan=False,
        hide_input_in_errors=True,
    )


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
    digest: IdentifierText
    reference: IdentifierText | None = None
    repository: IdentifierText | None = None
    timestamp: datetime | None = None
