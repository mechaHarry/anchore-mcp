from typing import Annotated, Literal
import unicodedata

from pydantic import AfterValidator, BaseModel, ConfigDict, Field


def _reject_blank_or_control_characters(value: str) -> str:
    if not value.strip():
        raise ValueError("value must contain a non-whitespace character")
    if any(unicodedata.category(character) == "Cc" for character in value):
        raise ValueError("value must not contain control characters")
    return value


LocatorText = Annotated[str, AfterValidator(_reject_blank_or_control_characters)]


class LocatorModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class DigestLocator(LocatorModel):
    kind: Literal["digest"]
    digest: Annotated[LocatorText, Field(min_length=1, max_length=1024)]


class ReferenceLocator(LocatorModel):
    kind: Literal["reference"]
    reference: Annotated[LocatorText, Field(min_length=1, max_length=1024)]


class RepositoryLocator(LocatorModel):
    kind: Literal["repository"]
    registry: Annotated[LocatorText, Field(min_length=1, max_length=255)]
    repository: Annotated[LocatorText, Field(min_length=1, max_length=1024)]


ImageLocator = Annotated[DigestLocator | ReferenceLocator, Field(discriminator="kind")]
PolicyImageLocator = Annotated[
    DigestLocator | ReferenceLocator | RepositoryLocator,
    Field(discriminator="kind"),
]
