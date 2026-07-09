from typing import Annotated, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, Field

from anchore_mcp.models.common import validate_identifier_text


LocatorText = Annotated[str, AfterValidator(validate_identifier_text)]


class LocatorModel(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)


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
