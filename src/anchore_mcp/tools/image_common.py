"""Shared typed image-locator resolution for thin tool adapters."""

from anchore_mcp.anchore.pagination import JsonHttpClient
from anchore_mcp.config import AnchoreConnection
from anchore_mcp.domain.images import validate_full_image_reference
from anchore_mcp.domain.resolution import (
    Disambiguation,
    Incomplete,
    Resolved,
    resolve_image_reference,
)
from anchore_mcp.errors import EnumerationIncompleteError, TrustEvidenceError
from anchore_mcp.models.common import EnumerationState, SelectedImage
from anchore_mcp.models.locators import DigestLocator, ImageLocator


async def resolve_image_locator(
    client: JsonHttpClient,
    connection: AnchoreConnection,
    locator: ImageLocator,
) -> tuple[SelectedImage, EnumerationState]:
    """Resolve one typed locator and retain truthful enumeration state."""

    if isinstance(locator, DigestLocator):
        return (
            SelectedImage(digest=locator.digest.strip()),
            EnumerationState(complete=True, pages_fetched=0),
        )
    try:
        reference = validate_full_image_reference(locator.reference)
    except ValueError as error:
        raise TrustEvidenceError(str(error)) from None
    resolution = await resolve_image_reference(client, connection, reference)
    if isinstance(resolution, Incomplete):
        raise EnumerationIncompleteError(resolution.reason)
    if isinstance(resolution, Disambiguation):
        raise TrustEvidenceError("Image reference matched multiple analyzed image digests")
    if not isinstance(resolution, Resolved):
        raise TrustEvidenceError("No analyzed image matched the requested image reference")
    return (
        SelectedImage(
            digest=resolution.digest,
            reference=reference,
            repository=reference.rpartition(":")[0],
        ),
        EnumerationState(complete=True, pages_fetched=resolution.pages_fetched),
    )
