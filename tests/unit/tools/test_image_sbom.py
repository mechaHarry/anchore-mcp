import pytest
from fastmcp.exceptions import ToolError

from anchore_mcp.models.locators import DigestLocator
from anchore_mcp.tools.image_sbom import (
    DEFAULT_SBOM_MAX_RESPONSE_BYTES,
    MAX_SBOM_RESPONSE_BYTES,
    anchore_image_sbom,
)
from task12_support import RoutingHttp, connection, context


@pytest.mark.parametrize(
    ("format_name", "wire_name"),
    [("normal", "native-json"), ("spdx", "spdx-json"), ("cyclonedx", "cyclonedx-json")],
)
@pytest.mark.asyncio
async def test_sbom_maps_format_and_uses_default_cap(
    monkeypatch: pytest.MonkeyPatch,
    format_name: str,
    wire_name: str,
) -> None:
    path = f"/v2/images/sha256%3Aabc/sboms/{wire_name}"
    http = RoutingHttp({path: [({"format": wire_name}, 29)]})
    monkeypatch.setattr("anchore_mcp.tools.image_sbom.load_connection", connection)

    result = await anchore_image_sbom(
        context(http),
        DigestLocator(kind="digest", digest="sha256:abc"),
        format=format_name,  # type: ignore[arg-type]
    )

    assert http.calls[0][0] == path
    assert http.calls[0][2] == DEFAULT_SBOM_MAX_RESPONSE_BYTES == 20_000_000
    assert result.structured_content is not None
    assert result.structured_content["format"] == format_name
    assert result.structured_content["size_bytes"] == 29


@pytest.mark.asyncio
async def test_sbom_accepts_maximum_cap_and_rejects_out_of_range(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = "/v2/images/sha256%3Aabc/sboms/native-json"
    http = RoutingHttp({path: [({}, 2)]})
    monkeypatch.setattr("anchore_mcp.tools.image_sbom.load_connection", connection)
    locator = DigestLocator(kind="digest", digest="sha256:abc")

    await anchore_image_sbom(
        context(http), locator, format="normal", max_response_bytes=MAX_SBOM_RESPONSE_BYTES
    )
    assert http.calls[0][2] == 100_000_000

    with pytest.raises(ToolError, match="between 1 and 100000000"):
        await anchore_image_sbom(
            context(RoutingHttp({})),
            locator,
            format="normal",
            max_response_bytes=100_000_001,
        )
