from mcp.types import TextContent
import pytest

from anchore_mcp.anchore.http import MAX_RESPONSE_BYTES
from anchore_mcp.models.locators import DigestLocator
from anchore_mcp.tools.image_vulnerabilities import anchore_image_vulnerabilities
from task12_support import RoutingHttp, connection, context


@pytest.mark.asyncio
async def test_vulnerabilities_use_exact_route_size_and_structured_only_raw_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence = {"items": [{"owner": "person@example.test", "detail": "private-evidence"}]}
    http = RoutingHttp({"/v2/images/sha256%3Aabc/vuln/all": [(evidence, 37)]})
    monkeypatch.setattr("anchore_mcp.tools.image_vulnerabilities.load_connection", connection)

    result = await anchore_image_vulnerabilities(
        context(http), DigestLocator(kind="digest", digest="sha256:abc")
    )

    assert http.calls == [
        ("/v2/images/sha256%3Aabc/vuln/all", http.calls[0][1], MAX_RESPONSE_BYTES)
    ]
    assert result.structured_content is not None
    assert result.structured_content["vulnerabilities"] == evidence
    assert result.structured_content["size_bytes"] == 37
    assert result.structured_content["selection"] == {
        "complete": True,
        "pages_fetched": 0,
        "reason": None,
    }
    assert isinstance(result.content[0], TextContent)
    assert "private-evidence" not in result.content[0].text
    assert "person@example.test" not in result.content[0].text
