import httpx
import pytest

from anchore_mcp.anchore.http import MAX_RESPONSE_BYTES
from anchore_mcp.models.locators import DigestLocator
from anchore_mcp.tools.image_policy_check import anchore_image_policy_check
from task12_support import RoutingHttp, connection, context


@pytest.mark.asyncio
async def test_policy_check_keeps_locator_and_policy_context_separate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = "/v2/images/sha256%3Aabc/check"
    http = RoutingHttp({path: [({"status": "pass", "raw": "private-evidence"}, 31)]})
    monkeypatch.setattr("anchore_mcp.tools.image_policy_check.load_connection", connection)

    result = await anchore_image_policy_check(
        context(http),
        DigestLocator(kind="digest", digest="sha256:abc"),
        tag="registry.example/team/app:1",
        base_digest="sha256:base",
    )

    assert http.calls == [
        (
            path,
            httpx.QueryParams({"tag": "registry.example/team/app:1", "base_digest": "sha256:base"}),
            MAX_RESPONSE_BYTES,
        )
    ]
    assert result.structured_content is not None
    assert result.structured_content["policy"]["raw"] == "private-evidence"
    assert result.structured_content["size_bytes"] == 31
    assert "private-evidence" not in result.content[0].text  # type: ignore[union-attr]
