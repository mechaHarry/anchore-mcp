from fastmcp import Context
from fastmcp.exceptions import ToolError
import pytest

from anchore_mcp.models.locators import DigestLocator
from anchore_mcp.tools.remediation_handoff import anchore_remediation_handoff
from task12_support import RoutingHttp, connection, context


@pytest.mark.asyncio
async def test_handoff_v2_keeps_raw_evidence_out_of_text(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    http = RoutingHttp(
        {
            "/v2/images/sha256%3Aabc": [({"detail": "private-detail"}, 11)],
            "/v2/images/sha256%3Aabc/vuln/all": [({"items": ["private-vuln"]}, 13)],
            "/v2/images/sha256%3Aabc/check": [({"status": "pass", "raw": "private"}, 17)],
        }
    )
    monkeypatch.setattr("anchore_mcp.tools.remediation_handoff.load_connection", connection)

    result = await anchore_remediation_handoff(
        context(http), DigestLocator(kind="digest", digest="sha256:abc")
    )

    assert result.structured_content is not None
    assert result.structured_content["handoffVersion"] == "2.0.0"
    assert result.structured_content["totalSizeBytes"] == 41
    assert set(result.structured_content["evidence"]) == {
        "detail",
        "vulnerabilities",
        "policy",
    }
    text = result.content[0].text  # type: ignore[union-attr]
    assert "private-detail" not in text
    assert "private-vuln" not in text


@pytest.mark.asyncio
async def test_handoff_can_omit_policy_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    http = RoutingHttp(
        {
            "/v2/images/sha256%3Aabc": [({"detail": True}, 3)],
            "/v2/images/sha256%3Aabc/vuln/all": [({"items": []}, 5)],
        }
    )
    monkeypatch.setattr("anchore_mcp.tools.remediation_handoff.load_connection", connection)

    result = await anchore_remediation_handoff(
        context(http),
        DigestLocator(kind="digest", digest="sha256:abc"),
        include_policy_check=False,
    )

    assert result.structured_content is not None
    assert set(result.structured_content["evidence"]) == {"detail", "vulnerabilities"}
    assert result.structured_content["totalSizeBytes"] == 8
    assert all(not call[0].endswith("/check") for call in http.calls)


@pytest.mark.asyncio
async def test_all_task12_adapters_missing_config_are_safe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from anchore_mcp.tools.image_detail import anchore_image_detail
    from anchore_mcp.tools.image_policy_check import anchore_image_policy_check
    from anchore_mcp.tools.image_sbom import anchore_image_sbom
    from anchore_mcp.tools.image_vulnerabilities import anchore_image_vulnerabilities
    from anchore_mcp.tools.policy_blocking_vulnerabilities import (
        anchore_policy_blocking_vulnerabilities,
    )

    monkeypatch.delenv("ANCHORE_URL", raising=False)
    monkeypatch.delenv("ANCHORE_TOKEN", raising=False)
    locator = DigestLocator(kind="digest", digest="sha256:abc")
    empty_context = Context  # keep imports statically exercised
    del empty_context
    adapters = (
        lambda: anchore_image_vulnerabilities(context(RoutingHttp({})), locator),
        lambda: anchore_image_sbom(context(RoutingHttp({})), locator, format="normal"),
        lambda: anchore_image_policy_check(context(RoutingHttp({})), locator),
        lambda: anchore_image_detail(context(RoutingHttp({})), locator),
        lambda: anchore_policy_blocking_vulnerabilities(context(RoutingHttp({})), locator),
        lambda: anchore_remediation_handoff(context(RoutingHttp({})), locator),
    )
    for invoke in adapters:
        with pytest.raises(ToolError) as raised:
            await invoke()
        assert "token" not in str(raised.value).casefold()
        assert "traceback" not in str(raised.value).casefold()
