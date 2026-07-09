from fastmcp import Client
from fastmcp.exceptions import ToolError
import pytest

from anchore_mcp.server import create_server
from .support import FixtureHttp, RuntimeFactory, configured_env, fixture


REFERENCE = "registry.example/team/app:1"
REFERENCE_LOCATOR = {"kind": "reference", "reference": REFERENCE}
DIGEST_LOCATOR = {"kind": "digest", "digest": "sha256:abc"}


@pytest.mark.parametrize(
    ("version", "fixture_name"), [("v1", "images-v1.json"), ("v2", "images-v2.json")]
)
@pytest.mark.asyncio
async def test_image_listing_preserves_native_version_semantics(
    monkeypatch: pytest.MonkeyPatch, version: str, fixture_name: str
) -> None:
    configured_env(monkeypatch, version=version)
    http = FixtureHttp({f"/{version}/images": [fixture(fixture_name)]})
    async with Client(create_server(runtime_factory=RuntimeFactory(http))) as client:
        result = await client.call_tool("anchore_list_images", {})

    assert result.structured_content is not None
    assert len(result.structured_content["images"]) == 1
    assert result.structured_content["enumeration"]["complete"] is True


@pytest.mark.asyncio
async def test_unique_reference_resolution_is_explicit_and_complete(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configured_env(monkeypatch)
    resolution = fixture("resolution.json")
    detail = fixture("capabilities.json")["detail"]
    http = FixtureHttp({"/v2/images": [resolution["unique"]], "/v2/images/sha256%3Aabc": [detail]})
    async with Client(create_server(runtime_factory=RuntimeFactory(http))) as client:
        result = await client.call_tool("anchore_image_detail", {"locator": REFERENCE_LOCATOR})

    assert result.structured_content is not None
    assert result.structured_content["selected_image"]["digest"] == "sha256:abc"
    assert result.structured_content["selection"] == {
        "complete": True,
        "pages_fetched": 1,
        "reason": None,
    }


@pytest.mark.parametrize(
    ("outcome", "message"),
    [("ambiguous", "multiple analyzed"), ("incomplete", "malformed")],
)
@pytest.mark.asyncio
async def test_untrusted_reference_outcomes_fail_closed(
    monkeypatch: pytest.MonkeyPatch, outcome: str, message: str
) -> None:
    configured_env(monkeypatch)
    page = fixture("resolution.json")[outcome]
    http = FixtureHttp({"/v2/images": [page]})
    async with Client(create_server(runtime_factory=RuntimeFactory(http))) as client:
        with pytest.raises(ToolError, match=message):
            await client.call_tool("anchore_image_detail", {"locator": REFERENCE_LOCATOR})


@pytest.mark.asyncio
async def test_sbom_formats_policy_outcomes_blockers_and_handoff_are_native(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configured_env(monkeypatch)
    data = fixture("capabilities.json")
    sbom = data["sbom"]
    policy = data["policy"]
    vulnerabilities = data["vulnerabilities"]
    detail = data["detail"]
    http = FixtureHttp(
        {
            "/v2/images/sha256%3Aabc/sboms/native-json": [sbom["normal"]],  # type: ignore[index]
            "/v2/images/sha256%3Aabc/sboms/spdx-json": [sbom["spdx"]],  # type: ignore[index]
            "/v2/images/sha256%3Aabc/sboms/cyclonedx-json": [sbom["cyclonedx"]],  # type: ignore[index]
            "/v2/images/sha256%3Aabc/check": [
                policy["green"],  # type: ignore[index]
                policy["red"],  # type: ignore[index]
                policy["green"],  # type: ignore[index]
            ],
            "/v2/images/sha256%3Aabc/vuln/all": [vulnerabilities, vulnerabilities],
            "/v2/images/sha256%3Aabc": [detail],
        }
    )
    async with Client(create_server(runtime_factory=RuntimeFactory(http))) as client:
        sboms = [
            await client.call_tool(
                "anchore_image_sbom", {"locator": DIGEST_LOCATOR, "format": format_name}
            )
            for format_name in ("normal", "spdx", "cyclonedx")
        ]
        green = await client.call_tool(
            "anchore_policy_blocking_vulnerabilities", {"locator": DIGEST_LOCATOR}
        )
        blocked = await client.call_tool(
            "anchore_policy_blocking_vulnerabilities", {"locator": DIGEST_LOCATOR}
        )
        handoff = await client.call_tool("anchore_remediation_handoff", {"locator": DIGEST_LOCATOR})

    assert [
        result.structured_content["format"] for result in sboms if result.structured_content
    ] == ["normal", "spdx", "cyclonedx"]
    assert (
        green.structured_content is not None
        and green.structured_content["outcome"] == "already_green"
    )
    assert (
        blocked.structured_content is not None
        and blocked.structured_content["outcome"] == "blocked"
    )
    assert [
        item["vulnerability"]["vulnerability_id"] for item in blocked.structured_content["blockers"]
    ] == ["CVE-2099-0001"]
    assert handoff.structured_content is not None
    assert handoff.structured_content["handoffVersion"] == "2.0.0"
    assert set(handoff.structured_content["evidence"]) == {"detail", "vulnerabilities", "policy"}
