from fastmcp import Client
import pytest

from anchore_mcp.server import create_server
from ..semantic.support import FixtureHttp, RuntimeFactory, configured_env, fixture


@pytest.mark.asyncio
async def test_all_eight_native_tools_return_text_and_structured_content(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configured_env(monkeypatch)
    capabilities = fixture("capabilities.json")
    image = {"kind": "digest", "digest": "sha256:abc"}
    http = FixtureHttp(
        {
            "/v2/images": [fixture("images-v2.json")],
            "/v2/images/sha256%3Aabc/vuln/all": [
                capabilities["vulnerabilities"],
                capabilities["vulnerabilities"],
                capabilities["vulnerabilities"],
            ],
            "/v2/images/sha256%3Aabc/sboms/native-json": [capabilities["sbom"]["normal"]],  # type: ignore[index]
            "/v2/images/sha256%3Aabc/check": [
                capabilities["policy"]["green"],  # type: ignore[index]
                capabilities["policy"]["red"],  # type: ignore[index]
                capabilities["policy"]["green"],  # type: ignore[index]
            ],
            "/v2/images/sha256%3Aabc": [
                capabilities["detail"],
                capabilities["detail"],
            ],
        }
    )
    factory = RuntimeFactory(http)
    server = create_server(runtime_factory=factory)
    expected_connection = fixture("connection.json")

    calls: list[tuple[str, dict[str, object]]] = [
        ("anchore_connection_info", {}),
        ("anchore_list_images", {}),
        ("anchore_image_vulnerabilities", {"locator": image}),
        ("anchore_image_sbom", {"locator": image, "format": "normal"}),
        ("anchore_image_policy_check", {"locator": image}),
        ("anchore_policy_blocking_vulnerabilities", {"locator": image}),
        ("anchore_image_detail", {"locator": image}),
        ("anchore_remediation_handoff", {"locator": image}),
    ]
    async with Client(server) as client:
        results = [await client.call_tool(name, arguments) for name, arguments in calls]

    assert len(factory.runtimes) == 1
    assert factory.runtimes[0].closed is True
    assert all(result.content for result in results)
    assert all(result.structured_content for result in results)
    connection = results[0].structured_content
    assert connection is not None
    assert connection["configured"] is expected_connection["configured"]
    assert connection["context"]["base_url"] == expected_connection["base_url"]
    assert connection["context"]["api_version"] == expected_connection["api_version"]
