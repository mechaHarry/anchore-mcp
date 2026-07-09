import pytest

from anchore_mcp.models.locators import DigestLocator
from anchore_mcp.tools.policy_blocking_vulnerabilities import (
    anchore_policy_blocking_vulnerabilities,
)
from task12_support import RoutingHttp, connection, context


@pytest.mark.asyncio
async def test_policy_blocker_returns_only_compact_proven_blockers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy_path = "/v2/images/sha256%3Aabc/check"
    vuln_path = "/v2/images/sha256%3Aabc/vuln/all"
    http = RoutingHttp(
        {
            policy_path: [
                (
                    {
                        "status": "red",
                        "findings": [
                            {
                                "gate": "vulnerabilities",
                                "action": "stop",
                                "vulnerability_id": "CVE-2099-0001",
                            }
                        ],
                        "raw_policy_secret": "do-not-copy",
                    },
                    17,
                )
            ],
            vuln_path: [
                (
                    {
                        "items": [
                            {"vuln": "CVE-2099-0001", "package_name": "openssl"},
                            {"vuln": "CVE-2099-9999", "raw": "do-not-copy"},
                        ]
                    },
                    23,
                )
            ],
        }
    )
    monkeypatch.setattr(
        "anchore_mcp.tools.policy_blocking_vulnerabilities.load_connection", connection
    )

    result = await anchore_policy_blocking_vulnerabilities(
        context(http), DigestLocator(kind="digest", digest="sha256:abc")
    )

    assert result.structured_content is not None
    assert result.structured_content["outcome"] == "blocked"
    assert len(result.structured_content["blockers"]) == 1
    encoded = str(result.structured_content["blockers"])
    assert "CVE-2099-0001" in encoded
    assert "CVE-2099-9999" not in encoded
    assert "raw_policy_secret" not in encoded
    assert "do-not-copy" not in result.content[0].text  # type: ignore[union-attr]


@pytest.mark.asyncio
async def test_green_policy_returns_without_vulnerability_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy_path = "/v2/images/sha256%3Aabc/check"
    http = RoutingHttp({policy_path: [({"status": "green"}, 5)]})
    monkeypatch.setattr(
        "anchore_mcp.tools.policy_blocking_vulnerabilities.load_connection", connection
    )

    result = await anchore_policy_blocking_vulnerabilities(
        context(http), DigestLocator(kind="digest", digest="sha256:abc")
    )

    assert [call[0] for call in http.calls] == [policy_path]
    assert result.structured_content is not None
    assert result.structured_content["outcome"] == "already_green"
    assert result.structured_content["blockers"] == []
