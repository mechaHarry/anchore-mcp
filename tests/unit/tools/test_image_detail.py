import pytest
from fastmcp.exceptions import ToolError

from anchore_mcp.anchore.http import MAX_RESPONSE_BYTES
from anchore_mcp.models.locators import DigestLocator, ReferenceLocator
from anchore_mcp.tools.image_detail import anchore_image_detail
from task12_support import RoutingHttp, connection, context


@pytest.mark.asyncio
async def test_detail_reference_resolution_has_truthful_selection_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reference = "registry.example/team/app:1"
    http = RoutingHttp(
        {
            "/v2/images": [
                ({"items": [{"image_digest": "sha256:selected", "full_tag": reference}]}, 19)
            ],
            "/v2/images/sha256%3Aselected": [({"secret": "private-evidence"}, 41)],
        }
    )
    monkeypatch.setattr("anchore_mcp.tools.image_detail.load_connection", connection)

    result = await anchore_image_detail(
        context(http), ReferenceLocator(kind="reference", reference=reference)
    )

    assert [call[0] for call in http.calls] == [
        "/v2/images",
        "/v2/images/sha256%3Aselected",
    ]
    assert http.calls[1][2] == MAX_RESPONSE_BYTES
    assert result.structured_content is not None
    assert result.structured_content["selected_image"]["reference"] == reference
    assert result.structured_content["selection"] == {
        "complete": True,
        "pages_fetched": 1,
        "reason": None,
    }
    assert result.structured_content["size_bytes"] == 41
    assert "private-evidence" not in result.content[0].text  # type: ignore[union-attr]


@pytest.mark.asyncio
async def test_detail_unknown_failure_logs_no_raw_exception_text(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = "/v2/images/sha256%3Aabc"
    http = RoutingHttp({path: [RuntimeError("Bearer private-token raw-response")]})
    monkeypatch.setattr("anchore_mcp.tools.image_detail.load_connection", connection)

    with pytest.raises(ToolError, match="failed safely"):
        await anchore_image_detail(context(http), DigestLocator(kind="digest", digest="sha256:abc"))
    captured = capsys.readouterr()

    assert "RuntimeError" in captured.err
    assert "private-token" not in captured.err
    assert "raw-response" not in captured.err
    assert captured.out == ""


@pytest.mark.parametrize(
    ("page", "message"),
    [
        ({"items": []}, "No analyzed image matched"),
        (
            {
                "items": [
                    {
                        "image_digest": "sha256:one",
                        "full_tag": "registry.example/team/app:1",
                    },
                    {
                        "image_digest": "sha256:two",
                        "full_tag": "registry.example/team/app:1",
                    },
                ]
            },
            "multiple analyzed image digests",
        ),
        ({"unexpected": []}, "wrapper or rows were malformed"),
    ],
)
@pytest.mark.asyncio
async def test_reference_resolution_failures_are_safe_tool_errors(
    monkeypatch: pytest.MonkeyPatch,
    page: object,
    message: str,
) -> None:
    reference = "registry.example/team/app:1"
    http = RoutingHttp({"/v2/images": [(page, 5)]})
    monkeypatch.setattr("anchore_mcp.tools.image_detail.load_connection", connection)

    with pytest.raises(ToolError, match=message):
        await anchore_image_detail(
            context(http), ReferenceLocator(kind="reference", reference=reference)
        )


@pytest.mark.asyncio
async def test_invalid_reference_fails_before_http(monkeypatch: pytest.MonkeyPatch) -> None:
    http = RoutingHttp({})
    monkeypatch.setattr("anchore_mcp.tools.image_detail.load_connection", connection)

    with pytest.raises(ToolError, match="fully qualified"):
        await anchore_image_detail(
            context(http), ReferenceLocator(kind="reference", reference="nginx:latest")
        )

    assert http.calls == []
