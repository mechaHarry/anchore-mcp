from hypothesis import given, settings, strategies as st

from anchore_mcp.anchore.pagination import validate_next_link


@settings(max_examples=100, derandomize=True)
@given(st.text(max_size=500))
def test_foreign_continuations_are_never_followed(value: str) -> None:
    link = f'<https://foreign.example/{value}>; rel="next"'
    assert validate_next_link("https://anchore.example/api", "/v2/images", link) is None


@settings(max_examples=100, derandomize=True)
@given(st.binary(max_size=500))
def test_malformed_continuations_are_never_followed(value: bytes) -> None:
    link = value.decode("utf-8", errors="replace")
    continuation = validate_next_link("https://anchore.example/api", "/v2/images", link)
    if continuation is not None:
        path, _ = continuation
        assert path == "/v2/images"
