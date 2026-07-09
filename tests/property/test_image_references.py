from hypothesis import given, settings, strategies as st

from anchore_mcp.domain.images import validate_full_image_reference


@settings(max_examples=100, derandomize=True)
@given(st.text(max_size=300))
def test_arbitrary_reference_cannot_inject_path_or_query(value: str) -> None:
    try:
        normalized = validate_full_image_reference(value)
    except ValueError:
        return

    assert "?" not in normalized
    assert "#" not in normalized
    assert "\\" not in normalized
    assert not any(ord(character) < 0x20 for character in normalized)
