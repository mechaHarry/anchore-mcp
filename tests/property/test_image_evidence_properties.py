from typing import cast

from hypothesis import given, settings, strategies as st
from hypothesis.strategies import SearchStrategy
from pydantic import JsonValue

from anchore_mcp.domain.images import (
    MAX_IMAGE_REFERENCE_STRING_LENGTH,
    MAX_NORMALIZED_IMAGE_REFERENCES_PER_ROW,
    extract_reference_evidence,
)
from anchore_mcp.domain.resolution import Incomplete, resolve_image_rows


REFERENCE = "registry.example/team/app:exact"


def json_values(depth: int = 6) -> SearchStrategy[JsonValue]:
    scalar = cast(
        SearchStrategy[JsonValue],
        st.one_of(
            st.none(),
            st.booleans(),
            st.integers(min_value=-(2**31), max_value=2**31),
            st.text(max_size=1_100),
        ),
    )
    if depth == 0:
        return scalar
    child = json_values(depth - 1)
    return cast(
        SearchStrategy[JsonValue],
        st.one_of(
            scalar,
            st.lists(child, max_size=5),
            st.dictionaries(st.text(max_size=24), child, max_size=5),
        ),
    )


@given(row=json_values())
@settings(max_examples=100, deadline=None)
def test_arbitrary_depth_six_json_is_bounded_and_never_raises(row: JsonValue) -> None:
    evidence = extract_reference_evidence(row)

    assert len(evidence.references) <= MAX_NORMALIZED_IMAGE_REFERENCES_PER_ROW
    assert all(
        len(reference) <= MAX_IMAGE_REFERENCE_STRING_LENGTH for reference in evidence.references
    )


@given(row=json_values())
@settings(max_examples=100, deadline=None)
def test_incomplete_evidence_never_resolves_or_reports_no_match(row: JsonValue) -> None:
    overflowing_row: JsonValue = {"image_detail": [row for _ in range(65)]}
    evidence = extract_reference_evidence(overflowing_row)

    assert evidence.complete is False
    result = resolve_image_rows((overflowing_row,), REFERENCE)

    assert isinstance(result, Incomplete)
