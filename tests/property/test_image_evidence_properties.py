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
INCOMPLETE_REASONS = (
    "detail_entry_limit",
    "tag_entry_limit",
    "reference_limit",
    "scan_limit",
    "string_length_limit",
)


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


@given(
    key=st.sampled_from(
        [
            "full_tag",
            "fulltag",
            "image_tag",
            "imageTag",
            "tag",
            "tags",
            "image_detail",
            "imageDetail",
        ]
    ),
    payload=json_values(depth=5),
)
@settings(max_examples=100, deadline=None)
def test_recognized_evidence_fields_accept_hostile_recursive_values_without_raising(
    key: str, payload: JsonValue
) -> None:
    row: JsonValue = {key: payload}
    evidence = extract_reference_evidence(row)

    assert len(evidence.references) <= MAX_NORMALIZED_IMAGE_REFERENCES_PER_ROW
    assert all(
        len(reference) <= MAX_IMAGE_REFERENCE_STRING_LENGTH for reference in evidence.references
    )


@given(boundary=st.sampled_from([63, 64, 65]))
@settings(max_examples=100, deadline=None)
def test_detail_and_tag_entry_boundaries_are_exact(boundary: int) -> None:
    detail = extract_reference_evidence({"image_detail": [None] * boundary})
    tags = extract_reference_evidence({"tags": [None] * boundary})

    assert detail.complete is (boundary <= 64)
    assert detail.reason == (None if boundary <= 64 else "detail_entry_limit")
    assert tags.complete is (boundary <= 64)
    assert tags.reason == (None if boundary <= 64 else "tag_entry_limit")


@given(boundary=st.sampled_from([31, 32, 33]))
@settings(max_examples=100, deadline=None)
def test_normalized_reference_boundary_is_exact(boundary: int) -> None:
    evidence = extract_reference_evidence(
        {"tags": [f"registry.example/team/app:{index}" for index in range(boundary)]}
    )

    assert len(evidence.references) == min(boundary, 32)
    assert evidence.complete is (boundary <= 32)
    assert evidence.reason == (None if boundary <= 32 else "reference_limit")


@given(boundary=st.sampled_from([255, 256, 257]))
@settings(max_examples=100, deadline=None)
def test_scan_boundary_counts_non_string_entries(boundary: int) -> None:
    final_tag_count = boundary - (3 * 65) - 1
    details = [
        {"tags": [{"ignored": True}] * 64},
        {"tags": [{"ignored": True}] * 64},
        {"tags": [{"ignored": True}] * 64},
        {"tags": [{"ignored": True}] * final_tag_count},
    ]
    evidence = extract_reference_evidence({"image_detail": details})

    assert evidence.complete is (boundary <= 256)
    assert evidence.reason == (None if boundary <= 256 else "scan_limit")


def _incomplete_row(reason: str, payload: JsonValue) -> JsonValue:
    if reason == "detail_entry_limit":
        return {"image_detail": [payload] * 65}
    if reason == "tag_entry_limit":
        return {"tags": [payload] * 65}
    if reason == "reference_limit":
        return {"tags": [f"registry.example/team/app:{index}" for index in range(33)]}
    if reason == "scan_limit":
        return cast(
            JsonValue,
            {
                "image_detail": [
                    {"tags": [{"payload": payload}] * 64},
                    {"tags": [{"payload": payload}] * 64},
                    {"tags": [{"payload": payload}] * 64},
                    {"tags": [{"payload": payload}] * 61},
                ]
            },
        )
    return {"full_tag": "x" * (MAX_IMAGE_REFERENCE_STRING_LENGTH + 1)}


@given(
    reason=st.sampled_from(INCOMPLETE_REASONS),
    exact_first=st.booleans(),
    payload=json_values(depth=3),
)
@settings(max_examples=100, deadline=None)
def test_each_incomplete_reason_dominates_exact_matches_in_any_order(
    reason: str, exact_first: bool, payload: JsonValue
) -> None:
    incomplete_row = _incomplete_row(reason, payload)
    evidence = extract_reference_evidence(incomplete_row)
    exact_row: JsonValue = {"image_digest": "sha256:exact", "full_tag": REFERENCE}
    rows = (exact_row, incomplete_row) if exact_first else (incomplete_row, exact_row)
    result = resolve_image_rows(rows, REFERENCE)

    assert evidence.reason == reason
    assert isinstance(result, Incomplete)
