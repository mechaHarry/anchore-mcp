import pytest
from pydantic import TypeAdapter, ValidationError

from anchore_mcp.models.locators import ImageLocator, PolicyImageLocator


@pytest.mark.parametrize(
    ("locator", "expected_type"),
    [
        ({"kind": "digest", "digest": "sha256:abc"}, "DigestLocator"),
        (
            {"kind": "reference", "reference": "registry.example/team/app:latest"},
            "ReferenceLocator",
        ),
    ],
)
def test_image_locator_accepts_exact_discriminated_alternatives(
    locator: dict[str, str], expected_type: str
) -> None:
    adapter: TypeAdapter[ImageLocator] = TypeAdapter(ImageLocator)
    parsed = adapter.validate_python(locator)

    assert type(parsed).__name__ == expected_type


def test_locator_union_rejects_mixed_states() -> None:
    adapter: TypeAdapter[ImageLocator] = TypeAdapter(ImageLocator)

    with pytest.raises(ValidationError):
        adapter.validate_python(
            {"kind": "digest", "digest": "sha256:abc", "reference": "registry/app:tag"}
        )


@pytest.mark.parametrize(
    "locator",
    [
        {},
        {"digest": "sha256:abc"},
        {"kind": "digest"},
        {"kind": "digest", "reference": "registry/app:tag"},
        {"kind": "reference", "digest": "sha256:abc"},
        {"kind": "unknown", "digest": "sha256:abc"},
    ],
)
def test_image_locator_rejects_missing_or_mismatched_fields(locator: dict[str, str]) -> None:
    with pytest.raises(ValidationError):
        TypeAdapter(ImageLocator).validate_python(locator)


def test_repository_locator_is_policy_only() -> None:
    repository = {
        "kind": "repository",
        "registry": "registry.example",
        "repository": "team/app",
    }

    TypeAdapter(PolicyImageLocator).validate_python(repository)
    with pytest.raises(ValidationError):
        TypeAdapter(ImageLocator).validate_python(repository)


@pytest.mark.parametrize("value", ["", " ", "\t", "line\nbreak", "nul\x00byte", "del\x7fbyte"])
def test_locator_strings_reject_blank_or_control_characters(value: str) -> None:
    with pytest.raises(ValidationError):
        TypeAdapter(ImageLocator).validate_python({"kind": "digest", "digest": value})


def test_locator_string_lengths_are_bounded() -> None:
    adapter: TypeAdapter[PolicyImageLocator] = TypeAdapter(PolicyImageLocator)

    adapter.validate_python({"kind": "digest", "digest": "d" * 1024})
    adapter.validate_python({"kind": "repository", "registry": "r" * 255, "repository": "x" * 1024})
    with pytest.raises(ValidationError):
        adapter.validate_python({"kind": "digest", "digest": "d" * 1025})
    with pytest.raises(ValidationError):
        adapter.validate_python({"kind": "repository", "registry": "r" * 256, "repository": "repo"})


def test_locator_json_schema_exposes_discriminator_and_alternatives() -> None:
    image_schema = TypeAdapter(ImageLocator).json_schema()
    policy_schema = TypeAdapter(PolicyImageLocator).json_schema()

    assert image_schema["discriminator"]["propertyName"] == "kind"
    assert len(image_schema["oneOf"]) == 2
    assert set(image_schema["discriminator"]["mapping"]) == {"digest", "reference"}
    assert len(policy_schema["oneOf"]) == 3
    assert set(policy_schema["discriminator"]["mapping"]) == {
        "digest",
        "reference",
        "repository",
    }
