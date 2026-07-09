from anchore_mcp.security.pii import mask_pii_text, prepare_text


def test_masked_text_warns_without_mutating_structured_evidence() -> None:
    evidence = {"owner": "person@example.test"}

    masked = prepare_text("Contact person@example.test", evidence)

    assert masked.text == "Contact [email redacted]"
    assert masked.structured is evidence
    assert masked.warnings
    assert "heuristic" in masked.warnings[0].casefold()
    assert "distribution" in masked.warnings[0].casefold()


def test_masks_supported_pii_kinds_in_deterministic_warning_order() -> None:
    text = (
        "Call (415) 555-0123 or 415-555-0123 about 123-45-6789; "
        "email first@example.test or second@example.test."
    )

    masked = prepare_text(text, {"raw": text})

    assert masked.text == (
        "Call [phone redacted] or [phone redacted] about [id redacted]; "
        "email [email redacted] or [email redacted]."
    )
    assert masked.kinds == ("email", "ssn_like", "phone_like")
    assert len(masked.warnings) == 3
    assert "email" in masked.warnings[0].casefold()
    assert "government id" in masked.warnings[1].casefold()
    assert "phone" in masked.warnings[2].casefold()


def test_repeated_pii_kind_produces_one_warning() -> None:
    masked = mask_pii_text("one@example.test two@example.test")

    assert masked.kinds == ("email",)
    assert len(masked.warnings) == 1


def test_benign_text_is_unchanged_without_warnings() -> None:
    evidence: list[object] = []

    masked = prepare_text("No sensitive prose here.", evidence)

    assert masked.text == "No sensitive prose here."
    assert masked.structured is evidence
    assert masked.kinds == ()
    assert masked.warnings == ()


def test_phone_prefix_inside_alphanumeric_identifier_is_not_masked() -> None:
    text = "sha=1234567890abcdef"

    masked = mask_pii_text(text)

    assert masked.text == text
    assert masked.kinds == ()


def test_masks_unicode_and_punycode_email_addresses_completely() -> None:
    masked = mask_pii_text(
        "δοκιμή@παράδειγμα.δοκιμή and person@example.xn--p1ai and jose\u0301@example.test"
    )

    assert masked.text == "[email redacted] and [email redacted] and [email redacted]"
    assert masked.kinds == ("email",)


def test_phone_like_digits_inside_unicode_identifiers_are_not_masked() -> None:
    for text in ("id_1234567890_suffix", "α1234567890β"):
        masked = mask_pii_text(text)
        assert masked.text == text
        assert masked.kinds == ()


def test_benign_decomposed_unicode_text_is_unchanged() -> None:
    text = "Cafe\u0301 benign"

    masked = mask_pii_text(text)

    assert masked.text == text
    assert masked.kinds == ()
