"""Heuristic PII masking for generated textual tool content only."""

from dataclasses import dataclass
import re
from typing import Literal
import unicodedata


type PiiKind = Literal["email", "ssn_like", "phone_like"]

_EMAIL = re.compile(
    r"(?<![\w.%+-])[\w.!#$%&'*+/=?^`{|}~-]+@(?:[\w-]+\.)+"
    r"(?:xn--[A-Za-z0-9-]{2,59}|[^\W\d_]{2,63})(?![\w-])",
    re.IGNORECASE,
)
_SSN_LIKE = re.compile(r"\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b")
_PHONE_LIKE = re.compile(
    r"(?<!\w)(?:\+?1[-.\s]?)?(?:\([0-9]{3}\)|[0-9]{3})"
    r"[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}(?!\w)"
)

_WARNING_BY_KIND: dict[PiiKind, str] = {
    "email": (
        "Possible email address was masked by a heuristic. "
        "Limit distribution and verify recipients before sharing."
    ),
    "ssn_like": (
        "Possible government ID / SSN-like pattern was masked by a heuristic. "
        "Treat remaining content as sensitive and limit distribution."
    ),
    "phone_like": (
        "Possible phone number was masked by a heuristic. "
        "Limit distribution and verify the trust boundary before sharing."
    ),
}


@dataclass(frozen=True, slots=True)
class MaskedText:
    text: str
    kinds: tuple[PiiKind, ...]
    warnings: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class PreparedText[T]:
    text: str
    structured: T
    kinds: tuple[PiiKind, ...]
    warnings: tuple[str, ...]


def mask_pii_text(text: str) -> MaskedText:
    """Mask supported PII-like substrings and report each detected kind once."""

    text = unicodedata.normalize("NFC", text)
    detected: list[PiiKind] = []

    def replacement(kind: PiiKind, marker: str):
        def replace(_match: re.Match[str]) -> str:
            if kind not in detected:
                detected.append(kind)
            return marker

        return replace

    masked = _EMAIL.sub(replacement("email", "[email redacted]"), text)
    masked = _SSN_LIKE.sub(replacement("ssn_like", "[id redacted]"), masked)
    masked = _PHONE_LIKE.sub(replacement("phone_like", "[phone redacted]"), masked)
    kinds = tuple(detected)
    return MaskedText(
        text=masked,
        kinds=kinds,
        warnings=tuple(_WARNING_BY_KIND[kind] for kind in kinds),
    )


def prepare_text[T](text: str, structured: T) -> PreparedText[T]:
    """Mask generated prose while preserving structured Anchore evidence by identity."""

    masked = mask_pii_text(text)
    return PreparedText(
        text=masked.text,
        structured=structured,
        kinds=masked.kinds,
        warnings=masked.warnings,
    )
