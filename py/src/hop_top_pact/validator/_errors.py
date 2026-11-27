"""The errors of the validator package that carry no draft 13.4 code."""

from __future__ import annotations

from enum import StrEnum
from typing import Final

from hop_top_pact.errors import PactError

__all__ = ["ValidatorError", "ValidatorErrorKind"]


class ValidatorErrorKind(StrEnum):
    """Which failure a ValidatorError is: the Go sentinels Err* of the validator package."""

    NOT_FOUND = "NOT_FOUND"
    """A receipt a store does not hold."""
    TRANSITION = "TRANSITION"
    """An event the current state has no row for; a terminal state has none, so a sealed
    result is never changed."""


_MESSAGES: Final = {
    ValidatorErrorKind.NOT_FOUND: "validator: receipt not found",
    ValidatorErrorKind.TRANSITION: "validator: no transition",
}


class ValidatorError(PactError):
    """A validator failure of kind, with detail."""

    def __init__(self, kind: ValidatorErrorKind | str, detail: str = "") -> None:
        self.kind = ValidatorErrorKind(kind)
        self.detail = detail
        super().__init__(_MESSAGES[self.kind] + (f" {detail}" if detail else ""))
