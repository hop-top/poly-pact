"""The limits and the error of the strict decoder."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from hop_top_pact.errors import PactError

MAX_SAFE_INTEGER: Final = (1 << 53) - 1
"""The largest integer a core field may carry: 2^53-1."""

DEFAULT_MAX_BYTES: Final = 256 << 10
"""The decoded presentation limit of draft section 20.1, used when Limits.max_bytes is 0."""

DEFAULT_MAX_DEPTH: Final = 16
"""The JSON nesting limit of draft section 20.1; the outermost object or array has depth 1."""


@dataclass(frozen=True, slots=True)
class Limits:
    """Bounds of one decode: input size in bytes and nesting depth.

    A field that is zero or negative selects its default.
    """

    max_bytes: int = 0
    max_depth: int = 0

    def _resolved(self) -> tuple[int, int]:
        return (
            self.max_bytes if self.max_bytes > 0 else DEFAULT_MAX_BYTES,
            self.max_depth if self.max_depth > 0 else DEFAULT_MAX_DEPTH,
        )


class StrictJSONErrorKind(StrEnum):
    """Why a strict decode failed: the Go sentinels Err* of the strictjson package."""

    TARGET = "TARGET"
    """decode was given a target the decoder cannot fill."""
    SIZE = "SIZE"
    """The input is larger than Limits.max_bytes."""
    SYNTAX = "SYNTAX"
    """The input is not JSON."""
    INVALID_UTF8 = "INVALID_UTF8"
    """The input is not UTF-8."""
    LONE_SURROGATE = "LONE_SURROGATE"
    """A \\u escape is a surrogate that is not half of a pair."""
    DEPTH = "DEPTH"
    """Objects and arrays nest deeper than Limits.max_depth."""
    DUPLICATE_KEY = "DUPLICATE_KEY"
    """An object has two members of the same name."""
    UNKNOWN_FIELD = "UNKNOWN_FIELD"
    """A member name is not a field of the target."""
    NON_FINITE = "NON_FINITE"
    """A number is NaN or Infinity, or overflows binary64."""
    INTEGER = "INTEGER"
    """An integer is outside ±(2^53-1), or not a non-negative integer for an integer field."""
    NULL = "NULL"
    """null where the target cannot hold it."""
    TRAILING_DATA = "TRAILING_DATA"
    """Text follows the JSON value."""
    TYPE = "TYPE"
    """A value does not fit the target type."""


_MESSAGES: Final = {
    StrictJSONErrorKind.TARGET: "strictjson: target is not a type the decoder can fill",
    StrictJSONErrorKind.SIZE: "strictjson: input too large",
    StrictJSONErrorKind.SYNTAX: "strictjson: invalid JSON",
    StrictJSONErrorKind.INVALID_UTF8: "strictjson: invalid UTF-8",
    StrictJSONErrorKind.LONE_SURROGATE: "strictjson: unpaired surrogate escape",
    StrictJSONErrorKind.DEPTH: "strictjson: nesting too deep",
    StrictJSONErrorKind.DUPLICATE_KEY: "strictjson: duplicate member name",
    StrictJSONErrorKind.UNKNOWN_FIELD: "strictjson: unknown field",
    StrictJSONErrorKind.NON_FINITE: "strictjson: non-finite number",
    StrictJSONErrorKind.INTEGER: "strictjson: integer out of range or not an integer",
    StrictJSONErrorKind.NULL: "strictjson: null not allowed",
    StrictJSONErrorKind.TRAILING_DATA: "strictjson: data after the JSON value",
    StrictJSONErrorKind.TYPE: "strictjson: value does not fit the target type",
}


class StrictJSONError(PactError):
    """A strict decode refused its input.

    kind is the reason; path the RFC 6901 pointer of the offending member,
    empty for the document root; offset the byte offset in the input at
    which the problem was found (approximate for a TYPE or LONE_SURROGATE
    finding, which is reported after the whole input was read); detail adds
    specifics, such as the member name.
    """

    def __init__(
        self, kind: StrictJSONErrorKind, path: str = "", offset: int = 0, detail: str = ""
    ) -> None:
        self.kind = kind
        self.path = path
        self.offset = offset
        self.detail = detail
        super().__init__(str(self))

    def __str__(self) -> str:
        s = _MESSAGES.get(self.kind, f"strictjson: {self.kind}")
        if self.detail:
            s += ": " + self.detail
        if self.path:
            s += " at " + self.path
        return f"{s} (offset {self.offset})"
