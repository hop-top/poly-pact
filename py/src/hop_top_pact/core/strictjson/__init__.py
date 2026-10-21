"""Strict JSON decoding (draft section 7.1). Mirrors hop.top/pact-go/core/strictjson.

parse, parse_stream and decode reject, before they build a value:

- duplicate member names, compared after unescaping, in any object,
  including the open "extensions" and "attributes" objects and free-form
  values;
- member names that are not an exact, case-sensitive match of a field of
  the target dataclass, except inside mappings and free-form values such as
  extensions, attributes and headers;
- nesting deeper than Limits.max_depth (16 by default);
- non-finite numbers: NaN, Infinity and literals that overflow binary64;
- invalid UTF-8 and unpaired surrogate escapes;
- integer literals outside ±(2^53-1), anywhere in the document, and, for an
  integer-typed target field, negative or non-integer numbers;
- null for any target that cannot hold it (an optional annotation, ``X |
  None``, or a free-form JSONValue can);
- empty input, text after the JSON value, and input over Limits.max_bytes.

The decoder checks syntax and shape. It does not apply the schema's
patterns, lengths, enum sets or required members; a schema validator does.
A required member that is absent holds its zero value ("", 0, 0.0, False,
an empty tuple or mapping, a zero dataclass), as the Go target does.

The decoder is a port of the Go package's walker: one pass over the text in
step with the target type, reporting the first violation with the reason,
RFC 6901 path and byte offset the Go package reports. As there, an
unpaired surrogate is reported after every other violation of the walk, and
a value that does not fit its target type (TYPE, path empty, offset the end
of the value) after that. Nesting is tracked with an explicit stack, so the
depth limit holds whatever the interpreter's recursion limit.

Values: objects are dicts, arrays tuples, integer literals int, other
numbers float, strings str. A dataclass target is built from its fields'
annotations: str (and StrEnum), int, float, bool, a dataclass, tuple[X,
...], Mapping[str, X], X | None, and JSONValue (or any other union) for a
free-form value. The wire types of core.types also take their nullability
from their _MEMBERS tables.
"""

from __future__ import annotations

from typing import Protocol, TypeVar, cast

from hop_top_pact.core.strictjson._errors import (
    DEFAULT_MAX_BYTES,
    DEFAULT_MAX_DEPTH,
    MAX_SAFE_INTEGER,
    Limits,
    StrictJSONError,
    StrictJSONErrorKind,
)
from hop_top_pact.core.strictjson._target import FREE, prepare, target_of
from hop_top_pact.core.strictjson._walk import run
from hop_top_pact.core.types import JSONValue

__all__ = [
    "DEFAULT_MAX_BYTES",
    "DEFAULT_MAX_DEPTH",
    "MAX_SAFE_INTEGER",
    "Limits",
    "StrictJSONError",
    "StrictJSONErrorKind",
    "decode",
    "parse",
    "parse_stream",
]

T = TypeVar("T")


class _Reader(Protocol):
    def read(self, size: int, /) -> bytes | None: ...


def parse(data: bytes, limits: Limits | None = None) -> JSONValue:
    """Strict-parse the JSON text data into a free-form value (Go: Unmarshal into any)."""
    return cast(JSONValue, run(data, limits, FREE))


def parse_stream(fp: _Reader, limits: Limits | None = None) -> JSONValue:
    """parse for a binary stream: reads at most max_bytes + 1 bytes (Go: Decode)."""
    max_bytes, _ = (limits or Limits())._resolved()
    want = max_bytes + 1
    chunks: list[bytes] = []
    got = 0
    while got < want:
        b = fp.read(want - got)
        if not b:
            break
        chunks.append(b)
        got += len(b)
    return parse(b"".join(chunks), limits)


def decode(data: bytes, cls: type[T], limits: Limits | None = None) -> T:
    """Strict-decode the JSON text data into a value of cls, a wire dataclass or another
    target the module documentation lists; raise StrictJSONError on refusal."""
    try:
        target = target_of(cls)
        prepare(target)
    except (TypeError, NameError) as e:
        raise StrictJSONError(StrictJSONErrorKind.TARGET, detail=f"got {cls!r}: {e}") from e
    return cast(T, run(data, limits, target))
