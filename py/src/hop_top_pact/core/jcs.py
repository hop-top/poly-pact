"""RFC 8785 JSON Canonicalization Scheme. Mirrors hop.top/pact-go/core/jcs.

The canonical form is UTF-8 without insignificant white space, object members
sorted by name in UTF-16 code units, strings and numbers in the ECMAScript
serialization.
"""

from __future__ import annotations

import math
from collections.abc import Mapping
from json.encoder import encode_basestring
from typing import Final

from hop_top_pact.core import strictjson
from hop_top_pact.core.strictjson import (
    DEFAULT_MAX_DEPTH,
    MAX_SAFE_INTEGER,
    StrictJSONError,
    StrictJSONErrorKind,
)

__all__ = ["canonicalize", "canonicalize_value"]


def canonicalize(data: bytes) -> bytes:
    """Return the RFC 8785 canonical form of the JSON text data.

    data is first read by strictjson with its default limits, so a document
    that strictjson rejects is rejected here with the same StrictJSONError:
    duplicate member names, nesting over 16, input over 256 KiB, invalid
    UTF-8, unpaired surrogate escapes, text after the value, NaN and
    Infinity, number literals that overflow binary64, and integer literals
    outside ±(2^53-1). Any JSON value may be canonicalized, not only an
    object.
    """
    return canonicalize_value(strictjson.parse(data))


def canonicalize_value(value: object) -> bytes:
    """Return the RFC 8785 canonical form of the parsed JSON value.

    value is what strictjson.parse returns, or the same shapes built in
    code: a Mapping with str keys, a list or tuple, str, int, float, bool or
    None. For a parsed value the result equals canonicalize of the text it
    was parsed from. A value no strict parse with the default limits yields
    raises StrictJSONError, with the RFC 6901 path of the offending value:
    nesting over 16 (DEPTH), an integer outside ±(2^53-1) (INTEGER), NaN or
    an infinity (NON_FINITE), a string with a surrogate code point
    (LONE_SURROGATE). Any other type, and a member name that is not a str,
    raises TypeError.
    """
    out: list[str] = []
    _write(value, out, 0, [])
    return "".join(out).encode("utf-8")


def _fail(kind: StrictJSONErrorKind, path: list[str], detail: str) -> StrictJSONError:
    pointer = "".join("/" + p.replace("~", "~0").replace("/", "~1") for p in path)
    return StrictJSONError(kind, pointer, 0, detail)


def _write(v: object, out: list[str], depth: int, path: list[str]) -> None:
    if v is None:
        out.append("null")
    elif v is True:
        out.append("true")
    elif v is False:
        out.append("false")
    elif isinstance(v, str):
        out.append(_string(v, path))
    elif isinstance(v, int):
        if not -MAX_SAFE_INTEGER <= v <= MAX_SAFE_INTEGER:
            raise _fail(
                StrictJSONErrorKind.INTEGER, path, f"{int(v)} is outside ±{MAX_SAFE_INTEGER}"
            )
        out.append(int.__repr__(v))
    elif isinstance(v, float):
        out.append(_number(v, path))
    elif isinstance(v, Mapping):
        if depth >= DEFAULT_MAX_DEPTH:
            raise _fail(StrictJSONErrorKind.DEPTH, path, f"depth exceeds {DEFAULT_MAX_DEPTH}")
        for k in v:
            if not isinstance(k, str):
                raise TypeError(f"jcs: member name {k!r} is not a str")
        out.append("{")
        for i, k in enumerate(sorted(v, key=_utf16)):
            if i:
                out.append(",")
            out.append(_string(k, path, k))
            out.append(":")
            path.append(k)
            _write(v[k], out, depth + 1, path)
            path.pop()
        out.append("}")
    elif isinstance(v, list | tuple):
        if depth >= DEFAULT_MAX_DEPTH:
            raise _fail(StrictJSONErrorKind.DEPTH, path, f"depth exceeds {DEFAULT_MAX_DEPTH}")
        out.append("[")
        for i, x in enumerate(v):
            if i:
                out.append(",")
            path.append(str(i))
            _write(x, out, depth + 1, path)
            path.pop()
        out.append("]")
    else:
        raise TypeError(f"jcs: {type(v).__name__} is not a JSON value")


def _utf16(name: str) -> bytes:
    # RFC 8785 section 3.2.3 sorts by UTF-16 code units; big-endian UTF-16
    # bytes compare in that order. surrogatepass keeps a bad name sortable
    # until _string refuses it.
    return name.encode("utf-16-be", "surrogatepass")


def _string(s: str, path: list[str], key: str | None = None) -> str:
    """s as ECMAScript JSON.stringify writes it (RFC 8785 section 3.2.2.2): the quotation
    mark and the reverse solidus escaped, \\b \\t \\n \\f \\r in short form, other controls
    as lower-case \\u00xx, everything else (U+007F, U+2028 and U+2029 included) as is."""
    if not s.isascii():
        try:
            s.encode("utf-8")
        except UnicodeEncodeError as e:
            where = [*path, key] if key is not None else path
            raise _fail(
                StrictJSONErrorKind.LONE_SURROGATE,
                where,
                f"surrogate U+{ord(s[e.start]):04X} at character {e.start}",
            ) from None
    return encode_basestring(s)


def _number(f: float, path: list[str]) -> str:
    """f as ECMAScript Number::toString writes it (RFC 8785 section 3.2.2.3).

    NaN and the infinities are an error, zero of either sign is "0", and
    otherwise, with k the number of shortest round-trip digits and n the
    decimal point position (the value is 0.d1d2...dk * 10^n):

        k <= n <= 21     the digits, then n-k zeros
        0 < n <= 21      the first n digits, ".", the remaining digits
        -6 < n <= 0      "0.", then -n zeros, then the digits
        otherwise        d1, then "." and d2...dk when k > 1, then "e", a sign
                         that is always written, and the exponent n-1

    The digits are those of repr, the shortest that round-trip.
    """
    if not math.isfinite(f):
        raise _fail(StrictJSONErrorKind.NON_FINITE, path, f"{f!r} is not a JSON number")
    if f == 0:
        return "0"
    sign = "-" if f < 0 else ""
    r = repr(abs(f))  # 1e-07, 1.5e+300, 123.456, 100.0, 5e-324
    mantissa, _, exp = r.partition("e")
    whole, _, frac = mantissa.partition(".")
    raw = whole + frac
    digits = raw.lstrip("0")
    n = len(whole) + (int(exp) if exp else 0) - (len(raw) - len(digits))
    d = digits.rstrip("0")
    k = len(d)
    if k <= n <= _MAX_PLAIN:
        body = d + "0" * (n - k)
    elif 0 < n <= _MAX_PLAIN:
        body = d[:n] + "." + d[n:]
    elif -6 < n <= 0:
        body = "0." + "0" * -n + d
    else:
        e = n - 1
        body = d[0] + ("." + d[1:] if k > 1 else "") + ("e-" if e < 0 else "e+") + str(abs(e))
    return sign + body


_MAX_PLAIN: Final = 21
