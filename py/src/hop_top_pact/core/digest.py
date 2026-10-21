"""Object, artifact and bytes digests (draft section 7.4). Mirrors hop.top/pact-go/core/digest.

Each digest is the unpadded base64url SHA-256 of its input:

- object_digest(value): of the RFC 8785 canonical form of a JSON object;
- artifact_digest(compact): of the ASCII bytes of a compact JWS, exactly as
  given;
- bytes_digest(data): of the octets.

object_digest takes a parsed value (what strictjson.parse returns; received
JSON reaches it through the strict parse, which refuses duplicate members
and the other violations of draft section 7.1), a Mapping built in code, or a
dataclass: a wire type of core.types writes its members, leaving out an
absent optional member as Go's omitzero does, and any other dataclass writes
all its fields. Compare digests with hmac.compare_digest.
"""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import math
from collections.abc import Mapping
from typing import Any, Final

from hop_top_pact.core import Digest, jcs
from hop_top_pact.core.strictjson import (
    DEFAULT_MAX_BYTES,
    DEFAULT_MAX_DEPTH,
    MAX_SAFE_INTEGER,
    StrictJSONError,
    StrictJSONErrorKind,
)
from hop_top_pact.errors import PactError

__all__ = ["NotObjectError", "artifact_digest", "bytes_digest", "object_digest"]


class NotObjectError(PactError):
    """object_digest was given a value that is not a JSON object (Go: ErrNotObject)."""


def object_digest(value: object) -> Digest:
    """Return object_digest(value): the digest of the RFC 8785 canonical form of the
    JSON object value.

    The checks are Go's, whose ObjectDigest JSON-encodes the value and
    canonicalizes that text with the strict parse: StrictJSONError for what
    jcs.canonicalize_value refuses; SIZE when Go's encoding of the value is
    over 256 KiB (the canonical form plus 3 bytes for each U+2028 or U+2029,
    which Go escapes, and 1 for each -0.0, which Go writes "-0"); INTEGER for
    a float whose canonical form is an integer literal outside ±(2^53-1) (an
    integral value of magnitude above 2^53-1 and below 10^21), which a
    receiver's strict parse refuses. NotObjectError for a value that is not
    an object; TypeError for a value that is not JSON.
    """
    v = _json(value, 0)
    if not isinstance(v, Mapping):
        raise NotObjectError("digest: value is not a JSON object")
    canonical = jcs.canonicalize_value(v)
    found = _Floats()
    found.walk(v, [])
    size = (
        len(canonical)
        + 3 * (canonical.count(b"\xe2\x80\xa8") + canonical.count(b"\xe2\x80\xa9"))
        + found.negative_zeros
    )
    if size > DEFAULT_MAX_BYTES:
        raise StrictJSONError(
            StrictJSONErrorKind.SIZE,
            offset=DEFAULT_MAX_BYTES,
            detail=f"encoding is {size} bytes, limit is {DEFAULT_MAX_BYTES} bytes",
        )
    if found.unsafe is not None:
        path, f = found.unsafe
        raise StrictJSONError(
            StrictJSONErrorKind.INTEGER,
            path,
            0,
            f"{f!r} is written as an integer literal outside ±{MAX_SAFE_INTEGER}",
        )
    return bytes_digest(canonical)


class _Floats:
    """The floats of a value that canonicalize_value accepted (so at most 16 deep)."""

    def __init__(self) -> None:
        self.negative_zeros = 0
        self.unsafe: tuple[str, float] | None = None  # the first, with its RFC 6901 path

    def walk(self, v: object, path: list[str]) -> None:
        if isinstance(v, float):
            if v == 0 and math.copysign(1.0, v) < 0:
                self.negative_zeros += 1
            elif self.unsafe is None and _UNSAFE_LOW < abs(v) < _EXPONENT_FORM and v.is_integer():
                pointer = "".join("/" + p.replace("~", "~0").replace("/", "~1") for p in path)
                self.unsafe = (pointer, v)
        elif isinstance(v, Mapping):
            for k in sorted(v, key=lambda k: k.encode("utf-16-be")):
                self.walk(v[k], [*path, k])
        elif isinstance(v, list | tuple):
            for i, x in enumerate(v):
                self.walk(x, [*path, str(i)])


# Floats in this range are written without an exponent, as integer literals
# when integral (ECMAScript Number::toString, and Go's encoding/json).
_UNSAFE_LOW: Final = float(MAX_SAFE_INTEGER)
_EXPONENT_FORM: Final = 1e21


def artifact_digest(compact: str) -> Digest:
    """Return artifact_digest(compact): the digest of the ASCII bytes of the compact JWS
    serialization compact, exactly as given. Raises ValueError for a character outside
    ASCII."""
    if not compact.isascii():
        i = next(i for i, c in enumerate(compact) if not c.isascii())
        raise ValueError(f"digest: artifact has non-ASCII character {compact[i]!r} at offset {i}")
    return bytes_digest(compact.encode("ascii"))


def bytes_digest(data: bytes) -> Digest:
    """Return bytes_digest(data): the base64url SHA-256 of data, without padding."""
    sum_ = hashlib.sha256(data).digest()
    return Digest(base64.urlsafe_b64encode(sum_).rstrip(b"=").decode("ascii"))


def _json(v: Any, depth: int) -> Any:
    """v with its dataclasses written as JSON objects. Past the depth limit the value is
    left as it is, for canonicalize_value to refuse."""
    if depth > DEFAULT_MAX_DEPTH:
        return v
    if dataclasses.is_dataclass(v) and not isinstance(v, type):
        members: Mapping[str, Any] | None = getattr(type(v), "_MEMBERS", None)
        out: dict[str, Any] = {}
        for f in dataclasses.fields(v):
            x = getattr(v, f.name)
            if members is not None:
                m = members.get(f.name)
                if m is None or (x is None and not m.required):
                    continue
            out[f.name] = _json(x, depth + 1)
        return out
    if isinstance(v, Mapping):
        return {k: _json(x, depth + 1) for k, x in v.items()}
    if isinstance(v, list | tuple):
        return [_json(x, depth + 1) for x in v]
    return v
