"""Exact re-reads of signed payloads: the raw text of a top-level member, and JSON data whose
numbers keep the value they were written with (draft 8.4, Appendix A.1)."""

from __future__ import annotations

import json
from typing import Any

from hop_top_pact.core import strictjson
from hop_top_pact.validator import _schema

__all__ = ["exact_value", "raw_members"]

_DECODER = json.JSONDecoder()


def exact_value(data: bytes | str, limits: strictjson.Limits | None = None) -> Any:
    """Decode data as JSON data with exact numbers. It first applies the strict parse, so
    a text strictjson refuses (duplicate members, depth or size over the limits, invalid
    UTF-8, lone surrogates, out-of-range integers) is refused here with the same
    StrictJSONError; the exact reading follows only on text the strict parser accepted."""
    raw = data if isinstance(data, bytes) else data.encode("utf-8")
    strictjson.parse(raw, limits)
    return _schema.decode_json(raw.decode("utf-8"))


def raw_members(payload: bytes, limits: strictjson.Limits | None = None) -> dict[str, str]:
    """The text of each member of the top-level object of payload, as written. payload is
    strict-parsed first (see exact_value), so it is a valid JSON object text with distinct
    member names."""
    strictjson.parse(payload, limits)
    s = payload.decode("utf-8")
    out: dict[str, str] = {}
    i = _skip(s, 0)
    if i >= len(s) or s[i] != "{":
        raise strictjson.StrictJSONError(
            strictjson.StrictJSONErrorKind.TYPE, detail="not an object"
        )
    i = _skip(s, i + 1)
    if s[i] == "}":
        return out
    while True:
        key, i = _DECODER.raw_decode(s, i)
        i = _skip(s, i)
        i = _skip(s, i + 1)  # the colon
        _, end = _DECODER.raw_decode(s, i)
        out[key] = s[i:end]
        i = _skip(s, end)
        if s[i] == "}":
            return out
        i = _skip(s, i + 1)  # the comma


def _skip(s: str, i: int) -> int:
    while i < len(s) and s[i] in " \t\r\n":
        i += 1
    return i
