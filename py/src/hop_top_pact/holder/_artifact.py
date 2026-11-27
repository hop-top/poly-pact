"""Reading the artifacts an agent holds, and JSON Pointer lookups in them."""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any, Final, TypeVar

from hop_top_pact.adapter import Code
from hop_top_pact.core import VERSION, jcs, jws, limits, strictjson
from hop_top_pact.core.jws import base64url
from hop_top_pact.core.types import Evidence, JSONObject, JSONValue, ReputationSnapshot
from hop_top_pact.holder._errors import HolderError, unsupported_version

__all__ = [
    "MISSING",
    "Snapshot",
    "StoredEvidence",
    "array_index",
    "artifact",
    "lookup",
    "parse_evidence",
    "parse_snapshot",
    "peek",
    "pointer",
    "same_json",
    "version_of",
]

T = TypeVar("T")


class _Missing:
    def __repr__(self) -> str:
        return "MISSING"


MISSING: Final = _Missing()
"""The result of a lookup that finds no value; JSON null is a value."""


def peek(compact: str) -> tuple[bytes, str]:
    """The payload and the protected header typ of a compact JWS, decoded without verifying
    it. The holder reads the evidence and snapshots it was given only to select the ones a
    contract needs; the gateway verifies them under their issuers' authority (draft
    11.2). Raise ValueError for what is not a compact JWS with an attached payload."""
    seg = compact.split(".")
    if len(seg) != 3 or not all(seg):
        raise ValueError("not a compact JWS with an attached payload")
    try:
        header = base64url.decode(seg[0])
    except ValueError as e:
        raise ValueError(f"header: {e}") from e
    try:
        members = strictjson.decode(header, JSONObject)  # type: ignore[type-abstract]
    except strictjson.StrictJSONError as e:
        raise ValueError(f"header: {e}") from e
    typ = members.get("typ", "")
    if not isinstance(typ, str):
        raise ValueError("header typ: not a string")
    try:
        payload = base64url.decode(seg[1])
    except ValueError as e:
        raise ValueError(f"payload: {e}") from e
    return payload, typ


def version_of(payload: bytes) -> None:
    """Raise for a payload whose pact_version is a string other than 0.1 (draft 21). Other
    defects are left to the strict decoding."""
    try:
        v: Any = json.loads(payload)
    except ValueError:
        return
    s = v.get("pact_version") if isinstance(v, dict) else None
    if isinstance(s, str) and s != VERSION:
        raise unsupported_version(f"pact_version {s!r}, holder implements {VERSION!r}")


def artifact(compact: str, typ: str, cls: type[T]) -> tuple[bytes, T]:
    """Decode the compact JWS of slot typ into cls: the typ, the wire version, the draft
    20.1 payload limit and strict decoding."""
    try:
        payload, got = peek(compact)
    except ValueError as e:
        raise HolderError(Code.INVALID_MESSAGE, f"{typ}: {e}") from e
    if got != typ:
        raise HolderError(Code.INVALID_MESSAGE, f"typ {got!r} in a {typ} slot")
    version_of(payload)
    try:
        limits.validate_artifact_size(limits.defaults(), len(payload))
        return payload, strictjson.decode(payload, cls)
    except (limits.LimitError, strictjson.StrictJSONError) as e:
        raise HolderError(Code.INVALID_MESSAGE, f"{typ}: {e}") from e


class StoredEvidence:
    """An evidence artifact the agent holds."""

    __slots__ = ("claims", "compact")

    def __init__(self, compact: str, claims: Evidence) -> None:
        self.compact = compact
        self.claims = claims


class Snapshot:
    """A reputation snapshot the agent holds, with its value exactly as signed."""

    __slots__ = ("claims", "compact", "value")

    def __init__(self, compact: str, claims: ReputationSnapshot, value: JSONValue) -> None:
        self.compact = compact
        self.claims = claims
        self.value = value


def parse_evidence(compact: str) -> StoredEvidence:
    _, e = artifact(compact, jws.TYP_EVIDENCE, Evidence)
    return StoredEvidence(compact, e)


def parse_snapshot(compact: str) -> Snapshot:
    payload, s = artifact(compact, jws.TYP_REPUTATION, ReputationSnapshot)
    raw = strictjson.parse(payload)
    value = raw.get("value") if isinstance(raw, Mapping) else None
    return Snapshot(compact, s, value)


def pointer(p: str) -> list[str]:
    """Split an RFC 6901 JSON Pointer into its unescaped reference tokens. The empty
    pointer, the whole document, is not a field path. Raise ValueError."""
    if not p.startswith("/"):
        raise ValueError(f"path {p!r} is not a JSON Pointer to a member")
    tokens = p[1:].split("/")
    for i, t in enumerate(tokens):
        for j, c in enumerate(t):
            if c == "~" and (j + 1 == len(t) or t[j + 1] not in "01"):
                raise ValueError(f"path {p!r} has an invalid escape")
        tokens[i] = t.replace("~1", "/").replace("~0", "~")
    return tokens


def lookup(doc: object, tokens: list[str]) -> object:
    """The value at tokens in the JSON document doc (RFC 6901 section 4), or MISSING."""
    cur = doc
    for t in tokens:
        if isinstance(cur, Mapping):
            if t not in cur:
                return MISSING
            cur = cur[t]
        elif isinstance(cur, list | tuple):
            i = array_index(t)
            if i is None or i >= len(cur):
                return MISSING
            cur = cur[i]
        else:
            return MISSING
    return cur


def array_index(t: str) -> int | None:
    """An RFC 6901 array index: "0" or digits without a leading zero."""
    if not t or (len(t) > 1 and t[0] == "0") or not (t.isascii() and t.isdigit()):
        return None
    return int(t)


def same_json(a: object, b: object) -> bool:
    """Whether a and b are equal as JSON data: object member order is ignored, array order
    is significant (draft 8.4)."""
    try:
        return jcs.canonicalize_value(a) == jcs.canonicalize_value(b)
    except (strictjson.StrictJSONError, TypeError):
        return False
