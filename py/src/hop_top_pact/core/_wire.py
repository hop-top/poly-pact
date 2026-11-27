"""The JSON form of a wire value, and the canonical payload a signer signs. Private to
the package: the signing modules (contract, holder) share it."""

from __future__ import annotations

import dataclasses
from collections.abc import Mapping

from hop_top_pact.core import jcs
from hop_top_pact.core.types import Member

__all__ = ["payload", "to_json"]


def to_json(v: object) -> object:
    """v with its wire dataclasses written as JSON objects: the members of the type's
    table, an optional member left out when it is None, a required one written as
    null."""
    if dataclasses.is_dataclass(v) and not isinstance(v, type):
        members: Mapping[str, Member] | None = getattr(type(v), "_MEMBERS", None)
        out: dict[str, object] = {}
        for f in dataclasses.fields(v):
            x = getattr(v, f.name)
            if members is not None:
                m = members.get(f.name)
                if m is None or (x is None and not m.required):
                    continue
            out[f.name] = to_json(x)
        return out
    if isinstance(v, Mapping):
        return {k: to_json(x) for k, x in v.items()}
    if isinstance(v, list | tuple):
        return [to_json(x) for x in v]
    return v


def payload(v: object) -> bytes:
    """The RFC 8785 canonical JSON of the wire value v, which a strict decode reads back
    into an equal value. Raises what jcs.canonicalize_value raises."""
    return jcs.canonicalize_value(to_json(v))
