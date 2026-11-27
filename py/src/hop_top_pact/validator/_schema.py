"""Field-rule schemas and claim comparison (draft 8.4, 9.2, Appendix A.1).

JSON data here is what decode_json returns: dicts, lists, str, bool, None, int and Decimal,
so that a number keeps the exact value it was written with.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from decimal import Decimal
from fractions import Fraction
from typing import Any, Final

from hop_top_pact.core import jcs
from hop_top_pact.core.strictjson import StrictJSONError
from hop_top_pact.errors import PactError

__all__ = ["UnsupportedSchemaError"]


class UnsupportedSchemaError(PactError):
    """A field-rule schema the validator cannot evaluate as published: a keyword outside
    the restricted set of Appendix A.1, or a keyword with a malformed value. Such a rule
    is UNKNOWN with UNSUPPORTED_REQUIREMENT, never a permissive fallback (draft 22.2)."""

    def __init__(self, detail: str) -> None:
        self.detail = detail
        super().__init__(f"validator: unsupported field-rule schema: {detail}")


class _NotFound:
    def __repr__(self) -> str:
        return "NOT_FOUND"


NOT_FOUND: Final = _NotFound()
"""The result of a pointer that finds no value; JSON null is a value."""

# The nesting bound of a field-rule schema (Appendix A.1: the document's depth limits).
_MAX_SCHEMA_DEPTH: Final = 16

# The restricted Draft 2020-12 keyword set of Appendix A.1.
_KEYWORDS: Final = frozenset(
    {
        "type", "enum", "const", "properties", "required", "additionalProperties", "items",
        "minItems", "maxItems", "uniqueItems", "contains", "minContains", "maxContains",
        "minLength", "maxLength", "minimum", "maximum", "exclusiveMinimum",
        "exclusiveMaximum", "allOf", "anyOf", "oneOf", "not",
    }
)  # fmt: skip
_TYPES: Final = frozenset({"null", "boolean", "object", "array", "number", "string", "integer"})


def _no_constant(name: str) -> Any:
    raise ValueError(f"non-finite number {name}")


def decode_json(raw: bytes | str) -> Any:
    """Decode raw into JSON data, numbers kept exact (int, or Decimal for a fraction or an
    exponent). Raise ValueError."""
    return json.loads(raw, parse_float=Decimal, parse_constant=_no_constant)


def compile_schema(raw: bytes | str) -> Any:
    """Decode a field-rule schema and check that every keyword, at every depth, is one of
    Appendix A.1 with a well-formed value; raise UnsupportedSchemaError."""
    try:
        s = decode_json(raw)
    except ValueError as e:
        raise UnsupportedSchemaError(str(e)) from e
    return check_schema(s)


def check_schema(s: Any) -> Any:
    """Check an already decoded schema as compile_schema does and return it."""
    _check(s, 1)
    return s


def _check(s: Any, depth: int) -> None:
    if depth > _MAX_SCHEMA_DEPTH:
        raise UnsupportedSchemaError(f"nested deeper than {_MAX_SCHEMA_DEPTH}")
    if isinstance(s, bool):
        return
    if isinstance(s, Mapping):
        for k, v in s.items():
            if k not in _KEYWORDS:
                raise UnsupportedSchemaError(f"keyword {k!r}")
            _check_keyword(k, v, depth)
        return
    raise UnsupportedSchemaError("a schema is an object or a boolean")


def _is_list(v: Any) -> bool:
    return isinstance(v, list | tuple)


def _check_keyword(k: str, v: Any, depth: int) -> None:
    def bad() -> UnsupportedSchemaError:
        return UnsupportedSchemaError(f"malformed {k!r}")

    if k == "type":
        names = list(v) if _is_list(v) else [v]
        if not all(isinstance(n, str) and n in _TYPES for n in names):
            raise bad()
    elif k == "enum":
        if not _is_list(v):
            raise bad()
    elif k == "properties":
        if not isinstance(v, Mapping):
            raise bad()
        for sub in v.values():
            _check(sub, depth + 1)
    elif k == "required":
        if not _is_list(v) or not all(isinstance(n, str) for n in v):
            raise bad()
    elif k in ("additionalProperties", "items", "contains", "not"):
        _check(v, depth + 1)
    elif k in ("allOf", "anyOf", "oneOf"):
        if not _is_list(v) or len(v) == 0:
            raise bad()
        for sub in v:
            _check(sub, depth + 1)
    elif k in ("minItems", "maxItems", "minLength", "maxLength", "minContains", "maxContains"):
        n = rat_of(v)
        if n is None or n.denominator != 1 or n < 0:
            raise bad()
    elif k == "uniqueItems":
        if not isinstance(v, bool):
            raise bad()
    elif k in ("minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum") and rat_of(v) is None:
        raise bad()


def rat_of(v: Any) -> Fraction | None:
    """The exact value of a JSON number, or None for anything else."""
    if isinstance(v, bool) or not isinstance(v, int | Decimal):
        return None
    return Fraction(v)


def matches(s: Any, v: Any) -> bool:
    """Report whether the instance v satisfies the compiled schema s (JSON Schema Draft
    2020-12, restricted to Appendix A.1)."""
    if isinstance(s, bool):
        return s
    if isinstance(s, Mapping):
        return all(_keyword_holds(s, k, kv, v) for k, kv in s.items())
    return False


def _keyword_holds(s: Mapping[str, Any], k: str, kv: Any, v: Any) -> bool:
    if k == "type":
        names = list(kv) if _is_list(kv) else [kv]
        return any(_is_type(v, n) for n in names)
    if k == "enum":
        return any(json_equal(e, v) for e in kv)
    if k == "const":
        return json_equal(kv, v)
    if k == "not":
        return not matches(kv, v)
    if k in ("allOf", "anyOf", "oneOf"):
        hits = sum(1 for sub in kv if matches(sub, v))
        return (
            (k == "allOf" and hits == len(kv))
            or (k == "anyOf" and hits > 0)
            or (k == "oneOf" and hits == 1)
        )
    if isinstance(v, Mapping):
        return _object_holds(s, k, kv, v)
    if _is_list(v):
        return _array_holds(s, k, kv, v)
    if isinstance(v, str):
        n = rat_of(kv)
        if n is not None and k == "minLength":
            return len(v) >= n
        if n is not None and k == "maxLength":
            return len(v) <= n
        return True
    x = rat_of(v)
    if x is None:
        return True
    bound = rat_of(kv)
    if bound is None:
        return True
    if k == "minimum":
        return x >= bound
    if k == "maximum":
        return x <= bound
    if k == "exclusiveMinimum":
        return x > bound
    if k == "exclusiveMaximum":
        return x < bound
    return True


def _object_holds(s: Mapping[str, Any], k: str, kv: Any, v: Mapping[str, Any]) -> bool:
    if k == "properties":
        return all(matches(sub, v[name]) for name, sub in kv.items() if name in v)
    if k == "additionalProperties":
        props = s.get("properties")
        declared = props if isinstance(props, Mapping) else {}
        return all(name in declared or matches(kv, pv) for name, pv in v.items())
    if k == "required":
        return all(name in v for name in kv)
    return True


def _array_holds(s: Mapping[str, Any], k: str, kv: Any, v: Sequence[Any]) -> bool:
    def count(key: str, default: int) -> Fraction:
        n = rat_of(s.get(key))
        return n if n is not None else Fraction(default)

    length = Fraction(len(v))
    if k == "items":
        return all(matches(kv, item) for item in v)
    if k == "minItems":
        return length >= count(k, 0)
    if k == "maxItems":
        return length <= count(k, 0)
    if k == "uniqueItems":
        if kv:
            seen: set[bytes] = set()
            for item in v:
                c = canonical(item)
                if c is None or c in seen:
                    return False
                seen.add(c)
        return True
    if k == "contains":
        found = Fraction(sum(1 for item in v if matches(kv, item)))
        if found < count("minContains", 1):
            return False
        return not ("maxContains" in s and found > count("maxContains", 0))
    return True


def _is_type(v: Any, name: str) -> bool:
    if name == "null":
        return v is None
    if name == "boolean":
        return isinstance(v, bool)
    if name == "object":
        return isinstance(v, Mapping)
    if name == "array":
        return _is_list(v)
    if name == "string":
        return isinstance(v, str)
    if name == "number":
        return rat_of(v) is not None
    if name == "integer":
        n = rat_of(v)
        return n is not None and n.denominator == 1
    return False


def _plain(v: Any) -> Any:
    """v with its decimals written as floats, as the canonical form reads them."""
    if isinstance(v, Decimal):
        return float(v)
    if isinstance(v, Mapping):
        return {k: _plain(x) for k, x in v.items()}
    if _is_list(v):
        return [_plain(x) for x in v]
    return v


def canonical(v: Any) -> bytes | None:
    """The RFC 8785 form of JSON data: two values are equal as JSON data (draft 8.4) exactly
    when their canonical forms are. None when v has none."""
    try:
        return jcs.canonicalize_value(_plain(v))
    except (StrictJSONError, TypeError, OverflowError):
        return None


def json_equal(a: Any, b: Any) -> bool:
    """Report whether a and b are equal as JSON data."""
    ca = canonical(a)
    return ca is not None and ca == canonical(b)


_INDEX: Final = re.compile(r"[+-]?[0-9]+")


def pointer(doc: Any, p: str) -> Any:
    """Resolve an RFC 6901 JSON Pointer in JSON data; NOT_FOUND when there is no value."""
    if p == "":
        return doc
    if not p.startswith("/"):
        return NOT_FOUND
    cur = doc
    for tok in p[1:].split("/"):
        tok = tok.replace("~1", "/").replace("~0", "~")
        if isinstance(cur, Mapping):
            if tok not in cur:
                return NOT_FOUND
            cur = cur[tok]
        elif _is_list(cur):
            if _INDEX.fullmatch(tok) is None:
                return NOT_FOUND
            i = int(tok)
            if i < 0 or i >= len(cur) or (len(tok) > 1 and tok[0] == "0"):
                return NOT_FOUND
            cur = cur[i]
        else:
            return NOT_FOUND
    return cur


def compare(c: str, presented: Any, authoritative: Any) -> bool:
    """The claim comparison of draft 8.4."""
    if c == "equal":
        return json_equal(presented, authoritative)
    if c == "subset":
        p, a = _scalar_set(presented), _scalar_set(authoritative)
        return p is not None and a is not None and p <= a
    return False


def _scalar_set(v: Any) -> set[bytes] | None:
    """The canonical forms of an array of unique scalars."""
    if not _is_list(v):
        return None
    out: set[bytes] = set()
    for item in v:
        if isinstance(item, Mapping) or _is_list(item):
            return None
        c = canonical(item)
        if c is None or c in out:
            return None
        out.add(c)
    return out
