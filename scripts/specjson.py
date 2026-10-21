"""Strict JSON loading shared by the spec check scripts.

The loader enforces the parse rules of draft Section 7.1 that Python's json
module does not enforce by default: duplicate property names, non-finite
numbers (the NaN, Infinity and -Infinity constants, and a literal such as 1e999
that overflows to infinity) and invalid Unicode (a lone surrogate written as a
\\u escape) are rejected. A byte order mark and invalid UTF-8 are rejected too.

The check scripts load this file by path (importlib), not by import name, so
they keep running under `python3 -I`. Standard library only (Python 3.9 and
later).
"""

import json
import math
import re

__all__ = ["StrictJSONError", "loads", "load"]

_SURROGATE = re.compile("[\ud800-\udfff]")


class StrictJSONError(ValueError):
    """The text is not acceptable strict JSON."""


def _object(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise StrictJSONError("duplicate property name %s" % json.dumps(key))
        out[key] = value
    return out


def _constant(name):
    raise StrictJSONError("non-finite number %s" % name)


def _float(text):
    value = float(text)
    if not math.isfinite(value):
        raise StrictJSONError("non-finite number %s" % text)
    return value


def _check_strings(value):
    if isinstance(value, str):
        if _SURROGATE.search(value):
            raise StrictJSONError("invalid Unicode: lone surrogate in a string")
    elif isinstance(value, list):
        for item in value:
            _check_strings(item)
    elif isinstance(value, dict):
        for key, item in value.items():
            _check_strings(key)
            _check_strings(item)


def loads(text):
    """Parse one JSON text strictly; raise StrictJSONError otherwise."""
    try:
        value = json.loads(
            text,
            object_pairs_hook=_object,
            parse_constant=_constant,
            parse_float=_float,
        )
    except json.JSONDecodeError as exc:
        raise StrictJSONError("line %d column %d: %s" % (exc.lineno, exc.colno, exc.msg))
    _check_strings(value)
    return value


def load(path):
    """Read a file as UTF-8 and parse it strictly."""
    try:
        with open(path, "rb") as handle:
            raw = handle.read()
        text = raw.decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise StrictJSONError("cannot read as UTF-8: %s" % exc)
    return loads(text)
