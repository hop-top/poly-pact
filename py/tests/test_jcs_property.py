"""JCS over random JSON trees, checked against the rfc8785 oracle.

The counterpart of Go's FuzzCanonicalize. A fixed seed draws trees whose
doubles come from random 64-bit patterns (struct.unpack), so subnormals,
huge exponents and integral values beyond 2^53 occur. For every tree:
canonicalize_value equals the oracle; the canonical form of the tree's JSON
text equals it too; the output parses back to the same value and is
unchanged by a second pass, except where a float is written as an integer
literal beyond 2^53-1, which the strict parse refuses (as in Go).

PACT_FUZZ_EXAMPLES sets the number of trees (default 400) and
PACT_FUZZ_SEED the seed; make py-fuzz runs a long seeded pass.
"""

from __future__ import annotations

import json
import math
import os
import random
import struct
from typing import Any

import pytest
import rfc8785

from hop_top_pact.core import jcs, strictjson
from hop_top_pact.core.strictjson import MAX_SAFE_INTEGER, StrictJSONError, StrictJSONErrorKind

EXAMPLES = int(os.environ.get("PACT_FUZZ_EXAMPLES", "400"))
SEED = int(os.environ.get("PACT_FUZZ_SEED", "20261019"))
MAX_DEPTH = strictjson.DEFAULT_MAX_DEPTH

# Characters that stress string and key handling: the escapes, controls,
# DEL, the line separators, BMP and astral characters, and the code units
# around the surrogate range that sort differently by UTF-16 and by code point.
SPECIAL = '"\\/\b\f\n\r\t\x00\x01\x1f\x7f\u2028\u2029é€퟿￿\U00010000\U0001f602\U0010ffff'


def draw_double(rng: random.Random) -> float:
    while True:
        (f,) = struct.unpack("<d", rng.getrandbits(64).to_bytes(8, "little"))
        if math.isfinite(f):
            return float(f)


def draw_int(rng: random.Random) -> int:
    k = rng.choice((1, 4, 16, 32, 53))
    n = rng.getrandbits(k)
    n = min(n, MAX_SAFE_INTEGER)
    return -n if rng.random() < 0.5 else n


def draw_string(rng: random.Random) -> str:
    out = []
    for _ in range(rng.randrange(8)):
        r = rng.random()
        if r < 0.4:
            out.append(rng.choice(SPECIAL))
        elif r < 0.7:
            out.append(chr(rng.randrange(0x20, 0x7F)))
        else:
            c = rng.randrange(0x110000 - 0x800)
            out.append(chr(c + 0x800 if c >= 0xD800 else c))  # skip the surrogates
    return "".join(out)


def draw(rng: random.Random, depth: int) -> Any:
    r = rng.random()
    if depth < MAX_DEPTH and r < 0.25:
        return tuple(draw(rng, depth + 1) for _ in range(rng.randrange(4)))
    if depth < MAX_DEPTH and r < 0.5:
        return {draw_string(rng): draw(rng, depth + 1) for _ in range(rng.randrange(4))}
    if r < 0.7:
        return draw_double(rng)
    if r < 0.8:
        return draw_int(rng)
    if r < 0.9:
        return draw_string(rng)
    return rng.choice((None, True, False))


def deep(rng: random.Random) -> Any:
    # A tree at exactly the depth limit.
    v: Any = draw_double(rng)
    for _ in range(MAX_DEPTH):
        v = (v,) if rng.random() < 0.5 else {draw_string(rng): v}
    return v


def same(a: Any, b: Any) -> bool:
    """JSON value equality; numbers by value (JCS writes 1.0 as 1, -0.0 as 0)."""
    if isinstance(a, dict) and isinstance(b, dict):
        return a.keys() == b.keys() and all(same(a[k], b[k]) for k in a)
    if isinstance(a, tuple) and isinstance(b, tuple):
        return len(a) == len(b) and all(same(x, y) for x, y in zip(a, b, strict=True))
    if isinstance(a, bool) or isinstance(b, bool):
        return a is b
    if isinstance(a, int | float) and isinstance(b, int | float):
        return a == b
    return bool(a == b) and type(a) is type(b)


def beyond_safe_integer(v: Any) -> bool:
    """Whether a float of v is integral, beyond 2^53-1 and below 1e21 (written without exponent)."""
    if isinstance(v, dict):
        return any(beyond_safe_integer(x) for x in v.values())
    if isinstance(v, tuple):
        return any(beyond_safe_integer(x) for x in v)
    return isinstance(v, float) and MAX_SAFE_INTEGER < abs(v) < 1e21 and v.is_integer()


def check(tree: Any) -> None:
    out = jcs.canonicalize_value(tree)
    assert out == rfc8785.dumps(tree), tree
    for ascii_only in (False, True):
        text = json.dumps(tree, ensure_ascii=ascii_only).encode("utf-8")
        assert jcs.canonicalize(text) == out, text
    if beyond_safe_integer(tree):
        # An integral float beyond 2^53-1 is written as an integer literal.
        with pytest.raises(StrictJSONError) as ei:
            jcs.canonicalize(out)
        assert ei.value.kind is StrictJSONErrorKind.INTEGER, out
        return
    assert jcs.canonicalize(out) == out, out
    assert same(strictjson.parse(out), tree), out


def test_canonicalize_random_trees() -> None:
    rng = random.Random(SEED)  # noqa: S311 - a reproducible test sequence
    for i in range(EXAMPLES):
        tree = deep(rng) if i % 50 == 0 else draw(rng, 0)
        check(tree)


def test_canonicalize_random_doubles() -> None:
    rng = random.Random(SEED + 1)  # noqa: S311 - a reproducible test sequence
    for _ in range(EXAMPLES * 10):
        f = draw_double(rng)
        want = rfc8785.dumps(f)
        assert jcs.canonicalize_value(f) == want, f.hex()
        assert jcs.canonicalize(repr(f).encode("ascii")) == want, f.hex()
