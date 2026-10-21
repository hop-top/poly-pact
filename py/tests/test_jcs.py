"""RFC 8785 canonicalization. Port of go/core/jcs/jcs_test.go and number_test.go.

Expected values were produced by the RFC 8785 Appendix A reference
canonicalizer running on V8 (as in the Go tests), not by this package. The
number tests drive canonicalize_value with a float, the counterpart of the
Go package's internal appendNumber.
"""

from __future__ import annotations

import math
import struct

import pytest

from hop_top_pact.core import jcs, strictjson
from hop_top_pact.core.strictjson import StrictJSONError, StrictJSONErrorKind
from hop_top_pact.core.types import JSONValue

K = StrictJSONErrorKind

CANONICALIZE: list[tuple[str, str, str]] = [
    (
        "whitespace dropped",
        ' { "b" : [ { "z" : 1 , "y" : [ ] } , { } ] , "a" : { "d" : null , "c" : true ,'
        ' "e" : false } } \n',
        '{"a":{"c":true,"d":null,"e":false},"b":[{"y":[],"z":1},{}]}',
    ),
    ("array order kept", '[3,1,2,"b","a"]', '[3,1,2,"b","a"]'),
    ("empty containers", "[[],{}]", "[[],{}]"),
    ("top-level string", '"x"', '"x"'),
    ("top-level number", "1.50", "1.5"),
    ("top-level null", "null", "null"),
    ("top-level true", "true", "true"),
    ("top-level false", "false", "false"),
    ("top-level minus zero", "-0", "0"),
    # Property names sort by UTF-16 code units. U+10000 is the surrogate pair
    # D800 DC00, which sorts before U+FFFF; by code point or by UTF-8 bytes it
    # would sort after.
    (
        "keys by UTF-16 units",
        '{"\\uffff":1,"\\ud800\\udc00":2,"a":3,"ab":4,"":5,"B":6}',
        '{"":5,"B":6,"a":3,"ab":4,"\U00010000":2,"\uffff":1}',
    ),
    ("keys are compared unescaped", '{"\\u0062":1,"a":2}', '{"a":2,"b":1}'),
    (
        "key escapes follow string rules",
        '{"\\u000a":1,"\\"":2,"\\\\":3,"/":4}',
        '{"\\n":1,"\\"":2,"/":4,"\\\\":3}',
    ),
    (
        "string escapes",
        '"\\u0000\\u0001\\u0008\\u0009\\u000a\\u000b\\u000c\\u000d\\u001f \\" \\\\ / \\u007f'
        " \\u2028 \\u2029 \\u00e9 \\ud83d\\ude02 <>&'\"",
        '"\\u0000\\u0001\\b\\t\\n\\u000b\\f\\r\\u001f \\" \\\\ / \x7f \u2028 \u2029 \u00e9'
        " \U0001f602 <>&'\"",
    ),
    ("string literal chars kept", '"\u00e9\u20ac\U0001f602"', '"\u00e9\u20ac\U0001f602"'),
    ("no unicode normalization", '"A\\u030a"', '"A\u030a"'),
    (
        "numbers",
        "[1.0, -0, -0.0, 1E+2, 0.1, 1e21, 1e-7, 1.5e300, 5e-324, 1e-400, 0.000001, 0.0000001,"
        " 1e20, 123456789.125, 4.35, 0.30000000000000004, 1e22, 1e23, 12345678901234567890e0,"
        " 100e-2, 9007199254740991, -9007199254740991, 1.7976931348623157e308, 2.5e-5]",
        "[1,0,0,100,0.1,1e+21,1e-7,1.5e+300,5e-324,0,0.000001,1e-7,100000000000000000000,"
        "123456789.125,4.35,0.30000000000000004,1e+22,1e+23,12345678901234567000,1,"
        "9007199254740991,-9007199254740991,1.7976931348623157e+308,0.000025]",
    ),
    # The port adds the two float edges of the plan: 1e-400 underflows to 0
    # and 2.5e-324 rounds to the smallest subnormal.
    ("float edges", "[1e-400,2.5e-324,-2.5e-324]", "[0,5e-324,-5e-324]"),
]


# The cases whose canonical form writes a float beyond 2^53-1 as an integer.
BEYOND_SAFE_INTEGER = {"numbers"}


@pytest.mark.parametrize(("name", "src", "want"), CANONICALIZE, ids=[c[0] for c in CANONICALIZE])
def test_canonicalize(name: str, src: str, want: str) -> None:
    data = src.encode("utf-8")
    orig = bytes(data)
    got = jcs.canonicalize(data)
    assert got == want.encode("utf-8"), name
    assert data == orig, "input was modified"
    # A canonical form is canonical. The one exception: a float such as 1e20
    # is written without an exponent, and strictjson rejects an integer
    # literal that large (see test_canonical_output_beyond_safe_integer).
    if name in BEYOND_SAFE_INTEGER:
        with pytest.raises(StrictJSONError) as ei:
            jcs.canonicalize(got)
        assert ei.value.kind is K.INTEGER, name
    else:
        assert jcs.canonicalize(got) == got, f"not idempotent: {name}"
    # The parsed tree canonicalizes to the same bytes as the text.
    assert jcs.canonicalize_value(strictjson.parse(data)) == got, name


REJECTS: list[tuple[str, bytes, StrictJSONErrorKind]] = [
    ("empty input", b"", K.SYNTAX),
    ("only whitespace", b" ", K.SYNTAX),
    ("truncated", b'{"a":', K.SYNTAX),
    ("trailing comma", b"[1,]", K.SYNTAX),
    ("duplicate key", b'{"a":1,"a":2}', K.DUPLICATE_KEY),
    ("duplicate key in escaped form", b'{"a":1,"\\u0061":2}', K.DUPLICATE_KEY),
    ("duplicate key nested", b'{"o":{"k":1,"k":1}}', K.DUPLICATE_KEY),
    ("NaN", b"NaN", K.NON_FINITE),
    ("Infinity", b"[Infinity]", K.NON_FINITE),
    ("negative Infinity", b"-Infinity", K.NON_FINITE),
    ("overflowing literal", b"1e999", K.NON_FINITE),
    ("negative overflowing literal", b'{"a":-1e999}', K.NON_FINITE),
    ("integer 2^53", b"9007199254740992", K.INTEGER),
    ("integer -2^53", b"[-9007199254740992]", K.INTEGER),
    ("integer far outside", b'{"a":123456789012345678901234567890}', K.INTEGER),
    ("lone high surrogate", b'"\\ud800"', K.LONE_SURROGATE),
    ("lone low surrogate", b'"\\udc00"', K.LONE_SURROGATE),
    ("invalid UTF-8", b'"\xff"', K.INVALID_UTF8),
    ("encoded surrogate", b'"\xed\xa0\x80"', K.INVALID_UTF8),
    ("trailing data", b"{} {}", K.TRAILING_DATA),
    ("too deep", b"[" * 17 + b"]" * 17, K.DEPTH),
    ("too large", b'"' + b"a" * strictjson.DEFAULT_MAX_BYTES + b'"', K.SIZE),
]


@pytest.mark.parametrize(("name", "data", "want"), REJECTS, ids=[r[0] for r in REJECTS])
def test_canonicalize_rejects(name: str, data: bytes, want: StrictJSONErrorKind) -> None:
    with pytest.raises(StrictJSONError) as ei:
        jcs.canonicalize(data)
    assert ei.value.kind is want, name


def test_canonical_output_beyond_safe_integer() -> None:
    # Integer literals beyond ±(2^53-1) are rejected on input, but a float
    # such as 1e20 is accepted and its canonical form is a plain integer
    # literal, which canonicalize in turn rejects.
    out = jcs.canonicalize(b"[1e20,1e21,9007199254740993.0]")
    assert out == b"[100000000000000000000,1e+21,9007199254740992]"
    with pytest.raises(StrictJSONError) as ei:
        jcs.canonicalize(out)
    assert ei.value.kind is K.INTEGER


def test_canonicalize_at_depth_limit() -> None:
    src = b'{"a":' * 16 + b"1" + b"}" * 16
    assert jcs.canonicalize(src) == src


def test_canonicalize_sorts_many_keys() -> None:
    n = 200
    src = "{" + ",".join(f'"k{n - 1 - i:03d}":{i}' for i in range(n)) + "}"
    want = "{" + ",".join(f'"k{i:03d}":{n - 1 - i}' for i in range(n)) + "}"
    assert jcs.canonicalize(src.encode("ascii")) == want.encode("ascii")


# The number serialization samples of RFC 8785 Appendix B, less NaN and
# Infinity, which JSON cannot carry (see test_append_number_non_finite).
APPENDIX_B: list[tuple[int, str]] = [
    (0x0000000000000000, "0"),
    (0x8000000000000000, "0"),
    (0x0000000000000001, "5e-324"),
    (0x8000000000000001, "-5e-324"),
    (0x7FEFFFFFFFFFFFFF, "1.7976931348623157e+308"),
    (0xFFEFFFFFFFFFFFFF, "-1.7976931348623157e+308"),
    (0x4340000000000000, "9007199254740992"),
    (0xC340000000000000, "-9007199254740992"),
    (0x4430000000000000, "295147905179352830000"),
    (0x44B52D02C7E14AF5, "9.999999999999997e+22"),
    (0x44B52D02C7E14AF6, "1e+23"),
    (0x44B52D02C7E14AF7, "1.0000000000000001e+23"),
    (0x444B1AE4D6E2EF4E, "999999999999999700000"),
    (0x444B1AE4D6E2EF4F, "999999999999999900000"),
    (0x444B1AE4D6E2EF50, "1e+21"),
    (0x3EB0C6F7A0B5ED8C, "9.999999999999997e-7"),
    (0x3EB0C6F7A0B5ED8D, "0.000001"),
    (0x41B3DE4355555553, "333333333.3333332"),
    (0x41B3DE4355555554, "333333333.33333325"),
    (0x41B3DE4355555555, "333333333.3333333"),
    (0x41B3DE4355555556, "333333333.3333334"),
    (0x41B3DE4355555557, "333333333.33333343"),
    (0xBECBF647612F3696, "-0.0000033333333333333333"),
    (0x43143FF3C1CB0959, "1424953923781206.2"),
]


def bits(b: int) -> float:
    f: float = struct.unpack(">d", b.to_bytes(8, "big"))[0]
    return f


def fmt(f: float) -> str:
    return jcs.canonicalize_value(f).decode("ascii")


@pytest.mark.parametrize(("b", "want"), APPENDIX_B, ids=[f"{b:016x}" for b, _ in APPENDIX_B])
def test_append_number_appendix_b(b: int, want: str) -> None:
    assert fmt(bits(b)) == want


# The ES6 layout switches at 10^21 and 10^-6; the exponent form carries an
# explicit sign and no padding. Expected values come from V8 (JSON.stringify).
LAYOUT: list[tuple[float, str]] = [
    (1e21, "1e+21"),
    (-1e21, "-1e+21"),
    (9.999999999999999e20, "999999999999999900000"),
    (1e20, "100000000000000000000"),
    (1.23e20, "123000000000000000000"),
    (123456789012345680000.0, "123456789012345680000"),
    (1.5e25, "1.5e+25"),
    (1e100, "1e+100"),
    (2.0**70, "1.1805916207174113e+21"),
    (1e15, "1000000000000000"),
    (100.0, "100"),
    (123.0, "123"),
    (22.0, "22"),
    (12.5, "12.5"),
    (1234.5678, "1234.5678"),
    (0.5, "0.5"),
    (1.0 / 3, "0.3333333333333333"),
    (0.1 + 0.2, "0.30000000000000004"),
    (1e-6, "0.000001"),
    (2e-6, "0.000002"),
    (1.5e-6, "0.0000015"),
    (4.5e-6, "0.0000045"),
    (0.000123, "0.000123"),
    (9.999999999999997e-7, "9.999999999999997e-7"),
    (5e-7, "5e-7"),
    (1e-7, "1e-7"),
    (1.5e-7, "1.5e-7"),
    (-1.5e-7, "-1.5e-7"),
    (1.2345e-100, "1.2345e-100"),
    (2.2250738585072014e-308, "2.2250738585072014e-308"),
    (5e-324, "5e-324"),
    (2.0**53, "9007199254740992"),
    (2.0**53 + 2, "9007199254740994"),
    (1.7976931348623157e308, "1.7976931348623157e+308"),
    (-1.7976931348623157e308, "-1.7976931348623157e+308"),
    (-0.0, "0"),
    (0.0, "0"),
]


@pytest.mark.parametrize(("f", "want"), LAYOUT, ids=[w for _, w in LAYOUT])
def test_append_number_layout(f: float, want: str) -> None:
    assert fmt(f) == want


def test_append_number_round_trip() -> None:
    # The output parses back to the same value, for the edge cases and for a
    # sweep over exponents: shortest digits never lose information.
    vals = [bits(b) for b, _ in APPENDIX_B]
    for e in range(-330, 309):
        for m in ("1", "1.5", "9.999999999999998", "7.123456789012345"):
            v = float(f"{m}e{e}")
            if math.isinf(v):
                continue  # beyond the largest double: not a value to format
            vals += [v, -v]
    for f in vals:
        s = fmt(f)
        assert float(s) == f, (f, s)


def test_append_number_keeps_prefix() -> None:
    assert jcs.canonicalize_value((1.5,)) == b"[1.5]"
    assert jcs.canonicalize_value({"a": 1.5}) == b'{"a":1.5}'


@pytest.mark.parametrize("f", [math.nan, math.inf, -math.inf])
def test_append_number_non_finite(f: float) -> None:
    with pytest.raises(StrictJSONError) as ei:
        jcs.canonicalize_value([1, {"x": f}])
    assert ei.value.kind is K.NON_FINITE
    assert ei.value.path == "/1/x"


def test_append_number_repr_digits_relaid() -> None:
    # repr writes 1e-07, 1e+16 and 5e-324; RFC 8785 writes the ECMAScript form.
    assert [fmt(f) for f in (1e-7, 1e16, 5e-324, 1e-6, 1e21)] == [
        "1e-7",
        "10000000000000000",
        "5e-324",
        "0.000001",
        "1e+21",
    ]


def test_canonicalize_value_integers() -> None:
    assert jcs.canonicalize_value([0, -0, 9007199254740991, -9007199254740991]) == (
        b"[0,0,9007199254740991,-9007199254740991]"
    )
    for n in (1 << 53, -(1 << 53), 10**30):
        with pytest.raises(StrictJSONError) as ei:
            jcs.canonicalize_value({"n": n})
        assert ei.value.kind is K.INTEGER
        assert ei.value.path == "/n"
    # bool is not an integer.
    assert jcs.canonicalize_value([True, False]) == b"[true,false]"


def test_canonicalize_value_depth() -> None:
    v: JSONValue = 1
    for _ in range(16):
        v = (v,)
    assert jcs.canonicalize_value(v) == b"[" * 16 + b"1" + b"]" * 16
    with pytest.raises(StrictJSONError) as ei:
        jcs.canonicalize_value({"a": v})
    assert ei.value.kind is K.DEPTH
    # A self-referencing list stops at the limit instead of recursing.
    loop: list[object] = []
    loop.append(loop)
    with pytest.raises(StrictJSONError) as ei:
        jcs.canonicalize_value(loop)
    assert ei.value.kind is K.DEPTH


def test_canonicalize_value_strings() -> None:
    assert jcs.canonicalize_value("\U0001f602\u2028") == '"\U0001f602\u2028"'.encode()
    # Two surrogate code points are not a character: a parsed value never holds them.
    with pytest.raises(StrictJSONError) as ei:
        jcs.canonicalize_value("\ud83d\ude02")
    assert ei.value.kind is K.LONE_SURROGATE
    with pytest.raises(StrictJSONError) as ei:
        jcs.canonicalize_value({"k": ["ok", "a\ud800"]})
    assert ei.value.kind is K.LONE_SURROGATE
    assert ei.value.path == "/k/1"
    with pytest.raises(StrictJSONError) as ei:
        jcs.canonicalize_value({"\udc00": 1})
    assert ei.value.kind is K.LONE_SURROGATE


@pytest.mark.parametrize("bad", [b"x", object(), {1: 2}, {"a": {1.5}}, bytearray(b"a")])
def test_canonicalize_value_rejects_non_json(bad: object) -> None:
    with pytest.raises(TypeError):
        jcs.canonicalize_value(bad)


def test_canonicalize_value_accepts_mappings_and_lists() -> None:
    from types import MappingProxyType

    v = MappingProxyType({"b": [1, {"d": None}], "a": "x"})
    assert jcs.canonicalize_value(v) == b'{"a":"x","b":[1,{"d":null}]}'
