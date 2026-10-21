"""Strict JSON decoding. Port of go/core/strictjson/strictjson_test.go.

Sample mirrors the Go test's sample struct: a pointer field becomes an
optional annotation (null allowed), json.RawMessage a JSONValue member, a
map a Mapping. test_go_verdicts replays testdata/strictjson-go-verdicts.json:
the kind, RFC 6901 path and byte offset that the Go package reports for each
input, recorded by running hop.top/pact-go/core/strictjson (Go 1.26.9) on the
same inputs with the same sample type, an untyped target (any), a
map[string]any and core.OperationContext.
"""

from __future__ import annotations

import base64
import io
import json
import random
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from hop_top_pact.core import strictjson
from hop_top_pact.core.strictjson import Limits, StrictJSONError, StrictJSONErrorKind
from hop_top_pact.core.types import JSONValue, OperationContext
from hop_top_pact.errors import PactError

K = StrictJSONErrorKind
TESTDATA = Path(__file__).resolve().parent / "testdata"


@dataclass(frozen=True, kw_only=True)
class Inner:
    n: int = 0


@dataclass(frozen=True, kw_only=True)
class Sample:
    name: str = ""
    count: int = 0
    ratio: float = 0.0
    opt: str | None = None
    opt_count: int | None = None
    inner: Inner | None = None
    items: tuple[Inner, ...] = ()
    raw: JSONValue = None
    headers: Mapping[str, str] = field(default_factory=dict)
    extensions: Mapping[str, JSONValue] = field(default_factory=dict)


def decode(data: str | bytes, lim: Limits | None = None) -> Sample:
    b = data.encode("utf-8") if isinstance(data, str) else data
    return strictjson.decode(b, Sample, lim or Limits())


def kind_of(data: str | bytes, lim: Limits | None = None) -> StrictJSONErrorKind:
    with pytest.raises(StrictJSONError) as ei:
        decode(data, lim)
    return ei.value.kind


def test_decode_valid() -> None:
    src = (
        '{"name":"a","count":9007199254740991,"ratio":1.5e3,"opt":null,"opt_count":7,'
        '"inner":{"n":0},"items":[{"n":1},{"n":2}],"raw":{"x":[1,2,{"y":null}]},'
        '"headers":{"x-a":"1"},"extensions":{"k":{"deep":[true,false,null]}}}'
    )
    got = decode(src)
    assert (got.name, got.count, got.ratio) == ("a", 9007199254740991, 1500.0)
    assert isinstance(got.ratio, float)
    assert got.opt is None
    assert got.opt_count == 7
    assert got.inner == Inner(n=0)
    assert got.items == (Inner(n=1), Inner(n=2))
    assert got.raw == {"x": (1, 2, {"y": None})}
    assert got.headers == {"x-a": "1"}
    assert got.extensions == {"k": {"deep": (True, False, None)}}


def deep_arrays(n: int) -> str:
    return '{"extensions":{"a":' + "[" * (n - 2) + "]" * (n - 2) + "}}"


REJECTS: list[tuple[str, str | bytes, Limits, StrictJSONErrorKind]] = [
    ("duplicate top level", '{"name":"a","name":"b"}', Limits(), K.DUPLICATE_KEY),
    ("duplicate same value", '{"name":"a","name":"a"}', Limits(), K.DUPLICATE_KEY),
    ("duplicate nested struct", '{"inner":{"n":1,"n":2}}', Limits(), K.DUPLICATE_KEY),
    ("duplicate in open map", '{"extensions":{"a":{"b":1,"b":2}}}', Limits(), K.DUPLICATE_KEY),
    ("duplicate in headers", '{"headers":{"x":"1","x":"2"}}', Limits(), K.DUPLICATE_KEY),
    ("duplicate in raw", '{"raw":{"a":1,"a":2}}', Limits(), K.DUPLICATE_KEY),
    ("duplicate in array element", '{"items":[{"n":1},{"n":1,"n":1}]}', Limits(), K.DUPLICATE_KEY),
    ("duplicate after unescape", '{"name":"a","\\u006eame":"b"}', Limits(), K.DUPLICATE_KEY),
    ("unknown field", '{"name":"a","bogus":1}', Limits(), K.UNKNOWN_FIELD),
    ("unknown nested field", '{"inner":{"n":1,"m":2}}', Limits(), K.UNKNOWN_FIELD),
    ("unknown field in array element", '{"items":[{"n":1,"m":2}]}', Limits(), K.UNKNOWN_FIELD),
    ("case variant is unknown", '{"Name":"a"}', Limits(), K.UNKNOWN_FIELD),
    ("case variant beside real field", '{"name":"a","NAME":"b"}', Limits(), K.UNKNOWN_FIELD),
    (
        "depth 17 objects",
        '{"extensions":' + '{"a":' * 15 + "{}" + "}" * 15 + "}",
        Limits(),
        K.DEPTH,
    ),
    ("depth 17 arrays", deep_arrays(17), Limits(), K.DEPTH),
    ("custom depth", '{"raw":[[1]]}', Limits(max_depth=2), K.DEPTH),
    ("1e999", '{"ratio":1e999}', Limits(), K.NON_FINITE),
    ("-1e999 in raw", '{"raw":-1e999}', Limits(), K.NON_FINITE),
    ("NaN", '{"raw":NaN}', Limits(), K.NON_FINITE),
    ("Infinity", '{"raw":Infinity}', Limits(), K.NON_FINITE),
    ("-Infinity", '{"raw":-Infinity}', Limits(), K.NON_FINITE),
    ("invalid utf8 byte", b'{"name":"\xff"}', Limits(), K.INVALID_UTF8),
    ("invalid utf8 in key", b'{"na\xc0me":1}', Limits(), K.INVALID_UTF8),
    ("lone high surrogate", '{"name":"\\ud800"}', Limits(), K.LONE_SURROGATE),
    ("lone low surrogate", '{"name":"\\udc00"}', Limits(), K.LONE_SURROGATE),
    ("high then bmp", '{"name":"\\ud800A"}', Limits(), K.LONE_SURROGATE),
    ("reversed pair", '{"name":"\\udc00\\ud800"}', Limits(), K.LONE_SURROGATE),
    ("surrogate in key", '{"extensions":{"\\ud800":1}}', Limits(), K.LONE_SURROGATE),
    (
        "escaped backslash is not a surrogate escape guard",
        '{"name":"\\\\\\ud800"}',
        Limits(),
        K.LONE_SURROGATE,
    ),
    ("integer 2^53", '{"raw":9007199254740992}', Limits(), K.INTEGER),
    ("integer -2^53", '{"raw":-9007199254740992}', Limits(), K.INTEGER),
    ("integer huge", '{"raw":123456789012345678901234567890}', Limits(), K.INTEGER),
    ("integer of 5000 digits", '{"raw":' + "9" * 5000 + "}", Limits(), K.INTEGER),
    ("typed integer overflow", '{"count":9007199254740992}', Limits(), K.INTEGER),
    ("typed integer negative", '{"count":-1}', Limits(), K.INTEGER),
    ("typed integer fraction", '{"count":1.5}', Limits(), K.INTEGER),
    ("typed integer exponent form", '{"count":1e3}', Limits(), K.INTEGER),
    ("typed integer 1.0", '{"count":1.0}', Limits(), K.INTEGER),
    ("nullable integer negative", '{"opt_count":-5}', Limits(), K.INTEGER),
    ("trailing text", '{"name":"a"} x', Limits(), K.TRAILING_DATA),
    ("trailing value", '{"name":"a"}{}', Limits(), K.TRAILING_DATA),
    ("trailing brace", '{"name":"a"}}', Limits(), K.TRAILING_DATA),
    ("empty input", "", Limits(), K.SYNTAX),
    ("whitespace only", " \n", Limits(), K.SYNTAX),
    ("truncated", '{"name":"a"', Limits(), K.SYNTAX),
    ("bom", b"\xef\xbb\xbf{}", Limits(), K.SYNTAX),
    ("leading zero", '{"raw":01}', Limits(), K.SYNTAX),
    ("single quotes", "{'name':'a'}", Limits(), K.SYNTAX),
    ("trailing comma", '{"name":"a",}', Limits(), K.SYNTAX),
    ("too large", '{"name":"' + "a" * 64 + '"}', Limits(max_bytes=32), K.SIZE),
    ("null for string", '{"name":null}', Limits(), K.NULL),
    ("null for integer", '{"count":null}', Limits(), K.NULL),
    ("null for slice", '{"items":null}', Limits(), K.NULL),
    ("null for map", '{"headers":null}', Limits(), K.NULL),
    ("null document", "null", Limits(), K.NULL),
    ("type mismatch", '{"name":5}', Limits(), K.TYPE),
    ("type mismatch object", '{"name":{}}', Limits(), K.TYPE),
]


@pytest.mark.parametrize(("name", "data", "lim", "want"), REJECTS, ids=[r[0] for r in REJECTS])
def test_decode_rejects(
    name: str, data: str | bytes, lim: Limits, want: StrictJSONErrorKind
) -> None:
    assert kind_of(data, lim) is want, name


ACCEPTS: list[tuple[str, str, Limits]] = [
    (
        "depth 16 objects",
        '{"extensions":' + '{"a":' * 14 + "{}" + "}" * 14 + "}",
        Limits(),
    ),
    ("depth 16 arrays", deep_arrays(16), Limits()),
    ("max safe integer", '{"count":9007199254740991,"raw":9007199254740991}', Limits()),
    ("negative max safe in raw", '{"raw":-9007199254740991}', Limits()),
    ("zero count", '{"count":0}', Limits()),
    ("negative zero in raw", '{"raw":-0}', Limits()),
    ("largest finite float", '{"ratio":1.7976931348623157e308}', Limits()),
    ("negative float", '{"ratio":-12.5}', Limits()),
    ("float underflow is finite", '{"ratio":1e-999}', Limits()),
    ("surrogate pair", '{"name":"\U0001f600"}', Limits()),
    ("escaped surrogate pair", '{"name":"\\ud83d\\ude00"}', Limits()),
    ("escaped backslash then u", '{"name":"\\\\ud800"}', Limits()),
    ("replacement char literal", '{"name":"�"}', Limits()),
    ("case distinct keys in open map", '{"extensions":{"a":1,"A":2}}', Limits()),
    ("same key in sibling objects", '{"items":[{"n":1},{"n":2}],"inner":{"n":3}}', Limits()),
    ("trailing whitespace", '{"name":"a"}\n \t\r\n', Limits()),
    ("leading whitespace", ' \n{"name":"a"}', Limits()),
    ("null in raw", '{"raw":null}', Limits()),
    ("null in nullable", '{"opt":null,"opt_count":null}', Limits()),
    ("null in nullable struct pointer", '{"inner":null}', Limits()),
    ("custom depth", '{"raw":[[1]]}', Limits(max_depth=3)),
    ("exact size", '{"name":"a"}', Limits(max_bytes=12)),
    ("empty object", "{}", Limits()),
]


@pytest.mark.parametrize(("name", "data", "lim"), ACCEPTS, ids=[a[0] for a in ACCEPTS])
def test_decode_accepts(name: str, data: str, lim: Limits) -> None:
    assert isinstance(decode(data, lim), Sample), name


def test_decode_float_edges() -> None:
    # Go's ParseFloat returns 0 for 1e-400 without an error and 5e-324 for
    # 2.5e-324 (round half to even onto the smallest subnormal).
    got = decode('{"ratio":1e-400}')
    assert got.ratio == 0.0
    got = decode('{"ratio":2.5e-324}')
    assert got.ratio == 5e-324
    assert strictjson.parse(b"[1e-400,2.5e-324,-0.0]") == (0.0, 5e-324, -0.0)
    neg = strictjson.parse(b"-0.0")
    assert isinstance(neg, float)
    assert str(neg) == "-0.0"


def test_decode_free_form_target() -> None:
    assert strictjson.parse(b'{"a":[1,{"b":null}],"A":2}') == {"a": (1, {"b": None}), "A": 2}
    with pytest.raises(StrictJSONError) as ei:
        strictjson.parse(b'{"a":1,"a":2}')
    assert ei.value.kind is K.DUPLICATE_KEY
    with pytest.raises(StrictJSONError) as ei:
        strictjson.decode(b'{"x":9007199254740992}', Mapping[str, Any])  # type: ignore[type-abstract]
    assert ei.value.kind is K.INTEGER


@pytest.mark.parametrize(
    ("name", "data"),
    [
        ("walk failure", '{"name":"new","count":-1}'),
        ("decode failure", '{"name":"new","count":"x"}'),
    ],
)
def test_decode_does_not_fill_target_on_failure(name: str, data: str) -> None:
    # A failed decode returns nothing: there is no target to leave half filled.
    got: Sample | None = None
    with pytest.raises(StrictJSONError):
        got = decode(data)
    assert got is None, name


def test_decode_replaces_target() -> None:
    got = decode('{"headers":{"new":"2"}}')
    assert got.name == ""
    assert got.headers == {"new": "2"}


@pytest.mark.parametrize("target", [None, Sample(), 5, "Sample", list, bytes])
def test_decode_bad_target(target: Any) -> None:
    with pytest.raises(StrictJSONError) as ei:
        strictjson.decode(b"{}", target)
    assert ei.value.kind is K.TARGET


def test_unmarshal_matches_decode() -> None:
    data = b'{"name":"a","name":"b"}'
    for f in (
        lambda: strictjson.decode(data, Sample),
        lambda: strictjson.parse(data),
        lambda: strictjson.parse_stream(io.BytesIO(data)),
    ):
        with pytest.raises(StrictJSONError) as ei:
            f()
        assert ei.value.kind is K.DUPLICATE_KEY


def test_parse_stream_reads_at_most_one_byte_over_the_limit() -> None:
    class Counting(io.RawIOBase):
        def __init__(self, n: int) -> None:
            self.left, self.read_bytes = n, 0

        def readable(self) -> bool:
            return True

        def readinto(self, b: Any) -> int:
            k = min(len(b), self.left, 7)  # short reads
            b[:k] = b" " * k
            self.left -= k
            self.read_bytes += k
            return k

    src = Counting(10_000)
    with pytest.raises(StrictJSONError) as ei:
        strictjson.parse_stream(src, Limits(max_bytes=100))
    assert ei.value.kind is K.SIZE
    assert src.read_bytes == 101
    assert strictjson.parse_stream(io.BytesIO(b' {"a":[1]} '), Limits(max_bytes=11)) == {"a": (1,)}


def test_error_names_path_and_offset() -> None:
    with pytest.raises(StrictJSONError) as ei:
        decode('{"inner":{"n":1,"m":2}}')
    assert "/inner/m" in str(ei.value)
    assert "(offset 19)" in str(ei.value)


def test_depth_is_checked_before_body_is_read() -> None:
    # A hostile document opens many containers; the walk must stop at the
    # limit instead of tracking the whole input.
    with pytest.raises(StrictJSONError) as ei:
        strictjson.parse(b"[" * 100000, Limits(max_bytes=1 << 20))
    assert ei.value.kind is K.DEPTH


def test_depth_does_not_depend_on_the_recursion_limit() -> None:
    # A configured depth far above the interpreter's recursion limit holds.
    n = 200_000
    deep = b"[" * n + b"]" * n
    assert strictjson.parse(deep, Limits(max_bytes=1 << 20, max_depth=n)) is not None
    with pytest.raises(StrictJSONError) as ei:
        strictjson.parse(deep, Limits(max_bytes=1 << 20, max_depth=n - 1))
    assert ei.value.kind is K.DEPTH
    assert ei.value.offset == n


def test_example_decode() -> None:
    @dataclass(frozen=True)
    class V:
        name: str = ""

    with pytest.raises(StrictJSONError) as ei:
        strictjson.decode(b'{"name":"a","name":"b"}', V)
    assert ei.value.kind is K.DUPLICATE_KEY


def test_error_fields() -> None:
    with pytest.raises(StrictJSONError) as ei:
        decode('{"items":[{"n":1},{"n":1,"x~/":2}]}')
    e = ei.value
    assert e.kind is K.UNKNOWN_FIELD
    assert e.path == "/items/1/x~0~1"
    assert e.offset > 0
    assert isinstance(e, PactError)


def test_error_string() -> None:
    e = StrictJSONError(K.DUPLICATE_KEY, "/a", 7, '"a"')
    assert str(e) == 'strictjson: duplicate member name: "a" at /a (offset 7)'
    assert str(StrictJSONError(K.SYNTAX)) == "strictjson: invalid JSON (offset 0)"


TARGETS: dict[str, Any] = {
    "sample": Sample,
    "any": None,
    "map": Mapping[str, Any],
    "op": OperationContext,
}


def verdict_rows() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = json.loads(
        (TESTDATA / "strictjson-go-verdicts.json").read_text(encoding="utf-8")
    )
    return rows


def row_input(row: Mapping[str, Any]) -> bytes:
    if "input_b64" in row:
        return base64.b64decode(row["input_b64"])
    if "input_repeat" in row:
        text, count = row["input_repeat"]
        return str(text).encode("utf-8") * int(count)
    return str(row["input_text"]).encode("utf-8")


@pytest.mark.parametrize("row", verdict_rows(), ids=lambda r: str(r["name"]))
def test_go_verdicts(row: dict[str, Any]) -> None:
    data = row_input(row)
    lim = Limits(max_bytes=row.get("max_bytes", 0), max_depth=row.get("max_depth", 0))
    target = TARGETS[row["target"]]
    try:
        if target is None:
            strictjson.parse(data, lim)
        else:
            strictjson.decode(data, target, lim)
    except StrictJSONError as e:
        got = {"kind": str(e.kind), "path": e.path, "offset": e.offset}
    else:
        got = {"kind": "accept"}
    want = {k: row[k] for k in ("kind", "path", "offset") if k in row}
    assert got == want


SEEDS = [
    b"{}",
    b'{"name":"a"}',
    b'{"name":"a","name":"b"}',
    b'{"count":9007199254740992}',
    b'{"raw":[[[[[[[[[[[[[[[[[1]]]]]]]]]]]]]]]]]}',
    b'{"name":"\\ud800"}',
    b'{"name":"\xff"}',
    b'{"ratio":1e999}',
    b'{"raw":NaN}',
    b"{} x",
    b"",
    b"[",
    b'{"inner":{"n":1}}',
    b'{"extensions":{"a":{"a":1}}}',
]


def sample_json(s: Sample) -> bytes:
    def value(v: Any) -> Any:
        if isinstance(v, Inner | Sample):
            return {k: value(getattr(v, k)) for k in v.__dataclass_fields__}
        if isinstance(v, tuple):
            return [value(x) for x in v]
        if isinstance(v, Mapping):
            return {k: value(x) for k, x in v.items()}
        return v

    return json.dumps(value(s), ensure_ascii=False).encode("utf-8")


def test_unmarshal_fuzz_seeds() -> None:
    # The seeded counterpart of Go's FuzzUnmarshal: an accepted input is valid
    # JSON and survives a second strict decode of its own re-encoding; no
    # input raises anything but StrictJSONError.
    rng = random.Random(20261019)  # noqa: S311 - a reproducible test sequence
    inputs = list(SEEDS)
    for seed in SEEDS:
        for _ in range(40):
            b = bytearray(seed)
            for _ in range(rng.randint(1, 3)):
                op = rng.randrange(3)
                i = rng.randrange(len(b) + 1)
                if op == 0:
                    b[i:i] = bytes([rng.randrange(256)])
                elif op == 1 and b:
                    del b[min(i, len(b) - 1)]
                elif b:
                    b[min(i, len(b) - 1)] = rng.choice(b'{}[]",:0123456789-+.eEtrufalsn\\u ')
            inputs.append(bytes(b))
    for data in inputs:
        try:
            s = strictjson.decode(data, Sample)
        except StrictJSONError:
            continue
        json.loads(data.decode("utf-8"))
        again = strictjson.decode(sample_json(s), Sample)
        assert again == s, data
