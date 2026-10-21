"""Object, artifact and bytes digests. Port of go/core/digest/digest_test.go and
the Digest.Validate test of go/core/digest_test.go.

The Go tests that pass json.RawMessage hold received JSON text; in the port
received JSON is a parsed value (the strict parse refuses what the raw-text
cases test, such as a duplicate member), so those cases run through
strictjson.parse first.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any

import pytest

from hop_top_pact.core import DIGEST_LEN, Digest, digest, strictjson
from hop_top_pact.core.digest import NotObjectError
from hop_top_pact.core.strictjson import StrictJSONError, StrictJSONErrorKind
from hop_top_pact.core.types import Intent, OperationContext
from hop_top_pact.errors import PactError

K = StrictJSONErrorKind

# body_digest of draft Appendix B.3, the digest of zero bytes.
BODY_DIGEST_OF_EMPTY = "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"
# operation_digest and intent_digest of draft Appendix B.4, the digests of the
# B.3 and B.2 objects.
OPERATION_DIGEST_B3 = "R5nfhv7g_o93VPHK6a2o56-MyyGy75GQwXxDM4M3cn0"
INTENT_DIGEST_B2 = "t79YgXU70gzKitcuPJ_fUp4V_bM5MGooinyuyL8cE5M"
# SHA-256("abc"), the FIPS 180-4 example (hex ba7816bf...15ad), base64url.
DIGEST_OF_ABC = "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0"
# A JWS with the payload "{}" (e30) and the header {"alg":"ES256"}; the digest
# is SHA-256 over its 29 ASCII bytes, computed outside Go.
SHORT_JWS = "eyJhbGciOiJFUzI1NiJ9.e30.c2ln"
DIGEST_OF_SHORT_J = "E2ttONh1sD1zwHXFE8fH21SGQ5my65IRYl87KWSpu9o"


@dataclass(frozen=True)
class Text:
    """Received JSON text, parsed by the strict parse when the test runs."""

    data: bytes
    depth: int = 0


def resolve(v: Any) -> Any:
    if isinstance(v, Text):
        return strictjson.parse(v.data, strictjson.Limits(max_depth=v.depth))
    if isinstance(v, tuple):
        return tuple(resolve(x) for x in v)
    return v


def check_shape(d: str) -> None:
    assert isinstance(d, Digest)
    d.validate()
    assert not any(c in d for c in "=+/")


@pytest.mark.parametrize(
    ("name", "data", "want"),
    [
        ("empty", b"", BODY_DIGEST_OF_EMPTY),
        ("abc", b"abc", DIGEST_OF_ABC),
        ("bytearray", bytearray(b"abc"), DIGEST_OF_ABC),
    ],
)
def test_bytes_digest(name: str, data: bytes, want: str) -> None:
    got = digest.bytes_digest(data)
    assert got == want, name
    check_shape(got)


def test_artifact_digest() -> None:
    got = digest.artifact_digest(SHORT_JWS)
    assert got == DIGEST_OF_SHORT_J
    check_shape(got)
    assert got == digest.bytes_digest(SHORT_JWS.encode("ascii"))
    # The exact string, no trimming.
    assert digest.artifact_digest(SHORT_JWS + "\n") != got
    assert digest.artifact_digest("") == BODY_DIGEST_OF_EMPTY
    for s in ("é", SHORT_JWS + "é", "a\x80b", "\xff", "a\u2028b"):
        with pytest.raises(ValueError, match="non-ASCII"):
            digest.artifact_digest(s)


def canonical(text: str) -> str:
    """The digest of a hand-written RFC 8785 text."""
    return digest.bytes_digest(text.encode("utf-8"))


@dataclass(frozen=True)
class Unsorted:
    z: int
    a: str


CANONICAL_FORM: list[tuple[str, Any, str]] = [
    ("map members sorted", {"b": 2, "a": 1}, '{"a":1,"b":2}'),
    ("struct members sorted", Unsorted(z=1, a="x"), '{"a":"x","z":1}'),
    ("no HTML escaping", {"s": "<a>&b"}, '{"s":"<a>&b"}'),
    ("line separator is literal", {"s": "\u2028"}, '{"s":"\u2028"}'),
    # U+1F600 is the surrogate pair D83D DE00 in UTF-16 and sorts before
    # U+FF5E, while UTF-8 byte order puts it after.
    (
        "member names sort by UTF-16 code units",
        {"\uff5e": 2, "\U0001f600": 1},
        '{"\U0001f600":1,"\uff5e":2}',
    ),
    (
        "ECMAScript numbers",
        {"n": [-0.0, 1e21, 4.5, 100.0, 1e-7]},
        '{"n":[0,1e+21,4.5,100,1e-7]}',
    ),
    ("largest safe integer", {"n": (1 << 53) - 1}, '{"n":9007199254740991}'),
    ("empty containers", {"b": [], "a": {}}, '{"a":{},"b":[]}'),
    (
        "nested objects and null",
        {"z": None, "a": [{"y": True, "x": False}]},
        '{"a":[{"x":false,"y":true}],"z":null}',
    ),
    ("string escapes", {"s": 'q"\\\n\t\x01\x7f'}, '{"s":"q\\"\\\\\\n\\t\\u0001\x7f"}'),
    (
        "raw JSON text is canonicalized, not copied",
        Text(b' {\n  "b" : [ 1 , 2 ],\r\n  "a" : "x" }\n'),
        '{"a":"x","b":[1,2]}',
    ),
]


@pytest.mark.parametrize(
    ("name", "value", "want"), CANONICAL_FORM, ids=[c[0] for c in CANONICAL_FORM]
)
def test_object_digest_canonical_form(name: str, value: Any, want: str) -> None:
    got = digest.object_digest(resolve(value))
    assert got == canonical(want), name
    check_shape(got)


def test_object_digest_appendix_b_structs() -> None:
    # The core types, whose member order is not the sorted order, against the
    # values of the draft.
    op = OperationContext(
        operation_id="invoice-read-operation-0001",
        environment_id="https://gateway.example/environments/finance",
        principal_id="https://identity.example/principals/alice",
        action="invoice.read",
        resources=("https://invoices.example/invoices/INV-1042",),
        method="GET",
        target_uri="https://gateway.example/invoices/INV-1042",
        body_digest=BODY_DIGEST_OF_EMPTY,
        headers={},
    )
    assert digest.object_digest(op) == OPERATION_DIGEST_B3
    intent = Intent(
        intent_id="intent-september-invoices-007",
        purpose_id="https://policies.example/purposes/invoice-summary/v1",
        description="Read the approved September invoice to prepare the department summary.",
        task_id="native-task:september-summary-007",
    )
    assert digest.object_digest(intent) == INTENT_DIGEST_B2
    # An absent optional member is left out, as Go's omitzero does.
    assert digest.object_digest({"x": [intent]}) == canonical(
        '{"x":[{"description":"Read the approved September invoice to prepare the department'
        ' summary.","intent_id":"intent-september-invoices-007","purpose_id":'
        '"https://policies.example/purposes/invoice-summary/v1","task_id":'
        '"native-task:september-summary-007"}]}'
    )


@pytest.mark.parametrize(
    "value",
    [
        None,
        [{"a": 1}],
        [],
        "x",
        1,
        True,
        1.5,
        b'{"a":1}',
        Text(b"[{}]"),
        Text(b'"x"'),
        Text(b" 1 "),
        Text(b"null"),
        (Text(b"{}"),),
    ],
)
def test_object_digest_rejects_non_objects(value: Any) -> None:
    with pytest.raises(NotObjectError):
        digest.object_digest(resolve(value))


def nested(depth: int) -> Text:
    return Text(b'{"a":' * (depth - 1) + b"{}" + b"}" * (depth - 1), depth)


@pytest.mark.parametrize(
    ("name", "value", "want"),
    [
        ("NaN", {"n": math.nan}, K.NON_FINITE),
        ("Infinity", {"n": math.inf}, K.NON_FINITE),
        ("integer above 2^53-1", {"n": 1 << 53}, K.INTEGER),
        ("integer below -(2^53-1)", {"n": -(1 << 53)}, K.INTEGER),
        ("nesting depth 17", nested(17), K.DEPTH),
        ("lone surrogate", {"a": "\ud800"}, K.LONE_SURROGATE),
        ("over 256 KiB", {"s": "a" * strictjson.DEFAULT_MAX_BYTES}, K.SIZE),
    ],
)
def test_object_digest_limits(name: str, value: Any, want: StrictJSONErrorKind) -> None:
    with pytest.raises(StrictJSONError) as ei:
        digest.object_digest(resolve(value))
    assert ei.value.kind is want, name


def test_object_digest_limits_unsupported_type() -> None:
    with pytest.raises(TypeError):
        digest.object_digest({"c": object()})


@pytest.mark.parametrize(
    ("name", "text", "want"),
    [
        ("duplicate member", b'{"a":1,"a":2}', K.DUPLICATE_KEY),
        ("duplicate member, escaped", b'{"a":1,"\\u0061":2}', K.DUPLICATE_KEY),
        ("invalid UTF-8", b'{"a":"\xff"}', K.INVALID_UTF8),
        ("lone surrogate escape", b'{"a":"\\ud800"}', K.LONE_SURROGATE),
        ("malformed raw JSON", b'{"a":', K.SYNTAX),
    ],
)
def test_object_digest_limits_received_text(
    name: str, text: bytes, want: StrictJSONErrorKind
) -> None:
    # Received text reaches object_digest only through the strict parse.
    with pytest.raises(StrictJSONError) as ei:
        digest.object_digest(strictjson.parse(text))
    assert ei.value.kind is want, name


# Go's verdicts (hop.top/pact-go/core/digest.ObjectDigest, Go 1.26.9) for
# {"n": f}: an integral float above 2^53-1 and below 1e21 is written as an
# integer literal, which the strict re-parse refuses with ErrInteger.
GO_FLOAT_VERDICTS: list[tuple[float, str | None]] = [
    (float(1 << 53), None),
    (-float(1 << 53), None),
    (9007199254740991.0, "4dpIxqYInwbstOCiJZ5ljjeGskIPUrrM35KexkYNe0E"),
    (1e20, None),
    (9.999999999999999e20, None),
    (1e21, "8e4rYO6VoxcP3Aeld-XzUUztJoZ0Q9adomWsrerYEAc"),
    (1e16, None),
    (1.5e300, "UcmMvoGqYIL71tiCcu99Go78jW8T6xbII3YTkVBnZ2A"),
    (1e-7, "dH1tI7ZNGy1XmtuDK0TeMckch1u-96jjl_XRg6dGtUs"),
    (-0.0, "8wE_kzufuAq22ZXnrZ2jb2g4N7odgelQyUPUARHqwvA"),
    (123456789012345680000.0, None),
]


@pytest.mark.parametrize(
    ("f", "want"), GO_FLOAT_VERDICTS, ids=[repr(f) for f, _ in GO_FLOAT_VERDICTS]
)
def test_object_digest_limits_float_of_integer_value(f: float, want: str | None) -> None:
    if want is not None:
        assert digest.object_digest({"n": f}) == want
        return
    with pytest.raises(StrictJSONError) as ei:
        digest.object_digest({"n": f})
    assert ei.value.kind is K.INTEGER
    assert ei.value.path == "/n"
    # The same float parsed from text (9007199254740992.0) is refused too: a
    # digest is never taken over text a receiver's strict parse refuses.
    with pytest.raises(StrictJSONError) as ei:
        digest.object_digest(strictjson.parse(b'{"a":[{"n":9007199254740992.0}]}'))
    assert ei.value.path == "/a/0/n"


PAD = strictjson.DEFAULT_MAX_BYTES - len('{"s":""}')

# Go's verdicts for the size limit, which applies to Go's JSON encoding of the
# value: U+2028 and U+2029 are escaped there (6 bytes, 3 in the canonical
# form), -0.0 is written "-0" ("0" canonical); \b and \f are short in both.
GO_SIZE_VERDICTS: list[tuple[str, dict[str, Any], bool]] = [
    ("exact a", {"s": "a" * PAD}, True),
    ("a plus 1", {"s": "a" * (PAD + 1)}, False),
    ("2028 near limit", {"s": "a" * (PAD - 3) + "\u2028"}, False),
    ("2029 near limit", {"s": "a" * (PAD - 3) + "\u2029"}, False),
    ("2028 within", {"s": "a" * (PAD - 6) + "\u2028"}, True),
    ("bf near limit", {"s": "a" * (PAD - 2) + "\b"}, True),
    (
        "negative zero",
        {"z": -0.0, "s": "a" * (strictjson.DEFAULT_MAX_BYTES - len('{"s":"","z":0}'))},
        False,
    ),
]


@pytest.mark.parametrize(
    ("name", "value", "ok"), GO_SIZE_VERDICTS, ids=[c[0] for c in GO_SIZE_VERDICTS]
)
def test_object_digest_limits_size_of_go_encoding(
    name: str, value: dict[str, Any], ok: bool
) -> None:
    if ok:
        check_shape(digest.object_digest(value))
        return
    with pytest.raises(StrictJSONError) as ei:
        digest.object_digest(value)
    assert ei.value.kind is K.SIZE, name


def test_object_digest_limits_html_characters_do_not_count() -> None:
    # 100 KiB of '<' is 600 KiB when escaped as <, over the limit, and
    # 100 KiB canonical.
    check_shape(digest.object_digest({"s": "<" * (100 << 10)}))


def test_object_digest_limits_nesting_depth_16_is_accepted() -> None:
    check_shape(digest.object_digest(resolve(nested(16))))


def test_object_digest_ignores_input_shape() -> None:
    text = b'{"headers":{"x":"1"},"a":[3,2,1],"b":{"d":null,"c":1.5}}'
    via_parse = digest.object_digest(strictjson.parse(text))
    via_value = digest.object_digest(
        {"headers": {"x": "1"}, "a": [3, 2, 1], "b": {"c": 1.5, "d": None}}
    )
    want = canonical('{"a":[3,2,1],"b":{"c":1.5,"d":null},"headers":{"x":"1"}}')
    assert via_parse == via_value == want


def test_errors_are_pact_errors() -> None:
    assert issubclass(NotObjectError, PactError)
    assert issubclass(StrictJSONError, PactError)


VALID = [
    "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU",
    "A" * 43,
    "-" * 43,
    "_" * 43,
    "0" * 43,
]

INVALID = {
    "empty": "",
    "42 chars": "A" * 42,
    "44 chars": "A" * 44,
    "padded": "A" * 42 + "=",
    "standard plus": "A" * 42 + "+",
    "standard slash": "A" * 42 + "/",
    "space": "A" * 42 + " ",
    "newline suffix": "A" * 43 + "\n",
    "newline in place": "A" * 42 + "\n",
    "non-ascii": "A" * 42 + "é",
    "43 bytes unicode": "A" * 41 + "é",
    "nul": "A" * 42 + "\x00",
    "fullwidth letter": "A" * 42 + "\uff21",
    "non-ascii digit": "A" * 42 + "٣",
}


@pytest.mark.parametrize("d", VALID)
def test_digest_validate(d: str) -> None:
    assert len(d) == DIGEST_LEN
    Digest(d).validate()


@pytest.mark.parametrize(("name", "d"), INVALID.items(), ids=list(INVALID))
def test_digest_validate_rejects(name: str, d: str) -> None:
    with pytest.raises(ValueError, match="core: digest"):
        Digest(d).validate()
