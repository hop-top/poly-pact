"""Header selection and normalization. Port of go/core/binding/headers_test.go.

A header value that is not UTF-8 on the wire reaches a RawRequest with its
undecodable octets as lone surrogates (the "surrogateescape" error handler),
as the ASGI and WSGI helpers write it; esc() builds such a value.
"""

from __future__ import annotations

import dataclasses
from typing import Any

import pytest

from hop_top_pact.core import binding
from hop_top_pact.core.binding import RawRequest, RequestError, RequestErrorKind, Rule
from hop_top_pact.core.types import OperationContext

ORIGIN = "https://gateway.example"


def config(**changes: Any) -> binding.Config:
    cfg = binding.Config(
        origin=ORIGIN,
        header_allowlist=("if-match", "x-dry-run"),
        header_normalization_id="finance-header-normalization-1",
        mapping_version="finance-http-1",
        max_body=1 << 20,
    )
    return dataclasses.replace(cfg, **changes)


def esc(octets: bytes) -> str:
    """A header value as a server hands over the octets: UTF-8, surrogateescape."""
    return octets.decode("utf-8", "surrogateescape")


def parse(raw: str | bytes) -> RawRequest:
    """The RawRequest of the text of an HTTP/1.1 request, as a server reads it."""
    data = raw.encode("utf-8") if isinstance(raw, str) else raw
    head, _, body = data.partition(b"\r\n\r\n")
    request_line, *lines = head.split(b"\r\n")
    method, target, _version = request_line.split(b" ")
    headers = []
    for line in lines:
        name, _, value = line.partition(b":")
        headers.append((name.decode("latin-1"), esc(value.strip(b" \t"))))
    return RawRequest(
        method=method.decode("latin-1"),
        raw_request_uri=target.decode("latin-1"),
        headers=tuple(headers),
        body=body,
    )


def manual(method: str, headers: tuple[tuple[str, str], ...] = (), body: bytes = b"") -> RawRequest:
    # An origin-form request needs a Host line (request-binding.md RB-66),
    # unless the test gives its own.
    if not any(n.lower() == "host" for n, _ in headers):
        headers = (("Host", "gateway.example"), *headers)
    return RawRequest(method=method, raw_request_uri="/x", headers=headers, body=body)


def bind(cfg: binding.Config, req: RawRequest) -> OperationContext:
    return binding.from_request(
        cfg, req, "https://identity.example/principals/alice", "invoice.read", ["urn:x"]
    )


def want_rule(rule: Rule, cfg: binding.Config, req: RawRequest) -> None:
    with pytest.raises(RequestError) as info:
        bind(cfg, req)
    assert info.value.kind is RequestErrorKind.INVALID_REQUEST, str(info.value)
    assert info.value.rule is rule, str(info.value)


HEADERS: list[tuple[str, tuple[str, ...], str, dict[str, str]]] = [
    ("none", (), "\r\n", {}),
    ("allowlisted only", ("x-dry-run",), "X-Dry-Run: 1\r\nX-Other: 2\r\n\r\n", {"x-dry-run": "1"}),
    ("allowlist name lowercased", ("If-Match",), 'IF-MATCH: "v1"\r\n\r\n', {"if-match": '"v1"'}),
    (
        "field lines joined in order",
        ("x-dry-run",),
        "X-Dry-Run: b\r\nX-Other: 1\r\nx-dry-run: a\r\n\r\n",
        {"x-dry-run": "b, a"},
    ),
    ("list value kept", ("x-dry-run",), "X-Dry-Run: a,b ,  c\r\n\r\n", {"x-dry-run": "a,b ,  c"}),
    (
        "surrounding whitespace dropped",
        ("x-dry-run",),
        "X-Dry-Run: \t a \t\r\n\r\n",
        {"x-dry-run": "a"},
    ),
    ("empty value kept", ("x-dry-run",), "X-Dry-Run:\r\n\r\n", {"x-dry-run": ""}),
    (
        "obs-text that is UTF-8 kept",
        ("x-dry-run",),
        "X-Dry-Run: caf\u00e9\r\n\r\n",
        {"x-dry-run": "caf\u00e9"},
    ),
    (
        "credentials and signatures not covered",
        ("x-dry-run",),
        "Authorization: Bearer t\r\nPACT-Presentation: a.b.c\r\nSignature: sig1=:AA==:\r\n"
        "Signature-Input: sig1=()\r\nProxy-Authorization: Basic x\r\nCookie: s=1\r\n\r\n",
        {},
    ),
    (
        "content-type with body",
        ("x-dry-run",),
        "Content-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
        {"content-type": "application/json"},
    ),
    (
        "no content-type without body",
        ("x-dry-run",),
        "Content-Type: application/json\r\nContent-Length: 0\r\n\r\n",
        {},
    ),
    ("body without content-type", ("x-dry-run",), "Content-Length: 2\r\n\r\n{}", {}),
    (
        "allowlisted content-type without body",
        ("content-type",),
        "Content-Type: text/plain\r\n\r\n",
        {"content-type": "text/plain"},
    ),
    (
        "connection-listed excluded",
        ("x-dry-run", "if-match"),
        "Connection: keep-alive, X-Dry-Run\r\nX-Dry-Run: 1\r\nIf-Match: *\r\n\r\n",
        {"if-match": "*"},
    ),
    (
        "connection-listed across field lines",
        ("x-dry-run", "if-match"),
        "Connection: close\r\nConnection:\tif-match ,\r\nX-Dry-Run: 1\r\nIf-Match: *\r\n\r\n",
        {"x-dry-run": "1"},
    ),
    (
        "connection-listed content-type excluded",
        ("x-dry-run",),
        "Connection: Content-Type\r\nContent-Type: text/plain\r\nContent-Length: 1\r\n\r\na",
        {},
    ),
]


@pytest.mark.parametrize(
    ("allow", "raw", "want"), [h[1:] for h in HEADERS], ids=[h[0] for h in HEADERS]
)
def test_headers(allow: tuple[str, ...], raw: str, want: dict[str, str]) -> None:
    # Names are lowercase and come from the allowlist only; values are trimmed
    # and field lines of one name are joined with ", " in order (RFC 9110 5.2,
    # 5.3, 5.5); content-type is added when a body is present (draft 10.2).
    r = parse("POST /x HTTP/1.1\r\nHost: gateway.example\r\n" + raw)
    op = bind(config(header_allowlist=allow), r)
    assert dict(op.headers) == want


def test_headers_trimmed_when_built() -> None:
    # A request a program builds can carry whitespace a server would have
    # removed; the binding trims it itself.
    r = manual("GET", (("X-Dry-Run", " a\t"), ("X-Dry-Run", "\t b "), ("X-Dry-Run", "")))
    assert bind(config(), r).headers["x-dry-run"] == "a, b, "


def test_header_value_length() -> None:
    # Header values have maxLength 8192 in the schema; the limit applies to the
    # joined value.
    op = bind(config(), manual("GET", (("X-Dry-Run", "a" * 8192),)))
    assert len(op.headers["x-dry-run"]) == 8192
    want_rule(Rule.HEADER_TOO_LONG, config(), manual("GET", (("X-Dry-Run", "a" * 8193),)))
    r = manual("GET", (("X-Dry-Run", "a" * 4095), ("X-Dry-Run", "b" * 4096)))
    want_rule(Rule.HEADER_TOO_LONG, config(), r)
    # Characters, not octets: 8192 two-octet characters fit.
    op = bind(config(), manual("GET", (("X-Dry-Run", "\u00e9" * 8192),)))
    assert len(op.headers["x-dry-run"]) == 8192


REJECT_HEADERS: list[tuple[Rule, str, tuple[tuple[str, str], ...]]] = [
    (Rule.HEADER_VALUE, "NUL", (("X-Dry-Run", "a\x00b"),)),
    (Rule.HEADER_VALUE, "CR", (("X-Dry-Run", "a\rb"),)),
    (Rule.HEADER_VALUE, "LF", (("X-Dry-Run", "a\nb"),)),
    (Rule.HEADER_VALUE, "other control", (("X-Dry-Run", "a\x01b"),)),
    (Rule.HEADER_VALUE, "DEL", (("X-Dry-Run", "a\x7fb"),)),
    (Rule.HEADER_VALUE, "invalid UTF-8", (("X-Dry-Run", esc(b"\xff\xfe")),)),
    (
        Rule.HEADER_VALUE,
        "second field line",
        (("X-Dry-Run", "ok"), ("X-Dry-Run", esc(b"\xc0\xaf"))),
    ),
    (Rule.HEADER_VALUE, "content-type with body", (("Content-Type", "text/\x01plain"),)),
]


@pytest.mark.parametrize(
    ("rule", "headers"),
    [(r, h) for r, _, h in REJECT_HEADERS],
    ids=[f"{r}/{n}" for r, n, _ in REJECT_HEADERS],
)
def test_reject_headers(rule: Rule, headers: tuple[tuple[str, str], ...]) -> None:
    # One failing input per header rule.
    body = b"a" if any(n == "Content-Type" for n, _ in headers) else b""
    want_rule(rule, config(), manual("POST", headers, body))


def test_header_spellings_kept_in_order() -> None:
    # Go refuses a header stored under two map keys that differ only in case
    # (header-key-collision), because a map loses the order of its field
    # lines. A RawRequest holds the field lines in order, so the two spellings
    # are one header whose lines join in the order received.
    op = bind(config(), manual("POST", (("X-Dry-Run", "1"), ("x-dry-run", "2"))))
    assert dict(op.headers) == {"x-dry-run": "1, 2"}


def test_reject_header_value_over_the_wire_octets() -> None:
    # Obs-text passes through a server parser, so a header that is not UTF-8
    # reaches the binding from the wire.
    r = parse(b"GET /x HTTP/1.1\r\nHost: gateway.example\r\nX-Dry-Run: \xff\xfe\r\n\r\n")
    want_rule(Rule.HEADER_VALUE, config(), r)


def test_content_type_ignored_without_body() -> None:
    # Without a body, content-type is not part of the operation context unless
    # allowlisted, so its value is not examined.
    op = bind(config(), manual("GET", (("Content-Type", esc(b"\xff")),)))
    assert dict(op.headers) == {}


def test_host_not_covered() -> None:
    # One Host line is not refused and not covered; allowlisting host is a
    # configuration error (request-binding.md RB-20).
    r = manual("GET", (("Host", "evil.example"), ("X-Dry-Run", "1")))
    op = bind(config(), r)
    assert dict(op.headers) == {"x-dry-run": "1"}
    assert op.target_uri == "https://gateway.example/x"


DUPLICATE_HOST: list[tuple[str, tuple[tuple[str, str], ...]]] = [
    ("same value", (("Host", "gateway.example"), ("Host", "gateway.example"))),
    ("other value", (("Host", "gateway.example"), ("Host", "evil.example"))),
    ("two spellings", (("Host", "gateway.example"), ("host", "gateway.example"))),
    ("with an allowlisted header", (("Host", "a"), ("If-Match", '"v1"'), ("HOST", "b"))),
]


@pytest.mark.parametrize(
    "headers", [h for _, h in DUPLICATE_HOST], ids=[n for n, _ in DUPLICATE_HOST]
)
def test_reject_duplicate_host(headers: tuple[tuple[str, str], ...]) -> None:
    # More than one Host field line is refused (RFC 9112 3.2;
    # request-binding.md RB-65), with names in any case and even when the
    # values are equal.
    want_rule(Rule.DUPLICATE_HOST, config(), manual("GET", headers))


def test_reject_duplicate_host_parsed() -> None:
    r = parse("GET /x HTTP/1.1\r\nHost: gateway.example\r\nHost: gateway.example\r\n\r\n")
    want_rule(Rule.DUPLICATE_HOST, config(), r)


# Host values that are, and are not, uri-host [ ":" port ] with a non-empty
# host (RFC 9110 4.2.2, 7.2; RFC 3986 3.2.2, 3.2.3; request-binding.md RB-66).
VALID_HOSTS = [
    "gateway.example",
    "GATEWAY.example:443",
    "gateway.example:",
    "192.0.2.1:8443",
    "[::1]",
    "[2001:db8::1]:443",
    "[v1.x]",
    "g%41teway.example",
    " gateway.example\t",
]
INVALID_HOSTS = [
    "",
    "gate way.example",
    "gateway.example/x",
    "a@b",
    "[::1",
    "[fe80::1%25en0]",
    "[192.0.2.1]",
    "gateway.example:abc",
    "caf\u00e9.example",
    "%zz.example",
    ":443",
    "a:1:2",
    "[::1]x",
]


@pytest.mark.parametrize("value", VALID_HOSTS)
def test_valid_host(value: str) -> None:
    bind(config(), manual("GET", (("Host", value),)))


@pytest.mark.parametrize("value", INVALID_HOSTS)
def test_invalid_host(value: str) -> None:
    want_rule(Rule.INVALID_HOST, config(), manual("GET", (("Host", value),)))


def test_invalid_host_absolute_form() -> None:
    r = RawRequest(
        method="GET", raw_request_uri="https://gateway.example/x", headers=(("Host", "a@b"),)
    )
    want_rule(Rule.INVALID_HOST, config(), r)


def test_missing_host() -> None:
    # An origin-form request without Host has no authority; an absolute-form
    # target carries its own (RFC 9112 3.2.2).
    want_rule(Rule.MISSING_HOST, config(), RawRequest(method="GET", raw_request_uri="/x"))
    r = RawRequest(method="GET", raw_request_uri="https://gateway.example/x")
    assert bind(config(), r).target_uri == "https://gateway.example/x"


def test_header_names_ascii_case_only() -> None:
    # Names match without regard to ASCII case only: the Kelvin sign is not k.
    r = manual("GET", (("X-Dry-Run\u212a", "1"), ("IF-MATCH", "*")))
    op = bind(config(header_allowlist=("x-dry-runk", "if-match")), r)
    assert dict(op.headers) == {"if-match": "*"}
