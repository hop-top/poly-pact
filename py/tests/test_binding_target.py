"""Method, target and origin rules. Port of go/core/binding/target_test.go.

The Go tests read their requests with the net/http server parser; here
parse() reads the same HTTP/1.1 text the way the ASGI helper reads a
server's scope: the request-target unchanged (as Latin-1, so every octet is
one character) and each field line value without its surrounding SP and
HTAB. manual() builds a RawRequest field by field, for inputs a server
parser refuses. Go strings are octets: a Go literal such as "\\xfc" becomes a
bytes literal here.
"""

from __future__ import annotations

import dataclasses
from typing import Any

import pytest

from hop_top_pact.core import binding
from hop_top_pact.core.binding import RawRequest, RequestError, RequestErrorKind, Rule
from hop_top_pact.core.types import OperationContext

ORIGIN = "https://gateway.example"
PRINCIPAL = "https://identity.example/principals/alice"
ACTION = "invoice.read"
RESOURCE = "https://invoices.example/invoices/INV-1042"


def config(**changes: Any) -> binding.Config:
    """The origin of draft Appendix B and the names and identifiers of Appendix B.13."""
    cfg = binding.Config(
        origin=ORIGIN,
        header_allowlist=("if-match", "x-dry-run"),
        header_normalization_id="finance-header-normalization-1",
        mapping_version="finance-http-1",
        max_body=1 << 20,
    )
    return dataclasses.replace(cfg, **changes)


def parse(raw: str | bytes) -> RawRequest:
    """The RawRequest of the text of an HTTP/1.1 request, as a server reads it."""
    data = raw.encode("utf-8") if isinstance(raw, str) else raw
    head, _, body = data.partition(b"\r\n\r\n")
    request_line, *lines = head.split(b"\r\n")
    method, target, _version = request_line.split(b" ")
    headers = []
    for line in lines:
        name, _, value = line.partition(b":")
        headers.append(
            (name.decode("latin-1"), value.strip(b" \t").decode("utf-8", "surrogateescape"))
        )
    return RawRequest(
        method=method.decode("latin-1"),
        raw_request_uri=target.decode("latin-1"),
        headers=tuple(headers),
        body=body,
    )


def get(target: str | bytes) -> RawRequest:
    """A GET request for target as a server would read it."""
    t = target.encode("utf-8") if isinstance(target, str) else target
    return parse(b"GET " + t + b" HTTP/1.1\r\nHost: gateway.example\r\n\r\n")


def manual(method: str, target: str) -> RawRequest:
    """A request built by a program, for inputs a server parser refuses."""
    return RawRequest(method=method, raw_request_uri=target, headers=(("Host", "gateway.example"),))


def bind(cfg: binding.Config, req: RawRequest | None) -> OperationContext:
    return binding.from_request(cfg, req, PRINCIPAL, ACTION, [RESOURCE])


def want_rule(rule: Rule, cfg: binding.Config, req: RawRequest | None) -> None:
    """Require a refused request under rule, not a configuration or body error."""
    with pytest.raises(RequestError) as info:
        bind(cfg, req)
    assert info.value.kind is RequestErrorKind.INVALID_REQUEST, str(info.value)
    assert info.value.rule is rule, str(info.value)


@pytest.mark.parametrize(
    ("target", "want"),
    [
        ("/invoices/INV-1042", ORIGIN + "/invoices/INV-1042"),
        ("/", ORIGIN + "/"),
        ("/s?b=2&a=1&b=1", ORIGIN + "/s?b=2&a=1&b=1"),
        ("/files/a%20b?q=%C3%A9", ORIGIN + "/files/a%20b?q=%C3%A9"),
        ("/a:b@c!$&'()*+,;=?x=/?:@", ORIGIN + "/a:b@c!$&'()*+,;=?x=/?:@"),
        ("/a?", ORIGIN + "/a?"),
        ("/a..b", ORIGIN + "/a..b"),
        ("/.../", ORIGIN + "/.../"),
        ("/a.b/", ORIGIN + "/a.b/"),
        ("/.a/b./..c/", ORIGIN + "/.a/b./..c/"),
        ("/a?x=./..&y=/../.", ORIGIN + "/a?x=./..&y=/../."),
        ("//a//b", ORIGIN + "//a//b"),
        ("/a?u=%2F%3F%23", ORIGIN + "/a?u=%2F%3F%23"),
        ("/a%3Fb", ORIGIN + "/a%3Fb"),
        ("/a%25b", ORIGIN + "/a%25b"),
        ("/a%5Cb", ORIGIN + "/a%5Cb"),
        ("/a%00b", ORIGIN + "/a%00b"),
        ("/a?q=a+b%20c", ORIGIN + "/a?q=a+b%20c"),
        ("https://gateway.example/x?y=1", ORIGIN + "/x?y=1"),
        ("http://Other.Example:8080/x", ORIGIN + "/x"),
    ],
    ids=[
        "appendix B.3",
        "root",
        "query order",
        "uppercase escapes kept",
        "sub-delims colon at",
        "empty query kept",
        "dots inside a segment",
        "three dots",
        "dot in a segment",
        "dot prefix and suffix",
        "dot segments in the query",
        "double slash kept",
        "encoded slash in query",
        "encoded question mark in path",
        "encoded percent in path",
        "encoded backslash in path",
        "encoded NUL in path",
        "encoded space plus",
        "absolute-form",
        "absolute-form other authority",
    ],
)
def test_target_uri_preserved(target: str, want: str) -> None:
    # target_uri is the configured origin plus the exact path and query of the
    # request target; octets, percent encoding and query order are kept (draft
    # 10.2).
    assert bind(config(), get(target)).target_uri == want


def test_target_uri_ignores_forwarding_headers() -> None:
    # The origin comes from trusted configuration; Host and forwarding headers
    # cannot select it (draft 10.2).
    r = parse(
        "GET /x HTTP/1.1\r\nHost: evil.example\r\n"
        "X-Forwarded-Host: evil.example\r\nX-Forwarded-Proto: http\r\n"
        "Forwarded: host=evil.example;proto=http\r\n\r\n"
    )
    assert bind(config(), r).target_uri == ORIGIN + "/x"


def test_target_uri_length() -> None:
    # target_uri has maxLength 1024 in the schema.
    path = "/" + "a" * (1024 - len(ORIGIN) - 1)
    assert len(bind(config(), get(path)).target_uri) == 1024
    want_rule(Rule.TARGET_TOO_LONG, config(), get(path + "a"))


@pytest.mark.parametrize(
    ("method", "want"), [("GET", "GET"), ("get", "GET"), ("Patch", "PATCH"), ("DELETE", "DELETE")]
)
def test_method_uppercased(method: str, want: str) -> None:
    # method is the uppercase HTTP method (draft 10.2).
    r = parse(method + " /x HTTP/1.1\r\nHost: gateway.example\r\n\r\n")
    assert bind(config(), r).method == want


@pytest.mark.parametrize("method", ["", "M-SEARCH", "GET1", "\u017fet", "G\u0130T"])
def test_reject_method(method: str) -> None:
    # The schema pattern for method is ^[A-Z]+$, and only ASCII letters are
    # uppercased, so a Unicode case mapping cannot make one.
    want_rule(Rule.METHOD, config(), manual(method, "/x"))


# (rule, name, target, program): program builds the request by hand because a
# server parser refuses it.
REJECT_TARGET: list[tuple[Rule, str, str | bytes, bool]] = [
    (Rule.FRAGMENT, "path", "/a#b", False),
    (Rule.FRAGMENT, "query", "/a?b#c", False),
    (Rule.FRAGMENT, "empty", "/a#", False),
    (Rule.FRAGMENT, "absolute-form", "https://gateway.example/a#b", False),
    (Rule.USERINFO, "user and password", "https://u:p@gateway.example/x", False),
    (Rule.USERINFO, "user", "https://u@gateway.example/x", False),
    (Rule.USERINFO, "empty", "https://@gateway.example/x", False),
    (Rule.NON_ASCII_HOST, "raw UTF-8", "https://b\u00fccher.example/x", False),
    (Rule.NON_ASCII_HOST, "percent-encoded", "https://b%C3%BCcher.example/x", False),
    (Rule.NON_ASCII_HOST, "raw byte", b"https://b\xfccher.example/x", False),
    (Rule.ENCODED_UNRESERVED, "ALPHA", "/%41", False),
    (Rule.ENCODED_UNRESERVED, "alpha", "/a%7A", False),
    (Rule.ENCODED_UNRESERVED, "DIGIT", "/%30", False),
    (Rule.ENCODED_UNRESERVED, "hyphen", "/a%2Db", False),
    (Rule.ENCODED_UNRESERVED, "dot segment", "/%2E%2E/secret", False),
    (Rule.ENCODED_UNRESERVED, "underscore", "/a%5F", False),
    (Rule.ENCODED_UNRESERVED, "tilde in query", "/a?x=%7E", False),
    (Rule.LOWERCASE_HEX, "encoded slash", "/a%2fb", False),
    (Rule.LOWERCASE_HEX, "UTF-8", "/caf%c3%a9", False),
    (Rule.LOWERCASE_HEX, "query", "/a?x=%3d", False),
    (Rule.LOWERCASE_HEX, "mixed case", "/a?x=%aB", False),
    (Rule.LOWERCASE_HEX, "second digit", "/%3a", False),
    (Rule.INVALID_UTF8, "overlong slash", "/%C0%AF", False),
    (Rule.INVALID_UTF8, "overlong three octets", "/%E0%80%AF", False),
    (Rule.INVALID_UTF8, "overlong NUL in query", "/a?x=%C0%80", False),
    (Rule.INVALID_UTF8, "surrogate", "/%ED%A0%80", False),
    (Rule.INVALID_UTF8, "above U+10FFFF", "/%F4%90%80%80", False),
    (Rule.INVALID_UTF8, "FF", "/%FF", False),
    (Rule.INVALID_UTF8, "truncated", "/%C3", False),
    (Rule.INVALID_UTF8, "split by a slash", "/%C3/%A9", False),
    (Rule.DOT_SEGMENT, "single dot", "/a/./b", False),
    (Rule.DOT_SEGMENT, "double dot", "/a/../b", False),
    (Rule.DOT_SEGMENT, "root single dot", "/.", False),
    (Rule.DOT_SEGMENT, "root double dot", "/..", False),
    (Rule.DOT_SEGMENT, "trailing single dot", "/a/.", False),
    (Rule.DOT_SEGMENT, "trailing double dot", "/a/..", False),
    (Rule.DOT_SEGMENT, "before a query", "/a/..?x=1", False),
    (Rule.DOT_SEGMENT, "after an empty segment", "//../a", False),
    (Rule.DOT_SEGMENT, "absolute-form", "https://gateway.example/a/../b", False),
    (Rule.ENCODED_SLASH, "inside a segment", "/a%2Fb", False),
    (Rule.ENCODED_SLASH, "alone", "/%2F", False),
    (Rule.MALFORMED_ESCAPE, "non-hex in query", "/a?x=%zz", False),
    (Rule.MALFORMED_ESCAPE, "one digit at end of query", "/a?x=%4", False),
    (Rule.MALFORMED_ESCAPE, "bare percent in path", "/a%", True),
    (Rule.MALFORMED_ESCAPE, "non-hex in path", "/a%G1", True),
    (Rule.INVALID_CHARACTER, "raw UTF-8 in path", "/caf\u00e9", False),
    (Rule.INVALID_CHARACTER, "raw byte in query", b"/a?x=\xff", False),
    (Rule.INVALID_CHARACTER, "brackets in query", "/a?x[]=1", False),
    (Rule.INVALID_CHARACTER, "brace", "/a{b}", False),
    (Rule.INVALID_CHARACTER, "pipe", "/a|b", False),
    (Rule.INVALID_CHARACTER, "backslash", "/a\\b", False),
    (Rule.INVALID_CHARACTER, "quote", '/a"b', False),
    (Rule.INVALID_CHARACTER, "caret and backtick", "/a^`", False),
    (Rule.INVALID_CHARACTER, "angle brackets", "/a<b>", False),
    (Rule.INVALID_CHARACTER, "space", "/a b", True),
    (Rule.INVALID_CHARACTER, "tab", "/a\tb", True),
    (Rule.INVALID_CHARACTER, "DEL", "/a\x7fb", True),
    (Rule.TARGET_FORM, "asterisk-form", "*", False),
    (Rule.TARGET_FORM, "authority-form", "gateway.example:443", True),
    (Rule.TARGET_FORM, "opaque URI", "foo:bar", False),
    (Rule.TARGET_FORM, "other scheme", "ftp://gateway.example/x", False),
    (Rule.TARGET_FORM, "empty host", "https:///x", True),
    (Rule.TARGET_FORM, "absolute-form without path", "https://gateway.example", False),
    (Rule.TARGET_FORM, "absolute-form query without path", "https://gateway.example?x", False),
    (Rule.TARGET_FORM, "empty", "", True),
]


@pytest.mark.parametrize(
    ("rule", "target", "program"),
    [(r, t, p) for r, _, t, p in REJECT_TARGET],
    ids=[f"{r}/{n}" for r, n, _, _ in REJECT_TARGET],
)
def test_reject_target(rule: Rule, target: str | bytes, program: bool) -> None:
    # Failing inputs for every target rule. The ambiguous encodings are those of
    # draft 10.2: an encoded unreserved character, a lowercase hex digit in an
    # escape, invalid or overlong UTF-8 in the decoded octets, an encoded slash
    # in the path, and a dot segment, which the path segment normalization of
    # RFC 3986 6.2.2.3 would remove. An encoded dot segment such as %2E%2E is
    # refused as an encoded unreserved character.
    if program:
        assert isinstance(target, str)
        req = manual("GET", target)
    else:
        req = get(target)
    want_rule(rule, config(), req)


def test_reject_target_decoded_text() -> None:
    # A caller that decoded the request-target as UTF-8 hands over code points
    # above U+00FF; they are refused like the raw octets.
    want_rule(Rule.INVALID_CHARACTER, config(), manual("GET", "/\u20ac"))
    want_rule(Rule.NON_ASCII_HOST, config(), manual("GET", "https://\u20ac.example/x"))


def test_reject_programmatic_url() -> None:
    # Go's request carries a URL beside the request-target, so a program can
    # set a fragment or userinfo that the target does not show. A RawRequest
    # has the request-target only; the remaining case is the target itself.
    want_rule(Rule.USERINFO, config(), manual("GET", "https://u@gateway.example/x"))
    want_rule(Rule.USERINFO, config(), manual("GET", "ftp://u@gateway.example/x"))


def test_reject_no_request() -> None:
    # No request has nothing to bind.
    want_rule(Rule.NO_REQUEST, config(), None)


@pytest.mark.parametrize(
    ("origin", "want"),
    [
        ("https://gateway.example", "https://gateway.example"),
        ("HTTPS://Gateway.EXAMPLE", "https://gateway.example"),
        ("https://gateway.example:443", "https://gateway.example"),
        ("https://gateway.example:", "https://gateway.example"),
        ("https://gateway.example:8443", "https://gateway.example:8443"),
        ("https://GATEWAY.example:8443", "https://gateway.example:8443"),
        ("https://192.0.2.1:443", "https://192.0.2.1"),
        ("https://[2001:DB8::1]:443", "https://[2001:db8::1]"),
        ("https://[2001:db8::1]:8443", "https://[2001:db8::1]:8443"),
    ],
)
def test_origin_normalized(origin: str, want: str) -> None:
    # Scheme and host are lowercase and a default port is omitted (draft 10.2;
    # RFC 3986 6.2.2.1 and 6.2.3; RFC 9110 4.2.2 and 4.2.3).
    op = bind(config(origin=origin), get("/A%20B?Q"))
    assert op.target_uri == want + "/A%20B?Q"
