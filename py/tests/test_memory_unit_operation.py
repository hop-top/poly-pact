"""map_operation of the memory adapter (port of TestMapOperationRules of
go/adapters/memory/memory_unit_test.go).

A RawRequest keeps every field line in order and holds its body as bytes, so
Go's rows for a header stored under two map keys, an unreadable body and the
body restored after the read have no counterpart; a request with no
request-target is one with an empty raw_request_uri.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any

import pytest

from hop_top_pact.adapter import (
    AdapterError,
    Code,
    ContextMismatch,
    DependencyUnavailable,
    InvalidMessage,
    Principal,
    UnsupportedRequirement,
    code_of,
)
from hop_top_pact.adapter.adaptertest.compare import find
from hop_top_pact.adapters import memory as m
from hop_top_pact.core.binding import RawRequest, RequestError, Rule


def _with_route(method: str) -> Any:
    def mutate(st: m.State) -> m.State:
        mp = st.mappings[0]
        rt = m.Route(
            method=method,
            path="/invoices/{id}",
            action="invoice.write",
            resource="https://invoices.example/invoices/{id}",
        )
        return replace(st, mappings=(replace(mp, routes=(*mp.routes, rt)),))

    return mutate


def test_map_operation_rules(mem: Any) -> None:
    a, _ = mem.new_adapter()
    p: Principal = mem.alice()
    get = mem.get

    def mapped(r: RawRequest | None, pr: Principal = p, version: str = "map-1") -> Any:
        return a.map_operation(r, pr, version)

    # mapping version
    with pytest.raises(UnsupportedRequirement):
        mapped(get("https://gateway.example/invoices/1"), version="map-9")

    # no route
    for target in (
        "https://gateway.example/invoices",
        "https://gateway.example/invoices/1/approve",
        "https://gateway.example/other/1",
        "https://gateway.example/invoices/a%20b",
    ):
        with pytest.raises(UnsupportedRequirement):
            mapped(get(target))
    with pytest.raises(UnsupportedRequirement):
        mapped(mem.received("DELETE", "https://gateway.example/invoices/1"))

    # realm and credential
    other = replace(p, realm=replace(p.realm, tenant_id="globex"))
    with pytest.raises(ContextMismatch):
        mapped(get("https://gateway.example/invoices/1"), other)
    with pytest.raises(ContextMismatch):
        mapped(get("https://gateway.example/invoices/1"), Principal(realm=p.realm))
    target = "https://gateway.example/invoices/1"
    with pytest.raises(ContextMismatch):
        mapped(get(target, ("Authorization", "Bearer tok-bob-secret-2")))
    mapped(get(target, ("Authorization", "Bearer tok-alice-secret-1")))
    # An unknown token says nothing about the sender.
    mapped(get(target, ("Authorization", "Bearer tok-unknown-to-the-store")))

    # Every request the baseline mapping refuses is an INVALID_MESSAGE (draft
    # 10.2, 13.4): the class, its code, and nothing else, with no operation
    # context. Where the baseline mapping names the rule, the error carries it.
    def want_invalid(name: str, r: RawRequest | None, rule: Rule | None) -> None:
        with pytest.raises(AdapterError) as e:
            mapped(r)
        err = e.value
        assert isinstance(err, InvalidMessage), f"{name}: {err!r}"
        assert code_of(err) == Code.INVALID_MESSAGE, name
        assert find(err, DependencyUnavailable) is None, name
        assert find(err, UnsupportedRequirement) is None, name
        if rule is not None:
            re = find(err, RequestError)
            assert re is not None, f"{name}: no RequestError in {err!r}"
            assert re.rule == rule, f"{name}: rule {re.rule}"

    def with_header(k: str, v: str) -> Any:
        return get("https://gateway.example/invoices/1", (k, v))

    def with_target(rt: str) -> Any:
        return get(rt)

    def with_method(method: str) -> Any:
        return mem.received(method, "https://gateway.example/invoices/1")

    for name, r, rule in (
        ("fragment", get("https://gateway.example/invoices/1#f"), Rule.FRAGMENT),
        ("request-target fragment", with_target("/invoices/1#f"), Rule.FRAGMENT),
        ("userinfo", get("https://u:p@gateway.example/invoices/1"), Rule.USERINFO),
        ("content encoding", with_header("Content-Encoding", "gzip"), Rule.CONTENT_ENCODING),
        ("identity encoding", with_header("Content-Encoding", "identity"), Rule.CONTENT_ENCODING),
        ("blank content encoding", with_header("Content-Encoding", " "), Rule.CONTENT_ENCODING),
        (
            "transfer coding other than chunked",
            with_header("Transfer-Encoding", "gzip, chunked"),
            Rule.TRANSFER_CODING,
        ),
        ("method with a digit", with_method("GET1"), Rule.METHOD),
        ("method with a hyphen", with_method("M-SEARCH"), Rule.METHOD),
        ("no request-target", with_target(""), Rule.TARGET_FORM),
        ("asterisk-form", with_target("*"), Rule.TARGET_FORM),
        ("authority-form", with_target("gateway.example:443"), Rule.TARGET_FORM),
        (
            "absolute-form without a path",
            with_target("https://gateway.example?x=1"),
            Rule.TARGET_FORM,
        ),
        ("non-ASCII host", with_target("https://gatéway.example/invoices/1"), Rule.NON_ASCII_HOST),
        ("space in the query", with_target("/invoices/1?q=a b"), Rule.INVALID_CHARACTER),
        ("raw non-ASCII in the path", with_target("/invoices/é"), Rule.INVALID_CHARACTER),
        ("malformed escape", with_target("/invoices/1?q=%zz"), Rule.MALFORMED_ESCAPE),
        ("target too long", with_target("/invoices/1?q=" + "x" * 1024), Rule.TARGET_TOO_LONG),
        (
            "control octet in a covered header",
            with_header("X-Request-Kind", "a\x01b"),
            Rule.HEADER_VALUE,
        ),
        ("covered header not UTF-8", with_header("X-Request-Kind", "a\udcffb"), Rule.HEADER_VALUE),
        (
            "covered header too long",
            with_header("X-Request-Kind", "k" * 8193),
            Rule.HEADER_TOO_LONG,
        ),
        ("no request", None, None),
    ):
        want_invalid(name, r, rule)

    # Draft 10.2: an encoding is ambiguous when RFC 3986 syntax-based
    # normalization would change it, or when it hides structure. It is rejected,
    # never normalized.
    for name, target, rule in (
        (
            "encoded unreserved tilde",
            "https://gateway.example/invoices/INV%7E1",
            Rule.ENCODED_UNRESERVED,
        ),
        (
            "encoded unreserved letter",
            "https://gateway.example/invoices/%41",
            Rule.ENCODED_UNRESERVED,
        ),
        (
            "encoded dot segment",
            "https://gateway.example/invoices/%2E%2E/1",
            Rule.ENCODED_UNRESERVED,
        ),
        (
            "encoded unreserved in the query",
            "https://gateway.example/invoices/1?r=%7E",
            Rule.ENCODED_UNRESERVED,
        ),
        (
            "lowercase hex in the query",
            "https://gateway.example/invoices/1?a=%2f",
            Rule.LOWERCASE_HEX,
        ),
        (
            "lowercase hex in the path",
            "https://gateway.example/invoices/%c3%a9",
            Rule.LOWERCASE_HEX,
        ),
        ("encoded slash", "https://gateway.example/invoices/a%2Fb", Rule.ENCODED_SLASH),
        ("encoded slash lowercase", "https://gateway.example/invoices/a%2fb", Rule.LOWERCASE_HEX),
        ("overlong slash", "https://gateway.example/invoices/1%C0%AF", Rule.INVALID_UTF8),
        ("stray octet in the query", "https://gateway.example/invoices/1?q=%FF", Rule.INVALID_UTF8),
        ("surrogate", "https://gateway.example/invoices/%ED%A0%80", Rule.INVALID_UTF8),
        ("dot segment", "https://gateway.example/invoices/../admin", Rule.DOT_SEGMENT),
    ):
        want_invalid(name, get(target), rule)

    # Other escapes are not ambiguous: they are bound as sent, and the mapping
    # decides whether a route takes them.
    for target in (
        "https://gateway.example/invoices/a%5Cb",
        "https://gateway.example/invoices/a%00b",
        "https://gateway.example/invoices/a%25b",
    ):
        with pytest.raises(UnsupportedRequirement) as e:
            mapped(get(target))
        assert find(e.value, InvalidMessage) is None, target

    # target uri
    for given, want in {
        "https://internal.local:8443/invoices/1": "https://gateway.example/invoices/1",
        "https://internal.local/invoices/1?": "https://gateway.example/invoices/1?",
        "https://internal.local/invoices/1?b=2&a=%2F&a=1": "https://gateway.example/invoices/1?b=2&a=%2F&a=1",
        "https://internal.local/invoices/1?q=%C3%A9+%20&q=&z": "https://gateway.example/invoices/1?q=%C3%A9+%20&q=&z",
        "https://internal.local/invoices/INV~1?q=a+b%20c&r=~": "https://gateway.example/invoices/INV~1?q=a+b%20c&r=~",
        "http://Other.Example:8080/invoices/1?x=%3D%26&x=%2F%3F/?": "https://gateway.example/invoices/1?x=%3D%26&x=%2F%3F/?",
    }.items():
        assert mapped(get(given)).target_uri == want, given
    # An origin-form request-target is the path and query as sent.
    op = mapped(get("/invoices/INV~1?z=%2F&a=1"))
    assert op.target_uri == "https://gateway.example/invoices/INV~1?z=%2F&a=1"
    # The method is uppercased; the route is matched on the bound path.
    op = mapped(mem.received("get", "https://gateway.example/invoices/7"))
    assert (op.method, op.action, op.resources) == (
        "GET",
        "invoice.read",
        ("https://invoices.example/invoices/7",),
    )

    # operation id and environment
    def op_id(target: str, pr: Principal) -> str:
        o = mapped(get(target), pr)
        assert o.environment_id == mem.ENV
        return str(o.operation_id)

    u = "https://gateway.example/invoices/1"
    bob = replace(p, id="https://idp.example/bob")
    first, second = op_id(u, p), op_id(u, p)
    assert first, "no operation id"
    assert first == second, "the same request has two operation ids"
    assert first != op_id(u + "?x=1", p), "not specific to the request"
    assert first != op_id(u, bob), "not specific to the principal"

    # headers
    def post(body: bytes, *hdr: tuple[str, str]) -> Any:
        b, _ = mem.new_adapter(_with_route("POST"))
        return b.map_operation(
            mem.received("POST", "https://gateway.example/invoices/1", body, hdr), p, "map-1"
        )

    op = post(
        b"x",
        ("Content-Type", "text/plain"),
        ("X-Request-Kind", "  bulk\t"),
        ("Authorization", "Bearer t"),
    )
    assert dict(op.headers) == {"content-type": "text/plain", "x-request-kind": "bulk"}
    # Content-type is covered when there is a body, and only then.
    assert dict(post(b"", ("Content-Type", "text/plain")).headers) == {}
    # A header the request names in Connection is hop-by-hop for it (RFC 9110
    # 7.6.1), so it is not covered even when allowlisted.
    op = post(b"", ("X-Request-Kind", "bulk"), ("Connection", "x-request-kind"))
    assert dict(op.headers) == {}
    # Repeated headers are joined.
    op = mapped(get(u, ("X-Request-Kind", "a"), ("X-Request-Kind", "b")))
    assert op.headers["x-request-kind"] == "a, b"

    # body
    body = b"exact bytes \x00\xff\r\n"
    b, _ = mem.new_adapter(_with_route("PUT"))
    r = mem.received("PUT", "https://gateway.example/invoices/1", body)
    op = b.map_operation(r, p, "map-1")
    assert op.body_digest == "M24hzpYZfgDraiT_FZmtqZmmKetxRFnz_tSjno0bnXQ"
    assert r.body == body, "the request keeps its body"
    # A second mapping of the same request gives the same digest.
    assert b.map_operation(r, p, "map-1").body_digest == op.body_digest

    # body too large
    big = mem.received("PUT", "https://gateway.example/invoices/1", bytes(9 << 20))
    with pytest.raises(InvalidMessage) as too_large:
        b.map_operation(big, p, "map-1")
    re = find(too_large.value, RequestError)
    assert re is not None
    assert re.rule == Rule.BODY_TOO_LARGE
    assert len(big.body) == 9 << 20, "the request keeps its whole body"
