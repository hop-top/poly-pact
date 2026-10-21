"""from_asgi and from_wsgi, and the Go tests that need a server or a body stream.

ASGI facts come from the ASGI HTTP connection scope specification (version
2.5): raw_path is the path as received, without the query, optional;
query_string is the part after "?"; headers are byte pairs in the order
received; the server removes the chunked coding. WSGI facts come from PEP
3333: environ strings are Latin-1 "native strings", there is no raw
request-target, and an application reads at most CONTENT_LENGTH octets of
wsgi.input. RAW_URI is gunicorn's, REQUEST_URI the nginx uwsgi_params one.

The over-the-wire cases run a wsgiref server from the standard library. It
sets neither RAW_URI nor REQUEST_URI, so the test handler adds RAW_URI from
the request line, as gunicorn does.
"""

from __future__ import annotations

import dataclasses
import io
import socket
import threading
from collections.abc import Callable, Iterable
from typing import Any
from wsgiref.simple_server import WSGIRequestHandler, WSGIServer, make_server

import pytest

from hop_top_pact.core import binding
from hop_top_pact.core.binding import RawRequest, RequestError, RequestErrorKind, Rule
from hop_top_pact.core.types import OperationContext

ORIGIN = "https://gateway.example"
ABC_DIGEST = "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0"
OPERATION_DIGEST_B3 = "R5nfhv7g_o93VPHK6a2o56-MyyGy75GQwXxDM4M3cn0"


def config(**changes: Any) -> binding.Config:
    cfg = binding.Config(
        origin=ORIGIN,
        header_allowlist=("if-match", "x-dry-run"),
        header_normalization_id="finance-header-normalization-1",
        mapping_version="finance-http-1",
        max_body=1 << 20,
    )
    return dataclasses.replace(cfg, **changes)


def bind(cfg: binding.Config, req: RawRequest) -> OperationContext:
    return binding.from_request(
        cfg,
        req,
        "https://identity.example/principals/alice",
        "invoice.read",
        ["https://invoices.example/invoices/INV-1042"],
    )


def want_rule(rule: Rule, call: Callable[[], object]) -> None:
    with pytest.raises(RequestError) as info:
        call()
    assert info.value.kind is RequestErrorKind.INVALID_REQUEST, str(info.value)
    assert info.value.rule is rule, str(info.value)


# ASGI


def scope(**changes: Any) -> dict[str, Any]:
    s: dict[str, Any] = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.5"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "https",
        "path": "/caf\u00e9 x",
        "raw_path": b"/caf%C3%A9%20x",
        "query_string": b"b=2&a=%41",
        "root_path": "",
        "headers": [
            (b"host", b"gateway.example"),
            (b"x-dry-run", b"1"),
            (b"content-type", b"text/plain"),
            (b"X-Dry-Run", b"2"),
        ],
    }
    s.update(changes)
    return s


def test_from_asgi() -> None:
    req = binding.from_asgi(scope(), b"abc")
    assert req == RawRequest(
        method="POST",
        raw_request_uri="/caf%C3%A9%20x?b=2&a=%41",
        headers=(
            ("host", "gateway.example"),
            ("x-dry-run", "1"),
            ("content-type", "text/plain"),
            ("X-Dry-Run", "2"),
        ),
        body=b"abc",
    )
    # The decoded path is never read: raw_path is the request as received.
    req = binding.from_asgi(scope(raw_path=b"/a", path="/other", query_string=b""), b"")
    assert req.raw_request_uri == "/a"


def test_from_asgi_duplicate_host() -> None:
    # An ASGI scope keeps every field line, so a second Host line reaches the
    # binding and is refused (RFC 9112 3.2).
    s = scope(
        query_string=b"", headers=[(b"host", b"gateway.example"), (b"host", b"gateway.example")]
    )
    want_rule(Rule.DUPLICATE_HOST, lambda: bind(config(), binding.from_asgi(s, b"")))


def test_from_asgi_missing_host() -> None:
    # An ASGI server gives :authority as the host header (ASGI 2.5); a scope
    # without one has no authority for an origin-form target.
    s = scope(query_string=b"", headers=[(b"x-dry-run", b"1")])
    want_rule(Rule.MISSING_HOST, lambda: bind(config(), binding.from_asgi(s, b"")))


def test_from_wsgi_missing_host() -> None:
    # Without a Host line, a WSGI server sets no HTTP_HOST.
    env = environ()
    env.pop("HTTP_HOST", None)
    want_rule(Rule.MISSING_HOST, lambda: bind(config(), binding.from_wsgi(env)))


def test_from_asgi_header_octets() -> None:
    # Header values are the octets sent; one that is not UTF-8 keeps them as
    # lone surrogates, so the binding refuses it when it is covered.
    s = scope(
        query_string=b"",
        headers=[(b"host", b"gateway.example"), (b"x-dry-run", b"\xff\xfe"), (b"x-other", b"\xc0")],
    )
    req = binding.from_asgi(s, b"")
    assert req.headers == (
        ("host", "gateway.example"),
        ("x-dry-run", "\udcff\udcfe"),
        ("x-other", "\udcc0"),
    )
    want_rule(Rule.HEADER_VALUE, lambda: bind(config(), req))
    op = bind(config(header_allowlist=()), req)
    assert dict(op.headers) == {}
    s = scope(
        query_string=b"",
        headers=[(b"host", b"gateway.example"), (b"x-dry-run", "caf\u00e9".encode())],
    )
    assert bind(config(), binding.from_asgi(s, b"")).headers == {"x-dry-run": "caf\u00e9"}


def test_from_asgi_target_octets() -> None:
    # A raw octet outside ASCII in raw_path is refused, never decoded.
    req = binding.from_asgi(scope(raw_path=b"/caf\xc3\xa9", query_string=b""), b"")
    want_rule(Rule.INVALID_CHARACTER, lambda: bind(config(), req))


def test_from_asgi_refuses_without_raw_path() -> None:
    # raw_path is optional in ASGI; the decoded path cannot stand in for it.
    s = scope()
    del s["raw_path"]
    want_rule(Rule.TARGET_FORM, lambda: binding.from_asgi(s, b""))
    want_rule(Rule.TARGET_FORM, lambda: binding.from_asgi(scope(raw_path=None), b""))


def test_from_asgi_refuses_other_scopes() -> None:
    want_rule(Rule.NO_REQUEST, lambda: binding.from_asgi(scope(type="websocket"), b""))
    want_rule(Rule.NO_REQUEST, lambda: binding.from_asgi(scope(type="lifespan"), b""))


def test_from_asgi_defaults() -> None:
    # query_string and headers can be missing from a minimal scope.
    s = {"type": "http", "method": "GET", "path": "/x", "raw_path": b"/x"}
    assert binding.from_asgi(s, b"") == RawRequest(method="GET", raw_request_uri="/x")


# WSGI


def environ(**changes: Any) -> dict[str, Any]:
    e: dict[str, Any] = {
        "REQUEST_METHOD": "POST",
        "SCRIPT_NAME": "",
        "PATH_INFO": "/caf\u00c3\u00a9 x",
        "QUERY_STRING": "b=2",
        "RAW_URI": "/caf%C3%A9%20x?b=2",
        "SERVER_NAME": "gateway.example",
        "SERVER_PORT": "443",
        "SERVER_PROTOCOL": "HTTP/1.1",
        "CONTENT_TYPE": "text/plain",
        "CONTENT_LENGTH": "3",
        "HTTP_HOST": "gateway.example",
        "HTTP_X_DRY_RUN": "1",
        "wsgi.version": (1, 0),
        "wsgi.url_scheme": "https",
        "wsgi.input": io.BytesIO(b"abcdef"),
        "wsgi.errors": io.StringIO(),
    }
    e.update(changes)
    return e


def test_from_wsgi() -> None:
    env = environ()
    req = binding.from_wsgi(env)
    assert req == RawRequest(
        method="POST",
        raw_request_uri="/caf%C3%A9%20x?b=2",
        headers=(
            ("content-type", "text/plain"),
            ("content-length", "3"),
            ("host", "gateway.example"),
            ("x-dry-run", "1"),
        ),
        body=b"abc",
    )
    assert bind(config(), req).body_digest == ABC_DIGEST


def test_from_wsgi_request_uri() -> None:
    env = environ(REQUEST_URI="/r?x")
    del env["RAW_URI"]
    assert binding.from_wsgi(env).raw_request_uri == "/r?x"
    # RAW_URI wins when both are set.
    assert binding.from_wsgi(environ(REQUEST_URI="/r?x")).raw_request_uri == "/caf%C3%A9%20x?b=2"


def test_from_wsgi_refuses_without_raw_target() -> None:
    # PEP 3333 gives only the decoded PATH_INFO; without RAW_URI or REQUEST_URI
    # there is no request-target to bind, and none is rebuilt.
    env = environ()
    del env["RAW_URI"]
    with pytest.raises(RequestError) as info:
        binding.from_wsgi(env)
    assert info.value.kind is RequestErrorKind.INVALID_REQUEST
    assert info.value.rule is Rule.TARGET_FORM
    assert "no raw request-target" in str(info.value)
    want_rule(Rule.TARGET_FORM, lambda: binding.from_wsgi(environ(RAW_URI=None)))


def test_from_wsgi_native_strings() -> None:
    # environ strings are Latin-1 native strings (PEP 3333): a header value's
    # octets are recovered from them and read as UTF-8.
    env = environ(HTTP_X_DRY_RUN="caf\u00c3\u00a9", HTTP_X_BAD="\u00ff\u00fe")
    req = binding.from_wsgi(env)
    assert ("x-dry-run", "caf\u00e9") in req.headers
    assert ("x-bad", "\udcff\udcfe") in req.headers


def test_from_wsgi_no_body() -> None:
    # Without CONTENT_LENGTH (or with an empty one) and without a transfer
    # coding there is no body, and wsgi.input is not read.
    env = environ(CONTENT_LENGTH="", **{"wsgi.input": FailingInput()})
    assert binding.from_wsgi(env).body == b""
    env = environ(**{"wsgi.input": FailingInput()})
    del env["CONTENT_LENGTH"]
    assert binding.from_wsgi(env).body == b""


def test_from_wsgi_chunked() -> None:
    # A chunked request has no CONTENT_LENGTH; the server removes the coding
    # (PEP 3333) and wsgi.input ends with the body.
    env = environ(HTTP_TRANSFER_ENCODING="chunked", **{"wsgi.input": io.BytesIO(b"abc")})
    del env["CONTENT_LENGTH"]
    req = binding.from_wsgi(env)
    assert req.body == b"abc"
    assert bind(config(), req).body_digest == ABC_DIGEST


def test_body_restored() -> None:
    # The body can be read again after the binding: wsgi.input is replaced by
    # an in-memory copy.
    env = environ()
    binding.from_wsgi(env)
    assert env["wsgi.input"].read() == b"abc"


class FailingInput:
    def read(self, size: int = -1) -> bytes:
        raise OSError("connection reset")


def test_body_read_error() -> None:
    # A body that cannot be read is not a malformed request.
    with pytest.raises(RequestError) as info:
        binding.from_wsgi(environ(**{"wsgi.input": FailingInput()}))
    assert info.value.kind is RequestErrorKind.BODY_READ
    assert info.value.rule is None
    assert isinstance(info.value.__cause__, OSError)
    # A body shorter than its declared length ends early: the read failed.
    with pytest.raises(RequestError) as info:
        binding.from_wsgi(environ(CONTENT_LENGTH="9", **{"wsgi.input": io.BytesIO(b"abc")}))
    assert info.value.kind is RequestErrorKind.BODY_READ


def test_reject_body_too_large() -> None:
    # Go's declared-length and server-limit cases: with max_body, a declared
    # length over it is refused before anything is read, and a chunked body is
    # read one octet past it at most. Either way wsgi.input still yields the
    # whole body afterwards.
    env = environ(CONTENT_LENGTH="4", **{"wsgi.input": FailingInput()})
    want_rule(Rule.BODY_TOO_LARGE, lambda: binding.from_wsgi(env, max_body=3))
    env = environ(CONTENT_LENGTH="4", **{"wsgi.input": io.BytesIO(b"abcd")})
    want_rule(Rule.BODY_TOO_LARGE, lambda: binding.from_wsgi(env, max_body=3))
    assert env["wsgi.input"].read() == b"abcd"
    env = environ(HTTP_TRANSFER_ENCODING="chunked", **{"wsgi.input": io.BytesIO(b"abcdef")})
    del env["CONTENT_LENGTH"]
    want_rule(Rule.BODY_TOO_LARGE, lambda: binding.from_wsgi(env, max_body=3))
    assert env["wsgi.input"].read() == b"abcdef"
    env = environ(CONTENT_LENGTH="3", **{"wsgi.input": io.BytesIO(b"abc")})
    assert binding.from_wsgi(env, max_body=3).body == b"abc"


def test_from_wsgi_bad_content_length() -> None:
    for v in ("x", "-1", "+3", "3 ", "\u0663"):
        with pytest.raises(RequestError) as info:
            binding.from_wsgi(environ(CONTENT_LENGTH=v))
        assert info.value.kind is RequestErrorKind.BODY_READ, v


# Over the wire: a wsgiref server.


class QuietHandler(WSGIRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:
        pass


class RawURIHandler(QuietHandler):
    """Adds RAW_URI, the request-target of the request line, as gunicorn does."""

    def get_environ(self) -> dict[str, Any]:
        env: dict[str, Any] = super().get_environ()
        env["RAW_URI"] = self.path
        return env


def wire(raw: bytes, handler: type[WSGIRequestHandler] = RawURIHandler) -> dict[str, Any]:
    """Send raw to a wsgiref server and return the environ its application got."""
    got: list[dict[str, Any]] = []

    def app(env: dict[str, Any], start: Callable[..., Any]) -> Iterable[bytes]:
        n = int(env.get("CONTENT_LENGTH") or 0)
        env["wsgi.input"] = io.BytesIO(env["wsgi.input"].read(n))
        got.append(env)
        start("204 No Content", [])
        return []

    with make_server("127.0.0.1", 0, app, server_class=WSGIServer, handler_class=handler) as srv:
        t = threading.Thread(target=srv.handle_request)
        t.start()
        host, port = srv.server_address[:2]
        with socket.create_connection((str(host), int(port))) as c:
            c.sendall(raw)
            c.shutdown(socket.SHUT_WR)
            while c.recv(4096):
                pass
        t.join(5)
    assert got, "the application was not called"
    return got[0]


@pytest.mark.parametrize(
    ("rule", "target"),
    [
        (Rule.FRAGMENT, b"/a#b"),
        (Rule.USERINFO, b"https://u:p@gateway.example/x"),
        (Rule.NON_ASCII_HOST, "https://b\u00fccher.example/x".encode()),
        (Rule.ENCODED_UNRESERVED, b"/%41"),
        (Rule.LOWERCASE_HEX, b"/a%2fb"),
        (Rule.INVALID_UTF8, b"/%C0%AF"),
        (Rule.ENCODED_SLASH, b"/a%2Fb"),
        (Rule.DOT_SEGMENT, b"/a/../b"),
    ],
)
def test_reject_target_over_wire(rule: Rule, target: bytes) -> None:
    # The target rules that matter most, through a real server.
    env = wire(b"GET " + target + b" HTTP/1.1\r\nHost: gateway.example\r\n\r\n")
    req = binding.from_wsgi(env)
    want_rule(rule, lambda: bind(config(), req))


def test_reject_header_value_over_wire() -> None:
    # A server passes obs-text through, so a header that is not UTF-8 reaches
    # the binding from the wire.
    env = wire(b"GET /x HTTP/1.1\r\nHost: gateway.example\r\nX-Dry-Run: \xff\xfe\r\n\r\n")
    req = binding.from_wsgi(env)
    want_rule(Rule.HEADER_VALUE, lambda: bind(config(), req))


def test_reject_content_encoding_over_wire() -> None:
    raw = (
        b"POST /x HTTP/1.1\r\nHost: gateway.example\r\nContent-Encoding: gzip\r\n"
        b"Content-Length: 3\r\n\r\nabc"
    )
    req = binding.from_wsgi(wire(raw))
    assert req.body == b"abc"
    want_rule(Rule.CONTENT_ENCODING, lambda: bind(config(), req))


def test_appendix_b3_over_the_wire() -> None:
    # The Appendix B request, with credentials and a presentation header,
    # through a real server binds to the B.3 operation digest.
    from hop_top_pact.core import digest

    raw = (
        b"GET /invoices/INV-1042 HTTP/1.1\r\n"
        b"Host: gateway.example\r\n"
        b"Authorization: Bearer native-token\r\n"
        b"PACT-Presentation: eyJhbGciOiJFUzI1NiJ9.e30.c2ln\r\n"
        b"Accept: application/json\r\n\r\n"
    )
    op = bind(config(), binding.from_wsgi(wire(raw)))
    op = dataclasses.replace(
        op,
        operation_id="invoice-read-operation-0001",
        environment_id="https://gateway.example/environments/finance",
    )
    value = {k: getattr(op, k) for k in type(op)._MEMBERS if getattr(op, k) is not None}
    value["headers"] = dict(value["headers"])
    assert digest.object_digest(value) == OPERATION_DIGEST_B3


def test_wsgiref_without_raw_uri_is_refused() -> None:
    # The standard library's wsgiref server sets no raw request-target.
    env = wire(b"GET /x HTTP/1.1\r\nHost: gateway.example\r\n\r\n", QuietHandler)
    assert "RAW_URI" not in env
    assert "REQUEST_URI" not in env
    want_rule(Rule.TARGET_FORM, lambda: binding.from_wsgi(env))
