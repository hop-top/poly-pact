"""Body digest and coding rules. Port of go/core/binding/body_test.go.

A RawRequest holds the body after transfer decoding, so the Go cases that
read a body stream (a declared length that is not read, the body put back on
the request, a server byte limit, a read error) are ported against the WSGI
helper, which reads one, in test_binding_servers.py. The chunked cases run
through the ASGI helper: an ASGI server removes the chunked coding before the
application sees the body.
"""

from __future__ import annotations

import dataclasses
from typing import Any

import pytest

from hop_top_pact.core import binding
from hop_top_pact.core.binding import RawRequest, RequestError, RequestErrorKind, Rule
from hop_top_pact.core.types import OperationContext

ORIGIN = "https://gateway.example"
# body_digest of draft Appendix B.3: SHA-256 of zero bytes, base64url.
EMPTY_BODY_DIGEST = "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"
# SHA-256("abc"), the FIPS 180-4 example, base64url without padding.
ABC_DIGEST = "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0"


def config(**changes: Any) -> binding.Config:
    cfg = binding.Config(
        origin=ORIGIN,
        header_allowlist=("if-match", "x-dry-run"),
        header_normalization_id="finance-header-normalization-1",
        mapping_version="finance-http-1",
        max_body=1 << 20,
    )
    return dataclasses.replace(cfg, **changes)


def post(body: bytes, *headers: tuple[str, str]) -> RawRequest:
    # An origin-form request needs a Host line (request-binding.md RB-66).
    lines = (("Host", "gateway.example"), *headers)
    return RawRequest(method="POST", raw_request_uri="/x", headers=lines, body=body)


def asgi(body: bytes, *headers: tuple[bytes, bytes]) -> RawRequest:
    """A POST /x as an ASGI server hands it over, its body already de-chunked."""
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/x",
        "raw_path": b"/x",
        "query_string": b"",
        "headers": [(b"host", b"gateway.example"), *headers],
    }
    return binding.from_asgi(scope, body)


def bind(cfg: binding.Config, req: RawRequest) -> OperationContext:
    return binding.from_request(
        cfg, req, "https://identity.example/principals/alice", "invoice.read", ["urn:x"]
    )


def want_rule(rule: Rule, cfg: binding.Config, req: RawRequest) -> None:
    with pytest.raises(RequestError) as info:
        bind(cfg, req)
    assert info.value.kind is RequestErrorKind.INVALID_REQUEST, str(info.value)
    assert info.value.rule is rule, str(info.value)


def test_body_digest() -> None:
    # body_digest hashes the exact body bytes after transfer decoding; an empty
    # body hashes the empty byte string (draft 10.2).
    get = RawRequest(method="GET", raw_request_uri="/x", headers=(("Host", "gateway.example"),))
    assert bind(config(), get).body_digest == EMPTY_BODY_DIGEST
    assert bind(config(), dataclasses.replace(get, body=b"")).body_digest == EMPTY_BODY_DIGEST
    op = bind(config(), post(b"abc", ("Content-Length", "3")))
    assert op.body_digest == ABC_DIGEST
    # chunked: the transfer-decoded bytes are hashed.
    op = bind(config(), asgi(b"abc", (b"transfer-encoding", b"chunked")))
    assert op.body_digest == ABC_DIGEST
    assert bind(config(max_body=(1 << 63) - 1), post(b"abc")).body_digest == ABC_DIGEST
    assert bind(config(max_body=3), post(b"abc")).body_digest == ABC_DIGEST


@pytest.mark.parametrize(
    "headers",
    [
        (("Content-Encoding", "gzip"),),
        (("Content-Encoding", "identity"),),
        (("Content-Encoding", ""),),
        (("Content-Encoding", "gzip"), ("Content-Encoding", "br")),
        (("content-encoding", "gzip"),),
    ],
)
def test_reject_content_encoding(headers: tuple[tuple[str, str], ...]) -> None:
    # The baseline forbids HTTP content encodings on protected requests (draft
    # 10.2), so any Content-Encoding field is refused.
    want_rule(Rule.CONTENT_ENCODING, config(), post(b"abc", *headers))


def test_reject_content_encoding_from_a_server() -> None:
    r = asgi(b"abc", (b"content-encoding", b"gzip"), (b"content-length", b"3"))
    want_rule(Rule.CONTENT_ENCODING, config(), r)


def test_reject_transfer_coding() -> None:
    # Chunked is the only coding a server is known to remove; a request that
    # names another transfer coding has a body the binding cannot know to be
    # decoded.
    want_rule(Rule.TRANSFER_CODING, config(), post(b"abc", ("Transfer-Encoding", "gzip, chunked")))
    want_rule(Rule.TRANSFER_CODING, config(), post(b"abc", ("Transfer-Encoding", "gzip")))
    r = post(b"abc", ("Transfer-Encoding", "chunked"), ("transfer-encoding", "x"))
    want_rule(Rule.TRANSFER_CODING, config(), r)
    bind(config(), post(b"abc", ("Transfer-Encoding", "chunked")))
    bind(config(), post(b"abc", ("Transfer-Encoding", " Chunked ,")))


def test_reject_body_too_large() -> None:
    # A body over max_body is refused, whatever the declared length.
    cfg = config(max_body=3)
    want_rule(Rule.BODY_TOO_LARGE, cfg, post(b"abcd", ("Content-Length", "4")))
    want_rule(Rule.BODY_TOO_LARGE, cfg, post(b"abcdef"))
    want_rule(Rule.BODY_TOO_LARGE, cfg, post(b"abcd", ("Content-Length", "1")))
    # chunked
    want_rule(Rule.BODY_TOO_LARGE, cfg, asgi(b"abcd", (b"transfer-encoding", b"chunked")))
    # zero max_body admits only an empty body.
    zero = config(max_body=0)
    want_rule(Rule.BODY_TOO_LARGE, zero, post(b"a"))
    bind(zero, post(b""))


def test_content_type_with_body_covered_at_one_octet() -> None:
    op = bind(config(), post(b"a", ("Content-Type", "text/plain")))
    assert dict(op.headers) == {"content-type": "text/plain"}
