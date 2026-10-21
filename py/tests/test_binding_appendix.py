"""The draft Appendix B example. Port of go/core/binding/appendix_test.go.

The Go test sends the request to a real server; the over-the-wire leg is
test_appendix_b3_over_the_wire in test_binding_servers.py.
"""

from __future__ import annotations

import dataclasses
import os
from pathlib import Path
from typing import Any

import pytest

from hop_top_pact.core import binding, digest, jcs, strictjson
from hop_top_pact.core.binding import RawRequest
from hop_top_pact.core.strictjson import Limits

FIXTURES = Path(__file__).resolve().parents[2] / "spec" / "v1.0" / "fixtures"
# The operation_digest of draft Appendix B.4 and B.7, object_digest of the B.3
# operation context.
OPERATION_DIGEST_B3 = "R5nfhv7g_o93VPHK6a2o56-MyyGy75GQwXxDM4M3cn0"

B3_REQUEST = (
    b"GET /invoices/INV-1042 HTTP/1.1\r\n"
    b"Host: gateway.example\r\n"
    b"Authorization: Bearer native-token\r\n"
    b"PACT-Presentation: eyJhbGciOiJFUzI1NiJ9.e30.c2ln\r\n"
    b"Accept: application/json\r\n\r\n"
)


def config() -> binding.Config:
    return binding.Config(
        origin="https://gateway.example",
        header_allowlist=("if-match", "x-dry-run"),
        header_normalization_id="finance-header-normalization-1",
        mapping_version="finance-http-1",
        max_body=1 << 20,
    )


def parse(data: bytes) -> RawRequest:
    head, _, body = data.partition(b"\r\n\r\n")
    request_line, *lines = head.split(b"\r\n")
    method, target, _version = request_line.split(b" ")
    headers = tuple(
        (n.decode("latin-1"), v.strip(b" \t").decode("utf-8", "surrogateescape"))
        for n, _, v in (line.partition(b":") for line in lines)
    )
    return RawRequest(
        method=method.decode(), raw_request_uri=target.decode("latin-1"), headers=headers, body=body
    )


def appendix_b3() -> tuple[Any, str]:
    """The B.3 operation context and its digest, from the digest vector operation-b3."""
    path = FIXTURES / "vectors" / "digest" / "appendix-b.json"
    if not path.exists():
        if os.environ.get("PACT_REQUIRE_VECTORS") == "1":
            pytest.fail(f"{path} absent under PACT_REQUIRE_VECTORS=1")
        pytest.skip("no spec/ tree (mirror checkout)")
    vectors: Any = strictjson.parse(path.read_bytes(), Limits(max_bytes=1 << 20))
    (v,) = [v for v in vectors if v["id"] == "operation-b3"]
    return v["input"], v["expected_digest"]


def wire_value(op: Any) -> dict[str, Any]:
    out = {k: getattr(op, k) for k in type(op)._MEMBERS if getattr(op, k) is not None}
    out["headers"] = dict(out["headers"])
    return out


def test_appendix_b3() -> None:
    # The request of the Appendix B example, with credentials and a
    # presentation header, binds to the B.3 operation context and its digest
    # once the caller sets operation_id and environment_id.
    want, want_digest = appendix_b3()
    assert want_digest == OPERATION_DIGEST_B3, "the vector digest is not the one draft B.4 prints"
    op = binding.from_request(
        config(),
        parse(B3_REQUEST),
        "https://identity.example/principals/alice",
        "invoice.read",
        ["https://invoices.example/invoices/INV-1042"],
    )
    assert op.operation_id == "", "the caller owns it"
    assert op.environment_id == "", "the caller owns it"
    op = dataclasses.replace(
        op,
        operation_id="invoice-read-operation-0001",
        environment_id="https://gateway.example/environments/finance",
    )
    value = wire_value(op)
    assert jcs.canonicalize_value(value) == jcs.canonicalize_value(want)
    assert digest.object_digest(value) == OPERATION_DIGEST_B3


def test_caller_values() -> None:
    # Principal, action and resources are the caller's, and the resources are
    # copied.
    res = ["https://invoices.example/invoices/1", "https://invoices.example/invoices/2"]
    req = RawRequest(method="GET", raw_request_uri="/x", headers=(("Host", "gateway.example"),))
    op = binding.from_request(
        config(), req, "https://identity.example/principals/bob", "invoice.list", res
    )
    assert op.principal_id == "https://identity.example/principals/bob"
    assert op.action == "invoice.list"
    res[0] = "changed"
    assert op.resources == (
        "https://invoices.example/invoices/1",
        "https://invoices.example/invoices/2",
    )
