"""Negotiation, key sources, the transport binding and operation mapping. Port of
go/holder/negotiate_test.go, keysource_test.go, transport_test.go and operation_test.go."""

from __future__ import annotations

import io
from dataclasses import replace
from typing import Any
from urllib.request import Request

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from hop_top_pact import contract, holder
from hop_top_pact.adapter import Code
from hop_top_pact.core import binding, digest, jws, strictjson
from hop_top_pact.core.enums import JWSAlgorithm, Mode
from hop_top_pact.core.types import GatewayMetadata

N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def b_metadata(ck: Any) -> GatewayMetadata:
    return strictjson.decode(ck.draft_block("B.13"), GatewayMetadata)


NEGOTIATE: dict[str, tuple[dict[str, Any], str, str]] = {
    "newer only": ({"wire_versions": ("0.2",)}, Code.INVALID_MESSAGE, "unsupported-version"),
    "none": ({"wire_versions": ()}, Code.INVALID_MESSAGE, "unsupported-version"),
    "prefix": ({"wire_versions": ("0.1.1", "0")}, Code.INVALID_MESSAGE, "unsupported-version"),
    "alg": (
        {"jws_algorithms": (JWSAlgorithm("Ed25519"),)},
        Code.UNSUPPORTED_REQUIREMENT,
        "",
    ),
    "gateway": ({"gateway_id": "https://gateway.example/other"}, Code.CONTEXT_MISMATCH, ""),
    "environment": (
        {"environment_id": "https://gateway.example/environments/other"},
        Code.CONTEXT_MISMATCH,
        "",
    ),
}


def test_negotiate(ck: Any, hk: Any) -> None:
    # The B.13 metadata negotiates wire version 0.1 and ES256. A gateway that lists no
    # version the holder implements, or not the key's algorithm, is refused; the holder never
    # downgrades (draft 13.1, 21). A metadata document for another gateway or environment is
    # a mismatch.
    h = hk.b_holder(hk.memory_key(1))
    assert h.negotiate(b_metadata(ck)) == "0.1"
    md = replace(b_metadata(ck), wire_versions=("0.2", "0.1"))
    assert h.negotiate(md) == "0.1"
    for name, (edit, code, kind) in NEGOTIATE.items():
        with hk.raises(code, kind):
            h.negotiate(replace(b_metadata(ck), **edit))
        assert name


def test_negotiate_ed25519(ck: Any, hk: Any) -> None:
    # An Ed25519 key needs Ed25519 both negotiated locally and advertised.
    ed = holder.MemoryKey.ed25519(hk.ed_key())
    h = hk.b_holder(ed)
    md = replace(b_metadata(ck), jws_algorithms=(JWSAlgorithm("ES256"), JWSAlgorithm("Ed25519")))
    with hk.raises(Code.UNSUPPORTED_REQUIREMENT):
        h.negotiate(md)
    h.algorithms = jws.Algorithms((jws.ALG_ES256, jws.ALG_ED25519))
    assert h.negotiate(md) == "0.1"


def test_memory_key_es256(ck: Any, hk: Any) -> None:
    # The public key is the fixture holder JWK with no optional members, and signatures are
    # 64-octet low-S ECDSA over SHA-256 of the signing input (RFC 7518 section 3.4).
    k = hk.memory_key(1)
    pub = k.public_jwk()
    want = ck.fixture_jwk("holder")
    assert (pub.kty, pub.crv, pub.x, pub.y) == (want.kty, want.crv, want.x, want.y)
    assert (pub.kid, pub.alg, pub.use) == ("", "", "")
    data = b"eyJhbGciOiJFUzI1NiJ9.e30"
    key_pub = ck.scalar_key(1).public_key()
    # Half of all raw ECDSA signatures have a high S: 64 low-S ones in a row show that the
    # key normalizes.
    for _ in range(64):
        sig = k.sign(data)
        assert len(sig) == 64
        r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
        key_pub.verify(encode_dss_signature(r, s), data, ec.ECDSA(hashes.SHA256()))
        assert s <= N >> 1, "high S"
    with pytest.raises(ValueError, match="no ES256 key"):
        holder.MemoryKey.es256(None)
    with pytest.raises(jws.JWSError):
        holder.MemoryKey.es256(ec.generate_private_key(ec.SECP384R1()))
    with pytest.raises(ValueError, match="Ed25519"):
        holder.MemoryKey.ed25519(None)


def test_ed25519_presentation(ck: Any, hk: Any) -> None:
    # Where Ed25519 is negotiated (draft 7.2), an Ed25519 holder key signs a presentation
    # that verifies; without the negotiation the holder refuses the key.
    ed = holder.MemoryKey.ed25519(hk.ed_key())
    pub = ed.public_jwk()
    jkt = jws.thumbprint(pub)
    t = ck.B4_TIME
    c = hk.issue(contract.MemoryReplay(4), jkt, ck.b4_requirements(), hk.b_operation(), ck.at(t))
    in_ = hk.b_input()
    in_ = replace(
        in_,
        contract=c.compact,
        profile=replace(in_.profile, holder_jkt=jkt),
        evidence=(
            hk.sign_evidence(2, "test-issuer-key-1", replace(hk.b_evidence(), holder_jkt=jkt)),
        ),
        reputation=hk.sign_snapshot_for(t, jkt),
    )
    h = hk.b_holder(ed)
    with hk.raises(Code.UNSUPPORTED_REQUIREMENT):
        h.present(in_, ck.at(t))
    h.algorithms = jws.Algorithms((jws.ALG_ES256, jws.ALG_ED25519))
    p = h.present(in_, ck.at(t))
    hk.gateway_run(
        p.compact, enrolled=pub, actual=hk.b_operation(), now=ck.at(t + 1), algs=h.algorithms
    )


STDIO = {
    "transport_profile": "stdio-ipc",
    "channels": ("uds",),
    "framing": "ndjson",
    "identity_assurance": ("kernel-peer",),
    "max_frame_bytes": 360448,
    "version": "0.1",
}
NAMED = {"pact-transport-profile-v1": STDIO}
TRANSPORT = [
    ("https contract, default holder", None, Mode.ENFORCED, "", None),
    ("https contract, https holder", None, Mode.ENFORCED, "https", None),
    ("https contract, stdio-ipc holder", None, Mode.ENFORCED, "stdio-ipc", Code.CONTEXT_MISMATCH),
    ("stdio-ipc contract, stdio-ipc holder", NAMED, Mode.ENFORCED, "stdio-ipc", None),
    ("stdio-ipc contract, default holder", NAMED, Mode.ENFORCED, "", Code.CONTEXT_MISMATCH),
    ("stdio-ipc contract, https holder", NAMED, Mode.ENFORCED, "https", Code.CONTEXT_MISMATCH),
    ("observe stdio-ipc contract, https holder", NAMED, Mode.OBSERVE, "https", None),
    ("observe https contract, stdio-ipc holder", None, Mode.OBSERVE, "stdio-ipc", None),
]


@pytest.mark.parametrize(
    ("name", "ext", "mode", "transport", "want"), TRANSPORT, ids=[t[0] for t in TRANSPORT]
)
def test_transport_binding(
    ck: Any, hk: Any, name: str, ext: Any, mode: Mode, transport: str, want: str | None
) -> None:
    # An enforced-mode holder does not send a presentation over a transport other than the
    # one its contract names (draft 13.3.1, the downgrade rule). In observe mode the contract
    # is used and the gateway records the mismatch.
    r = replace(ck.b4_requirements(), extensions=ext, mode=mode)
    compact = hk.issue(
        contract.MemoryReplay(4), ck.B4_HOLDER_JKT, r, hk.b_operation(), ck.at(ck.B4_TIME)
    ).compact
    h = hk.b_holder(hk.memory_key(1))
    h.extensions = ("pact-transport-profile-v1",)
    h.transport = transport
    in_ = replace(hk.b_input(), contract=compact)
    if want is None:
        h.verify_contract(compact, hk.b_intent(), hk.b_operation(), ck.at(ck.B4_TIME))
        return
    with hk.raises(want):
        h.verify_contract(compact, hk.b_intent(), hk.b_operation(), ck.at(ck.B4_TIME))
    with hk.raises(want):
        h.present(in_, ck.at(ck.B4_TIME))


FINANCE = binding.Config(
    origin="https://gateway.example",
    header_allowlist=("if-match", "x-dry-run"),
    header_normalization_id="finance-header-normalization-1",
    mapping_version="finance-http-1",
    max_body=1 << 20,
)


def test_operation_from_request(ck: Any) -> None:
    # The outgoing request of the B.3 invoice read maps to the B.3 operation, whose
    # object_digest is the one the B.4 contract binds (draft 10.2).
    req = Request("https://gateway.example/invoices/INV-1042", method="GET")
    op = holder.operation_from_request(
        FINANCE,
        req,
        "invoice-read-operation-0001",
        ck.B4_ENV,
        ck.B4_PRINCIPAL,
        "invoice.read",
        ["https://invoices.example/invoices/INV-1042"],
    )
    assert digest.object_digest(op) == ck.B4_OP_DIGEST, op


def test_operation_from_request_body(ck: Any) -> None:
    # The body is hashed as sent and stays readable for sending; headers follow the
    # allowlist; the request-target is the one the client writes, so an ambiguous encoding is
    # refused.
    body = b'{"amount":"12.00"}'
    req = Request(
        "https://Gateway.Example:443/invoices/INV-1042/pay?b=2&a=1",
        data=io.BytesIO(body),
        method="POST",
    )
    req.add_header("Content-Type", "application/json")
    req.add_header("X-Dry-Run", "true")
    req.add_header("Authorization", "Bearer secret")
    op = holder.operation_from_request(
        FINANCE,
        req,
        "op-2",
        ck.B4_ENV,
        ck.B4_PRINCIPAL,
        "invoice.pay",
        ["https://invoices.example/invoices/INV-1042"],
    )
    assert op.method == "POST"
    assert op.target_uri == "https://gateway.example/invoices/INV-1042/pay?b=2&a=1"
    assert op.body_digest == digest.bytes_digest(body)
    assert dict(op.headers) == {"x-dry-run": "true", "content-type": "application/json"}
    assert (op.operation_id, op.environment_id) == ("op-2", ck.B4_ENV)
    assert (op.principal_id, op.action) == (ck.B4_PRINCIPAL, "invoice.pay")
    assert req.data == body, "the body is still sendable"

    bad = Request("https://gateway.example/invoices/%7Einv")
    with pytest.raises(holder.HolderError) as ei:
        holder.operation_from_request(
            FINANCE, bad, "op-3", ck.B4_ENV, ck.B4_PRINCIPAL, "invoice.read", []
        )
    assert ei.value.code == Code.INVALID_MESSAGE
    assert isinstance(ei.value.__cause__, binding.RequestError)
    assert ei.value.__cause__.rule == binding.Rule.ENCODED_UNRESERVED
    with pytest.raises(holder.HolderError) as ei:
        holder.operation_from_request(
            FINANCE, None, "op-4", ck.B4_ENV, ck.B4_PRINCIPAL, "invoice.read", []
        )
    assert ei.value.code == Code.INVALID_MESSAGE
