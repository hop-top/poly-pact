"""Signing. Port of go/core/jws/sign_test.go, plus the header text rules of the port.

The header text sign writes is the text Go's encoding/json writes for the
same header (SetEscapeHTML(false)): U+2028 and U+2029 escaped, the other
non-ASCII characters raw, control characters escaped, an unpaired surrogate
written as U+FFFD (Go writes U+FFFD for invalid UTF-8). The expected texts
below are the output of hop.top/pact-go/core/jws.Sign (Go 1.26.9).
"""

from __future__ import annotations

import base64
import os
from collections.abc import Callable
from functools import partial
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from hop_top_pact.core import jws

FIXTURES = Path(__file__).resolve().parents[2] / "spec" / "v1.0" / "fixtures"
HOLDER_JKT = "xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M"
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
SMALL_PAYLOAD = '{"pact_version":"0.1","jti":"unit"}'


def fixtures() -> Path:
    if not FIXTURES.exists():
        if os.environ.get("PACT_REQUIRE_VECTORS") == "1":
            pytest.fail(f"{FIXTURES} absent under PACT_REQUIRE_VECTORS=1")
        pytest.skip("no spec/ tree (mirror checkout)")
    return FIXTURES


def b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def scalar_key(n: int) -> ec.EllipticCurvePrivateKey:
    return ec.derive_private_key(n, ec.SECP256R1())


def fixture_jwk(name: str) -> jws.JWK:
    return jws.parse_jwk((fixtures() / "keys" / f"{name}.jwk.json").read_bytes())


def want_reason(f: Callable[[], object], want: jws.Reason) -> jws.JWSError:
    with pytest.raises(jws.JWSError) as info:
        f()
    assert jws.reason_of(info.value) == want, str(info.value)
    return info.value


def issuer_resolver() -> jws.StaticResolver:
    return jws.StaticResolver(
        key_sets={jws.Role.ISSUER: jws.new_key_set(fixture_jwk("issuer"))},
        expected_holder_jkt=HOLDER_JKT,
    )


def header_text(compact: str) -> str:
    return b64d(compact.split(".")[0]).decode("utf-8")


def test_sign_verify_round_trip() -> None:
    holder, issuer = scalar_key(1), scalar_key(2)
    issuer_jwk = fixture_jwk("issuer")
    sets: dict[jws.Role | str, jws.KeySet] = {}
    for typ in jws.typs():
        role = jws.typ_role(typ)
        if role is not None and role != jws.Role.HOLDER:
            sets[role] = jws.new_key_set(issuer_jwk)
    res = jws.StaticResolver(key_sets=sets, expected_holder_jkt=HOLDER_JKT)
    payload = b'{\n  "pact_version": "0.1",\n  "jti": "round-trip"\n}'
    for typ in jws.typs():
        role = jws.typ_role(typ)
        assert role is not None, typ
        if role == jws.Role.HOLDER:
            h, key, want_key = jws.Header(typ=typ), holder, fixture_jwk("holder")
        else:
            h, key, want_key = jws.Header(typ=typ, kid="test-issuer-key-1"), issuer, issuer_jwk
        compact = jws.sign(h, payload, key)
        p = jws.verify(compact, res)
        assert (p.compact, p.role, p.header.typ, p.header.alg) == (
            compact,
            role,
            typ,
            jws.ALG_ES256,
        )
        assert p.payload == payload
        assert len(p.signature) == 64
        assert (p.key.x, p.key.y) == (want_key.x, want_key.y)
        assert p.key_thumbprint == jws.thumbprint(want_key)
        if role == jws.Role.HOLDER:
            assert p.header.jwk is not None
            assert p.header.kid == ""
        else:
            assert p.header.jwk is None
            assert p.header.kid == "test-issuer-key-1"


def test_sign_holder_header() -> None:
    compact = jws.sign(jws.Header(typ=jws.TYP_PRESENTATION), SMALL_PAYLOAD.encode(), scalar_key(1))
    hj = fixture_jwk("holder")
    assert header_text(compact) == (
        '{"alg":"ES256","typ":"pact-presentation+jwt","jwk":'
        f'{{"kty":"EC","crv":"P-256","x":"{hj.x}","y":"{hj.y}"}}}}'
    )


def test_sign_rejects() -> None:
    issuer, holder = scalar_key(2), scalar_key(1)
    p384 = ec.generate_private_key(ec.SECP384R1())
    adv = fixture_jwk("adversarial")
    ev = jws.TYP_EVIDENCE
    R = jws.Reason
    cases: list[tuple[str, jws.Header, str, ec.EllipticCurvePrivateKey | None, jws.Reason]] = [
        ("nil key", jws.Header(typ=ev, kid="k"), SMALL_PAYLOAD, None, R.SIGNING_KEY),
        ("P-384 key", jws.Header(typ=ev, kid="k"), SMALL_PAYLOAD, p384, R.SIGNING_KEY),
        (
            "alg HS256",
            jws.Header(alg="HS256", typ=ev, kid="k"),
            SMALL_PAYLOAD,
            issuer,
            R.ALG_UNSUPPORTED,
        ),
        ("typ unknown", jws.Header(typ="JWT", kid="k"), SMALL_PAYLOAD, issuer, R.TYP_UNSUPPORTED),
        ("service without kid", jws.Header(typ=ev), SMALL_PAYLOAD, issuer, R.KID_MISSING),
        (
            "service with jwk",
            jws.Header(typ=ev, kid="k", jwk=adv),
            SMALL_PAYLOAD,
            issuer,
            R.JWK_UNEXPECTED,
        ),
        (
            "holder jwk of another key",
            jws.Header(typ=jws.TYP_PRESENTATION, jwk=adv),
            SMALL_PAYLOAD,
            holder,
            R.SIGNING_KEY,
        ),
        ("payload not JSON", jws.Header(typ=ev, kid="k"), "hello", issuer, R.PAYLOAD_JSON),
        ("payload array", jws.Header(typ=ev, kid="k"), "[]", issuer, R.PAYLOAD_JSON),
        (
            "payload duplicate member",
            jws.Header(typ=ev, kid="k"),
            '{"a":1,"a":2}',
            issuer,
            R.PAYLOAD_JSON,
        ),
    ]
    for name, h, payload, key, want in cases:
        err = want_reason(partial(jws.sign, h, payload.encode(), key), want)
        assert err.reason == want, name


def test_sign_writes_low_s() -> None:
    """S is the low value of (S, n-S); signing is randomized, so the test checks a
    property of many signatures. A signature is high-S about half the time."""
    key = scalar_key(2)
    res = issuer_resolver()
    for i in range(64):
        compact = jws.sign(
            jws.Header(typ=jws.TYP_EVIDENCE, kid="test-issuer-key-1"), SMALL_PAYLOAD.encode(), key
        )
        p = jws.verify(compact, res)
        assert int.from_bytes(p.signature[32:], "big") <= N >> 1, f"signature {i} has a high S"


# The kid values of the Go probe and the protected header text Go's Sign writes.
GO_HEADERS = [
    ("a\u2028b\u2029c", '"a\\u2028b\\u2029c"'),
    ('q"b\\s/', '"q\\"b\\\\s/"'),
    ("\x00\x01\x08\x09\x0a\x0c\x0d\x1f\x7f", '"\\u0000\\u0001\\b\\t\\n\\f\\r\\u001f\x7f"'),
    ("<>&", '"<>&"'),
    ("caf\u00e9 \U0001f600", '"caf\u00e9 \U0001f600"'),
    ("bad\udcffutf8", '"bad\ufffdutf8"'),
    ("\ufeff", '"\ufeff"'),
]


def test_sign_header_text_matches_go() -> None:
    key = scalar_key(2)
    for kid, want in GO_HEADERS:
        compact = jws.sign(jws.Header(typ=jws.TYP_EVIDENCE, kid=kid), b'{"a":1}', key)
        assert header_text(compact) == (
            '{"alg":"ES256","typ":"pact-evidence+jwt","kid":' + want + "}"
        ), repr(kid)


def test_sign_holder_jwk_members_escaped() -> None:
    """The embedded jwk keeps its optional members, in Go's order, escaped as Go does."""
    hk = scalar_key(1)
    pub = jws.public_jwk(hk.public_key())
    k = jws.JWK(kty=pub.kty, crv=pub.crv, x=pub.x, y=pub.y, kid="h\u2028", alg="ES256", use="sig")
    compact = jws.sign(jws.Header(typ=jws.TYP_PRESENTATION, jwk=k), b'{"a":1}', hk)
    # The header segment of the Go probe, byte for byte.
    assert compact.split(".")[0] == (
        "eyJhbGciOiJFUzI1NiIsInR5cCI6InBhY3QtcHJlc2VudGF0aW9uK2p3dCIsImp3ayI6eyJrdHkiOiJFQyIsImNy"
        "diI6IlAtMjU2IiwieCI6ImF4ZlI4dUVzUWtmNHZPYmxZNlJBOG5jRGZZRXQ2ek9nOUtFNVJkaVl3cFkiLCJ5Ijoi"
        "VC1OQzR2NGFmNXVPNS10S2ZBLWVGaXZPTTFkck1WN095N1pBYURlX1VmVSIsImtpZCI6ImhcdTIwMjgiLCJhbGci"
        "OiJFUzI1NiIsInVzZSI6InNpZyJ9fQ"
    )
    p = jws.verify(compact, jws.StaticResolver(expected_holder_jkt=HOLDER_JKT))
    assert p.header.jwk == k
