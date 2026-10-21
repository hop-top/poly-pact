"""Verification of the compact JWS profile. Port of go/core/jws/jws_test.go and
rfc7515_internal_test.go.

The test keys are the P-256 keys of spec/v1.0/fixtures/keys (scalar 1 holder,
2 issuer, 3 adversarial). A test that reads them fails when spec/ is absent
under PACT_REQUIRE_VECTORS=1 (make py-test) and skips otherwise.
"""

from __future__ import annotations

import base64
import os
from collections.abc import Callable
from dataclasses import dataclass, field
from functools import partial
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from hop_top_pact.core import jws, strictjson
from hop_top_pact.core.jws import base64url

FIXTURES = Path(__file__).resolve().parents[2] / "spec" / "v1.0" / "fixtures"
# The holder_jkt printed in draft Appendix C.
HOLDER_JKT = "xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M"
# The order of P-256 (SEC 2, section 2.4.2).
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

EVIDENCE_HEADER = '{"alg":"ES256","typ":"pact-evidence+jwt","kid":"test-issuer-key-1"}'
SMALL_PAYLOAD = '{"pact_version":"0.1","jti":"unit"}'


def fixtures() -> Path:
    if not FIXTURES.exists():
        if os.environ.get("PACT_REQUIRE_VECTORS") == "1":
            pytest.fail(f"{FIXTURES} absent under PACT_REQUIRE_VECTORS=1")
        pytest.skip("no spec/ tree (mirror checkout)")
    return FIXTURES


def b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def scalar_key(n: int) -> ec.EllipticCurvePrivateKey:
    return ec.derive_private_key(n, ec.SECP256R1())


def fixture_jwk(name: str) -> jws.JWK:
    return jws.parse_jwk((fixtures() / "keys" / f"{name}.jwk.json").read_bytes())


def raw_sig(signing_input: str, key: ec.EllipticCurvePrivateKey) -> bytes:
    """R || S of a signature made with cryptography directly; S may be high."""
    r, s = decode_dss_signature(key.sign(signing_input.encode(), ec.ECDSA(hashes.SHA256())))
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def raw_compact(header: str, payload: str, key: ec.EllipticCurvePrivateKey) -> str:
    """Sign header.payload directly, so tests can build inputs sign refuses to make."""
    si = b64(header.encode()) + "." + b64(payload.encode())
    return si + "." + b64(raw_sig(si, key))


def want_reason(f: Callable[[], object], want: jws.Reason) -> jws.JWSError:
    with pytest.raises(jws.JWSError) as info:
        f()
    assert jws.reason_of(info.value) == want, str(info.value)
    assert info.value.reason == want
    return info.value


def issuer_resolver() -> jws.StaticResolver:
    """Trusts the issuer test key for the issuer role; expects the Appendix C holder_jkt."""
    return jws.StaticResolver(
        key_sets={jws.Role.ISSUER: jws.new_key_set(fixture_jwk("issuer"))},
        expected_holder_jkt=HOLDER_JKT,
    )


def jwk_json(k: jws.JWK) -> str:
    return f'{{"kty":"{k.kty}","crv":"{k.crv}","x":"{k.x}","y":"{k.y}"}}'


def header_cases() -> list[tuple[str, str, int, jws.Reason]]:
    hj = fixture_jwk("holder")
    xy = f'"kty":"EC","crv":"P-256","x":"{hj.x}","y":"{hj.y}"'
    hjwk = "{" + xy + "}"
    ev = '"typ":"pact-evidence+jwt","kid":"test-issuer-key-1"'
    pres = '"alg":"ES256","typ":"pact-presentation+jwt"'
    R = jws.Reason
    return [
        ("alg none", '{"alg":"none",' + ev + "}", 2, R.ALG_UNSUPPORTED),
        ("alg HS256", '{"alg":"HS256",' + ev + "}", 2, R.ALG_UNSUPPORTED),
        ("alg HS512", '{"alg":"HS512",' + ev + "}", 2, R.ALG_UNSUPPORTED),
        ("alg RS256", '{"alg":"RS256",' + ev + "}", 2, R.ALG_UNSUPPORTED),
        ("alg PS256", '{"alg":"PS256",' + ev + "}", 2, R.ALG_UNSUPPORTED),
        ("alg EdDSA", '{"alg":"EdDSA",' + ev + "}", 2, R.ALG_UNSUPPORTED),
        ("alg Ed25519 not in phase 1", '{"alg":"Ed25519",' + ev + "}", 2, R.ALG_UNSUPPORTED),
        ("alg es256 lowercase", '{"alg":"es256",' + ev + "}", 2, R.ALG_UNSUPPORTED),
        ("alg missing", "{" + ev + "}", 2, R.ALG_UNSUPPORTED),
        ("alg not a string", '{"alg":["ES256"],' + ev + "}", 2, R.ALG_UNSUPPORTED),
        ("jku", '{"alg":"ES256",' + ev + ',"jku":"https://trust.example/jwks"}', 2, R.HEADER_JKU),
        ("x5u", '{"alg":"ES256",' + ev + ',"x5u":"https://trust.example/c.pem"}', 2, R.HEADER_X5U),
        ("x5c", '{"alg":"ES256",' + ev + ',"x5c":["MIIB"]}', 2, R.HEADER_X5C),
        ("crit", '{"alg":"ES256",' + ev + ',"crit":["ext"],"ext":1}', 2, R.HEADER_CRIT),
        ("crit empty", '{"alg":"ES256",' + ev + ',"crit":[]}', 2, R.HEADER_CRIT),
        ("b64 false", '{"alg":"ES256",' + ev + ',"b64":false}', 2, R.HEADER_B64),
        (
            "b64 false with crit",
            '{"alg":"ES256",' + ev + ',"b64":false,"crit":["b64"]}',
            2,
            R.HEADER_CRIT,
        ),
        ("typ missing", '{"alg":"ES256","kid":"test-issuer-key-1"}', 2, R.TYP_UNSUPPORTED),
        ("typ JWT", '{"alg":"ES256","typ":"JWT","kid":"test-issuer-key-1"}', 2, R.TYP_UNSUPPORTED),
        (
            "typ unlisted",
            '{"alg":"ES256","typ":"pact-profile+jwt","kid":"test-issuer-key-1"}',
            2,
            R.TYP_UNSUPPORTED,
        ),
        (
            "typ not a string",
            '{"alg":"ES256","typ":7,"kid":"test-issuer-key-1"}',
            2,
            R.TYP_UNSUPPORTED,
        ),
        ("kid missing", '{"alg":"ES256","typ":"pact-evidence+jwt"}', 2, R.KID_MISSING),
        ("kid empty", '{"alg":"ES256","typ":"pact-evidence+jwt","kid":""}', 2, R.KID_MISSING),
        ("kid not a string", '{"alg":"ES256","typ":"pact-evidence+jwt","kid":1}', 2, R.HEADER_JSON),
        (
            "kid unknown",
            '{"alg":"ES256","typ":"pact-evidence+jwt","kid":"test-issuer-key-2"}',
            2,
            R.KID_UNKNOWN,
        ),
        (
            "jwk on a service-signed typ",
            '{"alg":"ES256",' + ev + ',"jwk":' + hjwk + "}",
            2,
            R.JWK_UNEXPECTED,
        ),
        ("duplicate member", '{"alg":"ES256",' + ev + ',"alg":"ES256"}', 2, R.HEADER_JSON),
        ("not an object", '["ES256"]', 2, R.HEADER_JSON),
        ("not JSON", "alg=ES256", 2, R.HEADER_JSON),
        ("lone surrogate", '{"alg":"ES256",' + ev + ',"x":"\\ud800"}', 2, R.HEADER_JSON),
        ("holder jwk missing", "{" + pres + ',"kid":"test-holder-key-1"}', 1, R.JWK_MISSING),
        ("holder jwk not an object", "{" + pres + ',"jwk":"x"}', 1, R.JWK_INVALID),
        (
            "holder jwk with d",
            "{" + pres + ',"jwk":{' + xy + ',"d":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE"}}',
            1,
            R.JWK_PRIVATE,
        ),
        (
            "holder jwk P-384",
            "{" + pres + f',"jwk":{{"kty":"EC","crv":"P-384","x":"{hj.x}","y":"{hj.y}"}}}}',
            1,
            R.JWK_CURVE,
        ),
        (
            "holder jwk RSA",
            "{" + pres + ',"jwk":{"kty":"RSA","n":"AQAB","e":"AQAB"}}',
            1,
            R.JWK_CURVE,
        ),
        (
            "holder jwk off curve",
            "{"
            + pres
            + f',"jwk":{{"kty":"EC","crv":"P-256","x":"{hj.x}","y":"{fixture_jwk("issuer").y}"}}}}',
            1,
            R.JWK_OFF_CURVE,
        ),
        (
            "holder jwk short x",
            "{" + pres + f',"jwk":{{"kty":"EC","crv":"P-256","x":"{hj.x[:42]}","y":"{hj.y}"}}}}',
            1,
            R.JWK_INVALID,
        ),
        (
            "holder jwk of another key",
            "{" + pres + ',"jwk":' + jwk_json(fixture_jwk("adversarial")) + "}",
            3,
            R.HOLDER_JKT_MISMATCH,
        ),
    ]


def test_verify_rejects_headers() -> None:
    """Each header draft 7.2 prohibits. Every input carries a valid signature over its
    own signing input, so the rejection comes from the header alone."""
    res = issuer_resolver()
    for name, header, scalar, want in header_cases():
        compact = raw_compact(header, SMALL_PAYLOAD, scalar_key(scalar))
        err = want_reason(partial(jws.verify, compact, res), want)
        assert err.reason == want, name


def compact_form_cases() -> list[tuple[str, str, jws.Reason]]:
    good = raw_compact(EVIDENCE_HEADER, SMALL_PAYLOAD, scalar_key(2))
    h, p, s = good.split(".")
    si = h + "." + p
    R = jws.Reason
    std = s.replace("-", "+").replace("_", "/") + "+"
    deep = "".join(['{"a":'] * 17) + "1" + "}" * 17
    return [
        ("two segments", si, R.COMPACT_FORM),
        ("four segments", good + ".AAAA", R.COMPACT_FORM),
        ("five segments (JWE shape)", h + ".." + p + ".." + s, R.COMPACT_FORM),
        ("empty header", "." + p + "." + s, R.COMPACT_FORM),
        ("empty string", "", R.COMPACT_FORM),
        ("detached payload", h + ".." + s, R.PAYLOAD_DETACHED),
        ("empty signature", si + ".", R.SIGNATURE_LENGTH),
        ("padded header", h + "=." + p + "." + s, R.BASE64_URL),
        ("padded signature", good + "==", R.BASE64_URL),
        ("line feed in payload", h + "." + p[:5] + "\n" + p[5:] + "." + s, R.BASE64_URL),
        ("carriage return in header", h[:5] + "\r" + h[5:] + "." + p + "." + s, R.BASE64_URL),
        ("space in signature", si + "." + s[:5] + " " + s[5:], R.BASE64_URL),
        ("standard alphabet", si + "." + std, R.BASE64_URL),
        ("unencoded payload", h + '.{"jti":"unit"}.' + s, R.BASE64_URL),
        ("unencoded payload with a period", h + "." + SMALL_PAYLOAD + "." + s, R.COMPACT_FORM),
        ("length 1 mod 4", si + "." + s + "AAA", R.BASE64_URL),
        ("payload not JSON", h + "." + b64(b"hello") + "." + s, R.PAYLOAD_JSON),
        ("payload array", h + "." + b64(b"[1]") + "." + s, R.PAYLOAD_JSON),
        ("payload duplicate member", h + "." + b64(b'{"a":1,"a":1}') + "." + s, R.PAYLOAD_JSON),
        ("payload invalid UTF-8", h + "." + b64(b'{"a":"\xff"}') + "." + s, R.PAYLOAD_JSON),
        ("payload too deep", h + "." + b64(deep.encode()) + "." + s, R.PAYLOAD_JSON),
        ("payload null", h + "." + b64(b"null") + "." + s, R.PAYLOAD_JSON),
    ]


def test_verify_rejects_compact_form() -> None:
    res = issuer_resolver()
    for name, compact, want in compact_form_cases():
        err = want_reason(partial(jws.verify, compact, res), want)
        assert err.reason == want, name


def test_verify_rejects_signatures() -> None:
    """RFC 7518 section 3.4: exactly 64 octets, R and S in [1, n-1], over the received
    signing input. InvalidSignature from cryptography is signature-invalid."""
    issuer = scalar_key(2)
    si = b64(EVIDENCE_HEADER.encode()) + "." + b64(SMALL_PAYLOAD.encode())
    sig = raw_sig(si, issuer)
    r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")

    def enc(r: int, s: int) -> str:
        return si + "." + b64(r.to_bytes(32, "big") + s.to_bytes(32, "big"))

    flipped = bytearray(sig)
    flipped[10] ^= 0x80
    other = b64(EVIDENCE_HEADER.encode()) + "." + b64(b'{"pact_version":"0.1","jti":"other"}')
    R = jws.Reason
    cases = [
        ("63 octets", si + "." + b64(sig[:63]), R.SIGNATURE_LENGTH),
        ("65 octets", si + "." + b64(sig + b"\x00"), R.SIGNATURE_LENGTH),
        ("96 octets", si + "." + b64(bytes(96)), R.SIGNATURE_LENGTH),
        ("r zero", enc(0, s), R.SIGNATURE_INVALID),
        ("s zero", enc(r, 0), R.SIGNATURE_INVALID),
        ("all zero", enc(0, 0), R.SIGNATURE_INVALID),
        ("r = n", enc(N, s), R.SIGNATURE_INVALID),
        ("s = n", enc(r, N), R.SIGNATURE_INVALID),
        ("r = 2^256-1", enc((1 << 256) - 1, s), R.SIGNATURE_INVALID),
        ("bit flipped", si + "." + b64(bytes(flipped)), R.SIGNATURE_INVALID),
        ("other payload", other + "." + b64(sig), R.SIGNATURE_INVALID),
        ("other key", si + "." + b64(raw_sig(si, scalar_key(3))), R.SIGNATURE_INVALID),
    ]
    res = issuer_resolver()
    for name, compact, want in cases:
        err = want_reason(partial(jws.verify, compact, res), want)
        assert err.reason == want, name
    # Neither RFC 7518 nor the draft has a low-S rule: the high-S twin verifies.
    p = jws.verify(enc(r, N - s), res)
    assert int.from_bytes(p.signature[32:], "big") == N - s


def test_verify_uses_received_signing_input() -> None:
    """The signature covers the received bytes: white space, member order and escapes a
    serializer would change still verify, and come back unchanged."""
    header = '{ "kid" : "test\\u002dissuer-key-1",\n"typ":"pact-evidence+jwt" , "alg":"ES256" }'
    payload = '{\n  "z": 1.50,\n  "a": "caf\\u00e9 \\/ café",\n  "pact_version": "0.1"\n}'
    compact = raw_compact(header, payload, scalar_key(2))
    p = jws.verify(compact, issuer_resolver())
    assert p.payload == payload.encode()
    assert p.raw_header == header.encode()
    assert p.signing_input == compact[: compact.rindex(".")]
    assert p.compact == compact
    assert (p.header.kid, p.header.typ, p.header.alg) == (
        "test-issuer-key-1",
        jws.TYP_EVIDENCE,
        jws.ALG_ES256,
    )


def test_verifier_expected_typ() -> None:
    compact = raw_compact(EVIDENCE_HEADER, SMALL_PAYLOAD, scalar_key(2))
    v = jws.Verifier(keys=issuer_resolver(), typ=jws.TYP_ADMISSION)
    want_reason(lambda: v.verify(compact), jws.Reason.TYP_MISMATCH)
    jws.Verifier(keys=issuer_resolver(), typ=jws.TYP_EVIDENCE).verify(compact)
    jws.Verifier(keys=issuer_resolver(), typ="").verify(compact)


def test_verifier_compact_size() -> None:
    res = issuer_resolver()
    big = "A" * (jws.DEFAULT_MAX_COMPACT_BYTES - 1)
    want_reason(lambda: jws.verify(big + ".A.A", res), jws.Reason.COMPACT_SIZE)
    compact = raw_compact(EVIDENCE_HEADER, SMALL_PAYLOAD, scalar_key(2))
    v = jws.Verifier(keys=res, max_compact_bytes=len(compact) - 1)
    want_reason(lambda: v.verify(compact), jws.Reason.COMPACT_SIZE)
    jws.Verifier(keys=res, max_compact_bytes=len(compact)).verify(compact)
    # The limit counts UTF-8 octets, as Go's len does.
    wide = "é" * (jws.DEFAULT_MAX_COMPACT_BYTES // 2 - 1) + ".A.A"
    want_reason(lambda: jws.verify(wide, res), jws.Reason.COMPACT_SIZE)


def test_verifier_json_limits() -> None:
    payload = '{"pact_version":"0.1","pad":"' + "x" * 100 + '"}'
    compact = raw_compact(EVIDENCE_HEADER, payload, scalar_key(2))
    v = jws.Verifier(keys=issuer_resolver(), limits=strictjson.Limits(max_bytes=100))
    err = want_reason(lambda: v.verify(compact), jws.Reason.PAYLOAD_JSON)
    assert isinstance(err.__cause__, strictjson.StrictJSONError)
    assert err.__cause__.kind == strictjson.StrictJSONErrorKind.SIZE
    assert err.err is err.__cause__


@dataclass
class RecordingResolver:
    keys: jws.KeySet | None = None
    jkt: str = ""
    keys_err: Exception | None = None
    holder_err: Exception | None = None
    reqs: list[jws.KeyRequest] = field(default_factory=list)

    def trusted_keys(self, req: jws.KeyRequest) -> jws.KeySet | None:
        self.reqs.append(req)
        if self.keys_err is not None:
            raise self.keys_err
        return self.keys

    def holder_jkt(self, req: jws.KeyRequest) -> str:
        self.reqs.append(req)
        if self.holder_err is not None:
            raise self.holder_err
        return self.jkt


def test_key_request() -> None:
    compact = raw_compact(EVIDENCE_HEADER, SMALL_PAYLOAD, scalar_key(2))
    rr = RecordingResolver(keys=jws.new_key_set(fixture_jwk("issuer")))
    jws.verify(compact, rr)
    assert rr.reqs == [
        jws.KeyRequest(
            typ=jws.TYP_EVIDENCE,
            role=jws.Role.ISSUER,
            kid="test-issuer-key-1",
            header=EVIDENCE_HEADER.encode(),
            payload=SMALL_PAYLOAD.encode(),
        )
    ]
    holder_compact = jws.sign(
        jws.Header(typ=jws.TYP_PRESENTATION), SMALL_PAYLOAD.encode(), scalar_key(1)
    )
    rr = RecordingResolver(jkt=HOLDER_JKT)
    jws.verify(holder_compact, rr)
    assert [(r.role, r.typ) for r in rr.reqs] == [(jws.Role.HOLDER, jws.TYP_PRESENTATION)]


def test_resolver_failures() -> None:
    compact = raw_compact(EVIDENCE_HEADER, SMALL_PAYLOAD, scalar_key(2))
    holder_compact = jws.sign(
        jws.Header(typ=jws.TYP_PRESENTATION), SMALL_PAYLOAD.encode(), scalar_key(1)
    )
    cause = TimeoutError("deadline exceeded")
    R = jws.Reason
    cases: list[tuple[str, str, jws.KeyResolver | None, jws.Reason, Exception | None]] = [
        ("nil resolver", compact, None, R.KEY_UNAVAILABLE, None),
        ("key set error", compact, RecordingResolver(keys_err=cause), R.KEY_UNAVAILABLE, cause),
        ("nil key set", compact, RecordingResolver(), R.KID_UNKNOWN, None),
        (
            "holder jkt error",
            holder_compact,
            RecordingResolver(holder_err=cause),
            R.KEY_UNAVAILABLE,
            cause,
        ),
        ("holder jkt empty", holder_compact, RecordingResolver(), R.KEY_UNAVAILABLE, None),
        ("static resolver without the role", compact, jws.StaticResolver(), R.KID_UNKNOWN, None),
        (
            "static resolver without holder_jkt",
            holder_compact,
            jws.StaticResolver(),
            R.KEY_UNAVAILABLE,
            None,
        ),
    ]
    for name, c, res, want, wrapped in cases:
        err = want_reason(partial(jws.verify, c, res), want)
        if wrapped is not None:
            assert err.__cause__ is wrapped, name


def test_header_decisions() -> None:
    """Members the draft does not define are ignored (RFC 7515 section 4), a kid next
    to a holder jwk plays no part in key selection, and typ is compared exactly."""
    issuer = scalar_key(2)
    res = issuer_resolver()
    ignored = (
        '{"alg":"ES256","typ":"pact-evidence+jwt","kid":"test-issuer-key-1",'
        '"cty":"json","x5t#S256":"abc","pact-note":{"a":1}}'
    )
    jws.verify(raw_compact(ignored, SMALL_PAYLOAD, issuer), res)
    with_kid = (
        '{"alg":"ES256","typ":"pact-presentation+jwt","kid":"no-such-key","jwk":'
        + jwk_json(fixture_jwk("holder"))
        + "}"
    )
    p = jws.verify(raw_compact(with_kid, SMALL_PAYLOAD, scalar_key(1)), res)
    assert p.header.kid == "no-such-key"
    assert p.role == jws.Role.HOLDER
    for typ in ("PACT-EVIDENCE+JWT", "application/pact-evidence+jwt", " pact-evidence+jwt"):
        h = f'{{"alg":"ES256","typ":"{typ}","kid":"test-issuer-key-1"}}'
        c = raw_compact(h, SMALL_PAYLOAD, issuer)
        want_reason(partial(jws.verify, c, res), jws.Reason.TYP_UNSUPPORTED)


def test_reason_of() -> None:
    assert jws.reason_of(None) is None
    assert jws.reason_of(ValueError("x")) is None
    h = '{"alg":"ES256","typ":"pact-evidence+jwt","kid":"test-issuer-key-1","alg":"ES256"}'
    c = raw_compact(h, SMALL_PAYLOAD, scalar_key(2))
    err = want_reason(lambda: jws.verify(c, issuer_resolver()), jws.Reason.HEADER_JSON)
    assert isinstance(err.__cause__, strictjson.StrictJSONError)
    assert err.__cause__.kind == strictjson.StrictJSONErrorKind.DUPLICATE_KEY
    assert str(err).startswith("jws: header-json")
    # The reason of a JWSError behind another package error.
    from hop_top_pact.errors import PactError

    class Wrapper(PactError):
        pass

    outer = Wrapper("wrapped")
    outer.__cause__ = err
    assert jws.reason_of(outer) == jws.Reason.HEADER_JSON
    # Not through an exception of another library.
    foreign = RuntimeError("wrapped")
    foreign.__cause__ = err
    assert jws.reason_of(foreign) is None


def test_jws_error_is_pact_error() -> None:
    from hop_top_pact.errors import PactError

    e = jws.JWSError(jws.Reason.KID_UNKNOWN, "kid x", ValueError("cause"))
    assert isinstance(e, PactError)
    assert (e.reason, e.detail) == (jws.Reason.KID_UNKNOWN, "kid x")
    assert isinstance(e.__cause__, ValueError)
    assert str(e) == "jws: kid-unknown: kid x: cause"
    assert str(jws.JWSError(jws.Reason.KID_UNKNOWN)) == "jws: kid-unknown"
    assert str(jws.Reason.KID_UNKNOWN) == "kid-unknown"


def test_decode_segment() -> None:
    """RFC 7515 base64url: URL-safe alphabet, no padding, no white space, canonical."""
    assert base64url.decode("") == b""
    assert base64url.decode("AA") == b"\x00"
    assert base64url.decode("AAA") == b"\x00\x00"
    assert base64url.decode("_-8") == b"\xff\xef"
    assert base64url.encode(b"\xff\xef") == "_-8"
    for bad in ("AB", "AAB", "AA==", "AAA=", "A", "AAAAA", "A+A", "A/A", "AA\n", " AA", "AÀ"):
        with pytest.raises(ValueError, match="base64url"):
            base64url.decode(bad)


# RFC 7515 Appendix A.3: ES256 over P-256. Compact serialization, public key and
# R and S octets copied from the RFC text.
A3_COMPACT = (
    "eyJhbGciOiJFUzI1NiJ9"
    ".eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
    ".DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"
)
A3_X = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU"
A3_Y = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
A3_R = bytes(
    [
        14,
        209,
        33,
        83,
        121,
        99,
        108,
        72,
        60,
        47,
        127,
        21,
        88,
        7,
        212,
        2,
        163,
        178,
        40,
        3,
        58,
        249,
        124,
        126,
        23,
        129,
        154,
        195,
        22,
        158,
        166,
        101,
    ]
)
A3_S = bytes(
    [
        197,
        10,
        7,
        211,
        140,
        60,
        112,
        229,
        216,
        241,
        45,
        175,
        8,
        74,
        84,
        128,
        166,
        101,
        144,
        197,
        242,
        147,
        80,
        154,
        143,
        63,
        127,
        138,
        131,
        163,
        84,
        213,
    ]
)
# UTF-8 of the protected header {"alg":"ES256"}.
A3_HEADER = bytes([123, 34, 97, 108, 103, 34, 58, 34, 69, 83, 50, 53, 54, 34, 125])


def test_rfc7515_a3() -> None:
    h, p, s = A3_COMPACT.split(".")
    assert base64url.decode(h) == A3_HEADER
    sig = base64url.decode(s)
    assert sig == A3_R + A3_S
    k = jws.JWK(kty="EC", crv="P-256", x=A3_X, y=A3_Y)
    pub = jws.public_key_of(k)
    signing_input = h + "." + p
    assert jws._verify_es256(pub, signing_input, sig)
    assert not jws._verify_es256(pub, signing_input + "A", sig)
    # A PACT verifier still rejects the JWS: its header has no typ.
    want_reason(lambda: jws.verify(A3_COMPACT, jws.StaticResolver()), jws.Reason.TYP_UNSUPPORTED)
