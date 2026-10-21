"""JWK parsing, key sets and RFC 7638 thumbprints. Port of go/core/jws/jwk_test.go."""

from __future__ import annotations

import base64
import json
import os
from collections.abc import Callable
from functools import partial
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from hop_top_pact.core import jws

FIXTURES = Path(__file__).resolve().parents[2] / "spec" / "v1.0" / "fixtures"
HOLDER_JKT = "xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M"
# The field prime of P-256 (SEC 2, section 2.4.2).
P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF


def fixtures() -> Path:
    if not FIXTURES.exists():
        if os.environ.get("PACT_REQUIRE_VECTORS") == "1":
            pytest.fail(f"{FIXTURES} absent under PACT_REQUIRE_VECTORS=1")
        pytest.skip("no spec/ tree (mirror checkout)")
    return FIXTURES


def b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def fixture_jwk(name: str) -> jws.JWK:
    return jws.parse_jwk((fixtures() / "keys" / f"{name}.jwk.json").read_bytes())


def want_reason(f: Callable[[], object], want: jws.Reason) -> jws.JWSError:
    with pytest.raises(jws.JWSError) as info:
        f()
    assert jws.reason_of(info.value) == want, str(info.value)
    return info.value


def test_thumbprint_appendix_c() -> None:
    """RFC 7638 over crv, kty, x, y in that order gives the Appendix C holder_jkt;
    optional members and member order in the JWK do not matter."""
    for src in (
        '{"kty":"EC","crv":"P-256","x":"axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY",'
        '"y":"T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU"}',
        '{"y":"T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU","use":"sig",'
        '"x":"axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY","key_ops":["verify"],'
        '"crv":"P-256","kid":"k","kty":"EC"}',
    ):
        assert jws.thumbprint(jws.parse_jwk(src.encode())) == HOLDER_JKT, src


def test_thumbprint_rejects_invalid_keys() -> None:
    hj = fixture_jwk("holder")
    R = jws.Reason
    cases = [
        ("kty RSA", jws.JWK(kty="RSA", crv="P-256", x=hj.x, y=hj.y), R.JWK_CURVE),
        ("crv P-384", jws.JWK(kty="EC", crv="P-384", x=hj.x, y=hj.y), R.JWK_CURVE),
        ("short x", jws.JWK(kty="EC", crv="P-256", x=hj.x[:42], y=hj.y), R.JWK_INVALID),
        ("empty y", jws.JWK(kty="EC", crv="P-256", x=hj.x), R.JWK_INVALID),
        (
            "off curve",
            jws.JWK(kty="EC", crv="P-256", x=hj.x, y=fixture_jwk("issuer").y),
            R.JWK_OFF_CURVE,
        ),
    ]
    for name, k, want in cases:
        err = want_reason(partial(jws.thumbprint, k), want)
        assert err.reason == want, name


def parse_jwk_cases() -> list[tuple[str, str, jws.Reason]]:
    hj = fixture_jwk("holder")
    xy = f'"kty":"EC","crv":"P-256","x":"{hj.x}","y":"{hj.y}"'
    x33 = b64(b"\x00" + b64d(hj.x))
    std_y = hj.y.replace("-", "+").replace("_", "/")
    p = b64(P.to_bytes(32, "big"))
    R = jws.Reason
    return [
        ("d", "{" + xy + ',"d":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE"}', R.JWK_PRIVATE),
        ("RSA private p", "{" + xy + ',"p":"AQAB"}', R.JWK_PRIVATE),
        ("RSA private q", "{" + xy + ',"q":"AQAB"}', R.JWK_PRIVATE),
        ("RSA private dp", "{" + xy + ',"dp":"AQAB"}', R.JWK_PRIVATE),
        ("RSA private dq", "{" + xy + ',"dq":"AQAB"}', R.JWK_PRIVATE),
        ("RSA private qi", "{" + xy + ',"qi":"AQAB"}', R.JWK_PRIVATE),
        ("RSA private oth", "{" + xy + ',"oth":[]}', R.JWK_PRIVATE),
        ("symmetric k", "{" + xy + ',"k":"AQAB"}', R.JWK_PRIVATE),
        ("d null", "{" + xy + ',"d":null}', R.JWK_PRIVATE),
        ("not JSON", "kty=EC", R.JWK_INVALID),
        ("array", "[]", R.JWK_INVALID),
        ("duplicate member", "{" + xy + f',"x":"{hj.x}"}}', R.JWK_INVALID),
        ("x not a string", f'{{"kty":"EC","crv":"P-256","x":1,"y":"{hj.y}"}}', R.JWK_INVALID),
        ("kid not a string", "{" + xy + ',"kid":1}', R.JWK_INVALID),
        ("kid null", "{" + xy + ',"kid":null}', R.JWK_INVALID),
        ("kty missing", f'{{"crv":"P-256","x":"{hj.x}","y":"{hj.y}"}}', R.JWK_CURVE),
        (
            "kty OKP",
            '{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}',
            R.JWK_CURVE,
        ),
        ("crv lowercase", f'{{"kty":"EC","crv":"p-256","x":"{hj.x}","y":"{hj.y}"}}', R.JWK_CURVE),
        ("y missing", f'{{"kty":"EC","crv":"P-256","x":"{hj.x}"}}', R.JWK_INVALID),
        ("x padded", f'{{"kty":"EC","crv":"P-256","x":"{hj.x}=","y":"{hj.y}"}}', R.JWK_INVALID),
        ("y padded", f'{{"kty":"EC","crv":"P-256","x":"{hj.x}","y":"{hj.y}="}}', R.JWK_INVALID),
        (
            "y standard alphabet",
            f'{{"kty":"EC","crv":"P-256","x":"{hj.x}","y":"{std_y}"}}',
            R.JWK_INVALID,
        ),
        ("x 33 octets", f'{{"kty":"EC","crv":"P-256","x":"{x33}","y":"{hj.y}"}}', R.JWK_INVALID),
        (
            "x spare bits",
            f'{{"kty":"EC","crv":"P-256","x":"{hj.x[:42]}Z","y":"{hj.y}"}}',
            R.JWK_INVALID,
        ),
        (
            "off curve",
            f'{{"kty":"EC","crv":"P-256","x":"{hj.x}","y":"{fixture_jwk("issuer").y}"}}',
            R.JWK_OFF_CURVE,
        ),
        ("x = p", f'{{"kty":"EC","crv":"P-256","x":"{p}","y":"{hj.y}"}}', R.JWK_OFF_CURVE),
        (
            "x = y = 0",
            f'{{"kty":"EC","crv":"P-256","x":"{b64(bytes(32))}","y":"{b64(bytes(32))}"}}',
            R.JWK_OFF_CURVE,
        ),
        ("alg RS256", "{" + xy + ',"alg":"RS256"}', R.JWK_USAGE),
        ("use enc", "{" + xy + ',"use":"enc"}', R.JWK_USAGE),
        # key_ops (RFC 7517 section 4.3): a verification key names verify, and no
        # operation twice.
        ("key_ops sign", "{" + xy + ',"key_ops":["sign"]}', R.JWK_USAGE),
        ("key_ops encrypt", "{" + xy + ',"key_ops":["encrypt"]}', R.JWK_USAGE),
        ("key_ops empty", "{" + xy + ',"key_ops":[]}', R.JWK_USAGE),
        ("key_ops Verify", "{" + xy + ',"key_ops":["Verify"]}', R.JWK_USAGE),
        ("key_ops duplicate", "{" + xy + ',"key_ops":["verify","verify"]}', R.JWK_INVALID),
        ("key_ops a string", "{" + xy + ',"key_ops":"verify"}', R.JWK_INVALID),
        ("key_ops not strings", "{" + xy + ',"key_ops":["verify",5]}', R.JWK_INVALID),
        ("key_ops null", "{" + xy + ',"key_ops":null}', R.JWK_INVALID),
    ]


def test_parse_jwk() -> None:
    hj = fixture_jwk("holder")
    assert (hj.kid, hj.alg, hj.use, hj.kty, hj.crv) == (
        "test-holder-key-1",
        "ES256",
        "sig",
        "EC",
        "P-256",
    )
    for name, src, want in parse_jwk_cases():
        err = want_reason(partial(jws.parse_jwk, src.encode()), want)
        assert err.reason == want, name
    xy = f'"kty":"EC","crv":"P-256","x":"{hj.x}","y":"{hj.y}"'
    # Members the JWK specification does not define are ignored (RFC 7517 section 4).
    jws.parse_jwk(("{" + xy + ',"key_ops":["verify"],"x5t":"abc","ext":true}').encode())
    # key_ops that name verify, alone or with other operations, are accepted.
    for ops in ('["verify"]', '["sign","verify"]', '["verify","encrypt"]'):
        jws.parse_jwk(("{" + xy + ',"key_ops":' + ops + "}").encode())


def test_coordinates_checked_before_the_point() -> None:
    """A coordinate that is not 43 canonical characters for 32 octets is jwk-invalid
    even when its value would be a point of the curve, or not."""
    hj = fixture_jwk("holder")
    issuer_y = fixture_jwk("issuer").y
    for x, y in ((hj.x + "=", issuer_y), (hj.x[:42], issuer_y), (b64(b"\x00" + b64d(hj.x)), hj.y)):
        k = jws.JWK(kty="EC", crv="P-256", x=x, y=y)
        want_reason(partial(jws.public_key_of, k), jws.Reason.JWK_INVALID)
    pub = jws.public_key_of(hj)
    assert isinstance(pub, ec.EllipticCurvePublicKey)
    assert pub.public_numbers().x == int.from_bytes(b64d(hj.x), "big")


def test_public_jwk_keeps_leading_zeros() -> None:
    """Coordinates are the full 32 octets (RFC 7518 section 6.2.1.2) even when they start
    with a zero octet. P-256 scalar 379 is the smallest above 6 whose x does."""
    key = ec.derive_private_key(379, ec.SECP256R1())
    k = jws.public_jwk(key.public_key())
    x = b64d(k.x)
    assert (len(k.x), len(x), x[0]) == (43, 32, 0)
    assert (k.kid, k.alg, k.use) == ("", "", "")
    assert jws.public_key_of(k).public_numbers() == key.public_key().public_numbers()


def test_public_jwk_rejects() -> None:
    want_reason(partial(jws.public_jwk, None), jws.Reason.JWK_INVALID)
    p384 = ec.generate_private_key(ec.SECP384R1()).public_key()
    want_reason(partial(jws.public_jwk, p384), jws.Reason.JWK_CURVE)


def test_key_set() -> None:
    iss, val = fixture_jwk("issuer"), fixture_jwk("validator")
    s = jws.new_key_set(iss, val)
    got = s.lookup("test-validator-key-1")
    assert got is not None
    assert got.x == val.x
    assert s.lookup("test-holder-key-1") is None
    assert jws.KeySet().lookup("test-issuer-key-1") is None
    assert s.lookup("") is None
    want_reason(partial(jws.new_key_set, iss, iss), jws.Reason.KID_DUPLICATE)
    no_kid = jws.JWK(kty=iss.kty, crv=iss.crv, x=iss.x, y=iss.y)
    want_reason(partial(jws.new_key_set, no_kid), jws.Reason.KID_MISSING)
    bad = jws.JWK(kty=iss.kty, crv=iss.crv, x=iss.x, y=val.y, kid=iss.kid)
    want_reason(partial(jws.new_key_set, bad), jws.Reason.JWK_OFF_CURVE)
    wrong_use = jws.JWK(kty=iss.kty, crv=iss.crv, x=iss.x, y=iss.y, kid=iss.kid, use="enc")
    want_reason(partial(jws.new_key_set, wrong_use), jws.Reason.JWK_USAGE)


def test_fixture_thumbprints() -> None:
    """The thumbprints of the P-256 test keys, as the probe records report them."""
    want = {
        "holder": HOLDER_JKT,
        "issuer": "AhqHzaYXA5MzmDCrsseUsVBGKyfhDhvekx0THjH_xIE",
        "adversarial": "B3zQUJfL8WPQJT3fRc_9F85aNjqoqRkk-HMzwyAp7WU",
        "reputation-service": "BcYkeRReg8Py6HmUFJw6240ruOKnvInXb5rRtK6Z9xQ",
        "learning-controller": "yiaHWTOH-NAS43bw6yPHO8YTK_T9cLz9jZaCu3qOg_k",
        "validator": "uhdbksqePVMcTx2Fvr5RY78RjuSE2bd16nNAkdfZ36I",
    }
    for name, w in want.items():
        assert jws.thumbprint(fixture_jwk(name)) == w, name


def test_jwk_algorithm() -> None:
    assert jws.JWK(kty="EC", crv="P-256").algorithm() == jws.ALG_ES256
    assert jws.JWK(kty="OKP", crv="Ed25519").algorithm() == jws.ALG_ED25519
    want_reason(jws.JWK(kty="EC", crv="P-384").algorithm, jws.Reason.JWK_CURVE)


# RFC 8037 Appendix A.3: the thumbprint of the Ed25519 public key of Appendix A.2,
# over crv, kty and x (RFC 8037 section 2). The key is spec/v1.0/fixtures/keys/ed25519.
RFC8037_X = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
RFC8037_THUMBPRINT = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"


def test_thumbprint_okp_rfc8037() -> None:
    k = jws.JWK(kty="OKP", crv="Ed25519", x=RFC8037_X)
    assert jws.thumbprint(k) == RFC8037_THUMBPRINT
    # Optional members do not enter it.
    with_members = jws.JWK(kty="OKP", crv="Ed25519", x=RFC8037_X, kid="k", alg="Ed25519", use="sig")
    assert jws.thumbprint(with_members) == RFC8037_THUMBPRINT
    raw = json.loads((fixtures() / "keys" / "ed25519.jwk.json").read_bytes())
    fixture = jws.JWK(**{m: raw[m] for m in ("kty", "crv", "x", "kid", "alg", "use")})
    assert jws.thumbprint(fixture) == RFC8037_THUMBPRINT


def test_thumbprint_okp_rejects() -> None:
    """The OKP checks of Go's Ed25519PublicKey that need no point arithmetic: no y, and x
    the canonical base64url of 32 octets."""
    R = jws.Reason
    cases = [
        ("y present", jws.JWK(kty="OKP", crv="Ed25519", x=RFC8037_X, y=RFC8037_X), R.JWK_INVALID),
        ("x padded", jws.JWK(kty="OKP", crv="Ed25519", x=RFC8037_X + "="), R.JWK_INVALID),
        ("x short", jws.JWK(kty="OKP", crv="Ed25519", x=RFC8037_X[:42]), R.JWK_INVALID),
        (
            "x 33 octets",
            jws.JWK(kty="OKP", crv="Ed25519", x=b64(b"\x00" + b64d(RFC8037_X))),
            R.JWK_INVALID,
        ),
        ("x empty", jws.JWK(kty="OKP", crv="Ed25519"), R.JWK_INVALID),
        ("crv X25519", jws.JWK(kty="OKP", crv="X25519", x=RFC8037_X), R.JWK_CURVE),
    ]
    for name, k, want in cases:
        err = want_reason(partial(jws.thumbprint, k), want)
        assert err.reason == want, name
