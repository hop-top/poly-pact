"""Ed25519 and algorithm negotiation (draft 7.2). Port of go/core/jws/ed25519_test.go,
ed25519_point_test.go and ed25519_internal_test.go, and of the negotiated key_ops case
of jwk_test.go."""

from __future__ import annotations

import base64
import json
import os
from collections.abc import Callable
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from hop_top_pact.core import jws
from hop_top_pact.core.jws import _ed25519 as point

FIXTURES = Path(__file__).resolve().parents[2] / "spec" / "v1.0" / "fixtures"
# The Ed25519 pair of spec/v1.0/fixtures/keys: the seed of RFC 8032 section 7.1, test 1,
# which is also the private key of RFC 8037 Appendix A.1.
SEED_HEX = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
RFC8037_X = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
# The RFC 7638 thumbprint of that public key, RFC 8037 Appendix A.3.
RFC8037_JKT = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
# The compact JWS of RFC 8037 Appendix A.4, alg EdDSA.
RFC8037_A4 = (
    "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc."
    "hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg"
)
SMALL_PAYLOAD = '{"pact_version":"0.1","jti":"unit"}'
ED_HEADER = '{"alg":"Ed25519","typ":"pact-evidence+jwt","kid":"test-ed25519-key-1"}'
ES_HEADER = '{"alg":"ES256","typ":"pact-evidence+jwt","kid":"test-issuer-key-1"}'
# A deployment that has negotiated Ed25519 beside ES256 (draft 7.2).
NEGOTIATED = jws.Algorithms((jws.ALG_ES256, jws.ALG_ED25519))
R = jws.Reason


def b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def fixtures() -> Path:
    if not FIXTURES.exists():
        if os.environ.get("PACT_REQUIRE_VECTORS") == "1":
            pytest.fail(f"{FIXTURES} absent under PACT_REQUIRE_VECTORS=1")
        pytest.skip("no spec/ tree (mirror checkout)")
    return FIXTURES


def want_reason(f: Callable[[], object], want: jws.Reason) -> jws.JWSError:
    with pytest.raises(jws.JWSError) as info:
        f()
    assert jws.reason_of(info.value) == want, str(info.value)
    return info.value


def ed_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(SEED_HEX))


def raw_public(key: Ed25519PrivateKey) -> bytes:
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def ed_file() -> bytes:
    return (fixtures() / "keys" / "ed25519.jwk.json").read_bytes()


def ed_jwk() -> jws.JWK:
    return NEGOTIATED.parse_jwk(ed_file())


def fixture_jwk(name: str) -> jws.JWK:
    return jws.parse_jwk((fixtures() / "keys" / f"{name}.jwk.json").read_bytes())


def scalar_key(n: int) -> ec.EllipticCurvePrivateKey:
    return ec.derive_private_key(n, ec.SECP256R1())


def raw_ed(header: str, payload: str, key: Ed25519PrivateKey) -> str:
    """header.payload signed by key directly, so that tests build inputs the signers
    refuse to make."""
    si = b64(header.encode()) + "." + b64(payload.encode())
    return si + "." + b64(key.sign(si.encode()))


def raw_es(header: str, payload: str, key: ec.EllipticCurvePrivateKey) -> str:
    from cryptography.hazmat.primitives import hashes

    si = b64(header.encode()) + "." + b64(payload.encode())
    r, s = decode_dss_signature(key.sign(si.encode(), ec.ECDSA(hashes.SHA256())))
    n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    if s > n >> 1:
        s = n - s
    return si + "." + b64(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def mixed_resolver() -> jws.StaticResolver:
    """Trusts the issuer P-256 key and the Ed25519 key for the issuer role, and the
    RFC 8037 thumbprint for holders."""
    keys = NEGOTIATED.new_key_set(fixture_jwk("issuer"), ed_jwk())
    return jws.StaticResolver(key_sets={jws.Role.ISSUER: keys}, expected_holder_jkt=RFC8037_JKT)


def holder_header(x: str = RFC8037_X, alg: str = "Ed25519") -> str:
    return (
        '{"alg":"' + alg + '","typ":"pact-presentation+jwt","jwk":'
        '{"kty":"OKP","crv":"Ed25519","x":"' + x + '"}}'
    )


def test_ed25519_key_file() -> None:
    # The fixture key is the RFC 8037 A.2 public key, and its RFC 7638 thumbprint is
    # the A.3 value.
    k = ed_jwk()
    assert (k.kty, k.crv, k.x, k.y, k.alg, k.kid) == (
        "OKP",
        "Ed25519",
        RFC8037_X,
        "",
        jws.ALG_ED25519,
        "test-ed25519-key-1",
    )
    pub = k.ed25519_public_key()
    assert isinstance(pub, Ed25519PublicKey)
    assert pub.public_bytes_raw() == raw_public(ed_key())
    assert jws.thumbprint(k) == RFC8037_JKT
    assert k.algorithm() == jws.ALG_ED25519
    assert fixture_jwk("issuer").algorithm() == jws.ALG_ES256
    want_reason(jws.JWK(kty="RSA").algorithm, R.JWK_CURVE)
    own = jws.public_ed25519_jwk(ed_key().public_key())
    assert (own.x, own.kty, own.crv) == (k.x, "OKP", "Ed25519")


def test_ed25519_not_negotiated() -> None:
    # Without negotiation the profile is ES256 alone (draft 7.2): the OKP key, the alg
    # and the key set are all refused.
    data = ed_file()
    want_reason(lambda: jws.parse_jwk(data), R.JWK_CURVE)
    want_reason(lambda: jws.Algorithms().parse_jwk(data), R.JWK_CURVE)
    want_reason(lambda: jws.Algorithms((jws.ALG_ES256,)).parse_jwk(data), R.JWK_CURVE)
    want_reason(lambda: jws.new_key_set(ed_jwk()), R.JWK_CURVE)
    want_reason(lambda: jws.thumbprint(jws.JWK(kty="OKP", crv="Ed448", x=RFC8037_X)), R.JWK_CURVE)
    compact = raw_ed(ED_HEADER, SMALL_PAYLOAD, ed_key())
    res = mixed_resolver()
    for v in (
        jws.Verifier(keys=res),
        jws.Verifier(keys=res, algorithms=jws.Algorithms((jws.ALG_ES256,))),
    ):
        want_reason(lambda v=v: v.verify(compact), R.ALG_UNSUPPORTED)  # type: ignore[misc]
    # A holder presentation with an embedded OKP key is refused too.
    want_reason(
        lambda: jws.verify(raw_ed(holder_header(), SMALL_PAYLOAD, ed_key()), res),
        R.ALG_UNSUPPORTED,
    )


@pytest.mark.parametrize("algs", [NEGOTIATED, jws.Algorithms((jws.ALG_ED25519,))])
def test_ed25519_negotiated(algs: jws.Algorithms) -> None:
    # Once negotiated, an Ed25519 JWS verifies under an OKP key (RFC 8037 section 2, RFC
    # 9864 section 2.2), for a service signer by kid and for a holder by the thumbprint
    # of its embedded key.
    res, key = mixed_resolver(), ed_key()
    v = jws.Verifier(keys=res, algorithms=algs)
    p = v.verify(raw_ed(ED_HEADER, SMALL_PAYLOAD, key))
    assert p.header.alg == jws.ALG_ED25519
    assert p.key.kid == "test-ed25519-key-1"
    assert p.key_thumbprint == RFC8037_JKT
    assert len(p.signature) == 64
    p = v.verify(raw_ed(holder_header(), SMALL_PAYLOAD, key))
    assert p.header.jwk is not None
    assert p.header.jwk.kty == "OKP"
    assert p.key_thumbprint == RFC8037_JKT


def test_es256_under_negotiation() -> None:
    # ES256 still verifies when both are negotiated, and not when only Ed25519 is.
    res = mixed_resolver()
    es = raw_es(ES_HEADER, SMALL_PAYLOAD, scalar_key(2))
    jws.Verifier(keys=res, algorithms=NEGOTIATED).verify(es)
    only = jws.Verifier(keys=res, algorithms=jws.Algorithms((jws.ALG_ED25519,)))
    want_reason(lambda: only.verify(es), R.ALG_UNSUPPORTED)


def test_ed25519_changed_payload_or_signature_fails() -> None:
    res, key = mixed_resolver(), ed_key()
    v = jws.Verifier(keys=res, algorithms=NEGOTIATED)
    good = raw_ed(ED_HEADER, SMALL_PAYLOAD, key).split(".")
    other = raw_ed(ED_HEADER, '{"pact_version":"0.1","jti":"other"}', key).split(".")
    swapped = good[0] + "." + other[1] + "." + good[2]
    want_reason(lambda: v.verify(swapped), R.SIGNATURE_INVALID)
    sig = bytearray(b64d(good[2]))
    sig[63] ^= 0x01
    flipped = good[0] + "." + good[1] + "." + b64(bytes(sig))
    want_reason(lambda: v.verify(flipped), R.SIGNATURE_INVALID)


@pytest.mark.parametrize("alg", ["EdDSA", "eddsa", "ed25519", "none", "HS256", "Ed448"])
@pytest.mark.parametrize("listing", ["negotiated", "listing it"])
def test_ed25519_rejects_other_identifiers(alg: str, listing: str) -> None:
    # Negotiating Ed25519 admits that one identifier. EdDSA (RFC 9864 section 4.1.2
    # deprecates it; draft 7.2 does not accept it), none and HMAC stay refused even
    # with a valid Ed25519 signature and even when a deployment lists them.
    lenient = jws.Algorithms((jws.ALG_ES256, jws.ALG_ED25519, "EdDSA", "none", "HS256"))
    algs = NEGOTIATED if listing == "negotiated" else lenient
    h = '{"alg":"' + alg + '","typ":"pact-evidence+jwt","kid":"test-ed25519-key-1"}'
    v = jws.Verifier(keys=mixed_resolver(), algorithms=algs)
    want_reason(lambda: v.verify(raw_ed(h, SMALL_PAYLOAD, ed_key())), R.ALG_UNSUPPORTED)


def test_rfc8037_example_has_alg_eddsa() -> None:
    # Its signature is a valid Ed25519 signature, but its alg is EdDSA.
    lenient = jws.Algorithms((jws.ALG_ES256, jws.ALG_ED25519, "EdDSA", "none", "HS256"))
    v = jws.Verifier(keys=mixed_resolver(), algorithms=lenient)
    want_reason(lambda: v.verify(RFC8037_A4), R.ALG_UNSUPPORTED)


def test_ed25519_alg_key_mismatch() -> None:
    # The header alg must be the algorithm of the key that verifies it, in both
    # directions.
    v = jws.Verifier(keys=mixed_resolver(), algorithms=NEGOTIATED)
    holder = fixture_jwk("holder")
    holder_json = json.dumps(
        {"kty": holder.kty, "crv": holder.crv, "x": holder.x, "y": holder.y},
        separators=(",", ":"),
    )
    cases = {
        "Ed25519 header, P-256 kid": raw_ed(
            '{"alg":"Ed25519","typ":"pact-evidence+jwt","kid":"test-issuer-key-1"}',
            SMALL_PAYLOAD,
            ed_key(),
        ),
        "ES256 header, Ed25519 kid": raw_es(
            '{"alg":"ES256","typ":"pact-evidence+jwt","kid":"test-ed25519-key-1"}',
            SMALL_PAYLOAD,
            scalar_key(2),
        ),
        "Ed25519 header, P-256 holder jwk": raw_ed(
            '{"alg":"Ed25519","typ":"pact-presentation+jwt","jwk":' + holder_json + "}",
            SMALL_PAYLOAD,
            ed_key(),
        ),
        "ES256 header, OKP holder jwk": raw_es(
            holder_header(alg="ES256"), SMALL_PAYLOAD, scalar_key(1)
        ),
    }
    for name, compact in cases.items():
        err = want_reason(lambda c=compact: v.verify(c), R.JWK_USAGE)  # type: ignore[misc]
        assert err.reason == R.JWK_USAGE, name


def test_ed25519_parse_jwk() -> None:
    # An OKP key is checked as RFC 8037 section 2 writes it, once Ed25519 is negotiated.
    x = RFC8037_X
    holder = fixture_jwk("holder")
    base = '"kty":"OKP","crv":"Ed25519","x":"' + x + '"'
    cases = [
        ("d", "{" + base + ',"d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"}', R.JWK_PRIVATE),
        ("crv Ed448", '{"kty":"OKP","crv":"Ed448","x":"' + x + '"}', R.JWK_CURVE),
        ("crv X25519", '{"kty":"OKP","crv":"X25519","x":"' + x + '"}', R.JWK_CURVE),
        ("crv missing", '{"kty":"OKP","x":"' + x + '"}', R.JWK_CURVE),
        ("x missing", '{"kty":"OKP","crv":"Ed25519"}', R.JWK_INVALID),
        (
            "x 31 octets",
            '{"kty":"OKP","crv":"Ed25519","x":"' + b64(b64d(x)[:31]) + '"}',
            R.JWK_INVALID,
        ),
        ("x padded", '{"kty":"OKP","crv":"Ed25519","x":"' + x + '="}', R.JWK_INVALID),
        ("y present", "{" + base + ',"y":"' + x + '"}', R.JWK_INVALID),
        ("alg EdDSA", "{" + base + ',"alg":"EdDSA"}', R.JWK_USAGE),
        ("alg ES256", "{" + base + ',"alg":"ES256"}', R.JWK_USAGE),
        ("use enc", "{" + base + ',"use":"enc"}', R.JWK_USAGE),
        (
            "EC key with alg Ed25519",
            '{"kty":"EC","crv":"P-256","x":"'
            + holder.x
            + '","y":"'
            + holder.y
            + '","alg":"Ed25519"}',
            R.JWK_USAGE,
        ),
        ("key_ops sign", "{" + base + ',"key_ops":["sign"]}', R.JWK_USAGE),
    ]
    for name, src, want in cases:
        err = want_reason(lambda s=src: NEGOTIATED.parse_jwk(s.encode()), want)  # type: ignore[misc]
        assert err.reason == want, name
    NEGOTIATED.parse_jwk(("{" + base + "}").encode())  # a bare OKP key
    NEGOTIATED.parse_jwk(("{" + base + ',"key_ops":["verify"]}').encode())
    NEGOTIATED.parse_jwk((fixtures() / "keys" / "issuer.jwk.json").read_bytes())  # P-256 too


def test_sign_ed25519() -> None:
    # sign_ed25519 writes alg Ed25519 and a deterministic RFC 8032 signature over the
    # received signing input.
    key = ed_key()
    v = jws.Verifier(keys=mixed_resolver(), algorithms=NEGOTIATED)
    compact = jws.sign_ed25519(
        jws.Header(typ=jws.TYP_EVIDENCE, kid="test-ed25519-key-1"), SMALL_PAYLOAD.encode(), key
    )
    assert compact == raw_ed(ED_HEADER, SMALL_PAYLOAD, key)
    v.verify(compact)
    holder = jws.sign_ed25519(jws.Header(typ=jws.TYP_PRESENTATION), SMALL_PAYLOAD.encode(), key)
    assert v.verify(holder).key_thumbprint == RFC8037_JKT
    payload = SMALL_PAYLOAD.encode()
    for alg in (jws.ALG_ES256, "EdDSA"):
        h = jws.Header(alg=alg, typ=jws.TYP_EVIDENCE, kid="k")
        want_reason(lambda h=h: jws.sign_ed25519(h, payload, key), R.ALG_UNSUPPORTED)  # type: ignore[misc]
    h = jws.Header(typ=jws.TYP_EVIDENCE, kid="k")
    want_reason(lambda: jws.sign_ed25519(h, payload, None), R.SIGNING_KEY)
    want_reason(lambda: jws.sign_ed25519(h, payload, scalar_key(2)), R.SIGNING_KEY)  # type: ignore[arg-type]
    h = jws.Header(alg=jws.ALG_ED25519, typ=jws.TYP_EVIDENCE, kid="k")
    want_reason(lambda: jws.sign(h, payload, scalar_key(2)), R.ALG_UNSUPPORTED)
    other = Ed25519PrivateKey.from_private_bytes(bytes(32))
    other_jwk = jws.public_ed25519_jwk(other.public_key())
    h = jws.Header(typ=jws.TYP_PRESENTATION, jwk=other_jwk)
    want_reason(lambda: jws.sign_ed25519(h, payload, key), R.SIGNING_KEY)


def test_negotiated_key_ops_of_jwk_test() -> None:
    okp = '"kty":"OKP","crv":"Ed25519","x":"' + RFC8037_X + '"'
    NEGOTIATED.parse_jwk(("{" + okp + ',"key_ops":["verify"]}').encode())
    want_reason(
        lambda: NEGOTIATED.parse_jwk(("{" + okp + ',"key_ops":["sign"]}').encode()), R.JWK_USAGE
    )


# RFC 8032 section 7.1 public keys: tests 1, 2, 3, 1024 and SHA(abc), then the base point B
# of section 5.1 (y = 4/5, x even). All are of the prime order L.
RFC8032_PUBLIC_KEYS = [
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
    "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
    "278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e",
    "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
    "5866666666666666666666666666666666666666666666666666666666666666",
]


def okp(hex_key: str) -> jws.JWK:
    return jws.JWK(kty="OKP", crv="Ed25519", x=b64(bytes.fromhex(hex_key)), kid="k")


@pytest.mark.parametrize("h", RFC8032_PUBLIC_KEYS)
def test_ed25519_public_key_rfc8032_vectors(h: str) -> None:
    k = okp(h)
    assert k.ed25519_public_key().public_bytes_raw().hex() == h
    jws.Algorithms((jws.ALG_ED25519,)).new_key_set(k)


FF = "ff" * 30
Z31 = "00" * 31
INVALID = [
    # Step 1: y, bit 255 cleared, is p or more.
    ("y = p", "ed" + FF + "7f", "y is not below p"),
    ("y = p + 1, the identity not reduced", "ee" + FF + "7f", "y is not below p"),
    ("y = p, sign bit set", "ed" + FF + "ff", "y is not below p"),
    ("y = 2^255 - 1", "ff" + FF + "7f", "y is not below p"),
    # Steps 2 and 3: no square for y = 2 and y = 7.
    ("y = 2, no x", "02" + Z31, "no x"),
    ("y = 2, no x, sign bit set", "02" + "00" * 30 + "80", "no x"),
    ("y = 7, no x", "07" + Z31, "no x"),
    # Step 4: x = 0 with x_0 = 1, for y = 1 and y = p - 1.
    ("y = 1, x = 0, sign bit set", "01" + "00" * 30 + "80", "x = 0 with the sign bit set"),
    ("y = p - 1, x = 0, sign bit set", "ec" + FF + "ff", "x = 0 with the sign bit set"),
    # Small order: the eight points P with [8]P the identity.
    ("identity (0, 1)", "01" + Z31, "small order"),
    ("order 2 (0, -1)", "ec" + FF + "7f", "small order"),
    ("order 4 (sqrt(-1), 0)", "00" * 32, "small order"),
    ("order 4 (-sqrt(-1), 0)", Z31 + "80", "small order"),
    (
        "order 8, 1",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
        "small order",
    ),
    (
        "order 8, 2",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
        "small order",
    ),
    (
        "order 8, 3",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
        "small order",
    ),
    (
        "order 8, 4",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
        "small order",
    ),
    # Mixed order: [8]P is not the identity, so the small-order check passes them.
    ("B + order 2", "9599999999999999999999999999999999999999999999999999999999999999", "[L]A"),
    ("B + order 4", "5252cc0a7f208133b620acbd4537eba2a4123bf0a8c2e4f980c3b31bb69765ea", "[L]A"),
    ("B + order 8", "da99e28ba529cdde35a25fba9059e78ecaee239f99755b9b1aa4f65df00803e2", "[L]A"),
    (
        "test 1 + order 2",
        "16a567fe7d4ef5482ab4012c369bf8c5f11e8d0c2559dcda50fde59708f8aee5",
        "[L]A",
    ),
    (
        "test 1 + order 4",
        "40c7570f4dd54835b9131184410ed4a0cc93e7d9ad053cbc6d07a62426999582",
        "[L]A",
    ),
    (
        "test 1 + order 8",
        "3b5b475c4b82dd1572799fc546f4c6c03e478c6654aa4c7f945b347ea32af60d",
        "[L]A",
    ),
]


@pytest.mark.parametrize(("name", "key", "msg"), INVALID, ids=[c[0] for c in INVALID])
def test_ed25519_public_key_invalid_encodings(name: str, key: str, msg: str) -> None:
    k = okp(key)
    err = want_reason(k.ed25519_public_key, R.JWK_OFF_CURVE)
    assert msg in str(err), str(err)
    algs = jws.Algorithms((jws.ALG_ED25519,))
    want_reason(lambda: algs.new_key_set(k), R.JWK_OFF_CURVE)
    text = '{"kty":"OKP","crv":"Ed25519","x":"' + k.x + '"}'
    want_reason(lambda: algs.parse_jwk(text.encode()), R.JWK_OFF_CURVE)
    want_reason(lambda: jws.thumbprint(k), R.JWK_OFF_CURVE)


def test_rfc8037_a4_signature() -> None:
    pub = jws.JWK(kty="OKP", crv="Ed25519", x=RFC8037_X).ed25519_public_key()
    last = RFC8037_A4.rindex(".")
    sig = b64d(RFC8037_A4[last + 1 :])
    assert point.verify_ed25519(pub, RFC8037_A4[:last], sig)
    changed = bytes([sig[0] ^ 1]) + sig[1:]
    assert not point.verify_ed25519(pub, RFC8037_A4[:last], changed)
    assert not point.verify_ed25519(pub, RFC8037_A4[:last], sig[:63])


def test_recover_x_on_curve() -> None:
    # For y = 0..299, recover_x finds an x exactly when (y^2 - 1) / (d y^2 + 1) is a
    # square mod p, by Euler's criterion, and then (x, y) is on the curve.
    p, d = point._P, point._D
    half = (p - 1) // 2
    square = 0
    for y in range(300):
        yy = y * y
        u, v = (yy - 1) % p, (d * yy + 1) % p
        q = u * pow(v, -1, p) % p
        is_square = q == 0 or pow(q, half, p) == 1
        x = point.recover_x(y)
        assert (x is not None) == is_square, y
        if x is None:
            continue
        square += 1
        assert (yy - x * x - d * x * x * yy - 1) % p == 0, f"y = {y}: not on the curve"
    assert square > 0


def test_ed_mul_matches_affine() -> None:
    # [k]B by ed_mul, in extended coordinates, equals k affine additions of B for k =
    # 0..40, and [L]B is the identity (RFC 8032 section 5.1: B has order L).
    p = point._P
    by = 4 * pow(5, -1, p) % p
    bx = point.recover_x(by)
    assert bx is not None
    if bx & 1:
        bx = p - bx
    ax, ay = 0, 1
    for k in range(41):
        qx, qy, qz, _ = point.ed_mul(k, bx, by)
        zi = pow(qz, -1, p)
        assert (qx * zi % p, qy * zi % p) == (ax, ay), k
        assert point.ed_identity((qx, qy, qz, 0)) == (k == 0), k
        ax, ay = point.ed_add(ax, ay, bx, by)
    assert point.ed_identity(point.ed_mul(point._L, bx, by))
