"""Public JSON Web Keys of the profile and RFC 7638 thumbprints. Mirrors
go/core/jws/jwk.go for EC P-256 keys."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final

from cryptography.hazmat.primitives.asymmetric import ec

from hop_top_pact.core import strictjson
from hop_top_pact.core.jws import base64url
from hop_top_pact.core.jws.errors import JWSError, Reason
from hop_top_pact.core.jws.typ import ALG_ED25519, ALG_ES256
from hop_top_pact.core.types import JSONObject, JSONValue

__all__ = ["JWK", "parse_jwk", "public_jwk", "public_key_of", "thumbprint"]

# The private key members of RFC 7518 section 6: EC d, RSA d, p, q, dp, dq, qi,
# oth, and the symmetric k.
_PRIVATE_MEMBERS: Final = ("d", "p", "q", "dp", "dq", "qi", "oth", "k")
# The members a JWK keeps, in the order they are read and written.
_STRING_MEMBERS: Final = ("kty", "crv", "x", "y", "kid", "alg", "use")
# The octets of a P-256 coordinate (RFC 7518 section 6.2.1.2).
_COORDINATE_OCTETS: Final = 32


@dataclass(frozen=True, slots=True)
class JWK:
    """A public key in JSON Web Key form (RFC 7517): an EC P-256 key (RFC 7518 section
    6.2.1). An empty string is an absent member; kid, alg and use are optional.

    A JWK built in Python is checked when it is used: by public_key_of,
    thumbprint, new_key_set and sign.
    """

    kty: str = ""
    crv: str = ""
    x: str = ""
    y: str = ""
    kid: str = ""
    alg: str = ""
    use: str = ""

    def algorithm(self) -> str:
        """Return the one algorithm the key's kty and crv serve: ES256 for EC P-256,
        Ed25519 for OKP Ed25519 (RFC 9864 section 2.2, RFC 8037 section 2). Other key
        types raise JWSError(JWK_CURVE). The key material is not checked."""
        if self.kty == "EC" and self.crv == "P-256":
            return ALG_ES256
        if self.kty == "OKP" and self.crv == "Ed25519":
            return ALG_ED25519
        raise JWSError(
            Reason.JWK_CURVE,
            f"kty {self.kty!r} crv {self.crv!r}, want EC P-256 or, when negotiated, OKP Ed25519",
        )


def parse_jwk(data: bytes) -> JWK:
    """Strict-parse the JWK text data and check that it is a usable ES256 public key.

    A strict JSON object (draft 7.1) without private members, kty EC, crv
    P-256, x and y the canonical unpadded base64url of 32 octets each and
    together a point of the curve, alg and use, when present, ES256 and sig,
    and key_ops, when present, an array of distinct strings that names verify
    (RFC 7517 section 4.3). key_ops is checked, not kept. Members RFC 7517
    does not define for this use are ignored (RFC 7517 section 4). Raises
    JWSError.
    """
    try:
        m = _decode_object(data)
    except strictjson.StrictJSONError as e:
        raise JWSError(Reason.JWK_INVALID, "not a strict JSON object", e) from e
    return _jwk_from_object(m)


def _decode_object(data: bytes, limits: strictjson.Limits | None = None) -> JSONObject:
    """Strict-decode data as a JSON object (Go: Unmarshal into map[string]json.RawMessage);
    raise StrictJSONError, of kind TYPE when data is another JSON value."""
    return strictjson.decode(data, JSONObject, limits)  # type: ignore[type-abstract]


def _jwk_from_object(m: JSONValue) -> JWK:
    """parse_jwk for a value already strict-parsed, such as the jwk member of a header."""
    if not isinstance(m, Mapping):
        raise JWSError(Reason.JWK_INVALID, "not a strict JSON object")
    for name in _PRIVATE_MEMBERS:
        if name in m:
            raise JWSError(Reason.JWK_PRIVATE, "member " + name)
    values: dict[str, str] = {}
    for name in _STRING_MEMBERS:
        if name not in m:
            continue
        v = m[name]
        if not isinstance(v, str):
            raise JWSError(Reason.JWK_INVALID, name + " is not a string")
        values[name] = v
    k = JWK(**values)
    _check_key(k)
    if "key_ops" in m:
        _check_key_ops(m["key_ops"])
    return k


def _check_key_ops(ops: JSONValue) -> None:
    """A key_ops member (RFC 7517 section 4.3): an array of strings, none twice, that
    names verify, the operation a trusted public key serves."""
    if not isinstance(ops, tuple) or not all(isinstance(op, str) for op in ops):
        raise JWSError(Reason.JWK_INVALID, "key_ops is not an array of strings")
    for i, op in enumerate(ops):
        if op in ops[:i]:
            raise JWSError(Reason.JWK_INVALID, f"key_ops names {op!r} twice")
    if "verify" not in ops:
        raise JWSError(Reason.JWK_USAGE, f"key_ops {list(ops)!r} does not name verify")


def _check_key(k: JWK) -> ec.EllipticCurvePublicKey:
    """Check that k is a key for ES256 with valid material and fitting alg and use;
    return its public key. An Ed25519 key is refused as not negotiated."""
    alg = k.algorithm()
    if alg != ALG_ES256:
        raise JWSError(Reason.JWK_CURVE, f"kty {k.kty!r} crv {k.crv!r}: {alg} is not negotiated")
    pub = public_key_of(k)
    _check_usage(k, alg)
    return pub


def _check_usage(k: JWK, alg: str) -> None:
    """alg and use, when present, must be alg and sig."""
    if k.alg and k.alg != alg:
        raise JWSError(Reason.JWK_USAGE, f"alg {k.alg!r}, want {alg}")
    if k.use and k.use != "sig":
        raise JWSError(Reason.JWK_USAGE, f"use {k.use!r}, want sig")


def public_key_of(k: JWK) -> ec.EllipticCurvePublicKey:
    """Check kty, crv, x and y of k and return its public key; kid, alg and use are not
    looked at (Go: JWK.PublicKey).

    Each coordinate must be the canonical unpadded base64url of exactly 32
    octets before the point is built, so a malformed coordinate is
    jwk-invalid even where its value is not a point of the curve; a
    well-formed pair that is not a point (x or y not below p included) is
    jwk-off-curve.
    """
    if k.kty != "EC" or k.crv != "P-256":
        raise JWSError(Reason.JWK_CURVE, f"kty {k.kty!r} crv {k.crv!r}, want EC P-256")
    x = _coordinate("x", k.x)
    y = _coordinate("y", k.y)
    try:
        return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
    except ValueError as e:
        raise JWSError(Reason.JWK_OFF_CURVE, "", e) from e


def _coordinate(name: str, s: str) -> int:
    try:
        b = base64url.decode(s)
    except ValueError as e:
        raise JWSError(Reason.JWK_INVALID, name + " is not canonical base64url", e) from e
    if len(b) != _COORDINATE_OCTETS:
        raise JWSError(Reason.JWK_INVALID, f"{name} has {len(b)} octets, want {_COORDINATE_OCTETS}")
    return int.from_bytes(b, "big")


def public_jwk(key: ec.EllipticCurvePublicKey | None) -> JWK:
    """Return the JWK of the P-256 public key key, with x and y at their full 32 octets
    (RFC 7518 section 6.2.1.2) and no optional members."""
    if key is None:
        raise JWSError(Reason.JWK_INVALID, "no public key")
    if not isinstance(key, ec.EllipticCurvePublicKey) or key.curve.name != "secp256r1":
        raise JWSError(Reason.JWK_CURVE, "not a P-256 key")
    n = key.public_numbers()
    return JWK(
        kty="EC",
        crv="P-256",
        x=base64url.encode(n.x.to_bytes(_COORDINATE_OCTETS, "big")),
        y=base64url.encode(n.y.to_bytes(_COORDINATE_OCTETS, "big")),
    )


def thumbprint(k: JWK) -> str:
    """Return the RFC 7638 SHA-256 thumbprint of k, unpadded base64url.

    SHA-256 over the required members in lexicographic order without white
    space: {"crv":...,"kty":...,"x":...,"y":...} for an EC key and
    {"crv":...,"kty":...,"x":...} for an OKP key (RFC 8037 Appendix A.3).
    Optional members do not enter it. k must be a valid P-256 key (see
    public_key_of) or an OKP Ed25519 key with no y and an x of 32 octets in
    canonical base64url; the point of an Ed25519 key is not checked, which
    the Go package does (this package has no Ed25519). The values are hashed
    as written: base64url and fixed ASCII names, so nothing needs JSON
    escaping (RFC 7638 section 3.3).
    """
    if k.algorithm() == ALG_ES256:
        public_key_of(k)
        text = f'{{"crv":"{k.crv}","kty":"{k.kty}","x":"{k.x}","y":"{k.y}"}}'
    else:
        _okp_x(k)
        text = f'{{"crv":"{k.crv}","kty":"{k.kty}","x":"{k.x}"}}'
    return base64url.encode(hashlib.sha256(text.encode("ascii")).digest())


def _okp_x(k: JWK) -> bytes:
    """The x of an OKP Ed25519 key (RFC 8037 section 2): no y, 32 octets."""
    if k.y:
        raise JWSError(Reason.JWK_INVALID, "an OKP key has no y")
    try:
        b = base64url.decode(k.x)
    except ValueError as e:
        raise JWSError(Reason.JWK_INVALID, "x is not canonical base64url", e) from e
    if len(b) != _COORDINATE_OCTETS:
        raise JWSError(Reason.JWK_INVALID, f"x has {len(b)} octets, want {_COORDINATE_OCTETS}")
    return b
