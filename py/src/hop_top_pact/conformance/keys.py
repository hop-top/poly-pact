"""The ES256 test keys of the fixture directory. Mirrors go/runner/evalcase/keys.go."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from cryptography.hazmat.primitives.asymmetric import ec

from hop_top_pact.conformance.errors import CaseError, wrap
from hop_top_pact.core import strictjson
from hop_top_pact.core.jws import ALG_ES256, JWK, JWSError, base64url, parse_jwk, public_jwk
from hop_top_pact.errors import PactError

__all__ = ["KEYS_FILE", "Key", "load_keys"]

KEYS_FILE: Final = "keys/test-private-scalars.json"
"""The file of the private test values, relative to the fixture directory."""

_N: Final = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
_SCALAR_OCTETS: Final = 32


@dataclass(frozen=True, slots=True)
class Key:
    """An ES256 test key of KEYS_FILE: its role, its private key, and its public JWK
    file, whose kid signed files carry."""

    role: str
    private: ec.EllipticCurvePrivateKey
    public: JWK


@dataclass(frozen=True, slots=True)
class _ScalarKey:
    role: str = ""
    kid: str = ""
    alg: str = ""
    kty: str = ""
    crv: str = ""
    scalar: str = ""
    seed_hex: str = ""
    d: str = ""
    public_jwk: str = ""


@dataclass(frozen=True, slots=True)
class _Scalars:
    label: str = ""
    warning: str = ""
    encoding: str = ""
    keys: tuple[_ScalarKey, ...] = ()


def _private(d64: str) -> ec.EllipticCurvePrivateKey:
    """The P-256 private key of the raw scalar d64, as Go's ecdsa.ParseRawPrivateKey
    reads it: 32 octets, from 1 to n-1."""
    d = base64url.decode(d64)
    if len(d) != _SCALAR_OCTETS:
        raise ValueError(f"d has {len(d)} octets, want {_SCALAR_OCTETS}")
    v = int.from_bytes(d, "big")
    if not 0 < v < _N:
        raise ValueError("d is not a P-256 private scalar")
    return ec.derive_private_key(v, ec.SECP256R1())


def load_keys(fixtures: str | os.PathLike[str]) -> dict[str, Key]:
    """Read the ES256 test keys of KEYS_FILE under the fixture directory, by role, and
    check each against its public JWK file: the public point and the kid must match.
    The Ed25519 pair is not listed. Raises CaseError."""
    root = Path(fixtures)
    try:
        data = (root / KEYS_FILE).read_bytes()
    except OSError as e:
        raise wrap(KEYS_FILE, e) from e
    try:
        scalars = strictjson.decode(data, _Scalars)
    except strictjson.StrictJSONError as e:
        raise wrap(KEYS_FILE, e) from e
    out: dict[str, Key] = {}
    for k in scalars.keys:
        if k.alg != ALG_ES256:
            continue  # the Ed25519 pair is not an ES256 key
        try:
            priv = _private(k.d)
        except ValueError as e:
            raise wrap(f"{KEYS_FILE}: role {k.role}: d", e) from e
        try:
            pb = root.joinpath("keys", *k.public_jwk.split("/")).read_bytes()
        except OSError as e:
            raise wrap(f"{KEYS_FILE}: role {k.role}", e) from e
        try:
            jwk = parse_jwk(pb)
        except JWSError as e:
            raise wrap("keys/" + k.public_jwk, e) from e
        try:
            own = public_jwk(priv.public_key())
        except PactError as e:
            raise wrap(f"{KEYS_FILE}: role {k.role}", e) from e
        if own.x != jwk.x or own.y != jwk.y or jwk.kid != k.kid:
            raise CaseError(
                f"keys/{k.public_jwk} is not the public key of role {k.role} (kid {k.kid})"
            )
        out[k.role] = Key(role=k.role, private=priv, public=jwk)
    return out
