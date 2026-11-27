"""The holder key and its sources (draft 6.2, 6.4)."""

from __future__ import annotations

from typing import Protocol

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from hop_top_pact.core import jws

__all__ = ["KeySource", "MemoryKey"]

# The order of P-256 (SEC 2, section 2.4.2).
_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


class KeySource(Protocol):
    """Holds the enrolled holder key (draft 6.2, 6.4). The private key never leaves it: the
    holder asks it for the public key and for a signature over a JWS signing input, so an
    OS keychain, a hardware key or a workload signing service can implement it."""

    def public_jwk(self) -> jws.JWK:
        """Return the public key, EC P-256 for ES256 or, where negotiated, OKP Ed25519. It
        never carries private members."""
        ...

    def sign(self, signing_input: bytes) -> bytes:
        """Return the JWS signature over signing_input, the ASCII text of the protected
        header and payload segments joined by a period (RFC 7515 section 5.1), under the
        algorithm of the public key: the 64 octets R || S for ES256 (RFC 7518 section
        3.4), the RFC 8032 signature for Ed25519."""
        ...


class MemoryKey:
    """A KeySource over a private key in process memory, for tests and examples. It is not a
    protected key store: production holders keep their keys in one (draft 6.4)."""

    def __init__(
        self,
        es: ec.EllipticCurvePrivateKey | None,
        ed: Ed25519PrivateKey | None,
        pub: jws.JWK,
    ) -> None:
        self._es = es
        self._ed = ed
        self._pub = pub

    @classmethod
    def es256(cls, key: ec.EllipticCurvePrivateKey | None) -> MemoryKey:
        """A MemoryKey for an ES256 (P-256) key; raise ValueError for no key and JWSError
        for a key of another curve."""
        if key is None:
            raise ValueError("holder: no ES256 key")
        return cls(key, None, jws.public_jwk(key.public_key()))

    @classmethod
    def ed25519(cls, key: Ed25519PrivateKey | None) -> MemoryKey:
        """A MemoryKey for an Ed25519 key; raise ValueError for no key."""
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError("holder: no Ed25519 private key")
        return cls(None, key, jws.public_ed25519_jwk(key.public_key()))

    def public_jwk(self) -> jws.JWK:
        """The key's kty, crv and coordinates, with no optional members."""
        return self._pub

    def sign(self, signing_input: bytes) -> bytes:
        """ES256 signatures are randomized and written low-S, as jws.sign writes them;
        Ed25519 signatures are deterministic."""
        if self._ed is not None:
            return self._ed.sign(signing_input)
        assert self._es is not None
        r, s = decode_dss_signature(self._es.sign(signing_input, ec.ECDSA(hashes.SHA256())))
        if s > _N >> 1:
            s = _N - s
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")
