"""Algorithm negotiation (draft 7.2). Mirrors go/core/jws/alg.go."""

from __future__ import annotations

from hop_top_pact.core.jws.jwk import JWK, _parse_jwk
from hop_top_pact.core.jws.keys import KeySet, _new_key_set
from hop_top_pact.core.jws.typ import accepts

__all__ = ["Algorithms"]


class Algorithms(tuple[str, ...]):
    """The JOSE algorithms a deployment accepts for its signed artifacts (draft 7.2). An
    empty one is the baseline, ES256 alone. Ed25519 (RFC 9864 section 2.2) is accepted
    only when it is listed, that is, when it has been negotiated explicitly; its keys
    are OKP keys of curve Ed25519 (RFC 8037 section 2). ES256 and Ed25519 are the only
    algorithms the package implements: any other entry, the ambiguous EdDSA included,
    never matches a header or a key."""

    __slots__ = ()

    def accepts(self, alg: str) -> bool:
        """Report whether alg is an algorithm of self: ES256 or Ed25519, and listed in
        self, or ES256 when self is empty."""
        return accepts(self, alg)

    def parse_jwk(self, data: bytes) -> JWK:
        """parse_jwk for the algorithms of self: it also accepts an OKP Ed25519 public key
        when self accepts Ed25519. The key's alg member, when present, must be the
        algorithm of its kty and crv."""
        return _parse_jwk(data, self)

    def new_key_set(self, *keys: JWK) -> KeySet:
        """new_key_set for the algorithms of self: each key is checked as self.parse_jwk
        checks it."""
        return _new_key_set(self, keys)
