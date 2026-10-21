"""Trusted key sets, key requests and resolvers. Mirrors go/core/jws/keys.go."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Protocol

from cryptography.hazmat.primitives.asymmetric import ec

from hop_top_pact.core.jws.errors import JWSError, Reason
from hop_top_pact.core.jws.jwk import JWK, _check_key, thumbprint
from hop_top_pact.core.jws.typ import ALG_ES256, Role

__all__ = ["KeyRequest", "KeyResolver", "KeySet", "StaticResolver", "new_key_set"]


@dataclass(frozen=True, slots=True)
class _TrustedKey:
    """A checked key: alg is the one algorithm it verifies, pub its public key."""

    jwk: JWK
    alg: str
    pub: ec.EllipticCurvePublicKey
    thumbprint: str


def _trusted_key(k: JWK) -> _TrustedKey:
    """Check k as parse_jwk does and keep its public key and thumbprint."""
    pub = _check_key(k)
    return _TrustedKey(jwk=k, alg=ALG_ES256, pub=pub, thumbprint=thumbprint(k))


class KeySet:
    """A set of trusted ES256 public keys, looked up by kid. It is built from
    configuration with new_key_set, never from an artifact; KeySet() is empty."""

    __slots__ = ("_keys",)

    def __init__(self) -> None:
        self._keys: dict[str, _TrustedKey] = {}

    def lookup(self, kid: str) -> JWK | None:
        """Return the key with the given kid, or None."""
        k = self._trusted(kid)
        return k.jwk if k is not None else None

    def _trusted(self, kid: str) -> _TrustedKey | None:
        """The checked key with the given kid, or None; an empty kid finds nothing."""
        return self._keys.get(kid) if kid else None


def new_key_set(*keys: JWK) -> KeySet:
    """Return the key set of keys, each checked as parse_jwk checks it, with a non-empty
    kid unique within the set. Raises JWSError (KID_MISSING, KID_DUPLICATE, or the
    reason the key fails)."""
    s = KeySet()
    for i, k in enumerate(keys):
        if not k.kid:
            raise JWSError(Reason.KID_MISSING, f"key {i} has no kid")
        if k.kid in s._keys:
            raise JWSError(Reason.KID_DUPLICATE, f"kid {k.kid!r}")
        s._keys[k.kid] = _trusted_key(k)
    return s


@dataclass(frozen=True, slots=True)
class KeyRequest:
    """The key one verification needs, built from the protected header and payload after
    their structural checks and before the signature is checked: nothing in it is
    authenticated yet. A resolver may use header and payload only to choose which
    configured trust record or enrollment applies (draft 7.3: iss selects a trust
    record), never to obtain key material."""

    typ: str
    """The artifact's typ."""
    role: Role
    """The signer role the draft 7.3 table requires for typ."""
    kid: str
    """The header kid, empty when absent."""
    header: bytes
    """The decoded protected header, as received."""
    payload: bytes
    """The decoded payload, as received."""


class KeyResolver(Protocol):
    """Supplies the trusted keys of a verification. verify calls exactly one method,
    once: holder_jkt for Role.HOLDER, trusted_keys for every other role. An
    exception it raises becomes JWSError(KEY_UNAVAILABLE) with the exception as
    cause. The package never fetches keys."""

    def trusted_keys(self, req: KeyRequest) -> KeySet | None:
        """Return the key set trusted for req.role; None has no keys. The header kid is
        looked up in it and nowhere else."""
        ...

    def holder_jkt(self, req: KeyRequest) -> str:
        """Return the enrolled holder_jkt the embedded jwk of a holder-signed artifact
        must match (draft 6.2, 7.2)."""
        ...


@dataclass(frozen=True, slots=True)
class StaticResolver:
    """A KeyResolver over fixed configuration: one key set per role and one expected
    holder thumbprint."""

    key_sets: Mapping[Role | str, KeySet] = field(default_factory=dict)
    expected_holder_jkt: str = ""

    def trusted_keys(self, req: KeyRequest) -> KeySet | None:
        """Return key_sets[req.role], None when the role has none."""
        return self.key_sets.get(req.role)

    def holder_jkt(self, req: KeyRequest) -> str:
        """Return expected_holder_jkt; raise LookupError when it is empty."""
        if not self.expected_holder_jkt:
            raise LookupError("no expected holder_jkt configured")
        return self.expected_holder_jkt
