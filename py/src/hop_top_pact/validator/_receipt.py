"""Attestation signers and the in-memory receipt store (draft 12.1, 12.2)."""

from __future__ import annotations

import threading
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hop_top_pact.core import jws
from hop_top_pact.validator._config import Result
from hop_top_pact.validator._errors import ValidatorError, ValidatorErrorKind

__all__ = ["ES256Signer", "Ed25519Signer", "MemoryReceipts"]


@dataclass(frozen=True, slots=True)
class ES256Signer:
    """Signs attestations with a P-256 key (draft 7.2)."""

    kid: str
    key: EllipticCurvePrivateKey

    def sign_attestation(self, payload: bytes) -> str:
        """Sign payload as pact-admission+jwt; raise JWSError."""
        return jws.sign(jws.Header(typ=jws.TYP_ADMISSION, kid=self.kid), payload, self.key)


@dataclass(frozen=True, slots=True)
class Ed25519Signer:
    """Signs attestations with an Ed25519 key, for a gateway that negotiated Ed25519 (draft
    7.2, RFC 9864)."""

    kid: str
    key: Ed25519PrivateKey

    def sign_attestation(self, payload: bytes) -> str:
        """Sign payload as pact-admission+jwt; raise JWSError."""
        return jws.sign_ed25519(jws.Header(typ=jws.TYP_ADMISSION, kid=self.kid), payload, self.key)


class MemoryReceipts:
    """A ReceiptStore in the memory of one process, safe for concurrent use. A sealed receipt
    is stored once and never replaced."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._by_jti: dict[str, Result] = {}
        self._by_digest: dict[str, list[str]] = {}

    def put(self, r: Result) -> None:
        """Record r. A second receipt with the jti of a stored one is refused (ValueError)."""
        jti = r.attestation.jti
        with self._lock:
            if jti in self._by_jti:
                raise ValueError(f"validator: receipt {jti!r} already recorded")
            if jti == "":
                raise ValueError("validator: receipt without jti")
            self._by_jti[jti] = r
            self._by_digest.setdefault(r.attestation.requirements_digest, []).append(jti)

    def get(self, jti: str) -> Result:
        """Return the receipt whose jti is jti, or raise ValidatorError (NOT_FOUND)."""
        with self._lock:
            r = self._by_jti.get(jti)
        if r is None:
            raise ValidatorError(ValidatorErrorKind.NOT_FOUND)
        return r

    def by_contract(self, d: str) -> list[Result]:
        """Return the receipts of the contract whose requirements_digest is d, in the order
        they were recorded."""
        with self._lock:
            return [self._by_jti[j] for j in self._by_digest.get(d, [])]

    def all(self) -> dict[str, Result]:
        """Return every stored receipt, by jti, as a copy."""
        with self._lock:
            return dict(self._by_jti)
