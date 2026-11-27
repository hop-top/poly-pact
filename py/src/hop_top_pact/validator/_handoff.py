"""The gateway side of a sidecar deployment (draft 4.4, 11.5)."""

from __future__ import annotations

import json
import threading
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Protocol

from hop_top_pact.adapter import Code, Principal, Realm
from hop_top_pact.contract import CODE_EXPIRED, CODE_REPLAY, CODE_SECURITY_HOLD
from hop_top_pact.core import clock, digest, jws, strictjson
from hop_top_pact.core.enums import Decision, Mode
from hop_top_pact.core.types import AdmissionAttestation, OperationContext
from hop_top_pact.errors import PactError
from hop_top_pact.validator._config import HoldStore
from hop_top_pact.validator._problem import code_of, reject

__all__ = ["AttestationStore", "Handoff", "MemoryAttestations"]

# The JWS failures that mean the signer could not be authenticated; every other failure is a
# malformed message.
_PROOF = frozenset(
    {
        jws.Reason.SIGNATURE_INVALID,
        jws.Reason.KID_UNKNOWN,
        jws.Reason.KEY_UNAVAILABLE,
        jws.Reason.HOLDER_JKT_MISMATCH,
    }
)


def is_proof_failure(err: jws.JWSError) -> bool:
    """Report the JWS failures that mean the signer could not be authenticated."""
    return err.reason in _PROOF


class _IssuerKeys:
    """Resolves the key set of the trust record that the payload's iss names; the payload is
    not authenticated yet (jws.KeyRequest)."""

    def __init__(self, keys: Mapping[str, jws.KeySet]) -> None:
        self._keys = keys

    def trusted_keys(self, req: jws.KeyRequest) -> jws.KeySet | None:
        try:
            claims = json.loads(req.payload)
        except ValueError:
            return None
        iss = claims.get("iss") if isinstance(claims, dict) else None
        return self._keys.get(iss) if isinstance(iss, str) else None

    def holder_jkt(self, req: jws.KeyRequest) -> str:
        raise LookupError("not a holder-signed artifact")


class AttestationStore(Protocol):
    """Marks positive attestations consumed, atomically and once (draft 11.5). Gateway replicas
    share one store."""

    def consume(self, jti: str, until: datetime) -> None:
        """Mark jti consumed and keep the mark at least until until. A jti consumed before
        raises an error that carries the code REPLAY; a store that cannot answer raises
        another."""
        ...


class MemoryAttestations:
    """An AttestationStore in the memory of one process, safe for concurrent use."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._consumed: dict[str, datetime] = {}

    def consume(self, jti: str, until: datetime) -> None:
        """Mark jti consumed; a second call is a REPLAY rejection."""
        with self._lock:
            if jti in self._consumed:
                raise reject(CODE_REPLAY, f"attestation {jti!r} already consumed")
            self._consumed[jti] = until


@dataclass(slots=True, kw_only=True)
class Handoff:
    """The gateway side of a sidecar deployment (draft 4.4, 11.5): it accepts an attestation of
    a trusted validator for exactly the operation it was issued for, once.

    validators maps the iss of each trusted validator to its keys. audience and realm are
    the gateway's. algorithms are the negotiated JWS algorithms; empty is ES256 alone.
    skew is the allowed clock skew, 0 to 5 s. consumed marks accepted attestations;
    holds, when set, is checked at handoff (draft 11.5: current local security holds).
    """

    validators: Mapping[str, jws.KeySet] = field(default_factory=dict)
    audience: str = ""
    realm: Realm = field(default_factory=Realm)
    algorithms: jws.Algorithms = field(default_factory=jws.Algorithms)
    skew: timedelta = timedelta(0)
    consumed: AttestationStore | None = None
    holds: HoldStore | None = None

    def accept(
        self, compact: str, op: OperationContext, p: Principal, now: datetime
    ) -> AdmissionAttestation:
        """Verify the attestation compact for the actual operation op of the authenticated
        principal at the instant now (draft 11.5): the validator's signature, audience,
        realm, principal, operation digest, decision and expiry, then mark it consumed.
        The error is a Rejection carrying the draft 13.4 code of the refusal:
        INVALID_MESSAGE or INVALID_PROOF for the JWS, CONTEXT_MISMATCH for another gateway,
        principal, operation or a decision other than ADMISSIBLE, EXPIRED, SECURITY_HOLD,
        or REPLAY for an attestation already accepted. A Handoff without a consumed store
        raises ValueError."""
        if self.consumed is None:
            raise ValueError("validator: Handoff needs a Consumed store")
        try:
            parsed = jws.Verifier(
                keys=_IssuerKeys(self.validators), typ=jws.TYP_ADMISSION, algorithms=self.algorithms
            ).verify(compact)
        except jws.JWSError as e:
            if is_proof_failure(e):
                raise reject(Code.INVALID_PROOF, f"attestation signature: {e}") from e
            raise reject(Code.INVALID_MESSAGE, f"attestation: {e}") from e
        try:
            att = strictjson.decode(parsed.payload, AdmissionAttestation)
        except strictjson.StrictJSONError as e:
            raise reject(Code.INVALID_MESSAGE, f"attestation payload: {e}") from e
        try:
            op_digest = digest.object_digest(op)
        except (ValueError, TypeError, PactError) as e:
            raise reject(Code.INVALID_MESSAGE, f"operation: {e}") from e
        if (
            att.aud != self.audience
            or att.tenant_id != self.realm.tenant_id
            or att.environment_id != self.realm.environment_id
        ):
            raise reject(Code.CONTEXT_MISMATCH, "attestation is for another gateway or realm")
        if att.principal_id != p.id or op.principal_id != p.id:
            raise reject(Code.CONTEXT_MISMATCH, "attestation is for another principal")
        if att.operation_digest != op_digest or att.operation_id != op.operation_id:
            raise reject(Code.CONTEXT_MISMATCH, "attestation is for another operation")
        if att.decision != Decision.ADMISSIBLE or att.mode != Mode.ENFORCED:
            raise reject(Code.CONTEXT_MISMATCH, "attestation is not an enforced positive admission")
        try:
            clock.check_window(att.iat, att.nbf, att.exp, now, self.skew)
        except clock.ClockError as e:
            if e.kind == clock.ClockErrorKind.EXPIRED:
                raise reject(CODE_EXPIRED, "attestation expired") from e
            raise reject(Code.INVALID_MESSAGE, f"attestation: {e}") from e
        if self.holds is not None:
            try:
                holds = self.holds.holds(self.realm, att.sub)
            except Exception as e:
                raise reject(Code.DEPENDENCY_UNAVAILABLE, f"hold store: {e}") from e
            if holds:
                raise reject(CODE_SECURITY_HOLD, "a security hold is in force")
        try:
            self.consumed.consume(att.jti, datetime.fromtimestamp(att.exp, UTC))
        except Exception as e:
            if code_of(e) == CODE_REPLAY:
                raise reject(CODE_REPLAY, "attestation already accepted") from e
            raise reject(Code.DEPENDENCY_UNAVAILABLE, f"attestation store: {e}") from e
        return att
