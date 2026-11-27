"""Issuing requirement contracts (draft 9.1, 11.1 steps 1 to 3)."""

from __future__ import annotations

import secrets
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from fractions import Fraction
from typing import Final, Protocol

from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey

from hop_top_pact.adapter import BindingStatus, Code, Realm
from hop_top_pact.contract._errors import (
    CODE_REPLAY,
    CODE_SECURITY_HOLD,
    ContractError,
)
from hop_top_pact.contract._replay import ReplayStore
from hop_top_pact.contract._types import (
    SELECTION_CONSISTENCY_CHECK,
    Authenticated,
    Contract,
    Requirements,
    ThresholdRule,
)
from hop_top_pact.contract._validate import REPUTATION_PREFIX, bounded, validate, within
from hop_top_pact.core import VERSION, _wire, clock, digest, jws
from hop_top_pact.core.enums import RuleSource
from hop_top_pact.core.jws import base64url
from hop_top_pact.core.types import (
    ContractRequest,
    FieldRule,
    JSONObject,
    JSONValue,
    RequirementContract,
)
from hop_top_pact.errors import PactError

__all__ = ["ES256Signer", "Publisher", "Signer"]

_EPOCH: Final = datetime(1970, 1, 1, tzinfo=UTC)
_SECOND: Final = timedelta(seconds=1)


class Signer(Protocol):
    """Signs a contract payload as a compact JWS of typ pact-requirements+jwt under the
    publisher's key. It signs the payload bytes exactly as given."""

    def sign_contract(self, payload: bytes) -> str:
        """Return the compact JWS of payload."""
        ...


@dataclass(frozen=True, slots=True)
class ES256Signer:
    """Signs contracts with an ES256 key whose kid the header names (draft 7.2)."""

    kid: str
    key: EllipticCurvePrivateKey

    def sign_contract(self, payload: bytes) -> str:
        """Sign payload under typ pact-requirements+jwt, kid and key; raise JWSError."""
        return jws.sign(jws.Header(typ=jws.TYP_REQUIREMENTS, kid=self.kid), payload, self.key)


@dataclass(slots=True, kw_only=True)
class Publisher:
    """A gateway-authorized requirement publisher (draft 7.3, 9.1).

    issuer is iss: the URI of the publisher's trust record. audience is aud: the
    gateway the contracts are for. realm is the gateway's tenant and
    environment. signer signs the contracts and replay registers their nonces.
    lifetime is exp - iat, whole seconds from 1 s to 60 s; zero is 60 s (draft
    9.1, 20.1). purposes are the purpose identifiers of the gateway's installed
    purpose mapping (draft 10.1): a request whose intent names another is
    refused with UNSUPPORTED_PURPOSE; None leaves the purpose to the installed
    purpose/operation check of the evaluation (draft 11.3 step 8).
    protected_paths are the profile paths that the installed mapping (draft
    17.2) classifies as identity, tenant membership, role membership,
    delegation or approval; a self rule on one of them or on a descendant is
    refused (Appendix A.2). The principal, delegation and reputation paths are
    refused whatever it lists.
    """

    issuer: str = ""
    audience: str = ""
    realm: Realm = field(default_factory=Realm)
    signer: Signer | None = None
    replay: ReplayStore | None = None
    lifetime: timedelta = timedelta(0)
    purposes: tuple[str, ...] | None = None
    protected_paths: tuple[str, ...] = ()

    def issue(
        self,
        req: ContractRequest,
        auth: Authenticated,
        r: Requirements,
        now: datetime,
    ) -> Contract:
        """Answer req with a signed contract at the publisher time now (draft 9.1, 11.1
        steps 1 to 3). It refuses, issuing nothing:

        - without native authentication (auth.principal.id empty) or an ACTIVE
          binding of the agent and key that req names: INVALID_PROOF, or
          CONTEXT_MISMATCH when the agent is enrolled for another workload of the
          realm (draft 6.1, 17.1), or SECURITY_HOLD when the binding is marked
          compromised (draft 6.4, 9.1);
        - when the principal's realm is not self.realm, or req.operation names
          another principal or environment: CONTEXT_MISMATCH;
        - when self.purposes is not None and does not list the purpose req.intent
          names: UNSUPPORTED_PURPOSE (draft 10.1);
        - when req carries extensions: UNSUPPORTED_REQUIREMENT (draft 7.1);
        - requirements that do not make a valid contract (Appendix A.2, A.3), have
          no conservative set, select a set other than the conservative one without
          SELECTION_CONSISTENCY_CHECK in context_checks or without a canonical field
          rule for each of r.thresholds (draft 9.4), or hold a self rule on a path of
          self.protected_paths: INVALID_MESSAGE.

        req.operation is the operation context the gateway mapped from the request it
        authenticated (draft 10.2); the contract binds its object_digest and that of
        req.intent. iat and nbf are now in whole seconds and exp is iat plus
        self.lifetime. jti, contract_id and nonce are each 128 random bits. The
        payload is signed through self.signer, and the nonce is registered in
        self.replay until the later of exp and iat + 65 s (draft 7.5 with the
        baseline skew); a signer or store failure is DEPENDENCY_UNAVAILABLE, a nonce
        the store already holds a REPLAY.

        A Publisher with an empty issuer, audience or realm member, no signer or no
        replay, or a lifetime outside 1 to 60 whole seconds, issues nothing and
        raises ValueError; so does a signer that does not return a compact JWS of
        the payload it was given.
        """
        lifetime, replay, signer = self._check()
        self._check_native(req, auth)
        if self.purposes is not None and req.intent.purpose_id not in self.purposes:
            raise ContractError(Code.UNSUPPORTED_PURPOSE, f"purpose {req.intent.purpose_id!r}")
        if req.extensions:
            raise ContractError(Code.UNSUPPORTED_REQUIREMENT, "contract request extensions")
        try:
            _check_selection(r)
            self._check_protected(r.field_rules)
        except ValueError as e:
            raise ContractError(Code.INVALID_MESSAGE, str(e)) from e
        op_digest = _object_digest("operation", req.operation)
        intent_digest = _object_digest("intent", req.intent)
        try:
            ids = [base64url.encode(secrets.token_bytes(16)) for _ in range(3)]
        except OSError as e:
            raise ContractError(Code.DEPENDENCY_UNAVAILABLE, f"random: {e}") from e
        d = now - _EPOCH
        iat = d.days * 86400 + d.seconds
        claims = RequirementContract(
            pact_version=VERSION,
            iss=self.issuer,
            sub=req.agent_id,
            aud=self.audience,
            jti=ids[0],
            iat=iat,
            nbf=iat,
            exp=iat + lifetime // _SECOND,
            tenant_id=self.realm.tenant_id,
            contract_id=ids[1],
            environment_id=self.realm.environment_id,
            holder_jkt=auth.binding.holder_jkt,
            operation_digest=op_digest,
            intent_digest=intent_digest,
            base_revision=r.policy.base_revision,
            selected_set=r.selected_set,
            field_rules=tuple(r.field_rules),
            context_checks=tuple(r.context_checks),
            learning_policy_digest=r.policy.learning_policy_digest,
            learning_artifact_digest=r.policy.learning_artifact_digest,
            nonce=ids[2],
            mode=r.mode,
            extensions=r.extensions,
        )
        try:
            validate(claims)
            payload = _wire.payload(claims)
        except (ValueError, TypeError, PactError) as e:
            raise ContractError(Code.INVALID_MESSAGE, str(e)) from e
        try:
            compact = signer.sign_contract(payload)
        except Exception as e:
            raise ContractError(Code.DEPENDENCY_UNAVAILABLE, f"sign: {e}") from e
        _signed_payload(compact, payload)
        try:
            artifact = digest.artifact_digest(compact)
        except ValueError as e:
            raise ValueError(f"contract: signer output: {e}") from e
        c = Contract(compact=compact, claims=claims, digest=artifact)
        until = clock.replay_retention(claims.exp, claims.iat, clock.BASELINE_SKEW)
        try:
            replay.register(c.nonce_record(), now, until)
        except ContractError as e:
            if e.code in (CODE_REPLAY, Code.DEPENDENCY_UNAVAILABLE):
                raise ContractError(e.code, f"register nonce: {e}") from e
            raise ContractError(Code.DEPENDENCY_UNAVAILABLE, f"register nonce: {e}") from e
        except Exception as e:
            raise ContractError(Code.DEPENDENCY_UNAVAILABLE, f"register nonce: {e}") from e
        return c

    def _check(self) -> tuple[timedelta, ReplayStore, Signer]:
        """Validate the publisher's configuration and return its lifetime, store and
        signer."""
        if not bounded(self.issuer, self.audience, self.realm.tenant_id, self.realm.environment_id):
            raise ValueError("contract: publisher issuer, audience and realm are required")
        if self.signer is None or self.replay is None:
            raise ValueError("contract: publisher signer and replay are required")
        lifetime = self.lifetime or 60 * _SECOND
        most = clock.max_lifetime(clock.Artifact.CONTRACT)
        if lifetime < _SECOND or lifetime > most or lifetime % _SECOND != timedelta(0):
            raise ValueError(f"contract: lifetime {self.lifetime} is not 1 to 60 whole seconds")
        return lifetime, self.replay, self.signer

    def _check_native(self, req: ContractRequest, auth: Authenticated) -> None:
        """Apply draft 9.1: native authentication and a trustworthy binding of the agent
        and key the request names, in the publisher's realm."""
        b, p = auth.binding, auth.principal
        if not p.id:
            raise ContractError(Code.INVALID_PROOF, "no native authentication")
        if p.realm != self.realm:
            raise ContractError(
                Code.CONTEXT_MISMATCH, f"principal realm {p.realm}, publisher realm {self.realm}"
            )
        if b.status == BindingStatus.UNKNOWN and b.enrolled_elsewhere:
            raise ContractError(Code.CONTEXT_MISMATCH, "agent enrolled for another workload")
        if b.status == BindingStatus.COMPROMISED:
            raise ContractError(CODE_SECURITY_HOLD, f"agent binding {str(b.status)!r}")
        if b.status != BindingStatus.ACTIVE:
            raise ContractError(Code.INVALID_PROOF, f"agent binding {str(b.status)!r}")
        if b.agent_id != req.agent_id or b.holder_jkt != req.holder_jkt:
            raise ContractError(
                Code.INVALID_PROOF,
                f"request names agent {req.agent_id!r} key {req.holder_jkt!r}, "
                f"binding {b.agent_id!r} key {b.holder_jkt!r}",
            )
        if req.operation.principal_id != p.id:
            raise ContractError(
                Code.CONTEXT_MISMATCH,
                f"operation principal {req.operation.principal_id!r}, authenticated {p.id!r}",
            )
        if req.operation.environment_id != self.realm.environment_id:
            raise ContractError(
                Code.CONTEXT_MISMATCH, f"operation environment {req.operation.environment_id!r}"
            )

    def _check_protected(self, rules: tuple[FieldRule, ...]) -> None:
        """Refuse a self rule on a path of self.protected_paths or a descendant of one
        (Appendix A.2)."""
        for r in rules:
            if r.source != RuleSource.SELF:
                continue
            for protected in self.protected_paths:
                if within(r.path, protected):
                    raise ValueError(
                        f"a self rule cannot decide {r.path}, which the installed mapping protects"
                    )


def _object_digest(name: str, value: object) -> str:
    try:
        return digest.object_digest(value)
    except (ValueError, TypeError, PactError) as e:
        raise ContractError(Code.INVALID_MESSAGE, f"{name}: {e}") from e


def _check_selection(r: Requirements) -> None:
    """Apply draft 9.4 (a) and (b); raise ValueError."""
    if not bounded(r.conservative_set):
        raise ValueError("the policy's conservative set is required")
    if r.selected_set == r.conservative_set:
        return
    if SELECTION_CONSISTENCY_CHECK not in r.context_checks:
        raise ValueError(
            f"selected set {r.selected_set!r} is not the conservative set "
            f"{r.conservative_set!r} and context_checks lacks {SELECTION_CONSISTENCY_CHECK}"
        )
    for i, t in enumerate(r.thresholds):
        try:
            path, keyword, want = _threshold_rule(t)
        except ValueError as e:
            raise ValueError(f"thresholds[{i}]: {e}") from e
        if not any(
            fr.source == RuleSource.EVIDENCE
            and fr.path == path
            and _schema_keyword(fr.schema, keyword, want)
            for fr in r.field_rules
        ):
            raise ValueError(
                f"selected set {r.selected_set!r} has no evidence rule on {path} "
                f"with {keyword} {want!r} (draft 9.4 (b))"
            )


def _threshold_rule(t: ThresholdRule) -> tuple[str, str, int | str]:
    """The canonical field rule of a threshold (draft 9.4 (b)): its path, and the schema
    keyword and the JSON value it must have."""
    minimum = bool(t.dimension or t.statistic)
    if minimum and t.security_status:
        raise ValueError("a threshold is a minimum or a security status, not both")
    if t.security_status:
        return REPUTATION_PREFIX + "/security_status", "const", str(t.security_status)
    if not (t.dimension and t.statistic):
        raise ValueError("a minimum names a dimension and a statistic")
    path = f"{REPUTATION_PREFIX}/dimensions/{_escape(t.dimension)}/{_escape(t.statistic)}"
    return path, "minimum", t.minimum


def _escape(token: str) -> str:
    """Escape a JSON Pointer reference token (RFC 6901)."""
    return token.replace("~", "~0").replace("/", "~1")


def _schema_keyword(schema: JSONObject | bool | None, keyword: str, want: int | str) -> bool:
    """Whether the schema object has keyword with the JSON value want: numerically
    equal for a number, the same string for a string."""
    if not isinstance(schema, Mapping) or keyword not in schema:
        return False
    got: JSONValue = schema[keyword]
    if isinstance(want, str):
        return isinstance(got, str) and got == want
    if isinstance(got, bool) or not isinstance(got, int | float):
        return False
    try:
        return Fraction(got) == want
    except (ValueError, OverflowError):
        return False


def _signed_payload(compact: str, payload: bytes) -> None:
    """Check that compact is a JWS of payload, so that claims always describe what was
    signed; raise ValueError."""
    parts = compact.split(".")
    if len(parts) != 3:
        raise ValueError("contract: signer did not return a compact JWS")
    try:
        got = base64url.decode(parts[1])
    except ValueError:
        got = None
    if got != payload:
        raise ValueError("contract: signer signed other bytes than the payload")
