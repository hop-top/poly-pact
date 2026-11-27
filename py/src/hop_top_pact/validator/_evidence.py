"""Evidence artifacts and the reputation snapshot (draft 8.3, 11.3 steps 7 and 9, 15.2, A.2)."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from hop_top_pact.adapter import Code
from hop_top_pact.core import Digest, _wire, clock, jws, limits, strictjson
from hop_top_pact.core.enums import CheckStatus, SecurityStatus
from hop_top_pact.core.types import Evidence, ReputationSnapshot
from hop_top_pact.validator import _schema
from hop_top_pact.validator._checks import REPUTATION_PATH
from hop_top_pact.validator._config import Issuer
from hop_top_pact.validator._decide import (
    REASON_CONTEXT_MISMATCH,
    REASON_INVALID_CLAIM,
    REASON_INVALID_PROOF,
    REASON_REVOKED_EVIDENCE,
    REASON_SECURITY_HOLD,
    REASON_STALE_EVIDENCE,
    REASON_UNAVAILABLE,
    REASON_UNSUPPORTED,
)
from hop_top_pact.validator._eval import AuthClaim, Evaluation
from hop_top_pact.validator._handoff import IssuerKeys, is_proof_failure
from hop_top_pact.validator._outcome import Outcome, ok
from hop_top_pact.validator._problem import code_of


@dataclass(slots=True)
class Fault:
    """Why an evidence artifact or a snapshot was rejected or could not be established: the
    result and reason code it gives the check and the field rules that rely on it."""

    result: CheckStatus
    reason: str


def rejected(reason: str) -> Fault:
    return Fault(CheckStatus.FAIL, reason)


def trust_keys(issuers: Sequence[Issuer]) -> IssuerKeys:
    return IssuerKeys({i.id: i.keys for i in issuers if i.keys is not None})


def issuer_of(issuers: Sequence[Issuer], id_: str) -> Issuer | None:
    for i in issuers:
        if i.id == id_:
            return i
    return None


def evidence_validity(e: Evaluation) -> Outcome:
    """Draft 11.3 step 7 for the evidence artifacts: each is verified under its own issuer's
    authority, never the agent's (draft 11.2). An accepted artifact contributes its claims
    to the field rules; a rejected one contributes nothing, and the rules on its paths fail
    with its reason."""
    worst: Fault | None = None
    ids: list[str] = []
    for compact in e.pres.evidence:
        ev, fault = verify_evidence(e, compact)
        if ev is not None and ev.jti:
            ids.append(ev.jti)
        if fault is None:
            continue
        for c in ev.claims if ev is not None else ():
            if fault.result == CheckStatus.FAIL:
                e.failed_paths[c.path] = fault.reason
            else:
                e.pending_paths[c.path] = fault.reason
        if worst is None or (fault.result == CheckStatus.FAIL and worst.result != CheckStatus.FAIL):
            worst = fault
    e.evidence_ids = ids
    o = ok()
    if worst is not None:
        o = Outcome(result=worst.result, reason=worst.reason)
    o.evidence = list(ids)
    return o


def verify_evidence(e: Evaluation, compact: str) -> tuple[Evidence | None, Fault | None]:
    cfg, lim = e.v.config, e.v.limits()
    assert e.v.status is not None
    try:
        parsed = jws.Verifier(
            keys=trust_keys(cfg.issuers),
            typ=jws.TYP_EVIDENCE,
            algorithms=cfg.algorithms,
            limits=limits.artifact_json(lim),
        ).verify(compact)
        limits.validate_artifact_size(lim, len(parsed.payload))
        ev = strictjson.decode(parsed.payload, Evidence, limits.artifact_json(lim))
    except jws.JWSError as err:
        return None, rejected(
            REASON_INVALID_PROOF if is_proof_failure(err) else REASON_INVALID_CLAIM
        )
    except (limits.LimitError, strictjson.StrictJSONError):
        return None, rejected(REASON_INVALID_CLAIM)
    if ev.sub != e.pres.sub or ev.holder_jkt != e.jkt:
        return ev, rejected(REASON_INVALID_PROOF)
    if (
        ev.aud != cfg.audience
        or ev.tenant_id != cfg.realm.tenant_id
        or ev.environment_id != cfg.realm.environment_id
    ):
        return ev, rejected(REASON_CONTEXT_MISMATCH)
    if ev.pact_version != "0.1":
        return ev, rejected(REASON_INVALID_CLAIM)
    f = window(e, clock.Artifact.EVIDENCE, ev.iat, ev.nbf, ev.exp)
    if f is not None:
        return ev, f
    trust = issuer_of(cfg.issuers, ev.iss)
    for c in ev.claims:
        if trust is None or c.path not in trust.claim_paths:
            # A claim outside the issuer's claim-path authority: the evidence is rejected (draft
            # 8.3, 22.2).
            return ev, rejected(REASON_INVALID_CLAIM)
    try:
        st = e.v.status.evidence_status(ev.iss, ev.status_ref)
    except Exception:
        return ev, Fault(CheckStatus.UNKNOWN, REASON_UNAVAILABLE)
    if st.revoked:
        return ev, rejected(REASON_REVOKED_EVIDENCE)
    e.expiries.append(ev.exp)
    for c in ev.claims:
        e.claims.append(
            AuthClaim(
                path=c.path,
                issuer=ev.iss,
                value=c.value,
                observed_at=datetime.fromtimestamp(ev.iat, UTC),
                status_at=st.checked_at,
                evidence_id=ev.jti,
                source_id=st.source_id,
            )
        )
    return ev, None


def window(e: Evaluation, a: clock.Artifact, iat: int, nbf: int, exp: int) -> Fault | None:
    """Apply the time rules of draft 7.5 and the lifetime of draft 20.1 to an embedded
    artifact: an expired one is stale, one from the future or with too long a life is
    invalid."""
    assert e.v.clock is not None
    try:
        clock.check_window(iat, nbf, exp, e.v.clock.now(), e.v.config.skew)
    except clock.ClockError as err:
        if err.kind == clock.ClockErrorKind.EXPIRED:
            return rejected(REASON_STALE_EVIDENCE)
        return rejected(REASON_INVALID_CLAIM)
    try:
        clock.check_lifetime(a, iat, exp)
    except clock.ClockError:
        return rejected(REASON_INVALID_CLAIM)
    return None


def reputation_context(e: Evaluation) -> Outcome:
    """Draft 11.3 step 9 for the presented snapshot: its provenance, subject, holder,
    audience, realm, freshness, scoring-policy epoch, context and hold state (draft 15.2,
    A.2). An accepted snapshot is the authoritative value for the reputation paths its
    service may assert. The result names the snapshot and the gateway's selection record
    (draft A.2)."""
    snap, fault = verify_snapshot(e)
    paths: Sequence[str] = ()
    if snap is not None:
        t = issuer_of(e.v.config.reputation_services, snap.iss)
        if t is not None:
            paths = t.claim_paths
    o = ok()
    if fault is not None:
        o = Outcome(result=fault.result, reason=fault.reason)
        for p in paths:
            if fault.result == CheckStatus.FAIL:
                e.failed_paths[p] = fault.reason
            else:
                e.pending_paths[p] = fault.reason
    else:
        assert snap is not None
        accept_snapshot(e, snap, paths)
        o = o.at(datetime.fromtimestamp(snap.iat, UTC))
    if e.snapshot_jti:
        o.evidence = [e.snapshot_jti]
    if e.sel_err is None and e.sel.record_ref:
        o.source_ref = e.sel.record_ref
    return o


def verify_snapshot(e: Evaluation) -> tuple[ReputationSnapshot | None, Fault | None]:
    cfg, lim = e.v.config, e.v.limits()
    assert e.pres.reputation is not None
    assert e.v.clock is not None
    try:
        parsed = jws.Verifier(
            keys=trust_keys(cfg.reputation_services),
            typ=jws.TYP_REPUTATION,
            algorithms=cfg.algorithms,
            limits=limits.artifact_json(lim),
        ).verify(e.pres.reputation)
        limits.validate_artifact_size(lim, len(parsed.payload))
        snap = strictjson.decode(parsed.payload, ReputationSnapshot, limits.artifact_json(lim))
    except jws.JWSError as err:
        return None, rejected(
            REASON_INVALID_PROOF if is_proof_failure(err) else REASON_INVALID_CLAIM
        )
    except (limits.LimitError, strictjson.StrictJSONError):
        return None, rejected(REASON_INVALID_CLAIM)
    if snap.jti:
        e.snapshot_jti = snap.jti
    v = snap.value
    if snap.sub != e.pres.sub or snap.holder_jkt != e.jkt:
        return snap, rejected(REASON_INVALID_PROOF)
    if (
        snap.aud != cfg.audience
        or snap.tenant_id != cfg.realm.tenant_id
        or snap.environment_id != cfg.realm.environment_id
    ):
        return snap, rejected(REASON_CONTEXT_MISMATCH)
    try:
        Digest(v.provenance_digest).validate()
        bad = snap.pact_version != "0.1"
    except ValueError:
        bad = True
    if bad:
        return snap, rejected(REASON_INVALID_CLAIM)
    f = window(e, clock.Artifact.SNAPSHOT, snap.iat, snap.nbf, snap.exp)
    if f is not None:
        return snap, f
    now = e.v.clock.now()
    if (
        v.evidence_cutoff > snap.iat
        or datetime.fromtimestamp(v.evidence_cutoff, UTC) > now + cfg.skew
    ):
        return snap, rejected(REASON_INVALID_CLAIM)
    if e.active_err is not None:
        return snap, Fault(CheckStatus.UNKNOWN, REASON_UNAVAILABLE)
    if v.scoring_policy_revision not in e.active.scoring_policy_revisions:
        return snap, rejected(REASON_CONTEXT_MISMATCH)
    if v.security_status == SecurityStatus.HOLD or v.hold_refs:
        return snap, rejected(REASON_SECURITY_HOLD)
    if not e.binding_known:
        return snap, Fault(CheckStatus.UNKNOWN, REASON_UNAVAILABLE)
    if e.v.contexts is None:
        return snap, Fault(CheckStatus.UNKNOWN, REASON_UNSUPPORTED)
    try:
        want = e.v.contexts.reputation_context(e.check_input())
    except Exception as err:
        code = code_of(err) or str(Code.DEPENDENCY_UNAVAILABLE)
        return snap, Fault(CheckStatus.UNKNOWN, code)
    if not _schema.json_equal(_wire.to_json(want), _wire.to_json(v.context)):
        return snap, rejected(REASON_CONTEXT_MISMATCH)
    return snap, None


def accept_snapshot(e: Evaluation, snap: ReputationSnapshot, paths: Sequence[str]) -> None:
    """Make the snapshot value the authoritative value of the reputation paths its service
    may assert (Appendix A.2). Each value is observed at the snapshot's iat and
    status-checked at the evaluation's security-hold check, never by the snapshot's own
    security_status or hold_refs."""
    e.snapshot = snap
    e.expiries.append(snap.exp)
    value: Any = _wire.to_json(snap.value)
    at = datetime.fromtimestamp(snap.iat, UTC)
    checked = e.holds_at if e.holds_err is None else None  # none when the hold check failed
    for p in paths:
        if not p.startswith(REPUTATION_PATH):
            continue
        rel = p[len(REPUTATION_PATH) :]
        if rel != "" and not rel.startswith("/"):
            continue
        v = _schema.pointer(value, rel)
        if v is _schema.NOT_FOUND:
            continue
        e.claims.append(
            AuthClaim(
                path=p,
                issuer=snap.iss,
                value=v,
                observed_at=at,
                status_at=checked,
                evidence_id=snap.jti,
                source_id=snap.iss,
                hold_check=True,
            )
        )
