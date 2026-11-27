"""Sealing an evaluation: the final checks, the decision, the durable record and the signed
attestation (draft 11.3 step 10, 12.1, 12.2)."""

from __future__ import annotations

import contextlib
import os
from datetime import datetime

from hop_top_pact import contract
from hop_top_pact.adapter import BindingStatus, Code
from hop_top_pact.core import _wire
from hop_top_pact.core.enums import Decision, TerminalReason
from hop_top_pact.core.jws import base64url
from hop_top_pact.core.types import AdmissionAttestation, CheckResult, JSONValue
from hop_top_pact.validator._checks import (
    CHECK_ACTIVE_POLICY,
    CHECK_AGENT_HOLDER_BINDING,
    CHECK_CONTRACT_VALIDITY,
    CHECK_EVIDENCE_VALIDITY,
    CHECK_INTENT_BINDING,
    CHECK_NATIVE_AUTHENTICATION,
    CHECK_NONCE,
    CHECK_OPERATION_BINDING,
    CHECK_PROFILE_VALIDITY,
    CHECK_RECEIPT_STORE,
    CHECK_REPUTATION_CONTEXT,
    CHECK_SECURITY_HOLD,
    actual_digest,
    over,
    set_check,
)
from hop_top_pact.validator._config import Result
from hop_top_pact.validator._decide import (
    REASON_INVALID_PROOF,
    REASON_REQUIREMENTS_CHANGED,
    REASON_SECURITY_HOLD,
    REASON_UNAVAILABLE,
    decide,
)
from hop_top_pact.validator._eval import Evaluation
from hop_top_pact.validator._outcome import fail, not_evaluated, unix, unknown
from hop_top_pact.validator._problem import reject
from hop_top_pact.validator._state import seal_event

# The longest receipt validity of draft 12.1 and 20.1.
RECEIPT_LIFETIME = 60

_PROTOCOL = (
    CHECK_NATIVE_AUTHENTICATION,
    CHECK_AGENT_HOLDER_BINDING,
    CHECK_CONTRACT_VALIDITY,
    CHECK_NONCE,
    CHECK_OPERATION_BINDING,
    CHECK_INTENT_BINDING,
    CHECK_PROFILE_VALIDITY,
    CHECK_EVIDENCE_VALIDITY,
    CHECK_REPUTATION_CONTEXT,
    CHECK_SECURITY_HOLD,
    CHECK_ACTIVE_POLICY,
    CHECK_RECEIPT_STORE,
)


def terminal(e: Evaluation) -> TerminalReason:
    return e.ended if e.ended is not None else TerminalReason.COMPLETED


def seal(e: Evaluation) -> Result:
    """Draft 11.3 step 10 and the terminal transition of draft 12.2: the final checks of a
    positive result, the decision, the durable record and the signed attestation. A receipt
    that cannot be recorded is never positive (draft 12.2, 18)."""
    assert e.v.clock is not None
    assert e.v.receipts is not None
    over(e)
    checks = ordered(e)
    decision = decide(checks, terminal(e))
    if decision == Decision.ADMISSIBLE:
        final_checks(e)
        over(e)
        checks = ordered(e)
        decision = decide(checks, terminal(e))
    at = e.v.clock.now()
    if e.ended is not None:
        assert e.ended_at is not None
        at = e.ended_at
    res = sign(e, checks, decision, at)
    try:
        e.v.receipts.put(res)
    except Exception as perr:
        if decision == Decision.ADMISSIBLE:
            set_check(e, CHECK_RECEIPT_STORE, unknown(REASON_UNAVAILABLE))
            checks = ordered(e)
            decision = Decision.DEFERRED
            res = sign(e, checks, decision, at)
            with contextlib.suppress(Exception):
                e.v.receipts.put(res)
        fire_seal(e, decision)
        err = reject(str(Code.DEPENDENCY_UNAVAILABLE), f"receipt not recorded: {perr}")
        err.result = res
        raise err from perr
    fire_seal(e, decision)
    return res


def fire_seal(e: Evaluation, d: Decision) -> None:
    # The machine is this evaluation's own and has not been sealed, so the transition exists;
    # an error here would be a defect, not an input.
    e.m.fire(seal_event(d, terminal(e)))


def final_checks(e: Evaluation) -> None:
    """The final check of draft 11.3 step 10 before a positive result: the contract is still
    active, and no security hold or binding revocation became effective during the
    evaluation."""
    v = e.v
    assert v.policies is not None
    assert v.holds is not None
    assert v.native is not None
    try:
        active = v.policies.active()
    except Exception:
        set_check(e, CHECK_ACTIVE_POLICY, unknown(REASON_UNAVAILABLE))
    else:
        try:
            e.con.check_active(active.policy)
        except contract.ContractError:
            set_check(e, CHECK_ACTIVE_POLICY, fail(REASON_REQUIREMENTS_CHANGED))
    try:
        holds = list(v.holds.holds(v.config.realm, e.pres.sub))
    except Exception:
        set_check(e, CHECK_SECURITY_HOLD, unknown(REASON_UNAVAILABLE))
    else:
        if holds:
            o = fail(REASON_SECURITY_HOLD)
            o.evidence = holds
            set_check(e, CHECK_SECURITY_HOLD, o)
    pr = e.req.principal
    try:
        b = v.native.resolve_agent_binding(pr.realm, pr.workload, e.pres.sub)
    except Exception:
        set_check(e, CHECK_AGENT_HOLDER_BINDING, unknown(REASON_UNAVAILABLE))
        return
    if b.status == BindingStatus.COMPROMISED:
        set_check(e, CHECK_AGENT_HOLDER_BINDING, fail(REASON_SECURITY_HOLD))
    elif b.status != BindingStatus.ACTIVE or b.holder_jkt != e.jkt or b.agent_id != e.pres.sub:
        set_check(e, CHECK_AGENT_HOLDER_BINDING, fail(REASON_INVALID_PROOF))


def ordered(e: Evaluation) -> list[CheckResult]:
    """The check results in receipt order: the protocol checks, the field rules and the
    contract's context checks, each exactly once. A rule or check that was not performed is
    UNKNOWN with NOT_EVALUATED, never PASS (draft 12.1)."""
    out = [e.checks[i] for i in _PROTOCOL if i in e.checks]
    required = [r.rule_id for r in e.con.claims.field_rules] + list(e.con.claims.context_checks)
    for id_ in required:
        c = e.checks.get(id_)
        if c is None:
            set_check(e, id_, not_evaluated())
            from dataclasses import replace

            c = replace(e.checks[id_], checked_at=seal_unix(e))
            e.checks[id_] = c
        out.append(c)
    return out


def seal_unix(e: Evaluation) -> int:
    assert e.v.clock is not None
    if e.ended is not None:
        assert e.ended_at is not None
        return unix(e.ended_at)
    return unix(e.v.clock.now())


def sign(e: Evaluation, checks: list[CheckResult], d: Decision, at: datetime) -> Result:
    """Build and sign the attestation (draft 12.1)."""
    from hop_top_pact.validator._validator import object_digest

    assert e.v.signer is not None
    jti = base64url.encode(os.urandom(16))
    iat = unix(at)
    exp = iat + RECEIPT_LIFETIME
    p, c = e.pres, e.con
    if d == Decision.ADMISSIBLE:
        for x in (p.exp, c.claims.exp, p.profile.expires_at, *e.expiries):
            exp = min(exp, x)
    pol = c.claims
    att = AdmissionAttestation(
        pact_version="0.1",
        iss=e.v.config.issuer,
        sub=p.sub,
        aud=e.v.config.audience,
        jti=jti,
        iat=iat,
        nbf=iat,
        exp=exp,
        tenant_id=e.v.config.realm.tenant_id,
        presentation_id=p.jti,
        operation_id=e.req.operation.operation_id,
        principal_id=e.req.operation.principal_id,
        environment_id=e.v.config.realm.environment_id,
        holder_jkt=e.jkt,
        profile_digest=object_digest(e.profile_raw),
        intent_digest=object_digest(e.intent_raw),
        operation_digest=actual_digest(e),
        requirements_digest=c.digest,
        learning_policy_digest=pol.learning_policy_digest,
        learning_artifact_digest=pol.learning_artifact_digest,
        decision=d,
        terminal_reason=terminal(e),
        mode=pol.mode,
        checks=tuple(checks),
        extensions=extensions(e),
    )
    try:
        payload = _wire.payload(att)
        compact = e.v.signer.sign_attestation(payload)
    except Exception as err:
        raise reject(str(Code.DEPENDENCY_UNAVAILABLE), f"signer: {err}") from err
    return Result(receipt=compact, attestation=att)


def extensions(e: Evaluation) -> dict[str, JSONValue] | None:
    """The contract's supported extensions, which the attestation carries too (draft 21)."""
    out: dict[str, JSONValue] | None = None
    for name, v in (e.con.claims.extensions or {}).items():
        if name in e.v.config.supported_extensions:
            if out is None:
                out = {}
            out[name] = v
    return out
