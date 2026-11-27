"""The checks of draft 11.3 steps 2 to 9 that the admission left to the evaluation."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from hop_top_pact import contract
from hop_top_pact.adapter import BindingStatus, Code, NativeClaim, freshness
from hop_top_pact.core import _wire, clock
from hop_top_pact.core.enums import CheckStatus, RuleSource, TerminalReason
from hop_top_pact.core.types import CheckResult, FieldRule
from hop_top_pact.validator import _schema
from hop_top_pact.validator._decide import (
    REASON_CONFLICTING_EVIDENCE,
    REASON_CONTEXT_MISMATCH,
    REASON_INVALID_CLAIM,
    REASON_MISSING_FIELD,
    REASON_REQUIREMENTS_CHANGED,
    REASON_SATISFIED,
    REASON_SECURITY_HOLD,
    REASON_STALE_EVIDENCE,
    REASON_UNAVAILABLE,
    REASON_UNSUPPORTED,
)
from hop_top_pact.validator._eval import AuthClaim, Evaluation
from hop_top_pact.validator._outcome import (
    Outcome,
    fail,
    ok,
    unix,
    unix_of,
    unknown,
)
from hop_top_pact.validator._problem import code_of

CHECK_NATIVE_AUTHENTICATION = "native-authentication"
CHECK_AGENT_HOLDER_BINDING = "agent-holder-binding"
CHECK_CONTRACT_VALIDITY = "contract-validity"
CHECK_NONCE = "nonce"
CHECK_OPERATION_BINDING = "operation-binding"
CHECK_INTENT_BINDING = "intent-binding"
CHECK_PROFILE_VALIDITY = "profile-validity"
CHECK_EVIDENCE_VALIDITY = "evidence-validity"
CHECK_REPUTATION_CONTEXT = "reputation-context"
CHECK_SECURITY_HOLD = "security-hold"
CHECK_ACTIVE_POLICY = "active-policy"
CHECK_RECEIPT_STORE = "receipt-store"
CHECK_NATIVE_PRINCIPAL_BINDING = "native-principal-binding-v1"
CHECK_SELECTION_CONSISTENCY = contract.SELECTION_CONSISTENCY_CHECK

# The profile path of the principal the presentation claims to act for (draft 17.5). A field
# rule on it that does not match its native value is a principal that differs:
# CONTEXT_MISMATCH (draft 13.4).
PRINCIPAL_PATH = "/attributes/environment/principal_id"
# The profile path a reputation snapshot is mapped to (draft 15.2, A.2).
REPUTATION_PATH = "/attributes/reputation"


def set_check(e: Evaluation, id_: str, o: Outcome) -> None:
    """Record the result of a check, at the current instant."""
    assert e.v.clock is not None
    e.checks[id_] = CheckResult(
        check_id=id_,
        result=o.result,
        reason_code=o.reason,
        checked_at=unix(e.v.clock.now()),
        source_observed_at=o.observed,
        status_checked_at=o.status,
        evidence_ids=tuple(o.evidence or ()),
        source_id=o.source_id or e.v.config.source_id,
        source_ref=o.source_ref,
    )


def over(e: Evaluation) -> bool:
    """Report whether the evaluation has ended: cancelled, or at or past its deadline (draft
    12.2). The first end is kept. This is the one place the cancelled predicate is polled."""
    if e.ended is not None:
        return True
    assert e.v.clock is not None
    assert e.deadline is not None
    now = e.v.clock.now()
    if e.cancelled is not None and e.cancelled():
        e.ended, e.ended_at = TerminalReason.CANCELLED, now
    elif now >= e.deadline:
        e.ended, e.ended_at = TerminalReason.EXPIRED, e.deadline
    else:
        return False
    return True


def native(e: Evaluation, id_: str, read: Callable[[], Outcome]) -> None:
    """Run one check that needs a native read (draft 12.1). Once the evaluation is cancelled
    or past its deadline, no read is issued, and a read that completes after that is
    discarded: the check was not performed."""
    if over(e):
        return
    o = read()
    if over(e):
        return
    set_check(e, id_, o)


def run(e: Evaluation) -> None:
    """Evaluate every check of draft 11.3 steps 2 to 9 that the admission left to the
    evaluation. The checks on inputs the validator holds come first; the native reads (draft
    12.1) last, so that an evaluation cancelled or expired while they are outstanding still
    records what it established."""
    from hop_top_pact.validator._evidence import evidence_validity, reputation_context
    from hop_top_pact.validator._selection import selection_consistency

    v = e.v
    assert v.policies is not None
    assert v.holds is not None
    assert v.clock is not None
    c = e.con
    try:
        e.active, e.active_err = v.policies.active(), None
    except Exception as err:
        e.active_err = err
    try:
        e.sel, e.sel_err = v.policies.selection(c), None
    except Exception as err:
        e.sel_err = err
    try:
        e.holds, e.holds_err = list(v.holds.holds(v.config.realm, e.pres.sub)), None
    except Exception as err:
        e.holds_err = err
    e.holds_at = v.clock.now()

    set_check(e, CHECK_NATIVE_AUTHENTICATION, native_authentication(e))
    set_check(e, CHECK_AGENT_HOLDER_BINDING, agent_holder_binding(e))
    set_check(e, CHECK_CONTRACT_VALIDITY, contract_validity(e))
    set_check(e, CHECK_NONCE, e.nonce)
    set_check(e, CHECK_OPERATION_BINDING, operation_binding(e))
    set_check(e, CHECK_INTENT_BINDING, intent_binding(e))
    set_check(e, CHECK_PROFILE_VALIDITY, profile_validity(e))
    set_check(e, CHECK_EVIDENCE_VALIDITY, evidence_validity(e))
    if e.pres.reputation is not None:
        set_check(e, CHECK_REPUTATION_CONTEXT, reputation_context(e))
    set_check(e, CHECK_SECURITY_HOLD, security_hold(e))
    set_check(e, CHECK_ACTIVE_POLICY, active_policy(e))

    for r in c.claims.field_rules:
        if r.source != RuleSource.NATIVE:
            set_check(e, r.rule_id, rule(e, r))
    for id_ in c.claims.context_checks:
        if id_ == CHECK_NATIVE_PRINCIPAL_BINDING:
            set_check(e, id_, native_principal_binding(e))
        elif id_ == CHECK_SELECTION_CONSISTENCY:
            set_check(e, id_, selection_consistency(e))
    for r in c.claims.field_rules:
        if r.source == RuleSource.NATIVE:
            native(e, r.rule_id, lambda r=r: native_rule(e, r))  # type: ignore[misc]
    for id_ in c.claims.context_checks:
        if id_ not in (CHECK_NATIVE_PRINCIPAL_BINDING, CHECK_SELECTION_CONSISTENCY):
            native(e, id_, lambda id_=id_: context_check(e, id_))  # type: ignore[misc]


def native_authentication(e: Evaluation) -> Outcome:
    pr = e.req.principal
    if pr.realm != e.v.config.realm:
        return fail(REASON_CONTEXT_MISMATCH)
    return ok().at(pr.authenticated_at)


def agent_holder_binding(e: Evaluation) -> Outcome:
    if not e.binding_known:
        return unknown(REASON_UNAVAILABLE)
    b = e.binding
    o = ok()
    if b.status == BindingStatus.COMPROMISED:
        o = fail(REASON_SECURITY_HOLD)
    o.observed, o.status, o.source_id = (
        unix_of(b.observed_at),
        unix_of(b.status_checked_at),
        b.source_id,
    )
    if b.source_ref:
        o.source_ref = b.source_ref
    return o


def contract_validity(e: Evaluation) -> Outcome:
    """Draft 11.3 step 3: the contract names this agent, gateway and realm, carries only
    supported extensions, lists selection-consistency-v1 when it selects a set other than
    the conservative one, and, when the validator holds the table of its pinned selector,
    holds exactly the authorized field rules and context checks of its set."""
    cfg, c = e.v.config, e.con
    try:
        c.check(
            contract.Expect(
                agent_id=e.pres.sub,
                audience=cfg.audience,
                realm=cfg.realm,
                supported_extensions=tuple(cfg.supported_extensions),
            )
        )
    except contract.ContractError as err:
        if err.code == str(Code.UNSUPPORTED_REQUIREMENT):
            return unknown(REASON_UNSUPPORTED)
        return fail(REASON_CONTEXT_MISMATCH)
    if e.pres.aud != cfg.audience or e.pres.tenant_id != c.claims.tenant_id:
        return fail(REASON_CONTEXT_MISMATCH)
    if e.active_err is not None or e.sel_err is not None:
        return unknown(REASON_UNAVAILABLE)
    if (
        c.claims.selected_set != e.active.conservative_set
        and CHECK_SELECTION_CONSISTENCY not in c.claims.context_checks
    ):
        return fail(REASON_CONTEXT_MISMATCH)
    s = e.sel.selector
    if s is not None:
        # The validator holds the table: the contract's rules and checks are exactly its entry
        # for the set, array order significant.
        rules = s.rules(c.claims.selected_set)
        if rules is None or not _schema.json_equal(
            _wire.to_json(tuple(rules)), _wire.to_json(c.claims.field_rules)
        ):
            return fail(REASON_CONTEXT_MISMATCH)
        checks = s.checks(c.claims.selected_set)
        if checks is None or not _schema.json_equal(list(checks), list(c.claims.context_checks)):
            return fail(REASON_CONTEXT_MISMATCH)
    return ok()


def actual_digest(e: Evaluation) -> str:
    """The object_digest of the actual operation (draft 12.1)."""
    from hop_top_pact.core import digest

    try:
        return digest.object_digest(e.req.operation)
    except Exception:
        return ""


def operation_binding(e: Evaluation) -> Outcome:
    """Draft 11.3 step 5: the actual operation and the presented one are the operation the
    contract was issued for."""
    from hop_top_pact.validator._validator import object_digest

    want = e.con.claims.operation_digest
    if actual_digest(e) != want or object_digest(e.op_raw) != want:
        return fail(REASON_CONTEXT_MISMATCH)
    return ok()


def intent_binding(e: Evaluation) -> Outcome:
    from hop_top_pact.validator._validator import object_digest

    if object_digest(e.intent_raw) != e.con.claims.intent_digest:
        return fail(REASON_CONTEXT_MISMATCH)
    return ok()


def profile_validity(e: Evaluation) -> Outcome:
    """Draft 11.3 step 6, but for the field rules: subject, tenant, age and lifetime, and the
    enrolled operator (Appendix A.2). The holder was bound before the evaluation began."""
    pf, cfg = e.pres.profile, e.v.config
    assert e.v.clock is not None
    if (
        pf.agent_id != e.pres.sub
        or pf.tenant_id != e.con.claims.tenant_id
        or pf.tenant_id != cfg.realm.tenant_id
    ):
        return fail(REASON_CONTEXT_MISMATCH)
    try:
        clock.check_window(pf.created_at, pf.created_at, pf.expires_at, e.v.clock.now(), cfg.skew)
    except clock.ClockError as err:
        if err.kind == clock.ClockErrorKind.EXPIRED:
            return fail(REASON_STALE_EVIDENCE)
        return fail(REASON_INVALID_CLAIM)
    try:
        clock.check_lifetime(clock.Artifact.PROFILE, pf.created_at, pf.expires_at)
    except clock.ClockError:
        return fail(REASON_INVALID_CLAIM)
    if not e.binding_known:
        return unknown(REASON_UNAVAILABLE)
    if pf.operator_id != e.binding.operator_id:
        return fail(REASON_CONTEXT_MISMATCH)
    return ok().at(datetime.fromtimestamp(pf.created_at, UTC))


def security_hold(e: Evaluation) -> Outcome:
    assert e.v.clock is not None
    if e.holds_err is not None:
        return unknown(REASON_UNAVAILABLE)
    if e.holds:
        o = fail(REASON_SECURITY_HOLD)
        o.evidence = list(e.holds)
        return o.at(e.v.clock.now())
    return ok().at(e.v.clock.now())


def active_policy(e: Evaluation) -> Outcome:
    """The active-policy check of draft 11.3 step 3 and 12.2: a contract invalidated by a
    policy change is FAIL with REQUIREMENTS_CHANGED, which defers."""
    assert e.v.clock is not None
    if e.active_err is not None:
        return unknown(REASON_UNAVAILABLE)
    try:
        e.con.check_active(e.active.policy)
    except contract.ContractError:
        return fail(REASON_REQUIREMENTS_CHANGED)
    return ok().at(e.v.clock.now())


def native_principal_binding(e: Evaluation) -> Outcome:
    """The check of draft 17.5: the principal the profile claims to act for is the one
    authenticate_native established."""
    v = _schema.pointer(e.profile, PRINCIPAL_PATH)
    if v is _schema.NOT_FOUND:
        return fail(REASON_MISSING_FIELD)
    if not isinstance(v, str) or v != e.req.operation.principal_id:
        return fail(REASON_CONTEXT_MISMATCH)
    return ok().at(e.req.principal.authenticated_at)


def context_check(e: Evaluation, id_: str) -> Outcome:
    """Run an installed check through check_context (draft 17.1), with the principal and
    binding this evaluation established. A check the gateway did not install, or one that
    needs a binding the enrollment source could not establish, is UNKNOWN: it was not
    performed."""
    assert e.v.native is not None
    if id_ not in e.v.config.installed_checks:
        return unknown(REASON_UNSUPPORTED)
    if not e.binding_known:
        return unknown(REASON_UNAVAILABLE)
    got = e.v.native.check_context(id_, e.check_input())
    o = Outcome(result=got.result.check_status(), reason=got.reason_code, source_id=got.source_id)
    if o.result == CheckStatus.PASS and o.reason == "":
        o.reason = REASON_SATISFIED
    if o.result != CheckStatus.PASS and o.reason == "":
        o = unknown(REASON_UNAVAILABLE)
        o.source_id = got.source_id
    if got.source_ref:
        o.source_ref = got.source_ref
    o.observed = unix_of(got.observed_at)
    return o


# Field rules (draft 9.2, 8.4).


def fresh(e: Evaluation, r: FieldRule, c: NativeClaim) -> tuple[CheckStatus, freshness.ReasonCode]:
    """Apply the age limits of r to a source's times (draft 9.2), the limit zero meaning a
    time no earlier than the start of this evaluation."""
    assert e.v.clock is not None
    ev = freshness.Evaluator(skew=e.v.config.skew, start=e.start)
    return ev.evaluate(r, c, e.v.clock.now())


def presented(e: Evaluation, r: FieldRule) -> tuple[object, Outcome | None]:
    """Apply the checks every field rule shares: the path is present and the presented value
    satisfies the rule's schema (draft 9.2). It returns the value, or the outcome of the
    rule."""
    try:
        schema = _schema.check_schema(e.schemas[r.rule_id])
    except (_schema.UnsupportedSchemaError, KeyError):
        return None, unknown(REASON_UNSUPPORTED)
    value = _schema.pointer(e.profile, r.path)
    if value is _schema.NOT_FOUND:
        return None, fail(REASON_MISSING_FIELD)
    if not _schema.matches(schema, value):
        return None, fail(REASON_INVALID_CLAIM)
    return value, None


def rule(e: Evaluation, r: FieldRule) -> Outcome:
    """Evaluate a self or evidence field rule (draft 9.2, 8.4)."""
    value, o = presented(e, r)
    if o is not None:
        return o
    if r.source == RuleSource.SELF:
        return ok()
    if r.source != RuleSource.EVIDENCE:
        return unknown(REASON_UNSUPPORTED)
    found: list[AuthClaim] = [
        c for c in e.claims if c.path == r.path and c.issuer in r.allowed_issuers
    ]
    if not found:
        if r.path in e.pending_paths:
            return unknown(e.pending_paths[r.path])
        if r.path in e.failed_paths:
            return fail(e.failed_paths[r.path])
        return fail(REASON_MISSING_FIELD)
    for c in found[1:]:
        if not _schema.json_equal(c.value, found[0].value):
            return fail(REASON_CONFLICTING_EVIDENCE)
    auth = found[0]
    # A snapshot value was observed at the snapshot's iat; its status check is the validator's
    # security-hold check (Appendix A.2).
    claim = NativeClaim(
        observed_at=auth.observed_at, status_checked_at=auth.status_at, source_id=auth.source_id
    )
    res, code = fresh(e, r, claim)
    if res == CheckStatus.UNKNOWN and auth.hold_check and e.holds_err is not None:
        return unknown(REASON_UNAVAILABLE)
    if res != CheckStatus.PASS:
        return Outcome(result=res, reason=str(code))
    if not _schema.compare(str(r.comparison), value, auth.value):
        return fail(REASON_INVALID_CLAIM)
    o = ok()
    o.observed, o.status, o.evidence = (
        unix_of(auth.observed_at),
        unix_of(auth.status_at),
        [auth.evidence_id],
    )
    return o


def native_rule(e: Evaluation, r: FieldRule) -> Outcome:
    """Evaluate a native field rule: the presented value is compared with the value
    read_native_claim returns for the approved native path (draft 8.5, 9.2, 17.2)."""
    from hop_top_pact.adapter import ClaimContext

    assert e.v.native is not None
    value, o = presented(e, r)
    if o is not None:
        return o
    m = None
    for nm in e.v.config.native_mappings:
        if r.native_path is not None and nm.path == r.path and nm.native_path == r.native_path:
            m = nm
    if m is None:
        return unknown(REASON_UNSUPPORTED)
    s = m.source
    if s is not None and (
        r.max_age_seconds < s.best_max_age_seconds
        or r.status_max_age_seconds < s.best_status_max_age_seconds
    ):
        # The source cannot meet the demanded freshness (draft 17.2).
        return unknown(REASON_UNSUPPORTED)
    try:
        claim = e.v.native.read_native_claim(
            m.native_path,
            ClaimContext(
                principal=e.req.principal, intent=e.pres.intent, operation=e.req.operation
            ),
        )
    except Exception as err:
        code = code_of(err)
        if code == str(Code.MISSING_FIELD):
            return fail(REASON_MISSING_FIELD)
        if code == str(Code.UNSUPPORTED_REQUIREMENT):
            return unknown(REASON_UNSUPPORTED)
        return unknown(REASON_UNAVAILABLE)
    res, code_ = fresh(e, r, claim)
    if (
        code_ != freshness.ReasonCode.CLOCK_AHEAD
        and m.source is not None
        and not m.source.live_check
        and claim.status_checked_at is not None
        and e.start - claim.status_checked_at > timedelta(seconds=r.status_max_age_seconds)
    ):
        # A cached answer the source cannot refresh, such as a stopped push feed: the check
        # cannot currently be completed (draft 18).
        return unknown(REASON_UNAVAILABLE)
    if res != CheckStatus.PASS:
        return Outcome(result=res, reason=str(code_))
    if not _schema.compare(str(r.comparison), value, claim.value):
        if r.path == PRINCIPAL_PATH:
            return fail(REASON_CONTEXT_MISMATCH)
        return fail(REASON_INVALID_CLAIM)
    o = ok()
    o.observed, o.status, o.source_id = (
        unix_of(claim.observed_at),
        unix_of(claim.status_checked_at),
        claim.source_id,
    )
    if claim.source_ref:
        o.source_ref = claim.source_ref
    return o
