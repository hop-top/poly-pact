"""The checks of read_native_claim, check_context and authorize_native (Go
adaptertest, checks_native.go)."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from hop_top_pact.adapter._types import (
    AgentBinding,
    BindingStatus,
    CheckInput,
    CheckOutcome,
    ClaimContext,
    Decision,
    Effect,
    NativeClaim,
    Obligation,
    Verdict,
)
from hop_top_pact.adapter.adaptertest.casefile import (
    ABSENT,
    OUT_ALLOW,
    OUT_CLAIM,
    OUT_DENY,
    OUT_ERROR,
    OUT_NOT_ALLOWED,
    OUT_UNKNOWN,
    ExpectClaim,
    ExpectDecision,
    ObligationJSON,
)
from hop_top_pact.adapter.adaptertest.compare import (
    SKEW,
    CaseRun,
    error_text,
    json_equal,
    render,
)
from hop_top_pact.adapter.adaptertest.leak import json_text, scan_error, scan_value
from hop_top_pact.core.types import OperationContext


def claim(r: CaseRun) -> None:
    """Run a read_native_claim case."""
    k = r.case.call
    cc = ClaimContext(principal=r.principal(), intent=k.intent, operation=k.operation)
    assert r.subject is not None
    a = r.subject.adapter
    c, err, ok = r.call("read_native_claim", lambda: a.read_native_claim(k.native_path, cc))
    if not ok:
        return
    scan_error(r, "read_native_claim", err)
    if c is not None:
        scan_value(r, "read_native_claim claim", c)

    e = r.case.expect
    if e.outcome == OUT_CLAIM:
        if err is not None or c is None:
            r.fail(
                f"read_native_claim raised {error_text(err) if err else 'nothing'}, want a claim"
            )
            return
        if not isinstance(c, NativeClaim):
            r.fail(f"read_native_claim returned {type(c).__name__}, want a NativeClaim")
            return
        check_claim_invariants(r, c)
        check_claim(r, c, e.claim)
    elif e.outcome == OUT_ERROR:
        if err is None:
            r.fail("read_native_claim returned a claim, want an error")
            return
        r.want_reason("read_native_claim", err)


def check_claim_invariants(r: CaseRun, c: NativeClaim) -> None:
    """What holds for every claim an adapter returns: observed_at is the original
    observation and status_checked_at a check that took place, and neither lies
    beyond the allowed skew in the future ("No source observation or status-check
    time may be later than now + clock_skew", draft A.2); and the source is named
    (draft 8.3, 17.1, 17.2)."""
    r.not_after("observed_at", c.observed_at, r.now + SKEW)
    r.not_after("status_checked_at", c.status_checked_at, r.now + SKEW)
    if not c.source_id:
        r.fail("claim names no source")


def check_claim(r: CaseRun, c: NativeClaim, want: ExpectClaim | None) -> None:
    if want is None:
        return
    if want.value is not ABSENT:
        try:
            eq = json_equal(want.value, c.value)
        except ValueError as e:
            r.fail(f"claim value does not encode as JSON: {e}")
        else:
            if not eq:
                r.fail(f"claim value is {render(c.value)}, want {render(want.value)}")
    r.want_time("observed_at", want.observed_at, c.observed_at)
    r.want_time("status_checked_at", want.status_checked_at, c.status_checked_at)
    if want.source_id and c.source_id != want.source_id:
        r.fail(f"source id is {c.source_id!r}, want {want.source_id!r}")
    if want.source_ref and c.source_ref != want.source_ref:
        r.fail(f"source ref is {c.source_ref!r}, want {want.source_ref!r}")


def check(r: CaseRun) -> None:
    """Run a check_context case. check_context raises nothing (draft 17.2): an
    exception, a PactError included, fails the case."""
    k = r.case.call
    binding: AgentBinding | None = None
    if k.binding is not None:
        b = k.binding
        binding = AgentBinding(
            agent_id=b.agent_id,
            operator_id=b.operator_id,
            holder_jkt=b.holder_jkt,
            status=BindingStatus(b.status) if b.status else BindingStatus.ACTIVE,
        )
    op = k.operation
    if op is None:
        r.fail("the case has no operation")
        return
    inp = CheckInput(
        principal=r.principal(),
        binding=binding,
        intent=k.intent,
        operation=op,
        evidence_refs=k.evidence_refs or (),
    )
    check_id = k.check_id or ""
    assert r.subject is not None
    a = r.subject.adapter
    try:
        out: object = a.check_context(check_id, inp)
    except Exception as err:
        r.fail(
            f"check_context raised {type(err).__name__}: {error_text(err)}; a check raises"
            " nothing, and one it did not perform is UNKNOWN"
        )
        return
    scan_value(r, "check_context outcome", out)
    if not isinstance(out, CheckOutcome):
        r.fail(f"check_context returned {type(out).__name__}, want a CheckOutcome")
        return

    e = r.case.expect
    if not Verdict.is_valid(out.result):
        r.fail(f"check result {out.result!r} is not PASS, FAIL or UNKNOWN")
    elif out.result != e.outcome:
        r.fail(
            f"check {check_id!r} returned {out.result} ({out.reason_code}), want"
            f" {e.outcome}: a check the adapter did not perform is never PASS"
        )
    if not out.reason_code:
        r.fail("check returned no reason code")
    if e.reason_code and out.reason_code != e.reason_code:
        r.fail(f"check reason code is {out.reason_code!r}, want {e.reason_code!r}")
    r.not_after("check observed_at", out.observed_at, r.now + SKEW)


def authorize(r: CaseRun) -> None:
    """Run an authorize_native case."""
    k = r.case.call
    p = r.principal()
    op: OperationContext | None = k.operation
    if op is None:
        r.fail("the case has no operation")
        return
    assert r.subject is not None
    a = r.subject.adapter
    res, err, ok = r.call("authorize_native", lambda: a.authorize_native(p, op))
    if not ok:
        return
    scan_error(r, "authorize_native", err)
    if err is None and not isinstance(res, Decision):
        r.fail(f"authorize_native returned {type(res).__name__}, want a Decision")
        return
    d = res if isinstance(res, Decision) else None
    if d is not None:
        scan_value(r, "authorize_native decision", d)

    e = r.case.expect
    if d is not None:
        check_decision_invariants(r, d)
    if e.outcome in (OUT_ALLOW, OUT_DENY, OUT_UNKNOWN):
        if err is not None or d is None:
            raised = error_text(err) if err else "nothing"
            r.fail(f"authorize_native raised {raised}, want effect {e.outcome}")
            return
        if d.effect != e.outcome:
            r.fail(
                f"decision effect is {d.effect}, want {e.outcome}: a native decision is"
                " returned as it is, and PACT cannot rewrite a denial"
            )
        check_decision(r, d, e.decision)
    elif e.outcome == OUT_NOT_ALLOWED:
        if d is not None and d.permits():
            r.fail(
                f"decision is {d.effect}, want anything but ALLOW: the policy holds no rule"
                " that allows this principal"
            )
    elif e.outcome == OUT_ERROR:
        if err is None:
            r.fail(f"authorize_native returned {d.effect if d else None}, want an error")
            return
        r.want_reason("authorize_native", err)


def check_decision_invariants(r: CaseRun, d: Decision) -> None:
    """What holds for every decision an adapter returns: the effect is one of the
    three, the policy source that decided is named, and the decision time cannot
    lie beyond the allowed skew in the future (draft 7.5, 17.1, A.2)."""
    if not Effect.is_valid(d.effect):
        r.fail(f"decision effect {d.effect!r} is not ALLOW, DENY or UNKNOWN")
    if not d.source_id:
        r.fail(
            "decision names no source: every native decision names the policy source that decided"
        )
    r.not_after("decided_at", d.decided_at, r.now + SKEW)


def check_decision(r: CaseRun, d: Decision, want: ExpectDecision | None) -> None:
    if want is None:
        return
    if want.source_id and d.source_id != want.source_id:
        r.fail(f"decision source id is {d.source_id!r}, want {want.source_id!r}")
    want_record(r, want.source_ref, d.source_ref)
    r.want_time("decided_at", want.decided_at, d.decided_at)
    if want.policy_revision and d.policy_revision != want.policy_revision:
        r.fail(
            f"policy revision is {d.policy_revision!r}, want {want.policy_revision!r}: the"
            " revision is reported as the source gave it"
        )
    if want.obligations is None:
        return
    if not same_obligations(d.obligations, want.obligations):
        r.fail(
            f"obligations are {json_text(d.obligations)}, want"
            f" {json_text([_obligation(o) for o in want.obligations])}"
        )


def _obligation(o: ObligationJSON) -> Obligation:
    return Obligation(id=o.id, attributes={} if o.attributes is None else o.attributes)


def same_obligations(got: Sequence[Obligation], want: Sequence[ObligationJSON]) -> bool:
    """Compare obligations as JSON data, in order; no and empty attributes are the
    same."""
    if len(got) != len(want):
        return False
    for g, w in zip(got, want, strict=True):
        if g.id != w.id:
            return False
        ga: Mapping[str, object] = g.attributes or {}
        wa: Mapping[str, object] = w.attributes or {}
        if not ga and not wa:
            continue
        try:
            if not json_equal(dict(wa), dict(ga)):
                return False
        except ValueError:
            return False
    return True


def want_record(r: CaseRun, want: object, got: str) -> None:
    """Compare the decision record of a decision with the expected source_ref:
    ABSENT or "" is not checked, None requires an empty record, since the source
    keeps none, and any other string must be equal."""
    if want is ABSENT:
        return
    if want is None:
        if got:
            r.fail(
                f"decision source ref is {got!r}, want none: the source keeps no record of"
                " the decision and the adapter must not supply one"
            )
        return
    if not isinstance(want, str):
        r.fail(f"source_ref: expected value {render(want)} is not a string or null")
        return
    if want and got != want:
        r.fail(f"decision source ref is {got!r}, want {want!r}")
