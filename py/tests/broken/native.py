"""read_native_claim, check_context and authorize_native of the broken adapter,
with their defects (Go adapters/internal/broken, native.go)."""

from __future__ import annotations

from dataclasses import replace
from datetime import timedelta
from typing import TYPE_CHECKING

from broken.defects import Defect
from broken.freshness import check_freshness
from broken.identity import same_realm
from hop_top_pact.adapter import (
    AgentBinding,
    CheckInput,
    CheckOutcome,
    ClaimContext,
    Decision,
    DependencyUnavailable,
    Effect,
    NativeClaim,
    Principal,
    Realm,
    Verdict,
)
from hop_top_pact.adapter.adaptertest import ABSENT
from hop_top_pact.adapters import memory
from hop_top_pact.adapters.memory.freshness import source_time
from hop_top_pact.core.clock import BASELINE_SKEW
from hop_top_pact.core.types import Intent, JSONValue, OperationContext
from hop_top_pact.errors import PactError

if TYPE_CHECKING:
    from broken.adapter import BrokenAdapter

__all__ = ["authorize_native", "check_context", "read_native_claim"]


def _realm(r: memory.Realm) -> Realm:
    return Realm(tenant_id=r.tenant_id, environment_id=r.environment_id)


def _raw_claim(b: BrokenAdapter, path: str, cc: ClaimContext) -> NativeClaim | None:
    """The record behind a claim as the source stores it, with no check of the
    times."""
    for c in b.state().claims:
        if not c.applies(path, cc):
            continue
        if c.value is ABSENT:
            return None
        value: JSONValue = c.value  # type: ignore[assignment]
        return NativeClaim(
            value=value,
            observed_at=source_time(c.observed_at),
            status_checked_at=source_time(c.status_checked_at),
            source_id=c.source_id,
            source_ref=c.source_ref,
        )
    return None


def _with_resource(op: OperationContext | None, resource: str) -> OperationContext:
    if op is None:
        return OperationContext(
            operation_id="",
            environment_id="",
            principal_id="",
            action="",
            resources=(resource,),
            method="",
            target_uri="",
            body_digest="",
            headers={},
        )
    return replace(op, resources=(resource,))


def _with_task(intent: Intent | None, task_id: str) -> Intent:
    if intent is None:
        return Intent(intent_id="", purpose_id="", description="", task_id=task_id)
    return replace(intent, task_id=task_id)


def read_native_claim(b: BrokenAdapter, native_path: str, cc: ClaimContext) -> NativeClaim:
    """The memory adapter's, with the claim defects."""
    claims = b.state().claims
    if b.has(Defect.CONFLATE_CLAIM_REALMS):
        # Look the principal up in the realm of the first record that names it.
        for rec in claims:
            if rec.path == native_path and rec.principal == cc.principal.id:
                cc = replace(cc, principal=replace(cc.principal, realm=_realm(rec.realm)))
                break
    if b.has(Defect.IGNORE_CLAIM_RESOURCE):
        # Take the first record of the path whatever resource it names, by making
        # its resource the one the operation lists.
        for rec in claims:
            if rec.resource and replace(rec, resource="").applies(native_path, cc):
                cc = replace(cc, operation=_with_resource(cc.operation, rec.resource))
                break
    if b.has(Defect.IGNORE_CLAIM_TASK):
        # Take the first record of the path whatever task it names, by making its
        # task the task of the intent.
        for rec in claims:
            if rec.task_id and replace(rec, task_id="").applies(native_path, cc):
                cc = replace(cc, intent=_with_task(cc.intent, rec.task_id))
                break
    try:
        c = b.base.read_native_claim(native_path, cc)
    except PactError:
        # The memory adapter refused a time later than now plus the skew; pass it on.
        raw = _raw_claim(b, native_path, cc)
        if raw is None:
            raise
        limit = b.now() + BASELINE_SKEW
        future_observed = raw.observed_at is not None and raw.observed_at > limit
        future_checked = raw.status_checked_at is not None and raw.status_checked_at > limit
        if (b.has(Defect.PASS_FUTURE_OBSERVED_AT) and future_observed and not future_checked) or (
            b.has(Defect.PASS_FUTURE_STATUS_CHECKED) and future_checked and not future_observed
        ):
            return raw
        if b.has(Defect.CLAMP_FUTURE_CLAIM_TIMES) and (future_observed or future_checked):
            if future_observed:
                raw = replace(raw, observed_at=limit)
            if future_checked:
                raw = replace(raw, status_checked_at=limit)
            return raw
        raise
    if (
        b.has(Defect.NO_STATUS_SKEW_ALLOWANCE)
        and c.status_checked_at is not None
        and c.status_checked_at > b.now()
    ):
        raise DependencyUnavailable("broken: the source reports a status check after now")
    if b.has(Defect.RESTAMP_OBSERVED_AT):
        c = replace(c, observed_at=b.now())
    if b.has(Defect.STAMP_MISSING_TIMES):
        if c.observed_at is None:
            c = replace(c, observed_at=b.now())
        if c.status_checked_at is None:
            c = replace(c, status_checked_at=b.now())
    return c


def _verdict(c: memory.CheckRecord) -> CheckOutcome:
    return CheckOutcome(
        result=Verdict(c.result),
        reason_code=c.reason_code,
        source_id=c.source_id,
        source_ref=c.source_ref,
    )


def check_context(b: BrokenAdapter, check_id: str, inp: CheckInput) -> CheckOutcome:
    """The memory adapter's, with the check defects."""
    installed = b.state().checks
    empty = inp.binding is None or inp.binding == AgentBinding()
    if b.has(Defect.IGNORE_CHECK_SCOPE) or (b.has(Defect.TRUST_EMPTY_BINDING) and empty):
        # Take the first record of the id whatever agent or principal it is for, by
        # making the call the record's own.
        for rec in installed:
            if rec.id != check_id:
                continue
            if b.has(Defect.IGNORE_CHECK_SCOPE) and rec.principal:
                inp = replace(inp, principal=replace(inp.principal, id=rec.principal))
            if rec.agent_id:
                binding = inp.binding if inp.binding is not None else AgentBinding()
                inp = replace(inp, binding=replace(binding, agent_id=rec.agent_id))
            break
    out = check_freshness(b, check_id, b.base.check_context(check_id, inp))

    if b.has(Defect.NEVER_EVALUATE_CHECKS) and out.result != Verdict.UNKNOWN:
        return CheckOutcome(
            result=Verdict.FAIL, reason_code="CHECK_FAILED", source_id=out.source_id
        )
    if b.has(Defect.PREFIX_MATCH_CHECK):
        for c in installed:
            if c.id.startswith(check_id):
                return _verdict(c)
    if b.has(Defect.FOLD_CASE_CHECK):
        for c in installed:
            if _equal_fold(c.id, check_id):
                return _verdict(c)
    if b.has(Defect.FAIL_OPEN_UNKNOWN_CHECK) and out.result == Verdict.UNKNOWN:
        return CheckOutcome(result=Verdict.PASS, reason_code="REQUIREMENT_SATISFIED")
    if b.has(Defect.ECHO_REFS_IN_SOURCE):
        out = replace(out, source_ref=" ".join(inp.evidence_refs))
    return out


def _equal_fold(a: str, b: str) -> bool:
    """Equal under case folding, as Go's strings.EqualFold compares the ASCII check
    ids of the cases."""
    return a.casefold() == b.casefold()


def _rule_mentions(b: BrokenAdapter, principal: str, action: str) -> bool:
    """Whether any rule of any realm names the principal for the action."""
    return any(r.principal == principal and r.action == action for r in b.state().policy)


def authorize_native(b: BrokenAdapter, p: Principal, op: OperationContext) -> Decision:
    """The memory adapter's, with the authorization defects."""
    evaluated = p
    policy = b.state().policy
    if b.has(Defect.CONNECTOR_SUBSTITUTION):
        for r in policy:
            if r.effect == Effect.ALLOW and r.action == op.action and r.principal != p.id:
                evaluated = replace(evaluated, id=r.principal)
                break
    if b.has(Defect.CONFLATE_POLICY_REALMS):
        for r in policy:
            if r.principal == p.id and r.action == op.action and not same_realm(r.realm, p.realm):
                evaluated = replace(evaluated, realm=_realm(r.realm))
                break
    d = b.base.authorize_native(evaluated, op)

    if b.has(Defect.DEFAULT_ALLOW) and not _rule_mentions(b, p.id, op.action):
        d = replace(d, effect=Effect.ALLOW)
    if b.has(Defect.REWRITE_READ_DENY) and d.effect == Effect.DENY and op.method == "GET":
        d = replace(d, effect=Effect.ALLOW)
    if b.has(Defect.DROP_OBLIGATIONS):
        d = replace(d, obligations=())
    if b.has(Defect.DECISION_WITHOUT_SOURCE):
        d = replace(d, source_id="")
    if b.has(Defect.FUTURE_DECIDED_AT):
        d = replace(d, decided_at=b.now() + timedelta(hours=1))
    if (b.has(Defect.EXECUTE_ON_DENY) and d.effect == Effect.DENY) or (
        b.has(Defect.EXECUTE_ON_ALLOW) and d.effect == Effect.ALLOW
    ):
        b.fire("execute")
    return d
