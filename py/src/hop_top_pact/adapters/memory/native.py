"""read_native_claim, check_context and authorize_native of the memory adapter
(Go adapters/memory, native.go)."""

from __future__ import annotations

from typing import TYPE_CHECKING, Final, cast

from hop_top_pact.adapter import (
    CheckInput,
    CheckOutcome,
    ClaimContext,
    Decision,
    DependencyUnavailable,
    Effect,
    NativeClaim,
    Obligation,
    Principal,
    UnsupportedRequirement,
    Verdict,
)
from hop_top_pact.adapters.memory.freshness import (
    CODE_APPROVAL_SCOPE_MISMATCH,
    outage,
    run_check,
    source_time,
)
from hop_top_pact.adapters.memory.state import CheckRecord, MemoryAdapterError, PolicyRule
from hop_top_pact.core.clock import BASELINE_SKEW
from hop_top_pact.core.types import JSONValue, OperationContext

if TYPE_CHECKING:
    from hop_top_pact.adapters.memory.memory import MemoryAdapter

POLICY_SOURCE_ID: Final = "memory-policy"
"""The source a decision names when the rule that decided names no source of its
own, and when no rule applies: the adapter's own policy store."""


def read_native_claim(a: MemoryAdapter, native_path: str, cc: ClaimContext) -> NativeClaim:
    """The value at native_path in the context cc.

    Only a path in the approved list is readable. The record is looked up by
    realm, principal and path together, so a same-spelled principal of another
    realm has its own value. A record that names a resource is read only when
    cc.operation lists that resource, and a record that names a task only when
    cc.intent carries that task; nothing else in cc selects a record. observed_at
    and status_checked_at are what the source recorded and nothing else: a source
    that gives no time yields None, and the time of the read is never substituted.
    """
    if native_path not in a.st.approved_paths:
        raise UnsupportedRequirement(f"memory: {native_path!r} is not an approved native path")
    for c in a.st.claims:
        if not c.applies(native_path, cc):
            continue
        if a.unavailable(c.source_id):
            raise outage("read claim", c.source_id)
        observed, checked = source_time(c.observed_at), source_time(c.status_checked_at)
        a.check_source_times(observed, checked)
        value: JSONValue = c.value  # type: ignore[assignment]
        return NativeClaim(
            value=value,
            observed_at=observed,
            status_checked_at=checked,
            source_id=c.source_id,
            source_ref=c.source_ref,
        )
    raise MemoryAdapterError(
        f"memory: the source holds no value at {native_path!r} in this context"
    )


def check_context(a: MemoryAdapter, check_id: str, inp: CheckInput) -> CheckOutcome:
    """Run the installed check whose id equals check_id exactly.

    A check that is not installed is UNKNOWN with UNSUPPORTED_REQUIREMENT: the
    adapter did not perform it, so it cannot report that it passed (draft 17.2).
    There is no prefix, case-insensitive or empty-id match. An installed check is
    the record of that id that applies to the principal and the agent binding of
    inp (CheckRecord.applies); when the check is installed and no record of it
    applies, it is FAIL with CODE_APPROVAL_SCOPE_MISMATCH, never PASS, and the
    outcome names the source without the record's reference (draft 17.1,
    17.3.1). The record reports the verdict of its native state unless a finding
    of the source's availability, the record's freshness or the pinned revision
    comes first; see freshness.run_check.
    """
    other: CheckRecord | None = None
    for c in a.st.checks:
        if c.id != check_id:
            continue
        if c.applies(inp):
            return run_check(a, c)
        if other is None:
            other = c
    if other is not None:
        return CheckOutcome(
            result=Verdict.FAIL,
            reason_code=CODE_APPROVAL_SCOPE_MISMATCH,
            source_id=other.source_id,
        )
    return CheckOutcome(result=Verdict.UNKNOWN, reason_code="UNSUPPORTED_REQUIREMENT")


def _applies(r: PolicyRule, p: Principal, op: OperationContext) -> bool:
    return (
        r.principal == p.id
        and r.realm.tenant_id == p.realm.tenant_id
        and r.realm.environment_id == p.realm.environment_id
        and r.action == op.action
        and (not r.resource or r.resource in op.resources)
    )


def authorize_native(a: MemoryAdapter, p: Principal, op: OperationContext) -> Decision:
    """The native policy's decision for p and the operation, as the policy states it.

    The rules that name p, in p's realm, and the operation's action (and its
    resource, when the rule names one) apply. A deny wins over an unknown, and an
    unknown over an allow. When no rule applies the decision is a deny, so an
    absent rule is never an allow. The adapter evaluates p and no other
    principal, and it runs no downstream operation.

    The decision carries the provenance of the rule that decided as the rule
    gives it: its source, or POLICY_SOURCE_ID when it names none, its record, its
    decision time and its policy revision. The deny of no rule comes from
    POLICY_SOURCE_ID and has no record, time or revision. A decision time later
    than now plus the skew did not happen yet, so the decision is not passed on:
    it raises DependencyUnavailable.
    """
    first: dict[str, PolicyRule] = {}
    for r in a.st.policy:
        if _applies(r, p, op):
            first.setdefault(r.effect, r)
    decided = first.get(Effect.DENY) or first.get(Effect.UNKNOWN) or first.get(Effect.ALLOW)
    if decided is None:
        return Decision(
            effect=Effect.DENY,
            reason="no rule of the policy allows this principal",
            source_id=POLICY_SOURCE_ID,
        )
    d = decision_of(decided)
    if d.decided_at is not None and d.decided_at > a.clock.now() + BASELINE_SKEW:
        raise DependencyUnavailable("memory: the policy source reports a decision after now")
    return d


def decision_of(r: PolicyRule) -> Decision:
    return Decision(
        effect=Effect(r.effect),
        obligations=tuple(
            Obligation(id=o.id, attributes=cast(dict[str, JSONValue], dict(o.attributes or {})))
            for o in r.obligations
        ),
        reason=r.reason,
        source_id=r.source_id or POLICY_SOURCE_ID,
        source_ref=r.source_ref,
        decided_at=source_time(r.decided_at),
        policy_revision=r.policy_revision,
    )
