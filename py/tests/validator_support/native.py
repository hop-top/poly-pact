"""The in-memory native adapter of a case's native_context.json and the timed double that
holds its native reads (spec/v1.0/fixtures/README.md, exchange.json)."""

from __future__ import annotations

import threading
from collections.abc import Sequence
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from typing import Any
from urllib.parse import urlsplit

from hop_top_pact.adapter import (
    AgentBinding,
    AgentID,
    CheckInput,
    CheckOutcome,
    ClaimContext,
    DependencyUnavailable,
    NativeClaim,
    Principal,
    Realm,
    Verdict,
    Workload,
)
from hop_top_pact.adapters import memory
from hop_top_pact.conformance import (
    Amount,
    Approval,
    Delegation,
    Evaluation,
    Executor,
    ExecutorClass,
)
from hop_top_pact.core.clock import FakeClock
from hop_top_pact.core.types import Intent, OperationContext

ENROLLMENT_SOURCE = "fixture:enrollment-source"
DEFAULT_CHECK_AGE = 30
DELEGATION_PATH = "/attributes/delegation/authority_ref"
SATISFIED = "REQUIREMENT_SATISFIED"
WORKLOAD = "fixture:workload"


def verdict(v: Verdict, reason: str = "") -> tuple[str, str]:
    return str(v), reason or SATISFIED


def fresh(age: int) -> memory.CheckFreshness:
    return memory.CheckFreshness(max_age_seconds=age, status_max_age_seconds=age)


def amount_covered(a: Amount | None) -> bool:
    if a is None:
        return True
    try:
        return Decimal(a.requested) <= Decimal(a.approved)
    except InvalidOperation:
        return False


def resources_covered(approved: Sequence[str], requested: Sequence[str]) -> bool:
    if not approved:
        return True
    return all(r in approved for r in requested)


def approval_record(
    r: memory.CheckRecord, a: Approval | None, i: Intent, op: OperationContext, age: int
) -> memory.CheckRecord:
    """The native approval state as the result of draft 17.3.1. The record applies only to
    the agent and the principal the approval is bound to; for another one the adapter
    reports a scope mismatch."""
    if a is None:
        res, reason = verdict(Verdict.FAIL, "MISSING_FIELD")
        return _with(r, result=res, reason_code=reason)
    r = _with(r, principal=a.principal_id, agent_id=a.agent_id, source_ref=a.ref)
    if a.status_checked_at is not None:
        r = _with(
            r,
            observed_at=a.status_checked_at,
            status_checked_at=a.status_checked_at,
            freshness=fresh(age),
        )
    if (
        a.purpose_id != i.purpose_id
        or a.task_id != i.task_id
        or not amount_covered(a.amount)
        or not resources_covered(a.resources, op.resources)
    ):
        res, reason = verdict(Verdict.FAIL, "APPROVAL_SCOPE_MISMATCH")
    elif a.state == "approved":
        res, reason = verdict(Verdict.PASS)
        aa = a.approver_authority
        if aa is not None and aa.required_role not in aa.approver_roles:
            res, reason = verdict(Verdict.FAIL, "APPROVAL_AUTHORITY_MISMATCH")
    elif a.state == "pending":
        res, reason = verdict(Verdict.UNKNOWN, "APPROVAL_PENDING")
    elif a.state in ("rejected", "expired", "revoked"):
        res, reason = verdict(Verdict.FAIL, "APPROVAL_" + a.state.upper())
    else:
        res, reason = verdict(Verdict.UNKNOWN, "DEPENDENCY_UNAVAILABLE")
    return _with(r, result=res, reason_code=reason)


def _with(r: memory.CheckRecord, **kw: Any) -> memory.CheckRecord:
    from dataclasses import replace

    return replace(r, **kw)


def delegation_record(
    r: memory.CheckRecord, d: Delegation | None, i: Intent, p: Principal, age: int
) -> memory.CheckRecord:
    """native-delegation-v1 (draft 17.5): the native delegation is in force, for the
    authenticated principal and the task of the intent; its age is bounded like the source
    of its field rule."""
    if d is None:
        res, reason = verdict(Verdict.FAIL, "MISSING_FIELD")
        return _with(r, result=res, reason_code=reason)
    r = _with(
        r,
        source_ref=d.authority_ref,
        observed_at=d.observed_at,
        status_checked_at=d.observed_at,
        freshness=fresh(age),
    )
    if d.state == "revoked":
        res, reason = verdict(Verdict.FAIL, "REVOKED_EVIDENCE")
    elif d.state != "active":
        res, reason = verdict(Verdict.UNKNOWN, "DEPENDENCY_UNAVAILABLE")
    elif d.task_id != i.task_id:
        res, reason = verdict(Verdict.FAIL, "TASK_MISMATCH")
    elif d.principal_id != p.id:
        res, reason = verdict(Verdict.FAIL, "CONTEXT_MISMATCH")
    else:
        res, reason = verdict(Verdict.PASS)
    return _with(r, result=res, reason_code=reason)


def executor_record(
    r: memory.CheckRecord,
    ex: Executor | None,
    classes: Sequence[ExecutorClass],
    i: Intent,
    op: OperationContext,
) -> memory.CheckRecord:
    """execution-identity-v1 (draft 17.5): the executor that will run the operation is the
    declared class and binding."""
    if ex is None:
        res, reason = verdict(Verdict.UNKNOWN, "DEPENDENCY_UNAVAILABLE")
        return _with(r, result=res, reason_code=reason)
    for c in classes:
        if (
            c.principal_id != op.principal_id
            or c.task_id != i.task_id
            or c.operation_id != op.operation_id
        ):
            continue
        res, reason = verdict(Verdict.PASS)
        if c.class_ != ex.class_ or (
            c.executor_id is not None and c.executor_id != ex.principal_id
        ):
            res, reason = verdict(Verdict.FAIL, "EXECUTOR_MISMATCH")
        return _with(r, result=res, reason_code=reason)
    res, reason = verdict(Verdict.UNKNOWN, "UNSUPPORTED_REQUIREMENT")
    return _with(r, result=res, reason_code=reason)


def purpose_record(
    r: memory.CheckRecord, purposes: dict[str, list[str]], i: Intent, op: OperationContext
) -> memory.CheckRecord:
    """The verdict of purpose-operation-v1 under the installed purpose mapping (draft 10.1):
    an unrecognized purpose is UNKNOWN UNSUPPORTED_PURPOSE, an action the purpose does not
    cover FAIL CONTEXT_MISMATCH."""
    actions = purposes.get(i.purpose_id)
    if actions is None:
        res, reason = verdict(Verdict.UNKNOWN, "UNSUPPORTED_PURPOSE")
    elif op.action not in actions:
        res, reason = verdict(Verdict.FAIL, "CONTEXT_MISMATCH")
    else:
        res, reason = verdict(Verdict.PASS)
    return _with(r, result=res, reason_code=reason)


def origin_of(target: str) -> str:
    u = urlsplit(target)
    return memory.normalize_origin(f"{u.scheme}://{u.netloc}")


class TimedNative:
    """Holds the native reads of a submission until its native_reads_at: a read issued
    earlier completes then, moving the clock, unless the requestor cancels first at
    cancelled_at. cancel is the event the validator's cancelled predicate polls."""

    def __init__(
        self,
        inner: memory.MemoryAdapter,
        clk: FakeClock,
        ev: Evaluation,
        cancel: threading.Event,
    ) -> None:
        self.inner = inner
        self.clk = clk
        self.ev = ev
        self.cancel = cancel
        self._lock = threading.Lock()

    def _wait(self) -> bool:
        """Report whether the evaluation is cancelled when the read completes."""
        with self._lock:
            at = self.ev.native_reads_at
            if at is None or self.clk.now() >= datetime.fromtimestamp(at, UTC):
                return self.cancel.is_set()
            c = self.ev.cancelled_at
            if c is not None and c < at:
                self.clk.set(datetime.fromtimestamp(c, UTC))
                self.cancel.set()
                return True
            self.clk.set(datetime.fromtimestamp(at, UTC))
            return self.cancel.is_set()

    def resolve_agent_binding(
        self, realm: Realm, workload: Workload, agent: AgentID
    ) -> AgentBinding:
        return self.inner.resolve_agent_binding(realm, workload, agent)

    def read_native_claim(self, native_path: str, c: ClaimContext) -> NativeClaim:
        if self._wait():
            raise DependencyUnavailable("read cancelled")
        return self.inner.read_native_claim(native_path, c)

    def check_context(self, check_id: str, input: CheckInput) -> CheckOutcome:
        if self._wait():
            return CheckOutcome(result=Verdict.UNKNOWN, reason_code="DEPENDENCY_UNAVAILABLE")
        return self.inner.check_context(check_id, input)
