"""read_native_claim, check_context and authorize_native of the memory adapter
(port of the claim, check and authorization tests of
go/adapters/memory/memory_unit_test.go). Go's zero time is None, and a check
input without a binding has binding None."""

from __future__ import annotations

from dataclasses import replace
from datetime import timedelta
from typing import Any

import pytest

from hop_top_pact.adapter import (
    AgentBinding,
    BindingStatus,
    CheckInput,
    ClaimContext,
    DependencyUnavailable,
    Effect,
    Principal,
    Realm,
    UnsupportedRequirement,
    Verdict,
)
from hop_top_pact.adapter.adaptertest.compare import find
from hop_top_pact.adapters import memory as m
from hop_top_pact.core.types import Intent, OperationContext
from hop_top_pact.errors import PactError

ENV = "https://gateway.example/environments/finance"
REALM = m.Realm(tenant_id="acme", environment_id=ENV)
ALICE = "https://idp.example/alice"


def op(*resources: str, action: str = "", principal_id: str = "") -> OperationContext:
    return OperationContext(
        operation_id="",
        environment_id="",
        principal_id=principal_id,
        action=action,
        resources=resources,
        method="",
        target_uri="",
        body_digest="",
        headers={},
    )


def intent(task: str) -> Intent:
    return Intent(intent_id="", purpose_id="", description="", task_id=task)


def missing(err: BaseException) -> bool:
    """Whether err says the value is missing: neither an outage nor an unsupported
    path."""
    return (
        isinstance(err, PactError)
        and find(err, DependencyUnavailable) is None
        and find(err, UnsupportedRequirement) is None
    )


def test_read_native_claim(mem: Any) -> None:
    past, future, edge, past_skew = mem.at(-120), mem.at(3600), mem.at(5), mem.at(6)

    def rec(path: str, value: object, o: int | None, c: int | None) -> m.ClaimRecord:
        return m.ClaimRecord(
            realm=REALM,
            principal=ALICE,
            path=path,
            value=value,
            observed_at=o,
            status_checked_at=c,
            source_id="dir",
            source_ref="r-" + path,
        )

    a, _ = mem.new_adapter(
        lambda st: replace(
            st,
            approved_paths=(
                "/roles",
                "/null",
                "/future",
                "/checked",
                "/edge",
                "/checked-edge",
                "/checked-past",
            ),
            claims=(
                rec("/roles", ("approver", "viewer"), past, past),
                rec("/null", None, None, None),
                rec("/future", ("x",), future, None),
                rec("/checked", ("x",), past, future),
                rec("/edge", ("x",), edge, None),
                rec("/checked-edge", ("x",), past, edge),
                rec("/checked-past", ("x",), past, past_skew),
            ),
        )
    )

    def read(path: str, p: Principal) -> Any:
        return a.read_native_claim(path, ClaimContext(principal=p))

    def at(sec: int) -> Any:
        return mem.EPOCH + timedelta(seconds=sec)

    c = read("/roles", mem.alice())
    assert (c.source_id, c.source_ref, c.observed_at, c.status_checked_at) == (
        "dir",
        "r-/roles",
        at(past),
        at(past),
    )
    assert c.value == ("approver", "viewer")
    c = read("/null", mem.alice())
    assert (c.value, c.observed_at, c.status_checked_at) == (None, None, None)
    assert read("/edge", mem.alice()).observed_at == mem.T0 + timedelta(seconds=5)
    # Draft A.2: no status-check time may be later than now plus the skew.
    assert read("/checked-edge", mem.alice()).status_checked_at == mem.T0 + timedelta(seconds=5)
    for path in ("/future", "/checked", "/checked-past"):
        with pytest.raises(DependencyUnavailable):
            read(path, mem.alice())
    for path in ("/not-approved", ""):
        with pytest.raises(UnsupportedRequirement):
            read(path, mem.alice())
    alice_realm = mem.alice().realm
    for name, p in {
        "another principal": Principal(id="https://idp.example/bob", realm=alice_realm),
        "another tenant": Principal(id=ALICE, realm=Realm(tenant_id="globex", environment_id=ENV)),
        "another env": Principal(id=ALICE, realm=Realm(tenant_id="acme", environment_id="other")),
    }.items():
        with pytest.raises(PactError) as e:
            read("/roles", p)
        assert missing(e.value), f"{name}: a missing value is not {e.value!r}"


def test_read_native_claim_follows_the_clock(mem: Any) -> None:
    ahead = mem.at(600)
    a, clk = mem.new_adapter(
        lambda st: replace(st, claims=(replace(st.claims[0], observed_at=ahead),))
    )
    with pytest.raises(DependencyUnavailable):
        a.read_native_claim("/roles", ClaimContext(principal=mem.alice()))
    clk.advance(timedelta(minutes=10))
    c = a.read_native_claim("/roles", ClaimContext(principal=mem.alice()))
    assert c.observed_at == mem.T0 + timedelta(minutes=10)


def test_read_native_claim_scope(mem: Any) -> None:
    """A record that names a resource is read only for an operation that lists the
    resource, and a record that names a task only for an intent that carries the
    task (draft 17.1: "approved native path and context"). A record that names
    neither is read in any context."""
    doc1, doc2 = "https://docs.example/d/1", "https://docs.example/d/2"

    def rec(path: str, value: object, resource: str, task: str) -> m.ClaimRecord:
        return m.ClaimRecord(
            realm=REALM,
            principal=ALICE,
            path=path,
            value=value,
            source_id="src",
            resource=resource,
            task_id=task,
        )

    a, _ = mem.new_adapter(
        lambda st: replace(
            st,
            approved_paths=("/roles", "/classification", "/grant", "/both"),
            claims=(
                rec("/roles", ("approver",), "", ""),
                rec("/classification", "restricted", doc1, ""),
                rec("/classification", "internal", doc2, ""),
                rec("/grant", "grant-a", "", "task-a"),
                rec("/grant", "grant-b", "", "task-b"),
                rec("/both", "doc1-task-a", doc1, "task-a"),
            ),
        )
    )
    none = object()
    for name, path, i, o, want in (
        ("unscoped, no context", "/roles", None, None, ("approver",)),
        ("unscoped, any context", "/roles", intent("task-a"), op(doc1), ("approver",)),
        ("the first resource", "/classification", None, op(doc1), "restricted"),
        ("the second resource", "/classification", None, op(doc2), "internal"),
        (
            "a resource among several",
            "/classification",
            None,
            op("https://docs.example/d/9", doc2),
            "internal",
        ),
        (
            "a resource the operation does not list",
            "/classification",
            None,
            op("https://docs.example/d/9"),
            none,
        ),
        ("a resource fact with no operation", "/classification", None, None, none),
        (
            "a resource fact is not read from the intent",
            "/classification",
            intent(doc1),
            None,
            none,
        ),
        ("the first task", "/grant", intent("task-a"), None, "grant-a"),
        ("the second task", "/grant", intent("task-b"), op(doc1), "grant-b"),
        ("another task", "/grant", intent("task-c"), None, none),
        ("a task fact with no intent", "/grant", None, None, none),
        ("a task fact is not read from the resources", "/grant", None, op("task-a"), none),
        ("a task is matched exactly", "/grant", intent("TASK-A"), None, none),
        ("both scopes", "/both", intent("task-a"), op(doc1), "doc1-task-a"),
        ("both scopes, task missing", "/both", None, op(doc1), none),
        ("both scopes, resource missing", "/both", intent("task-a"), None, none),
    ):
        cc = ClaimContext(principal=mem.alice(), intent=i, operation=o)
        if want is none:
            with pytest.raises(PactError) as e:
                a.read_native_claim(path, cc)
            assert missing(e.value), f"{name}: a value out of scope is missing, not {e.value!r}"
            continue
        assert a.read_native_claim(path, cc).value == want, name

    # the realm still applies
    other = replace(mem.alice(), realm=replace(mem.alice().realm, tenant_id="globex"))
    with pytest.raises(PactError):
        a.read_native_claim("/classification", ClaimContext(principal=other, operation=op(doc1)))


def check_input(principal: str = "", agent: str | None = None) -> CheckInput:
    binding = None if agent is None else AgentBinding(agent_id=agent, status=BindingStatus.ACTIVE)
    return CheckInput(principal=Principal(id=principal), binding=binding, operation=op())


def test_check_context(mem: Any) -> None:
    future = mem.at(3600)
    a, _ = mem.new_adapter(
        lambda st: replace(
            st,
            checks=(
                *st.checks,
                m.CheckRecord(
                    id="failing-v1",
                    result="FAIL",
                    reason_code="APPROVAL_REJECTED",
                    source_id="approvals",
                    source_ref="a-1",
                ),
                m.CheckRecord(
                    id="pending-v1",
                    result="UNKNOWN",
                    reason_code="APPROVAL_PENDING",
                    source_id="approvals",
                ),
                m.CheckRecord(
                    id="future-v1",
                    result="PASS",
                    reason_code="REQUIREMENT_SATISFIED",
                    source_id="approvals",
                    observed_at=future,
                ),
            ),
        )
    )

    def run(check_id: str) -> Any:
        return a.check_context(check_id, check_input())

    for check_id, want in {
        "approval-v1": Verdict.PASS,
        "failing-v1": Verdict.FAIL,
        "pending-v1": Verdict.UNKNOWN,
        "": Verdict.UNKNOWN,
        "approval": Verdict.UNKNOWN,
        "approval-v10": Verdict.UNKNOWN,
        "APPROVAL-V1": Verdict.UNKNOWN,
        " approval-v1": Verdict.UNKNOWN,
        "approval-v1 ": Verdict.UNKNOWN,
    }.items():
        got = run(check_id)
        assert got.result == want, check_id
        assert got.reason_code, check_id
    got = run("nothing")
    assert (got.reason_code, got.source_id) == ("UNSUPPORTED_REQUIREMENT", "")
    got = run("failing-v1")
    assert (got.reason_code, got.source_ref) == ("APPROVAL_REJECTED", "a-1")
    got = run("future-v1")
    assert (got.result, got.reason_code) == (Verdict.UNKNOWN, "DEPENDENCY_UNAVAILABLE"), (
        "a check observed in the future must not pass"
    )


def test_check_context_scope(mem: Any) -> None:
    """A check whose record names a principal or an agent applies only in a call from
    that principal and that agent's binding; an installed check that no record
    applies to is FAIL with APPROVAL_SCOPE_MISMATCH, never PASS (draft 17.1,
    17.3.1)."""
    bob = "https://idp.example/bob"
    agent_a, agent_b = "https://agents.example/a", "https://agents.example/b"
    ok: dict[str, Any] = {
        "result": "PASS",
        "reason_code": "REQUIREMENT_SATISFIED",
        "source_id": "approvals",
    }
    a, _ = mem.new_adapter(
        lambda st: replace(
            st,
            checks=(
                *st.checks,
                m.CheckRecord(
                    id="scoped-v1", principal=ALICE, agent_id=agent_a, source_ref="appr-1", **ok
                ),
                m.CheckRecord(id="principal-only-v1", principal=ALICE, **ok),
                m.CheckRecord(id="agent-only-v1", agent_id=agent_a, **ok),
                m.CheckRecord(
                    id="two-v1",
                    principal=bob,
                    result="FAIL",
                    reason_code="APPROVAL_REJECTED",
                    source_id="approvals",
                ),
                m.CheckRecord(id="two-v1", principal=ALICE, **ok),
            ),
        )
    )
    mismatch = m.CODE_APPROVAL_SCOPE_MISMATCH
    for name, check_id, inp, want, code in (
        (
            "both match",
            "scoped-v1",
            check_input(ALICE, agent_a),
            Verdict.PASS,
            "REQUIREMENT_SATISFIED",
        ),
        ("other agent", "scoped-v1", check_input(ALICE, agent_b), Verdict.FAIL, mismatch),
        ("other principal", "scoped-v1", check_input(bob, agent_a), Verdict.FAIL, mismatch),
        ("no binding", "scoped-v1", check_input(ALICE), Verdict.FAIL, mismatch),
        ("no input at all", "scoped-v1", check_input(), Verdict.FAIL, mismatch),
        (
            "principal only, match",
            "principal-only-v1",
            check_input(ALICE),
            Verdict.PASS,
            "REQUIREMENT_SATISFIED",
        ),
        (
            "principal only, other",
            "principal-only-v1",
            check_input(bob, agent_a),
            Verdict.FAIL,
            mismatch,
        ),
        (
            "agent only, match",
            "agent-only-v1",
            check_input("", agent_a),
            Verdict.PASS,
            "REQUIREMENT_SATISFIED",
        ),
        ("agent only, none", "agent-only-v1", check_input(ALICE), Verdict.FAIL, mismatch),
        (
            "the record that applies is used",
            "two-v1",
            check_input(ALICE),
            Verdict.PASS,
            "REQUIREMENT_SATISFIED",
        ),
        (
            "the other record that applies is used",
            "two-v1",
            check_input(bob),
            Verdict.FAIL,
            "APPROVAL_REJECTED",
        ),
        (
            "no record applies to a third principal",
            "two-v1",
            check_input("https://idp.example/carol"),
            Verdict.FAIL,
            mismatch,
        ),
        (
            "not installed stays unknown",
            "absent-v1",
            check_input(ALICE, agent_a),
            Verdict.UNKNOWN,
            "UNSUPPORTED_REQUIREMENT",
        ),
    ):
        got = a.check_context(check_id, inp)
        assert (got.result, got.reason_code) == (want, code), name
    # a mismatch names no record of the approval
    assert a.check_context("scoped-v1", check_input(ALICE, agent_b)).source_ref == ""


def test_authorize_native(mem: Any) -> None:
    res = "https://invoices.example/invoices/1"

    def rule(
        principal: str, action: str, resource: str, effect: str, reason: str, *obl: m.Obligation
    ) -> m.PolicyRule:
        return m.PolicyRule(
            realm=REALM,
            principal=principal,
            action=action,
            resource=resource,
            effect=effect,
            reason=reason,
            obligations=obl,
        )

    a, _ = mem.new_adapter(
        lambda st: replace(
            st,
            policy=(
                rule(
                    ALICE,
                    "invoice.read",
                    res,
                    "ALLOW",
                    "r1",
                    m.Obligation(id="mask", attributes={"f": "iban"}),
                ),
                rule(ALICE, "invoice.read", "", "ALLOW", "r2"),
                rule(ALICE, "invoice.write", "", "ALLOW", "w1"),
                rule(ALICE, "invoice.write", res, "DENY", "w2"),
                rule(ALICE, "invoice.pay", "", "UNKNOWN", "p1"),
                rule(ALICE, "invoice.pay", "", "ALLOW", "p2"),
                rule("https://idp.example/bob", "invoice.read", "", "DENY", "b1"),
            ),
        )
    )

    def decide(p: Principal, o: OperationContext) -> Any:
        return a.authorize_native(p, o)

    alice = mem.alice()
    d = decide(alice, op(res, action="invoice.read"))
    assert (d.effect, d.reason) == (Effect.ALLOW, "r1")
    assert [(o.id, dict(o.attributes)) for o in d.obligations] == [("mask", {"f": "iban"})]
    d = decide(alice, op("https://invoices.example/invoices/2", action="invoice.read"))
    assert (d.effect, d.reason) == (Effect.ALLOW, "r2")
    d = decide(alice, op(res, action="invoice.write"))
    assert (d.effect, d.reason) == (Effect.DENY, "w2"), "a deny wins over an allow"
    d = decide(alice, op("https://invoices.example/invoices/2", action="invoice.write"))
    assert d.effect == Effect.ALLOW, "the deny names another resource"
    d = decide(alice, op(action="invoice.pay"))
    assert (d.effect, d.reason) == (Effect.UNKNOWN, "p1"), "an unknown wins over an allow"
    for name, p, o in (
        ("no rule for the action", alice, op(res, action="invoice.delete")),
        (
            "another principal",
            Principal(id="https://idp.example/carol", realm=alice.realm),
            op(res, action="invoice.read"),
        ),
        (
            "another realm",
            Principal(id=ALICE, realm=Realm(tenant_id="globex", environment_id=ENV)),
            op(res, action="invoice.read"),
        ),
        (
            "a denied principal",
            Principal(id="https://idp.example/bob", realm=alice.realm),
            op(res, action="invoice.read"),
        ),
        ("the empty principal", Principal(realm=alice.realm), op(res, action="invoice.read")),
        ("an operation with no data", alice, op()),
    ):
        assert not decide(p, o).permits(), name


def test_authorize_native_provenance(mem: Any) -> None:
    """A decision carries the source, the record, the time and the policy revision
    of the rule that decided, as the rule gives them, and names a source even when
    the rule names none or no rule applies. A decision time later than now plus
    the skew is not passed on."""
    decided, future, edge = mem.at(-2), mem.at(3600), mem.at(5)
    a, clk = mem.new_adapter(
        lambda st: replace(
            st,
            policy=(
                m.PolicyRule(
                    realm=REALM,
                    principal=ALICE,
                    action="invoice.read",
                    effect="ALLOW",
                    source_id="pdp-1",
                    source_ref="decision-8f0d",
                    decided_at=decided,
                    policy_revision="policy-2026-10-01",
                ),
                m.PolicyRule(realm=REALM, principal=ALICE, action="invoice.list", effect="DENY"),
                m.PolicyRule(
                    realm=REALM,
                    principal=ALICE,
                    action="invoice.pay",
                    effect="ALLOW",
                    source_id="pdp-1",
                    decided_at=future,
                ),
                m.PolicyRule(
                    realm=REALM,
                    principal=ALICE,
                    action="invoice.void",
                    effect="DENY",
                    source_id="pdp-1",
                    decided_at=future,
                ),
                m.PolicyRule(
                    realm=REALM,
                    principal=ALICE,
                    action="invoice.edge",
                    effect="ALLOW",
                    source_id="pdp-1",
                    decided_at=edge,
                ),
            ),
        )
    )

    def decide(action: str) -> Any:
        return a.authorize_native(mem.alice(), op(action=action))

    def at(sec: int) -> Any:
        return mem.EPOCH + timedelta(seconds=sec)

    d = decide("invoice.read")
    assert (d.effect, d.source_id, d.source_ref, d.decided_at, d.policy_revision) == (
        Effect.ALLOW,
        "pdp-1",
        "decision-8f0d",
        at(decided),
        "policy-2026-10-01",
    )
    d = decide("invoice.list")
    assert (d.effect, d.source_id, d.source_ref, d.decided_at, d.policy_revision) == (
        Effect.DENY,
        m.POLICY_SOURCE_ID,
        "",
        None,
        "",
    )
    d = decide("invoice.delete")
    assert (d.effect, d.source_id, d.decided_at) == (Effect.DENY, m.POLICY_SOURCE_ID, None)
    assert m.POLICY_SOURCE_ID, "the adapter's policy source has no id"
    for action in ("invoice.pay", "invoice.void"):
        with pytest.raises(DependencyUnavailable):
            decide(action)
    assert decide("invoice.edge").decided_at == at(edge)
    clk.advance(timedelta(hours=1))
    d = decide("invoice.pay")
    assert d.permits()
    assert d.decided_at == at(future)
