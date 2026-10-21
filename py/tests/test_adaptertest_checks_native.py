"""The checks of read_native_claim, check_context and authorize_native.

Port of go/adapter/adaptertest/checks_native_test.go. Go's zero time is None,
a json.RawMessage expectation is a parsed value with ABSENT for an absent
member, and an empty Go binding or intent of a call is None.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import timedelta
from typing import Any

from hop_top_pact.adapter import (
    AgentBinding,
    BindingStatus,
    CheckInput,
    CheckOutcome,
    ClaimContext,
    Decision,
    DependencyUnavailable,
    Effect,
    NativeClaim,
    Obligation,
    UnsupportedRequirement,
    Verdict,
)
from hop_top_pact.adapter.adaptertest import (
    BindingJSON,
    ExpectClaim,
    ExpectDecision,
    ObligationJSON,
)
from hop_top_pact.adapter.adaptertest.compare import SKEW, unix
from hop_top_pact.core.types import Intent

SECOND = timedelta(seconds=1)


def test_claim_checks(at: Any) -> None:
    good: NativeClaim = at.good_claim()
    observed = unix(at.NOW - timedelta(hours=1))
    checked = unix(at.NOW - timedelta(seconds=30))
    full = ExpectClaim(
        value=("approver",),
        observed_at=observed,
        status_checked_at=checked,
        source_id="directory-1",
        source_ref="entry-17",
    )
    case, fake = at.claim_case, at.claim_fake

    at.run_rows(
        [
            ("claim", fake(good, None), case("claim", claim=full), ()),
            (
                "claim but errors",
                fake(None, UnsupportedRequirement()),
                case("claim", claim=full),
                ("want a claim",),
            ),
            (
                "not a claim",
                fake(("approver",), None),
                case("claim", claim=full),
                ("want a NativeClaim",),
            ),
            (
                "value in another order",
                fake(replace(good, value=("a", "b")), None),
                case("claim", claim=ExpectClaim(value=("b", "a"))),
                ("claim value is",),
            ),
            (
                "object members in another order",
                fake(replace(good, value={"b": 1, "a": 2}), None),
                case("claim", claim=ExpectClaim(value={"b": 1, "a": 2})),
                (),
            ),
            (
                "null value",
                fake(replace(good, value=None), None),
                case("claim", claim=ExpectClaim(value=None)),
                (),
            ),
            (
                "value that does not encode",
                fake(replace(good, value=object()), None),  # type: ignore[arg-type]
                case("claim", claim=ExpectClaim(value=None)),
                ("does not encode",),
            ),
            (
                "restamped observation",
                fake(replace(good, observed_at=at.NOW), None),
                case("claim", claim=full),
                ("observed_at is", "not the time of the read"),
            ),
            (
                "restamped status check",
                fake(replace(good, status_checked_at=at.NOW), None),
                case("claim", claim=full),
                ("status_checked_at is",),
            ),
            (
                "observation supplied where the source gives none",
                fake(replace(good, observed_at=at.NOW), None),
                case("claim", claim=ExpectClaim(observed_at=None)),
                ("want the zero time",),
            ),
            (
                "zero time where the source gives one",
                fake(replace(good, observed_at=None), None),
                case("claim", claim=full),
                ("observed_at is the zero time",),
            ),
            (
                "zero times as the source gives none",
                fake(replace(good, observed_at=None, status_checked_at=None), None),
                case("claim", claim=ExpectClaim(observed_at=None, status_checked_at=None)),
                (),
            ),
            (
                "observation in the future",
                fake(replace(good, observed_at=at.NOW + timedelta(hours=1)), None),
                case("claim", claim=ExpectClaim()),
                ("observed_at is", "later than the allowed"),
            ),
            (
                "observation at the skew edge",
                fake(replace(good, observed_at=at.NOW + SKEW), None),
                case("claim", claim=ExpectClaim()),
                (),
            ),
            (
                "observation past the skew",
                fake(replace(good, observed_at=at.NOW + SKEW + SECOND), None),
                case("claim", claim=ExpectClaim()),
                ("later than the allowed",),
            ),
            # Draft A.2: no status-check time may be later than now plus the skew.
            (
                "status check past the skew",
                fake(replace(good, status_checked_at=at.NOW + SKEW + SECOND), None),
                case("claim", claim=ExpectClaim()),
                ("status_checked_at is", "later than the allowed"),
            ),
            (
                "status check at the skew edge",
                fake(replace(good, status_checked_at=at.NOW + SKEW), None),
                case("claim", claim=ExpectClaim()),
                (),
            ),
            (
                "status check at now",
                fake(replace(good, status_checked_at=at.NOW), None),
                case("claim", claim=ExpectClaim()),
                (),
            ),
            (
                "an expected time that is not an integer",
                fake(good, None),
                case("claim", claim=ExpectClaim(observed_at="1792076400")),
                ("is not an integer",),
            ),
            (
                "no source",
                fake(replace(good, source_id=""), None),
                case("claim", claim=ExpectClaim()),
                ("names no source",),
            ),
            (
                "wrong source",
                fake(good, None),
                case("claim", claim=ExpectClaim(source_id="other")),
                ("source id is",),
            ),
            (
                "wrong source ref",
                fake(good, None),
                case("claim", claim=ExpectClaim(source_ref="other")),
                ("source ref is",),
            ),
            (
                "error",
                fake(None, at.wrap("x", UnsupportedRequirement())),
                case("error", reason_code="UNSUPPORTED_REQUIREMENT"),
                (),
            ),
            ("error expected, claim returned", fake(good, None), case("error"), ("want an error",)),
        ]
    )

    # The claim context of draft 17.1 is the principal, the declared intent
    # and the actual operation of the case, passed as they are.
    got: list[tuple[str, ClaimContext]] = []

    def claim(path: str, c: ClaimContext) -> NativeClaim:
        got.append((path, c))
        return good

    op = at.good_op()
    intent = Intent(intent_id="i-1", purpose_id="p-1", description="", task_id="task-7")
    c = at.claim_case("claim")
    c = replace(c, call=replace(c.call, intent=intent, operation=op))
    at.want_clean(at.run_fake(at.FakeAdapter(claim=claim), c))
    path, cc = got[-1]
    assert path == "/attributes/environment/roles"
    assert (cc.principal.id, cc.principal.realm, cc.principal.workload) == (
        at.good_principal().id,
        at.ACME,
        "w-1",
    )
    assert cc.intent == intent
    assert cc.operation == op

    # a case without intent or operation passes neither
    at.want_clean(at.run_fake(at.FakeAdapter(claim=claim), at.claim_case("claim")))
    _, cc = got[-1]
    assert cc.principal.id == at.good_principal().id
    assert (cc.intent, cc.operation) == (None, None)


def test_check_checks(at: Any) -> None:
    unknown = CheckOutcome(result=Verdict.UNKNOWN, reason_code="UNSUPPORTED_REQUIREMENT")
    passed = CheckOutcome(
        result=Verdict.PASS,
        reason_code="REQUIREMENT_SATISFIED",
        source_id="approvals",
        observed_at=at.NOW - timedelta(minutes=1),
    )
    case, fake = at.check_case, at.check_fake

    def raising(check_id: str, inp: CheckInput) -> CheckOutcome:
        raise DependencyUnavailable()

    at.run_rows(
        [
            (
                "unknown",
                fake(unknown),
                case("x", "UNKNOWN", reason_code="UNSUPPORTED_REQUIREMENT"),
                (),
            ),
            ("unknown but pass", fake(passed), case("x", "UNKNOWN"), ("never PASS",)),
            ("pass", fake(passed), case("x", "PASS", reason_code="REQUIREMENT_SATISFIED"), ()),
            (
                "pass expected, unknown returned",
                fake(unknown),
                case("x", "PASS"),
                ("returned UNKNOWN",),
            ),
            (
                "fail",
                fake(CheckOutcome(result=Verdict.FAIL, reason_code="APPROVAL_REJECTED")),
                case("x", "FAIL", reason_code="APPROVAL_REJECTED"),
                (),
            ),
            (
                "wrong reason",
                fake(unknown),
                case("x", "UNKNOWN", reason_code="DEPENDENCY_UNAVAILABLE"),
                ("reason code is",),
            ),
            (
                "no reason",
                fake(CheckOutcome(result=Verdict.UNKNOWN)),
                case("x", "UNKNOWN"),
                ("no reason code",),
            ),
            (
                "undefined verdict",
                fake(CheckOutcome(result="OK", reason_code="X")),  # type: ignore[arg-type]
                case("x", "UNKNOWN"),
                ("not PASS, FAIL or UNKNOWN",),
            ),
            (
                "observation in the future",
                fake(
                    CheckOutcome(
                        result=Verdict.PASS,
                        reason_code="X",
                        observed_at=at.NOW + timedelta(hours=1),
                    )
                ),
                case("x", "PASS"),
                ("check observed_at",),
            ),
            (
                "raises",
                at.FakeAdapter(check=raising),
                case("x", "UNKNOWN"),
                ("a check raises nothing",),
            ),
            ("not an outcome", fake("UNKNOWN"), case("x", "UNKNOWN"), ("want a CheckOutcome",)),
        ]
    )

    got: list[tuple[str, CheckInput]] = []

    def check(check_id: str, inp: CheckInput) -> CheckOutcome:
        got.append((check_id, inp))
        return unknown

    # arguments reach the adapter
    c = at.check_case("", "UNKNOWN")
    principal = replace(c.call.principal, attributes={"device_id": "dev-1"})
    c = replace(
        c,
        call=replace(
            c.call,
            intent=Intent(intent_id="i-1", purpose_id="", description="", task_id=""),
            evidence_refs=("ref-1",),
            principal=principal,
            binding=BindingJSON(
                agent_id="https://agents.example/a",
                operator_id="https://ops.example/o",
                holder_jkt="thumb-1",
            ),
        ),
    )
    at.want_clean(at.run_fake(at.FakeAdapter(check=check), c))
    check_id, inp = got[-1]
    assert check_id == ""
    assert inp.intent is not None
    assert inp.intent.intent_id == "i-1"
    assert inp.evidence_refs == ("ref-1",)
    p = inp.principal
    assert (p.id, p.realm, p.workload) == (at.good_principal().id, at.ACME, "w-1")
    assert p.attributes["device_id"] == "dev-1", "the case's principal with its attributes"
    assert inp.operation.operation_id == "op-1"
    assert inp.binding == AgentBinding(
        agent_id="https://agents.example/a",
        operator_id="https://ops.example/o",
        holder_jkt="thumb-1",
        status=BindingStatus.ACTIVE,
    ), "a binding without status is ACTIVE"

    # a stated status reaches the adapter
    c = at.check_case("x", "UNKNOWN")
    c = replace(
        c,
        call=replace(
            c.call, binding=BindingJSON(agent_id="https://agents.example/a", status="REVOKED")
        ),
    )
    at.want_clean(at.run_fake(at.FakeAdapter(check=check), c))
    assert got[-1][1].binding is not None
    assert got[-1][1].binding.status == BindingStatus.REVOKED

    # a case without a binding passes none: the caller established no agent
    at.want_clean(at.run_fake(at.FakeAdapter(check=check), at.check_case("x", "UNKNOWN")))
    assert got[-1][1].binding is None


def test_authorize_checks(at: Any) -> None:
    def decision(e: str, **kw: Any) -> Decision:
        """A decision with effect e that names its source, as every decision must."""
        return Decision(effect=e, source_id="policy-1", **kw)  # type: ignore[arg-type]

    deny = decision(Effect.DENY, reason="policy 7")
    allow = decision(Effect.ALLOW)
    unknown = decision(Effect.UNKNOWN)
    audit = Obligation(id="audit", attributes={"level": "high"})
    want_audit = (ObligationJSON(id="audit", attributes={"level": "high"}),)
    case, fake = at.authz_case, at.authz_fake

    def obligations(o: tuple[ObligationJSON, ...]) -> ExpectDecision:
        return ExpectDecision(obligations=o)

    at.run_rows(
        [
            ("deny", fake(deny, None), case("DENY"), ()),
            (
                "deny rewritten to allow",
                fake(allow, None),
                case("DENY"),
                ("cannot rewrite a denial",),
            ),
            (
                "deny rewritten to unknown",
                fake(unknown, None),
                case("DENY"),
                ("decision effect is UNKNOWN",),
            ),
            (
                "deny but errors",
                fake(None, DependencyUnavailable()),
                case("DENY"),
                ("want effect DENY",),
            ),
            ("allow", fake(allow, None), case("ALLOW"), ()),
            ("unknown", fake(unknown, None), case("UNKNOWN"), ()),
            (
                "obligations kept",
                fake(decision(Effect.DENY, obligations=(audit,)), None),
                case("DENY", decision=obligations(want_audit)),
                (),
            ),
            (
                "obligations dropped",
                fake(deny, None),
                case("DENY", decision=obligations(want_audit)),
                ("obligations are",),
            ),
            (
                "obligation attributes changed",
                fake(
                    decision(
                        Effect.DENY,
                        obligations=(Obligation(id="audit", attributes={"level": "low"}),),
                    ),
                    None,
                ),
                case("DENY", decision=obligations(want_audit)),
                ("obligations are",),
            ),
            (
                "obligation added",
                fake(decision(Effect.DENY, obligations=(audit,)), None),
                case("DENY", decision=obligations(())),
                ("obligations are",),
            ),
            (
                "no and empty attributes are the same",
                fake(decision(Effect.DENY, obligations=(Obligation(id="x", attributes={}),)), None),
                case("DENY", decision=obligations((ObligationJSON(id="x"),))),
                (),
            ),
            (
                "undefined effect",
                fake(decision("PERMIT"), None),
                case("not_allowed"),
                ("not ALLOW, DENY or UNKNOWN",),
            ),
            ("not a decision", fake("ALLOW", None), case("ALLOW"), ("want a Decision",)),
            ("not allowed by a denial", fake(deny, None), case("not_allowed"), ()),
            ("not allowed by an unknown", fake(unknown, None), case("not_allowed"), ()),
            ("not allowed by an error", fake(None, at.Wrapped("x")), case("not_allowed"), ()),
            (
                "not allowed by an exception that is not a PactError",
                fake(None, RuntimeError("x")),
                case("not_allowed"),
                ("raised RuntimeError",),
            ),
            (
                "not allowed but allowed",
                fake(allow, None),
                case("not_allowed"),
                ("anything but ALLOW",),
            ),
            (
                "error",
                fake(None, DependencyUnavailable()),
                case("error", reason_code="DEPENDENCY_UNAVAILABLE"),
                (),
            ),
            (
                "error expected, decision returned",
                fake(deny, None),
                case("error"),
                ("want an error",),
            ),
        ]
    )


def test_decision_provenance(at: Any) -> None:
    """Every decision names the policy source that decided and a decision time that
    is not in the future beyond the skew, whatever the outcome the case expects; a
    case may pin the source, the record, the time and the policy revision the
    native source gave."""
    decided_at = at.NOW - 2 * SECOND
    full = Decision(
        effect=Effect.ALLOW,
        source_id="pdp-1",
        source_ref="decision-8f0d",
        decided_at=decided_at,
        policy_revision="policy-2026-10-01",
    )

    def pinned(**kw: Any) -> ExpectDecision:
        return ExpectDecision(**kw)

    every = pinned(
        source_id="pdp-1",
        source_ref="decision-8f0d",
        decided_at=unix(decided_at),
        policy_revision="policy-2026-10-01",
    )
    case, fake = at.authz_case, at.authz_fake

    at.run_rows(
        [
            (
                "provenance as the source gave it",
                fake(full, None),
                case("ALLOW", decision=every),
                (),
            ),
            (
                "only a source",
                fake(Decision(effect=Effect.DENY, source_id="pdp-1"), None),
                case("DENY"),
                (),
            ),
            (
                "no source",
                fake(replace(full, source_id=""), None),
                case("ALLOW"),
                ("decision names no source",),
            ),
            (
                "no source on a denial",
                fake(Decision(effect=Effect.DENY), None),
                case("DENY"),
                ("decision names no source",),
            ),
            (
                "no source where only not allowed is required",
                fake(Decision(effect=Effect.DENY), None),
                case("not_allowed"),
                ("decision names no source",),
            ),
            (
                "no source on an unknown",
                fake(Decision(effect=Effect.UNKNOWN), None),
                case("UNKNOWN"),
                ("decision names no source",),
            ),
            (
                "an error carries no decision",
                fake(None, DependencyUnavailable()),
                case("not_allowed"),
                (),
            ),
            (
                "decided in the future",
                fake(replace(full, decided_at=at.NOW + timedelta(hours=1)), None),
                case("ALLOW"),
                ("decided_at is", "later than the allowed"),
            ),
            (
                "decided in the future, not allowed",
                fake(
                    Decision(
                        effect=Effect.DENY,
                        source_id="pdp-1",
                        decided_at=at.NOW + timedelta(hours=1),
                    ),
                    None,
                ),
                case("not_allowed"),
                ("decided_at is", "later than the allowed"),
            ),
            (
                "decided at the skew edge",
                fake(replace(full, decided_at=at.NOW + SKEW), None),
                case("ALLOW"),
                (),
            ),
            (
                "decided past the skew",
                fake(replace(full, decided_at=at.NOW + SKEW + SECOND), None),
                case("ALLOW"),
                ("later than the allowed",),
            ),
            ("no decision time", fake(replace(full, decided_at=None), None), case("ALLOW"), ()),
            (
                "another source",
                fake(replace(full, source_id="pdp-2"), None),
                case("ALLOW", decision=every),
                ("decision source id is 'pdp-2', want 'pdp-1'",),
            ),
            (
                "record dropped",
                fake(replace(full, source_ref=""), None),
                case("ALLOW", decision=every),
                ("decision source ref is '', want 'decision-8f0d'",),
            ),
            (
                "revision rewritten",
                fake(replace(full, policy_revision="policy-2026-09-01"), None),
                case("ALLOW", decision=every),
                ("policy revision is 'policy-2026-09-01', want 'policy-2026-10-01'",),
            ),
            (
                "revision dropped",
                fake(replace(full, policy_revision=""), None),
                case("ALLOW", decision=every),
                ("policy revision is",),
            ),
            (
                "decision restamped",
                fake(replace(full, decided_at=at.NOW), None),
                case("ALLOW", decision=every),
                ("decided_at is", "not the time of the read"),
            ),
            (
                "decision time dropped",
                fake(replace(full, decided_at=None), None),
                case("ALLOW", decision=every),
                ("decided_at is the zero time",),
            ),
            (
                "decision time supplied where the source gives none",
                fake(full, None),
                case("ALLOW", decision=pinned(decided_at=None)),
                ("want the zero time",),
            ),
            (
                "record supplied where the source keeps none",
                fake(full, None),
                case("ALLOW", decision=pinned(source_ref=None)),
                ("decision source ref is 'decision-8f0d', want none",),
            ),
            (
                "no record where the source keeps none",
                fake(replace(full, source_ref=""), None),
                case("ALLOW", decision=pinned(source_ref=None)),
                (),
            ),
            (
                "an empty record is not checked",
                fake(full, None),
                case("ALLOW", decision=pinned(source_ref="")),
                (),
            ),
            (
                "a record that is not a string",
                fake(full, None),
                case("ALLOW", decision=pinned(source_ref=7)),
                ("source_ref: expected value 7 is not a string or null",),
            ),
            (
                "provenance is checked with the effect",
                fake(replace(full, source_id="pdp-2"), None),
                case("ALLOW", decision=pinned(source_id="pdp-1", obligations=())),
                ("decision source id is",),
            ),
        ]
    )
