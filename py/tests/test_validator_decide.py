"""The decision table and the state machine. Port of go/validator/decide_test.go."""

from __future__ import annotations

import pytest

from hop_top_pact import validator
from hop_top_pact.core.enums import CheckStatus, Decision, TerminalReason
from hop_top_pact.core.types import CheckResult
from hop_top_pact.validator import _state

OK, SAT = "PASS", "REQUIREMENT_SATISFIED"


def results(*rs: str) -> list[CheckResult]:
    return [
        CheckResult(
            check_id="c",
            result=CheckStatus(rs[i]) if rs[i] in CheckStatus._value2member_map_ else rs[i],  # type: ignore[arg-type]
            reason_code=rs[i + 1],
            checked_at=0,
            source_observed_at=None,
            status_checked_at=None,
            evidence_ids=(),
            source_id="",
            source_ref=None,
        )
        for i in range(0, len(rs) - 1, 2)
    ]


DECIDE = [
    ("all pass", results(OK, SAT, OK, SAT), "COMPLETED", "ADMISSIBLE"),
    (
        "not applicable counts",
        results(OK, SAT, "NOT_APPLICABLE", "POLICY"),
        "COMPLETED",
        "ADMISSIBLE",
    ),
    (
        "unknown defers",
        results(OK, SAT, "UNKNOWN", "DEPENDENCY_UNAVAILABLE"),
        "COMPLETED",
        "DEFERRED",
    ),
    ("not evaluated defers", results(OK, SAT, "UNKNOWN", "NOT_EVALUATED"), "COMPLETED", "DEFERRED"),
    (
        "fail is inadmissible",
        results(OK, SAT, "FAIL", "INVALID_CLAIM"),
        "COMPLETED",
        "INADMISSIBLE",
    ),
    (
        "fail and unknown is inadmissible (11.4)",
        results("UNKNOWN", "DEPENDENCY_UNAVAILABLE", "FAIL", "MISSING_FIELD"),
        "COMPLETED",
        "INADMISSIBLE",
    ),
    (
        "selection input changed defers",
        results(OK, SAT, "FAIL", "SELECTION_INPUT_CHANGED"),
        "COMPLETED",
        "DEFERRED",
    ),
    (
        "requirements changed defers",
        results(OK, SAT, "FAIL", "REQUIREMENTS_CHANGED"),
        "COMPLETED",
        "DEFERRED",
    ),
    (
        "stale contract beside a demonstrated fail is inadmissible",
        results("FAIL", "SELECTION_INPUT_CHANGED", "FAIL", "SECURITY_HOLD"),
        "COMPLETED",
        "INADMISSIBLE",
    ),
    ("undefined result defers", results(OK, SAT, "MAYBE", SAT), "COMPLETED", "DEFERRED"),
    ("no results never admits", [], "COMPLETED", "DEFERRED"),
    ("cancelled is deferred (12.2)", results(OK, SAT), "CANCELLED", "DEFERRED"),
    (
        "expired is deferred even with a fail (12.2)",
        results("FAIL", "INVALID_CLAIM"),
        "EXPIRED",
        "DEFERRED",
    ),
]


@pytest.mark.parametrize(("name", "checks", "terminal", "want"), DECIDE, ids=[c[0] for c in DECIDE])
def test_decide(name: str, checks: list[CheckResult], terminal: str, want: str) -> None:
    # The decision table of draft 11.4 and 12.2.
    assert validator.decide(checks, TerminalReason(terminal)) == Decision(want)


ROWS = [
    ("CONTRACT_ISSUED", "PRESENTED", "EVALUATING"),
    ("CONTRACT_ISSUED", "CONTRACT_EXPIRED", "EXPIRED"),
    ("EVALUATING", "PASSED", "SEALED_ADMISSIBLE"),
    ("EVALUATING", "FAILED", "SEALED_INADMISSIBLE"),
    ("EVALUATING", "UNAVAILABLE", "SEALED_DEFERRED"),
    ("EVALUATING", "CANCELLED", "CANCELLED"),
    ("EVALUATING", "DEADLINE", "EXPIRED"),
]


@pytest.mark.parametrize(("frm", "on", "to"), ROWS)
def test_next_rows(frm: str, on: str, to: str) -> None:
    assert validator.next(validator.State(frm), validator.Event(on)) == validator.State(to)


def test_next_terminal_states_never_change() -> None:
    terminal = [
        validator.State.SEALED_ADMISSIBLE,
        validator.State.SEALED_INADMISSIBLE,
        validator.State.SEALED_DEFERRED,
        validator.State.CANCELLED,
        validator.State.EXPIRED,
    ]
    for s in terminal:
        assert s.terminal()
        for e in validator.Event:
            with pytest.raises(validator.ValidatorError) as ei:
                validator.next(s, e)
            assert ei.value.kind == "TRANSITION"
    with pytest.raises(validator.ValidatorError):
        validator.next(validator.State.CONTRACT_ISSUED, validator.Event.PASSED)
    assert not validator.State.EVALUATING.terminal()
    assert not validator.State.CONTRACT_ISSUED.terminal()


def test_machine_seals_once() -> None:
    m = _state.Machine()
    m.fire(validator.Event.PRESENTED)
    assert m.fire(validator.Event.CANCELLED) == validator.State.CANCELLED
    with pytest.raises(validator.ValidatorError):
        m.fire(validator.Event.PASSED)
    assert m.state == validator.State.CANCELLED


@pytest.mark.parametrize(
    ("d", "t", "want"),
    [
        ("ADMISSIBLE", "COMPLETED", "PASSED"),
        ("INADMISSIBLE", "COMPLETED", "FAILED"),
        ("DEFERRED", "COMPLETED", "UNAVAILABLE"),
        ("DEFERRED", "CANCELLED", "CANCELLED"),
        ("DEFERRED", "EXPIRED", "DEADLINE"),
    ],
)
def test_seal_event(d: str, t: str, want: str) -> None:
    assert _state.seal_event(Decision(d), TerminalReason(t)) == validator.Event(want)


def test_check_identifiers() -> None:
    # The identifiers of the receipt table of draft 12.1, in order.
    assert [
        validator.CHECK_NATIVE_AUTHENTICATION,
        validator.CHECK_AGENT_HOLDER_BINDING,
        validator.CHECK_CONTRACT_VALIDITY,
        validator.CHECK_NONCE,
        validator.CHECK_OPERATION_BINDING,
        validator.CHECK_INTENT_BINDING,
        validator.CHECK_PROFILE_VALIDITY,
        validator.CHECK_EVIDENCE_VALIDITY,
        validator.CHECK_REPUTATION_CONTEXT,
        validator.CHECK_SECURITY_HOLD,
        validator.CHECK_ACTIVE_POLICY,
        validator.CHECK_RECEIPT_STORE,
    ] == [
        "native-authentication",
        "agent-holder-binding",
        "contract-validity",
        "nonce",
        "operation-binding",
        "intent-binding",
        "profile-validity",
        "evidence-validity",
        "reputation-context",
        "security-hold",
        "active-policy",
        "receipt-store",
    ]
    assert validator.CHECK_NATIVE_PRINCIPAL_BINDING == "native-principal-binding-v1"
    assert validator.CHECK_SELECTION_CONSISTENCY == "selection-consistency-v1"
