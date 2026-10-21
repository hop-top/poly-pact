"""The value types of the adapter contract.

Port of go/adapter/types_test.go. The field lists are written from the
contract of the section 17.1 functions and the frozen adapter contract;
adding, dropping or retyping a field is a contract change and must change
this table. Go's zero values are Python defaults: an absent time is None.
"""

from __future__ import annotations

import dataclasses
from enum import StrEnum
from typing import cast

import pytest

from hop_top_pact import adapter
from hop_top_pact.adapter import (
    BindingStatus,
    Decision,
    DenialReason,
    Effect,
    Obligation,
    Verdict,
)
from hop_top_pact.core.enums import CheckStatus


def fields(cls: type) -> list[str]:
    """'name: annotation' for every field of dataclass cls, in order."""
    return [f"{f.name}: {f.type}" for f in dataclasses.fields(cls)]


STRUCTS: list[tuple[type, list[str]]] = [
    (adapter.Realm, ["tenant_id: str", "environment_id: str"]),
    (
        adapter.Principal,
        [
            "id: str",
            "realm: Realm",
            "workload: Workload",
            "mechanism: Mechanism",
            "authenticated_at: datetime | None",
            "attributes: Mapping[str, JSONValue]",
        ],
    ),
    (
        adapter.AgentBinding,
        [
            "agent_id: str",
            "operator_id: str",
            "holder_jkt: str",
            "status: BindingStatus",
            "observed_at: datetime | None",
            "status_checked_at: datetime | None",
            "source_id: str",
            "source_ref: str",
            "enrolled_elsewhere: bool",
        ],
    ),
    (
        adapter.NativeClaim,
        [
            "value: JSONValue",
            "observed_at: datetime | None",
            "status_checked_at: datetime | None",
            "source_id: str",
            "source_ref: str",
        ],
    ),
    (
        adapter.CheckOutcome,
        [
            "result: Verdict",
            "reason_code: str",
            "source_id: str",
            "source_ref: str",
            "observed_at: datetime | None",
        ],
    ),
    (
        adapter.CheckInput,
        [
            "principal: Principal",
            "binding: AgentBinding | None",
            "intent: Intent | None",
            "operation: OperationContext",
            "evidence_refs: tuple[str, ...]",
        ],
    ),
    (
        adapter.ClaimContext,
        [
            "principal: Principal",
            "intent: Intent | None",
            "operation: OperationContext | None",
        ],
    ),
    (
        adapter.Decision,
        [
            "effect: Effect",
            "obligations: tuple[Obligation, ...]",
            "reason: str",
            "source_id: str",
            "source_ref: str",
            "decided_at: datetime | None",
            "policy_revision: str",
        ],
    ),
    (adapter.Obligation, ["id: str", "attributes: Mapping[str, JSONValue]"]),
    (
        adapter.Observation,
        [
            "event_id: str",
            "event_kind: EventKind",
            "context: ReputationContext",
            "task_id: str",
            "operation_id: str",
            "admission_receipt_id: str | None",
            "observed_at: datetime | None",
            "result: OutcomeResult",
            "dimension: Dimension",
            "severity: Severity",
            "evidence_refs: tuple[str, ...]",
            "attribution: Attribution",
            "supersedes: tuple[str, ...]",
            "details: str",
        ],
    ),
    (adapter.Signed, ["jws: str"]),
    (adapter.NoVisibility, ["reason: str"]),
    (adapter.Descriptor, ["protocol: str", "version: str", "mapping_revision: str"]),
]


@pytest.mark.parametrize(("cls", "want"), STRUCTS, ids=[c.__name__ for c, _ in STRUCTS])
def test_struct_fields(cls: type, want: list[str]) -> None:
    assert fields(cls) == want
    params = cls.__dataclass_params__  # type: ignore[attr-defined]
    assert params.frozen, f"{cls.__name__} is not frozen"


def test_native_denial_reason() -> None:
    """NativeDenial is an exception, not a dataclass; its one field is reason."""
    d = adapter.NativeDenial(DenialReason.NO_CREDENTIAL)
    assert d.reason == DenialReason.NO_CREDENTIAL


def test_zero_values_fail_closed() -> None:
    """A value built without arguments establishes nothing: an unknown binding,
    an unknown verdict, an effect that does not permit, no times."""
    b = adapter.AgentBinding()
    assert b.status == BindingStatus.UNKNOWN
    assert b.observed_at is None
    assert b.status_checked_at is None
    assert not b.enrolled_elsewhere
    assert adapter.CheckOutcome().result == Verdict.UNKNOWN
    assert not Decision().permits()
    assert adapter.NativeClaim().observed_at is None


def test_decision_has_no_override() -> None:
    """A denial is final by construction: besides the effect, the obligations and
    the reason, a decision carries only its provenance."""
    allowed = {
        "effect",
        "obligations",
        "reason",
        "source_id",
        "source_ref",
        "decided_at",
        "policy_revision",
    }
    for f in dataclasses.fields(Decision):
        assert f.name in allowed, f"Decision has unexpected field {f.name}"


ENUMS: list[tuple[type[StrEnum], dict[str, StrEnum], list[str]]] = [
    (
        BindingStatus,
        {
            "ACTIVE": BindingStatus.ACTIVE,
            "REVOKED": BindingStatus.REVOKED,
            "COMPROMISED": BindingStatus.COMPROMISED,
            "UNKNOWN": BindingStatus.UNKNOWN,
        },
        ["", "active", "SUSPENDED"],
    ),
    (
        Verdict,
        {"PASS": Verdict.PASS, "FAIL": Verdict.FAIL, "UNKNOWN": Verdict.UNKNOWN},
        ["", "pass", "NOT_APPLICABLE"],
    ),
    (
        Effect,
        {"ALLOW": Effect.ALLOW, "DENY": Effect.DENY, "UNKNOWN": Effect.UNKNOWN},
        ["", "allow", "PERMIT"],
    ),
    (
        DenialReason,
        {
            "NO_CREDENTIAL": DenialReason.NO_CREDENTIAL,
            "CREDENTIAL_REJECTED": DenialReason.CREDENTIAL_REJECTED,
        },
        ["", "user alice not found"],
    ),
]


@pytest.mark.parametrize(("cls", "valid", "bogus"), ENUMS, ids=[e[0].__name__ for e in ENUMS])
def test_enums(cls: type[StrEnum], valid: dict[str, StrEnum], bogus: list[str]) -> None:
    assert len(cls) == len(valid)
    for lit, member in valid.items():
        assert member.value == lit
        assert cls.is_valid(lit), lit  # type: ignore[attr-defined]
    for b in bogus:
        assert not cls.is_valid(b), b  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    ("verdict", "want"),
    [
        (Verdict.PASS, CheckStatus.PASS),
        (Verdict.FAIL, CheckStatus.FAIL),
        (Verdict.UNKNOWN, CheckStatus.UNKNOWN),
        # A check that reported nothing valid established nothing.
        ("", CheckStatus.UNKNOWN),
        ("NOT_APPLICABLE", CheckStatus.UNKNOWN),
    ],
)
def test_verdict_matches_draft_and_core(verdict: str, want: CheckStatus) -> None:
    """17.1 names exactly PASS, FAIL and UNKNOWN for check_context, and each maps
    to the CheckResult status of the same name."""
    assert Verdict.check_status(cast(Verdict, verdict)) == want


@pytest.mark.parametrize(
    ("d", "want"),
    [
        (Decision(effect=Effect.ALLOW), True),
        (Decision(effect=Effect.ALLOW, obligations=(Obligation(id="redact"),)), True),
        (Decision(effect=Effect.DENY), False),
        (Decision(effect=Effect.DENY, reason="allow"), False),
        (Decision(effect=Effect.UNKNOWN), False),
        (Decision(), False),
        (Decision(effect=cast(Effect, "allow")), False),
    ],
)
def test_decision_permits(d: Decision, want: bool) -> None:
    """Only an explicit allow permits; a deny, an unknown, the zero value and a
    mis-spelled effect fail closed."""
    assert d.permits() is want
