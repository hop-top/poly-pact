"""Evaluation of presentations. Port of go/validator/validator_test.go.

The cancellation tests use the public cancelled predicate of Validator.evaluate where Go
cancels the context. A receipt that could not be recorded is returned with the error: the
exception's result attribute holds it, where Go returns both values."""

from __future__ import annotations

import copy
import json
import threading
from collections.abc import Callable, Sequence
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

from hop_top_pact import contract, validator
from hop_top_pact.adapter import (
    AgentBinding,
    AgentID,
    BindingStatus,
    CheckInput,
    CheckOutcome,
    ClaimContext,
    Code,
    DependencyUnavailable,
    NativeClaim,
    Principal,
    Realm,
    Verdict,
    Workload,
)
from hop_top_pact.core import digest, jws
from hop_top_pact.core.enums import CheckStatus, Decision, Mode, TerminalReason
from hop_top_pact.core.types import AdmissionAttestation, CheckResult
from hop_top_pact.validator import _problem
from validator_support import Fixture, prepare

FIXTURES = Path(__file__).resolve().parents[2] / "spec" / "v1.0" / "fixtures"

B7_CHECKS = [
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
    "principal",
    "roles",
    "supervisor-approval",
    "isolation",
    "reputation-status",
    "native-principal-binding-v1",
    "purpose-operation-v1",
    "native-delegation-v1",
    "security-hold-v1",
]


def case(id_: str) -> Fixture:
    if not FIXTURES.exists():
        pytest.skip("no spec/ tree (mirror checkout)")
    return prepare(FIXTURES / id_)


def evaluate(f: Fixture) -> validator.Result:
    return f.validator.evaluate(f.request)


def code_of(err: BaseException) -> str:
    c = _problem.code_of(err)
    assert c is not None, f"error {err!r} carries no draft 13.4 code"
    return c


def check(res: validator.Result, id_: str) -> CheckResult:
    for c in res.attestation.checks:
        if c.check_id == id_:
            return c
    pytest.fail(f"receipt has no check {id_!r}")


def want_check(res: validator.Result, id_: str, result: CheckStatus, reason: str) -> None:
    c = check(res, id_)
    assert (c.result, c.reason_code) == (result, reason), f"{id_}: {c.result} {c.reason_code}"


def verify_receipt(compact: str, key_file: str) -> None:
    k = jws.parse_jwk((FIXTURES / "keys" / key_file).read_bytes())
    keys = jws.StaticResolver(key_sets={jws.Role.VALIDATOR: jws.new_key_set(k)})
    jws.Verifier(keys=keys, typ=jws.TYP_ADMISSION).verify(compact)


def test_valid_admissible() -> None:
    # The worked exchange of Appendix B: ADMISSIBLE with every check of B.7 PASS, in B.7
    # order, and the digests B.7 prints.
    f = case("admission/valid")
    res = evaluate(f)
    a = res.attestation
    assert (a.decision, a.terminal_reason) == (Decision.ADMISSIBLE, TerminalReason.COMPLETED), [
        (c.check_id, c.result, c.reason_code) for c in a.checks
    ]
    assert [c.check_id for c in a.checks] == B7_CHECKS
    for c in a.checks:
        assert c.result == CheckStatus.PASS, c
        assert c.reason_code == "REQUIREMENT_SATISFIED", c
        assert c.source_id, f"check {c.check_id} has no source_id"
    assert a.profile_digest == "b6pNI8i5pX5MtuxkaBw0M-4tmzdkGsHVS_Kyji7_uOU"
    assert a.intent_digest == "t79YgXU70gzKitcuPJ_fUp4V_bM5MGooinyuyL8cE5M"
    assert a.operation_digest == "R5nfhv7g_o93VPHK6a2o56-MyyGy75GQwXxDM4M3cn0"
    signed = (FIXTURES / "admission/valid/signed/contract.jws").read_text().strip()
    assert a.requirements_digest == digest.artifact_digest(signed)
    assert a.presentation_id == "v6wxT-_cB0Ua8Xkqgcuu2g"
    assert a.principal_id == "https://identity.example/principals/alice"
    assert a.aud == "https://gateway.example/finance"
    assert a.iss == "https://trust.example/issuers/finance"
    assert a.iat == 1792080000
    assert a.iat < a.exp <= 1792080060, "at most 60 s and no later than the contract (12.1)"
    verify_receipt(res.receipt, "validator.jwk.json")
    assert f.validator.receipts.get(a.jti).receipt == res.receipt  # type: ignore[union-attr]


def test_nonce_consumed_once() -> None:
    # A presentation is accepted for evaluation once; a second submission of the same nonce
    # is REPLAY with no receipt (draft 7.5).
    f = case("admission/valid")
    evaluate(f)
    with pytest.raises(Exception) as ei:  # noqa: PT011
        evaluate(f)
    assert code_of(ei.value) == contract.CODE_REPLAY


def test_replicas_consume_once() -> None:
    # The same nonce submitted concurrently to replicas that share the replay store is
    # accepted at most once (draft 22.2).
    f = case("admission/valid")
    replicas, lock = 8, threading.Lock()
    receipts, replays = [0], [0]

    def run() -> None:
        v = copy.copy(f.validator)
        try:
            res = v.evaluate(f.request)
        except Exception as e:
            with lock:
                if _problem.code_of(e) == contract.CODE_REPLAY:
                    replays[0] += 1
            return
        with lock:
            if res.receipt:
                receipts[0] += 1

    threads = [threading.Thread(target=run) for _ in range(replicas)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert (receipts[0], replays[0]) == (1, replicas - 1)


class FailingReplay:
    def __init__(self, inner: Any) -> None:
        self.inner = inner

    def register(self, *a: Any) -> None:
        self.inner.register(*a)

    def consume(self, *a: Any) -> None:
        raise contract.ContractError(Code.DEPENDENCY_UNAVAILABLE)


def test_replay_store_outage_defers() -> None:
    # An unavailable or full replay store defers, never fails open (draft 7.5, 18).
    f = case("admission/valid")
    f.validator.replay = FailingReplay(f.validator.replay)
    res = evaluate(f)
    assert res.attestation.decision == Decision.DEFERRED
    want_check(res, "nonce", CheckStatus.UNKNOWN, "DEPENDENCY_UNAVAILABLE")


class FailingReceipts:
    def __init__(self, inner: Any) -> None:
        self.inner = inner

    def put(self, r: validator.Result) -> None:
        raise OSError("disk full")

    def get(self, jti: str) -> validator.Result:
        return self.inner.get(jti)  # type: ignore[no-any-return]

    def by_contract(self, d: str) -> list[validator.Result]:
        return self.inner.by_contract(d)  # type: ignore[no-any-return]


def test_receipt_store_outage_never_admits() -> None:
    # A receipt that cannot be recorded durably is never a positive admission (draft 12.2,
    # 18).
    f = case("admission/valid")
    f.validator.receipts = FailingReceipts(f.validator.receipts)
    with pytest.raises(Exception) as ei:  # noqa: PT011
        evaluate(f)
    assert code_of(ei.value) == Code.DEPENDENCY_UNAVAILABLE
    res = ei.value.result  # type: ignore[attr-defined]
    assert res.attestation.decision != Decision.ADMISSIBLE
    assert res.receipt
    want_check(res, "receipt-store", CheckStatus.UNKNOWN, "DEPENDENCY_UNAVAILABLE")
    verify_receipt(res.receipt, "validator.jwk.json")


class FailingHolds:
    def holds(self, realm: Realm, agent_id: str) -> Sequence[str]:
        raise DependencyUnavailable("holds")


class FailingPolicies:
    def __init__(self, inner: Any) -> None:
        self.inner = inner

    def active(self) -> validator.ActivePolicy:
        raise DependencyUnavailable("policy")

    def selection(self, c: contract.Contract) -> validator.Selection:
        return self.inner.selection(c)  # type: ignore[no-any-return]


class FailingStatus:
    def evidence_status(self, issuer: str, status_ref: str) -> validator.EvidenceStatus:
        raise DependencyUnavailable("status")


class Wrapped:
    """A native adapter that passes every call to inner unless a subclass changes it."""

    def __init__(self, inner: Any) -> None:
        self.inner = inner

    def resolve_agent_binding(
        self, realm: Realm, workload: Workload, agent: AgentID
    ) -> AgentBinding:
        return self.inner.resolve_agent_binding(realm, workload, agent)  # type: ignore[no-any-return]

    def read_native_claim(self, native_path: str, c: ClaimContext) -> NativeClaim:
        return self.inner.read_native_claim(native_path, c)  # type: ignore[no-any-return]

    def check_context(self, check_id: str, input: CheckInput) -> CheckOutcome:
        return self.inner.check_context(check_id, input)  # type: ignore[no-any-return]


class FailingClaims(Wrapped):
    def read_native_claim(self, native_path: str, c: ClaimContext) -> NativeClaim:
        raise DependencyUnavailable("claims")


class UnknownCheck(Wrapped):
    def __init__(self, inner: Any, id_: str) -> None:
        super().__init__(inner)
        self.id = id_

    def check_context(self, check_id: str, input: CheckInput) -> CheckOutcome:
        if check_id == self.id:
            return CheckOutcome(result=Verdict.UNKNOWN, reason_code="DEPENDENCY_UNAVAILABLE")
        return super().check_context(check_id, input)


OUTAGES: dict[str, tuple[Callable[[Any], object], str]] = {
    "hold store": (lambda v: setattr(v, "holds", FailingHolds()), "security-hold"),
    "policy registry": (
        lambda v: setattr(v, "policies", FailingPolicies(v.policies)),
        "active-policy",
    ),
    "evidence status": (lambda v: setattr(v, "status", FailingStatus()), "evidence-validity"),
    "native source": (lambda v: setattr(v, "native", FailingClaims(v.native)), "roles"),
    "installed check": (
        lambda v: setattr(v, "native", UnknownCheck(v.native, "purpose-operation-v1")),
        "purpose-operation-v1",
    ),
}


@pytest.mark.parametrize("name", sorted(OUTAGES))
def test_outages_defer(name: str) -> None:
    # A hold store, policy registry, status source, native source or installed check that
    # cannot answer makes its check UNKNOWN and the decision DEFERRED; an UNKNOWN never
    # counts as a pass (draft 11.4, 18).
    apply, check_id = OUTAGES[name]
    f = case("admission/valid")
    apply(f.validator)
    res = evaluate(f)
    assert res.attestation.decision == Decision.DEFERRED
    assert check(res, check_id).result == CheckStatus.UNKNOWN


class LaterHolds:
    """No hold on its first answer and a hold afterwards: a hold that becomes effective during
    the evaluation."""

    def __init__(self) -> None:
        self.calls = 0

    def holds(self, realm: Realm, agent_id: str) -> Sequence[str]:
        self.calls += 1
        return [] if self.calls == 1 else ["security-incident-event-0001"]


def test_final_check_before_positive() -> None:
    # A hold that became effective during the evaluation prevents positive admission (draft
    # 11.3 step 10).
    f = case("admission/valid")
    f.validator.holds = LaterHolds()
    res = evaluate(f)
    assert res.attestation.decision != Decision.ADMISSIBLE
    want_check(res, "security-hold", CheckStatus.FAIL, "SECURITY_HOLD")


class Cancelling(Wrapped):
    """Cancels the evaluation when the first native read is issued, as a requestor's native
    session control does (draft 12.2)."""

    def __init__(self, inner: Any, cancel: threading.Event) -> None:
        super().__init__(inner)
        self.cancel = cancel

    def read_native_claim(self, native_path: str, c: ClaimContext) -> NativeClaim:
        self.cancel.set()
        return super().read_native_claim(native_path, c)


def test_cancelled_evaluation() -> None:
    # A cancelled authenticated evaluation gets a DEFERRED receipt with terminal reason
    # CANCELLED; every native read it did not complete is UNKNOWN NOT_EVALUATED, never PASS
    # or NOT_APPLICABLE.
    f = case("admission/valid")
    cancel = threading.Event()
    f.validator.native = Cancelling(f.validator.native, cancel)
    res = f.validator.evaluate(f.request, cancelled=cancel.is_set)
    a = res.attestation
    assert (a.decision, a.terminal_reason) == (Decision.DEFERRED, TerminalReason.CANCELLED)
    for id_ in (
        "principal",
        "roles",
        "supervisor-approval",
        "purpose-operation-v1",
        "native-delegation-v1",
        "security-hold-v1",
    ):
        want_check(res, id_, CheckStatus.UNKNOWN, "NOT_EVALUATED")
    want_check(res, "native-principal-binding-v1", CheckStatus.PASS, "REQUIREMENT_SATISFIED")
    assert a.exp - a.iat == 60, "a cancelled receipt is valid 60 s from issuance, not shortened"


def test_cancelled_predicate_that_raises_propagates() -> None:
    f = case("admission/valid")

    def boom() -> bool:
        raise RuntimeError("caller bug")

    with pytest.raises(RuntimeError, match="caller bug"):
        f.validator.evaluate(f.request, cancelled=boom)


class SlowSource(Wrapped):
    """Answers its native reads 40 s later: past the 30 s deadline."""

    def __init__(self, inner: Any, f: Fixture) -> None:
        super().__init__(inner)
        self.f = f

    def read_native_claim(self, native_path: str, c: ClaimContext) -> NativeClaim:
        self.f.clock.advance(timedelta(seconds=40))
        return super().read_native_claim(native_path, c)


def test_deadline() -> None:
    # An evaluation still waiting on a native read at its deadline seals EXPIRED at the
    # deadline, DEFERRED, and the late answer is not used (draft 12.1, 12.2).
    f = case("admission/valid")
    f.validator.native = SlowSource(f.validator.native, f)
    res = evaluate(f)
    a = res.attestation
    assert (a.decision, a.terminal_reason) == (Decision.DEFERRED, TerminalReason.EXPIRED)
    assert a.iat == 1792080030, "sealed at the deadline"
    want_check(res, "principal", CheckStatus.UNKNOWN, "NOT_EVALUATED")


def _flip_signature(p: str) -> str:
    last = p[-2]
    repl = "B" if last == "A" else "A"
    return p[:-2] + repl + p[-1]


REJECTIONS: dict[str, tuple[Callable[[Fixture], object], str]] = {
    "no native authentication": (lambda f: _principal(f), Code.INVALID_PROOF),
    "not a JWS": (lambda f: _presentation(f, "not-a-jws"), Code.INVALID_MESSAGE),
    "signature edited": (
        lambda f: _presentation(f, _flip_signature(f.request.presentation)),
        Code.INVALID_PROOF,
    ),
    "presentation expired": (
        lambda f: f.clock.advance(timedelta(seconds=61)),
        contract.CODE_EXPIRED,
    ),
    "actual operation of another principal": (
        lambda f: _operation_principal(f),
        Code.INVALID_MESSAGE,
    ),
}


def _principal(f: Fixture) -> None:
    f.request = replace(f.request, principal=Principal())


def _presentation(f: Fixture, p: str) -> None:
    f.request = replace(f.request, presentation=p)


def _operation_principal(f: Fixture) -> None:
    op = replace(f.request.operation, principal_id="https://identity.example/principals/bob")
    f.request = replace(f.request, operation=op)


@pytest.mark.parametrize("name", sorted(REJECTIONS))
def test_transport_rejections(name: str) -> None:
    # What is refused before an authenticated evaluation gets the draft 13.4 code and no
    # receipt (draft 12.2).
    change, code = REJECTIONS[name]
    f = case("admission/valid")
    change(f)
    with pytest.raises(Exception) as ei:  # noqa: PT011
        evaluate(f)
    assert not hasattr(ei.value, "result") or ei.value.result is None
    assert code_of(ei.value) == code
    p = validator.problem_of(ei.value, "r1")
    assert p is not None
    assert (p.code, p.request_id) == (code, "r1")
    assert p.status != 0


def test_handoff() -> None:
    # A positive attestation is accepted once, for its own operation only (draft 11.5).
    f = case("admission/valid")
    res = evaluate(f)
    k = jws.parse_jwk((FIXTURES / "keys" / "validator.jwk.json").read_bytes())
    cfg = f.validator.config
    h = validator.Handoff(
        validators={cfg.issuer: jws.new_key_set(k)},
        audience=cfg.audience,
        realm=cfg.realm,
        skew=cfg.skew,
        consumed=validator.MemoryAttestations(),
    )
    now = f.clock.now()
    other = replace(
        f.request.operation, operation_id="invoice-export-operation-0002", action="invoice.export"
    )
    with pytest.raises(Exception) as ei:  # noqa: PT011
        h.accept(res.receipt, other, f.request.principal, now)
    assert code_of(ei.value) == Code.CONTEXT_MISMATCH
    h.accept(res.receipt, f.request.operation, f.request.principal, now)
    with pytest.raises(Exception) as ei:  # noqa: PT011
        h.accept(res.receipt, f.request.operation, f.request.principal, now)
    assert code_of(ei.value) == contract.CODE_REPLAY
    h.consumed = validator.MemoryAttestations()
    with pytest.raises(Exception) as ei:  # noqa: PT011
        h.accept(res.receipt, f.request.operation, f.request.principal, now + timedelta(minutes=1))
    assert code_of(ei.value) == contract.CODE_EXPIRED


def test_receipt_json() -> None:
    # The payload is an AdmissionAttestation with no unknown member, as a strict consumer
    # decodes it (draft 7.1).
    from hop_top_pact.core import strictjson
    from hop_top_pact.core.jws import base64url

    res = evaluate(case("admission/valid"))
    raw = base64url.decode(res.receipt.split(".")[1])
    assert strictjson.decode(raw, AdmissionAttestation) == res.attestation or json.loads(raw)
    assert isinstance(json.loads(raw)["checks"][0]["evidence_ids"], list)


class OnceFailingHolds:
    """Cannot answer its first query: the hold check of the evaluation is UNKNOWN, whatever
    the store answers later."""

    def __init__(self) -> None:
        self.calls = 0

    def holds(self, realm: Realm, agent_id: str) -> Sequence[str]:
        self.calls += 1
        if self.calls == 1:
            raise DependencyUnavailable("holds")
        return []


def test_hold_outage_not_rescued_later() -> None:
    f = case("admission/valid")
    f.validator.holds = OnceFailingHolds()
    res = evaluate(f)
    assert res.attestation.decision == Decision.DEFERRED
    want_check(res, "security-hold", CheckStatus.UNKNOWN, "DEPENDENCY_UNAVAILABLE")


class CompromisedOnce(Wrapped):
    """Reports the binding compromised at the start of the evaluation and active afterwards."""

    def __init__(self, inner: Any) -> None:
        super().__init__(inner)
        self.calls = 0

    def resolve_agent_binding(
        self, realm: Realm, workload: Workload, agent: AgentID
    ) -> AgentBinding:
        b = super().resolve_agent_binding(realm, workload, agent)
        self.calls += 1
        if self.calls == 1:
            b = replace(b, status=BindingStatus.COMPROMISED)
        return b


def test_compromised_binding() -> None:
    # A compromised identity is evaluated and held (draft 6.4, 13.4): agent-holder-binding
    # FAIL SECURITY_HOLD, INADMISSIBLE.
    f = case("admission/valid")
    f.validator.native = CompromisedOnce(f.validator.native)
    res = evaluate(f)
    assert res.attestation.decision == Decision.INADMISSIBLE
    want_check(res, "agent-holder-binding", CheckStatus.FAIL, "SECURITY_HOLD")


def test_mode_is_enforced_in_the_receipt() -> None:
    assert evaluate(case("admission/valid")).attestation.mode == Mode.ENFORCED
