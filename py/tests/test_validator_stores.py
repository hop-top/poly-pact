"""Signers, receipt and attestation stores, and the sidecar handoff (draft 11.5, 12.1).

The Go tests reach these through a full evaluation (validator_test.go, TestHandoff and
TestReceiptJSON); these test them directly on attestations built here."""

from __future__ import annotations

from dataclasses import replace
from datetime import timedelta
from typing import Any

import pytest

from hop_top_pact import contract
from hop_top_pact.adapter import Code, Principal, Realm
from hop_top_pact.core import _wire, digest, jws
from hop_top_pact.core.enums import CheckStatus, Decision, Mode, TerminalReason
from hop_top_pact.core.types import AdmissionAttestation, CheckResult, OperationContext
from hop_top_pact.validator import (
    Ed25519Signer,
    ES256Signer,
    Handoff,
    MemoryAttestations,
    MemoryReceipts,
    Result,
    ValidatorError,
    _problem,
)

NOW = 1792080000


def attestation(ck: Any, **kw: Any) -> AdmissionAttestation:
    op = op_of(ck)
    base = AdmissionAttestation(
        pact_version="0.1",
        iss="https://trust.example/validators/finance",
        sub=ck.B4_AGENT,
        aud=ck.B4_GATEWAY,
        jti="attestationJti0000000a",
        iat=NOW,
        nbf=NOW,
        exp=NOW + 60,
        tenant_id=ck.B4_TENANT,
        presentation_id="v6wxT-_cB0Ua8Xkqgcuu2g",
        operation_id=op.operation_id,
        principal_id=op.principal_id,
        environment_id=ck.B4_ENV,
        holder_jkt=ck.B4_HOLDER_JKT,
        profile_digest="b6pNI8i5pX5MtuxkaBw0M-4tmzdkGsHVS_Kyji7_uOU",
        intent_digest=ck.B4_INTENT_DIGEST,
        operation_digest=digest.object_digest(op),
        requirements_digest="A" * 43,
        learning_policy_digest=ck.B4_POLICY_DIGEST,
        learning_artifact_digest=ck.B4_ARTIFACT_DIGEST,
        decision=Decision.ADMISSIBLE,
        terminal_reason=TerminalReason.COMPLETED,
        mode=Mode.ENFORCED,
        checks=(
            CheckResult(
                check_id="nonce",
                result=CheckStatus.PASS,
                reason_code="REQUIREMENT_SATISFIED",
                checked_at=NOW,
                source_observed_at=None,
                status_checked_at=None,
                evidence_ids=(),
                source_id="gateway",
                source_ref=None,
            ),
        ),
    )
    return replace(base, **kw)


def op_of(ck: Any) -> OperationContext:
    from hop_top_pact.core import strictjson

    return strictjson.decode(ck.draft_block("B.3"), OperationContext)


def signer(ck: Any) -> ES256Signer:
    return ES256Signer(kid="test-validator-key-1", key=ck.scalar_key(6))


def issue(ck: Any, **kw: Any) -> str:
    return signer(ck).sign_attestation(_wire.payload(attestation(ck, **kw)))


def handoff(ck: Any, **kw: Any) -> Handoff:
    return Handoff(
        validators={"https://trust.example/validators/finance": ck.fixture_key_set("validator")},
        audience=ck.B4_GATEWAY,
        realm=ck.B4_REALM,
        skew=timedelta(seconds=5),
        consumed=MemoryAttestations(),
        **kw,
    )


def principal(ck: Any) -> Principal:
    return Principal(id=ck.B4_PRINCIPAL, realm=ck.B4_REALM)


def accept(
    ck: Any, h: Handoff, compact: str, at: int = NOW, op: OperationContext | None = None
) -> Any:
    return h.accept(compact, op or op_of(ck), principal(ck), ck.at(at))


def test_signers_sign_pact_admission(ck: Any) -> None:
    compact = issue(ck)
    keys = jws.StaticResolver(key_sets={jws.Role.VALIDATOR: ck.fixture_key_set("validator")})
    p = jws.Verifier(keys=keys, typ=jws.TYP_ADMISSION).verify(compact)
    assert p.header.kid == "test-validator-key-1"
    # Ed25519 under a negotiated deployment.
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    ed = Ed25519Signer(kid="test-ed25519-key-1", key=Ed25519PrivateKey.from_private_bytes(seed))
    out = ed.sign_attestation(_wire.payload(attestation(ck)))
    algs = jws.Algorithms((jws.ALG_ES256, jws.ALG_ED25519))
    ed_keys = jws.StaticResolver(
        key_sets={
            jws.Role.VALIDATOR: algs.new_key_set(
                algs.parse_jwk(ck.fixture("keys/ed25519.jwk.json"))
            )
        }
    )
    got = jws.Verifier(keys=ed_keys, typ=jws.TYP_ADMISSION, algorithms=algs).verify(out)
    assert got.header.alg == jws.ALG_ED25519


def result_of(ck: Any, **kw: Any) -> Result:
    a = attestation(ck, **kw)
    return Result(receipt=signer(ck).sign_attestation(_wire.payload(a)), attestation=a)


def test_memory_receipts(ck: Any) -> None:
    m = MemoryReceipts()
    r1 = result_of(ck, jti="receiptJti00000000001")
    r2 = result_of(ck, jti="receiptJti00000000002")
    r3 = result_of(ck, jti="receiptJti00000000003", requirements_digest="B" * 43)
    for r in (r1, r2, r3):
        m.put(r)
    assert m.get("receiptJti00000000002") == r2
    assert m.by_contract("A" * 43) == [r1, r2]
    assert m.by_contract("C" * 43) == []
    assert set(m.all()) == {r.attestation.jti for r in (r1, r2, r3)}
    # A sealed receipt is stored once and never replaced; a receipt needs a jti.
    with pytest.raises(ValueError, match="already recorded"):
        m.put(replace(r1, receipt="other"))
    with pytest.raises(ValueError, match="without jti"):
        m.put(result_of(ck, jti=""))
    assert m.get(r1.attestation.jti) == r1
    with pytest.raises(ValidatorError) as ei:
        m.get("missing")
    assert ei.value.kind == "NOT_FOUND"
    m.all().clear()  # a copy
    assert len(m.all()) == 3


def test_memory_attestations_consume_once(ck: Any) -> None:
    m = MemoryAttestations()
    m.consume("jti-1", ck.at(NOW + 60))
    with pytest.raises(Exception) as ei:  # noqa: PT011
        m.consume("jti-1", ck.at(NOW + 60))
    assert _problem.code_of(ei.value) == contract.CODE_REPLAY
    m.consume("jti-2", ck.at(NOW + 60))


def test_handoff_accepts_once_for_its_own_operation(ck: Any) -> None:
    # A positive attestation is accepted once, for its own operation only (draft 11.5).
    h = handoff(ck)
    compact = issue(ck)
    other = replace(
        op_of(ck), operation_id="invoice-export-operation-0002", action="invoice.export"
    )
    with pytest.raises(Exception) as ei:  # noqa: PT011
        accept(ck, h, compact, op=other)
    assert _problem.code_of(ei.value) == Code.CONTEXT_MISMATCH
    assert accept(ck, h, compact).jti == "attestationJti0000000a"
    with pytest.raises(Exception) as ei:  # noqa: PT011
        accept(ck, h, compact)
    assert _problem.code_of(ei.value) == contract.CODE_REPLAY
    h.consumed = MemoryAttestations()
    with pytest.raises(Exception) as ei:  # noqa: PT011
        accept(ck, h, compact, at=NOW + 60)
    assert _problem.code_of(ei.value) == contract.CODE_EXPIRED


REJECTS: dict[str, tuple[dict[str, Any], str]] = {
    "another gateway": ({"aud": "https://gateway.example/other"}, Code.CONTEXT_MISMATCH),
    "another tenant": ({"tenant_id": "globex"}, Code.CONTEXT_MISMATCH),
    "another principal": (
        {"principal_id": "https://identity.example/principals/bob"},
        Code.CONTEXT_MISMATCH,
    ),
    "another operation digest": ({"operation_digest": "B" * 43}, Code.CONTEXT_MISMATCH),
    "not admissible": ({"decision": Decision.DEFERRED}, Code.CONTEXT_MISMATCH),
    "observe mode": ({"mode": Mode.OBSERVE}, Code.CONTEXT_MISMATCH),
    "not yet valid": ({"iat": NOW + 30, "nbf": NOW + 30, "exp": NOW + 60}, Code.INVALID_MESSAGE),
}


@pytest.mark.parametrize("name", sorted(REJECTS))
def test_handoff_rejections(ck: Any, name: str) -> None:
    kw, code = REJECTS[name]
    with pytest.raises(Exception) as ei:  # noqa: PT011
        accept(ck, handoff(ck), issue(ck, **kw))
    assert _problem.code_of(ei.value) == code


def test_handoff_signature_and_form(ck: Any) -> None:
    h = handoff(ck)
    compact = issue(ck)
    with pytest.raises(Exception) as ei:  # noqa: PT011
        accept(ck, h, compact[:-3] + ("AAA" if not compact.endswith("AAA") else "BBB"))
    assert _problem.code_of(ei.value) == Code.INVALID_PROOF
    with pytest.raises(Exception) as ei:  # noqa: PT011
        accept(ck, h, "not-a-jws")
    assert _problem.code_of(ei.value) == Code.INVALID_MESSAGE
    # Another validator's key does not verify it.
    other = replace(
        h, validators={"https://trust.example/validators/finance": ck.fixture_key_set("issuer")}
    )
    with pytest.raises(Exception) as ei:  # noqa: PT011
        accept(ck, other, compact)
    assert _problem.code_of(ei.value) == Code.INVALID_PROOF
    with pytest.raises(ValueError, match="Consumed"):
        accept(ck, replace(h, consumed=None), compact)


class Holds:
    def __init__(self, answer: list[str] | Exception) -> None:
        self.answer = answer

    def holds(self, realm: Realm, agent_id: str) -> list[str]:
        if isinstance(self.answer, Exception):
            raise self.answer
        return self.answer


class FailingStore:
    def consume(self, jti: str, until: Any) -> None:
        raise RuntimeError("store down")


def test_handoff_holds_and_store_outage(ck: Any) -> None:
    # A current local security hold refuses the handoff (draft 11.5); an outage defers.
    compact = issue(ck)
    with pytest.raises(Exception) as ei:  # noqa: PT011
        accept(ck, handoff(ck, holds=Holds(["hold-1"])), compact)
    assert _problem.code_of(ei.value) == contract.CODE_SECURITY_HOLD
    with pytest.raises(Exception) as ei:  # noqa: PT011
        accept(ck, handoff(ck, holds=Holds(RuntimeError("down"))), compact)
    assert _problem.code_of(ei.value) == Code.DEPENDENCY_UNAVAILABLE
    accept(ck, handoff(ck, holds=Holds([])), compact)
    h = replace(handoff(ck), consumed=FailingStore())
    with pytest.raises(Exception) as ei:  # noqa: PT011
        accept(ck, h, compact)
    assert _problem.code_of(ei.value) == Code.DEPENDENCY_UNAVAILABLE
