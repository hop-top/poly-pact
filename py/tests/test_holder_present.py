"""Presentations. Port of go/holder/present_test.go.

go/holder/validator_integration_test.go depends on the validator and is not ported here.
The Go test of a cancelled context has no counterpart: the calls take no context argument.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from datetime import timedelta
from typing import Any

import pytest

from hop_top_pact import contract, holder
from hop_top_pact.adapter import Code
from hop_top_pact.core import digest, jws
from hop_top_pact.core.types import OperationContext


def test_appendix_b_presentation_reproduces(ck: Any, hk: Any) -> None:
    # From the Appendix B inputs (the signed B.4 contract, B.5 evidence and B.6 snapshot of
    # the admission/valid fixture, the B.2 intent, the B.3 operation and a source profile
    # holding more than B.4 asks for), with the jti of the B.7 receipt, the holder builds
    # the fixture presentation: the same protected header and payload, byte for byte.
    # ES256 signatures are randomized, so the signature is compared by verification only.
    h = hk.b_holder(hk.memory_key(1))
    h.random = hk.jti_random(hk.B_PRESENTATION_ID)
    got = h.present(hk.b_input(), ck.at(ck.B4_TIME))
    want = ck.compact_of(hk.VALID + "signed/presentation.jws")
    assert got.compact.rsplit(".", 1)[0] == want.rsplit(".", 1)[0], (
        f"header {ck.segment(got.compact, 0)!r} want {ck.segment(want, 0)!r}\n"
        f"payload {ck.segment(got.compact, 1)!r}\nwant {ck.segment(want, 1)!r}"
    )
    from hop_top_pact.core import _wire

    assert _wire.payload(got.claims.profile) == ck.canonical(ck.draft_block("B.1"))
    assert got.profile_digest == hk.B_PROFILE_DIGEST
    assert got.claims.jti == hk.B_PRESENTATION_ID
    assert digest.object_digest(got.claims.operation) == ck.B4_OP_DIGEST
    assert digest.object_digest(got.claims.intent) == ck.B4_INTENT_DIGEST
    assert got.digest == digest.artifact_digest(got.compact)
    assert got.contract.compact == hk.b_input().contract
    # The gateway checks accept both the fixture and the rebuilt presentation.
    for compact in (want, got.compact):
        hk.gateway_run(
            compact,
            enrolled=ck.fixture_jwk("holder"),
            actual=hk.b_operation(),
            now=ck.at(ck.B4_TIME),
        )


def test_fresh_contract_presentation_passes(ck: Any, hk: Any) -> None:
    # A contract issued now by the publisher, presented by the holder, passes the gateway
    # checks, and the nonce record the presentation binds is the one the publisher
    # registered: it is consumed once, then replayed.
    now = ck.at(ck.B4_TIME + 3600)
    sec = ck.B4_TIME + 3600
    store = contract.MemoryReplay(16)
    c = hk.issue(store, ck.B4_HOLDER_JKT, ck.b4_requirements(), hk.b_operation(), now)
    in_ = hk.b_input()
    ev = replace(hk.b_evidence(), iat=sec, nbf=sec, exp=sec + 300)
    profile = replace(in_.profile, created_at=sec, expires_at=sec + 3600)
    in_ = replace(
        in_,
        contract=c.compact,
        evidence=(hk.sign_evidence(2, "test-issuer-key-1", ev),),
        reputation=hk.sign_snapshot_for(sec, ck.B4_HOLDER_JKT),
        profile=profile,
    )
    p = hk.b_holder(hk.memory_key(1)).present(in_, now)
    assert (p.claims.nonce, p.claims.iat, p.claims.exp) == (c.claims.nonce, sec, sec + 60)
    later = now + timedelta(seconds=2)
    _, rec = hk.gateway_run(
        p.compact, enrolled=ck.fixture_jwk("holder"), actual=hk.b_operation(), now=later
    )
    until = now + timedelta(seconds=65)
    store.consume(rec, later, until)
    with ck.raises(contract.CODE_REPLAY):
        store.consume(rec, now + timedelta(seconds=3), until)
    # Two presentations of one input differ in jti.
    q = hk.b_holder(hk.memory_key(1)).present(in_, now)
    assert q.claims.jti != p.claims.jti
    assert len(q.claims.jti) == 22


def test_wrong_key_fails(ck: Any, hk: Any, counting_key: Any) -> None:
    # A key source whose key is not the contract's holder_jkt (the second holder key,
    # scalar 10) signs nothing, and one that advertises the enrolled key but signs with
    # another (scalar 3) does not produce a presentation (draft 6.2, 11.2).
    other = counting_key(hk.memory_key(10), hk.memory_key(10))
    with hk.raises(Code.INVALID_PROOF):
        hk.b_holder(other).present(hk.b_input(), ck.at(ck.B4_TIME))
    assert other.signs == 0, "the wrong key signed"
    with hk.raises(Code.INVALID_PROOF):
        hk.b_holder(other).verify_contract(
            hk.b_input().contract, hk.b_intent(), hk.b_operation(), ck.at(ck.B4_TIME)
        )
    impostor = counting_key(hk.memory_key(1), hk.memory_key(3))
    with hk.raises(Code.INVALID_PROOF):
        hk.b_holder(impostor).present(hk.b_input(), ck.at(ck.B4_TIME))
    assert impostor.signs == 1

    # A presentation the wrong key signed, for a contract that names that key, fails the
    # gateway's binding to the enrolled key.
    jkt = jws.thumbprint(hk.memory_key(10).public_jwk())
    r = ck.b4_requirements()
    r = replace(
        r, field_rules=tuple(fr for fr in r.field_rules if fr.rule_id != "reputation-status")
    )
    c = hk.issue(contract.MemoryReplay(4), jkt, r, hk.b_operation(), ck.at(ck.B4_TIME))
    in_ = hk.b_input()
    ev = replace(hk.b_evidence(), holder_jkt=jkt)
    in_ = replace(
        in_,
        contract=c.compact,
        profile=replace(in_.profile, holder_jkt=jkt),
        evidence=(hk.sign_evidence(2, "test-issuer-key-1", ev),),
    )
    p = hk.b_holder(hk.memory_key(10)).present(in_, ck.at(ck.B4_TIME))
    with pytest.raises(ValueError, match="step 2"):
        hk.gateway_run(
            p.compact,
            enrolled=ck.fixture_jwk("holder"),
            actual=hk.b_operation(),
            now=ck.at(ck.B4_TIME),
        )


def test_stale_contract_fails(ck: Any, hk: Any) -> None:
    # A contract at or after its exp is EXPIRED, with no grace period (draft 7.5); one
    # signed by an untrusted publisher, or whose rules were edited after signing, fails the
    # publisher proof.
    for now in (hk.B_CONTRACT_EXP, hk.B_CONTRACT_EXP + 1, ck.B4_TIME + 3600):
        with hk.raises(holder.CODE_EXPIRED):
            hk.b_holder(hk.memory_key(1)).present(hk.b_input(), ck.at(now))
    h = hk.b_holder(hk.memory_key(1))
    h.publishers = {ck.B4_PUBLISHER: hk.key_set(jws.Algorithms(), "adversarial")}
    with hk.raises(Code.INVALID_PROOF):
        h.present(hk.b_input(), ck.at(ck.B4_TIME))
    in_ = hk.b_input()
    edited = in_.contract
    parts = edited.split(".")
    text = ck.segment(edited, 1).decode().replace('"const":"managed"', '"const":"shared"', 1)
    parts[1] = jws.base64url.encode(text.encode())
    in_ = replace(in_, contract=".".join(parts))
    with hk.raises(Code.INVALID_PROOF):
        hk.b_holder(hk.memory_key(1)).present(in_, ck.at(ck.B4_TIME))


EDITS: dict[str, Callable[[OperationContext], OperationContext]] = {
    "resource": lambda op: replace(op, resources=("https://invoices.example/invoices/INV-1043",)),
    "method": lambda op: replace(op, method="DELETE"),
    "target": lambda op: replace(op, target_uri=op.target_uri + "?all=1"),
    "body": lambda op: replace(op, body_digest=digest.bytes_digest(b"{}")),
    "header": lambda op: replace(op, headers={"x-dry-run": "false"}),
    "principal": lambda op: replace(op, principal_id="https://identity.example/principals/mallory"),
    "action": lambda op: replace(op, action="invoice.pay"),
}


@pytest.mark.parametrize("name", sorted(EDITS))
def test_modified_operation_fails(ck: Any, hk: Any, counting_key: Any, name: str) -> None:
    # An operation or intent that differs in any member from the one the contract binds
    # fails before signing (draft 10.3), and a presentation of the contracted operation
    # fails the gateway's binding check when the actual operation differs (draft 11.3 step
    # 5).
    edit = EDITS[name]
    key = counting_key(hk.memory_key(1), hk.memory_key(1))
    in_ = hk.b_input()
    in_ = replace(in_, operation=edit(in_.operation))
    with hk.raises(Code.CONTEXT_MISMATCH):
        hk.b_holder(key).present(in_, ck.at(ck.B4_TIME))
    assert key.signs == 0, "signed a presentation for a modified operation"
    p = hk.b_holder(hk.memory_key(1)).present(hk.b_input(), ck.at(ck.B4_TIME))
    actual: OperationContext = edit(hk.b_operation())
    with pytest.raises(ValueError, match="step 5"):
        hk.gateway_run(
            p.compact, enrolled=ck.fixture_jwk("holder"), actual=actual, now=ck.at(ck.B4_TIME)
        )


def test_modified_intent_fails(ck: Any, hk: Any) -> None:
    in_ = hk.b_input()
    in_ = replace(
        in_,
        intent=replace(
            in_.intent, purpose_id="https://policies.example/purposes/invoice-payment/v1"
        ),
    )
    with hk.raises(Code.CONTEXT_MISMATCH):
        hk.b_holder(hk.memory_key(1)).present(in_, ck.at(ck.B4_TIME))


@pytest.mark.parametrize(
    ("name", "edit"),
    [
        ("agent", {"agent_id": "https://identity.example/agents/other"}),
        ("gateway", {"gateway": "https://gateway.example/other"}),
        ("tenant", {"tenant_id": "globex"}),
        ("env", {"environment_id": "https://gateway.example/environments/other"}),
    ],
)
def test_contract_context(ck: Any, hk: Any, name: str, edit: dict[str, str]) -> None:
    # A contract for another agent, gateway or realm is a context mismatch (draft 11.2,
    # 11.3 step 3).
    h = hk.b_holder(hk.memory_key(1))
    for field, value in edit.items():
        if field in ("tenant_id", "environment_id"):
            h.realm = replace(h.realm, **{field: value})
        else:
            setattr(h, field, value)
    with hk.raises(Code.CONTEXT_MISMATCH):
        h.verify_contract(hk.b_input().contract, hk.b_intent(), hk.b_operation(), ck.at(ck.B4_TIME))


def test_contract_verifies_for_its_own_context(ck: Any, hk: Any) -> None:
    c = hk.b_holder(hk.memory_key(1)).verify_contract(
        hk.b_input().contract, hk.b_intent(), hk.b_operation(), ck.at(ck.B4_TIME)
    )
    assert c.claims.nonce == "N8WrKpg8XNb9Wh_QuWlHbw"
    assert c.claims.selected_set == "supervised"


def test_unsupported_contract_extension(ck: Any, hk: Any) -> None:
    # A contract extension the holder does not support defers (draft 7.1, 21); a supported
    # one is accepted.
    r = replace(
        ck.b4_requirements(), extensions={"https://ext.example/pact/transport-hint": {"v": 1}}
    )
    c = hk.issue(contract.MemoryReplay(4), ck.B4_HOLDER_JKT, r, hk.b_operation(), ck.at(ck.B4_TIME))
    h = hk.b_holder(hk.memory_key(1))
    with hk.raises(Code.UNSUPPORTED_REQUIREMENT):
        h.verify_contract(c.compact, hk.b_intent(), hk.b_operation(), ck.at(ck.B4_TIME))
    h.extensions = ("https://ext.example/pact/transport-hint",)
    h.verify_contract(c.compact, hk.b_intent(), hk.b_operation(), ck.at(ck.B4_TIME))


def test_presentation_lifetime(ck: Any, hk: Any) -> None:
    # exp - iat is the configured lifetime, 60 s by default and never more (draft 7.5,
    # 20.1).
    h = hk.b_holder(hk.memory_key(1))
    h.lifetime = timedelta(seconds=30)
    p = h.present(hk.b_input(), ck.at(ck.B4_TIME + 5))
    t = ck.B4_TIME + 5
    assert (p.claims.iat, p.claims.nbf, p.claims.exp) == (t, t, t + 30)
    for bad in (timedelta(seconds=61), timedelta(milliseconds=1500), timedelta(seconds=-1)):
        h.lifetime = bad
        with hk.raises(Code.INVALID_MESSAGE):
            h.present(hk.b_input(), ck.at(ck.B4_TIME))
    h = hk.b_holder(hk.memory_key(1))
    h.skew = timedelta(seconds=6)
    with hk.raises(Code.INVALID_MESSAGE):
        h.present(hk.b_input(), ck.at(ck.B4_TIME))


def test_key_source_unavailable(ck: Any, hk: Any, failing_key: Any) -> None:
    # A key source that cannot sign defers; a random source that fails does too.
    with hk.raises(Code.DEPENDENCY_UNAVAILABLE):
        hk.b_holder(failing_key(hk.memory_key(1))).present(hk.b_input(), ck.at(ck.B4_TIME))
    h = hk.b_holder(hk.memory_key(1))
    h.random = lambda n: b"short"
    with hk.raises(Code.DEPENDENCY_UNAVAILABLE):
        h.present(hk.b_input(), ck.at(ck.B4_TIME))


def test_limits(ck: Any, hk: Any) -> None:
    # A presentation is never truncated to fit the draft 20.1 limits; an input over them
    # fails. The contract binds the original intent, so the oversized one also mismatches;
    # the limit is checked first.
    in_ = hk.b_input()
    in_ = replace(in_, intent=replace(in_.intent, description="x" * 4097))
    with hk.raises(Code.INVALID_MESSAGE):
        hk.b_holder(hk.memory_key(1)).present(in_, ck.at(ck.B4_TIME))


def test_error_codes() -> None:
    # Each error carries its draft 13.4 code.
    for code, want in (
        (Code.INVALID_MESSAGE, "INVALID_MESSAGE"),
        (Code.INVALID_PROOF, "INVALID_PROOF"),
        (Code.CONTEXT_MISMATCH, "CONTEXT_MISMATCH"),
        (Code.UNSUPPORTED_REQUIREMENT, "UNSUPPORTED_REQUIREMENT"),
        (Code.MISSING_FIELD, "MISSING_FIELD"),
        (holder.CODE_CONFLICTING_EVIDENCE, "CONFLICTING_EVIDENCE"),
        (holder.CODE_EXPIRED, "EXPIRED"),
        (Code.DEPENDENCY_UNAVAILABLE, "DEPENDENCY_UNAVAILABLE"),
    ):
        e = holder.HolderError(code)
        assert e.code == want
        assert str(e).startswith("holder: ")
    v = holder.HolderError(Code.INVALID_MESSAGE, "x", "unsupported-version")
    assert (v.code, v.kind) == ("INVALID_MESSAGE", "unsupported-version")
