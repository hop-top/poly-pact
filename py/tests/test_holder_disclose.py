"""Requirement-driven disclosure. Port of go/holder/disclose_test.go."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from typing import Any

import pytest

from hop_top_pact import contract, holder
from hop_top_pact.adapter import Code
from hop_top_pact.core import _wire, jws
from hop_top_pact.core.types import AgentProfile, Claim, Evidence, ReputationSnapshot


def with_attr(in_: holder.Input, **attrs: Any) -> holder.Input:
    return replace(
        in_, profile=replace(in_.profile, attributes={**in_.profile.attributes, **attrs})
    )


def test_disclosure_is_requirement_driven(ck: Any, hk: Any) -> None:
    # The view holds exactly the attribute paths the contract's rules name, the reputation
    # value is the snapshot's (draft 15.2), attributes no rule names are withheld (draft
    # 8.1, 19), and only the evidence a rule uses is attached.
    in_ = hk.b_input()
    unused = replace(
        hk.b_evidence(),
        claims=(Claim(path="/attributes/capabilities/languages", value=("en", "fr")),),
        jti="unusedEvidence000000000",
    )
    in_ = replace(in_, evidence=(hk.sign_evidence(2, "test-issuer-key-1", unused), *in_.evidence))
    p = hk.b_holder(hk.memory_key(1)).present(in_, ck.at(ck.B4_TIME))
    attrs = _wire.payload(p.claims.profile.attributes).decode()
    for withheld in ("display_name", "capabilities", "build-17"):
        assert withheld not in attrs, attrs
    assert p.claims.evidence == (hk.b_input().evidence[0],)
    assert p.claims.reputation == hk.b_input().reputation
    # A contract without reputation rules attaches no snapshot.
    r = ck.b4_requirements()
    r = replace(
        r, field_rules=tuple(fr for fr in r.field_rules if fr.rule_id != "reputation-status")
    )
    c = hk.issue(contract.MemoryReplay(4), ck.B4_HOLDER_JKT, r, hk.b_operation(), ck.at(ck.B4_TIME))
    in_ = replace(hk.b_input(), contract=c.compact)
    p = hk.b_holder(hk.memory_key(1)).present(in_, ck.at(ck.B4_TIME))
    assert p.claims.reputation is None
    assert "reputation" not in p.claims.profile.attributes


def drop(name: str) -> Callable[[holder.Input], holder.Input]:
    def edit(in_: holder.Input) -> holder.Input:
        attrs = {k: v for k, v in in_.profile.attributes.items() if k != name}
        return replace(in_, profile=replace(in_.profile, attributes=attrs))

    return edit


MISSING: dict[str, Callable[[holder.Input], holder.Input]] = {
    "native value": drop("delegation"),
    "no evidence": lambda in_: replace(in_, evidence=()),
    "no snapshot": lambda in_: replace(in_, reputation=""),
    "self-asserted reputation": lambda in_: with_attr(
        replace(in_, reputation=""), reputation={"security_status": "CLEAR"}
    ),
}


@pytest.mark.parametrize("name", sorted(MISSING))
def test_missing_values_fail(ck: Any, hk: Any, name: str) -> None:
    # A rule's value the agent does not hold, an evidence rule without applicable
    # evidence, and a reputation rule without a snapshot fail; the holder does not fill them
    # in (draft 8.6, 9.2).
    with hk.raises(Code.MISSING_FIELD):
        hk.b_holder(hk.memory_key(1)).present(MISSING[name](hk.b_input()), ck.at(ck.B4_TIME))


def test_evidence_supplies_a_missing_value(ck: Any, hk: Any) -> None:
    # Evidence supplies a value the source profile lacks: it is authoritative.
    in_ = with_attr(hk.b_input(), runtime={})
    p = hk.b_holder(hk.memory_key(1)).present(in_, ck.at(ck.B4_TIME))
    assert p.claims.profile.attributes["runtime"] == {"isolation": "managed"}


INAPPLICABLE: dict[str, Callable[[Evidence], Evidence]] = {
    "audience": lambda e: replace(e, aud="https://gateway.example/other"),
    "subject": lambda e: replace(e, sub="https://identity.example/agents/other"),
    "holder": lambda e: replace(e, holder_jkt="A" * 43),
    "tenant": lambda e: replace(e, tenant_id="globex"),
    "env": lambda e: replace(e, environment_id="https://gateway.example/environments/other"),
    "issuer": lambda e: replace(e, iss="https://trust.example/issuers/other"),
    "expired": lambda e: replace(e, iat=1792079400, nbf=1792079400, exp=1792080000),
    "future": lambda e: replace(e, iat=1792080060, nbf=1792080060, exp=1792080300),
    "path": lambda e: replace(
        e, claims=(replace(e.claims[0], path="/attributes/runtime"), *e.claims[1:])
    ),
}


@pytest.mark.parametrize("name", sorted(INAPPLICABLE))
def test_inapplicable_evidence_is_not_used(ck: Any, hk: Any, name: str) -> None:
    # Evidence for another audience, subject, holder key or realm, from an issuer the rule
    # does not allow, expired, or of another claim path is not used (draft 8.3, 8.4).
    e = INAPPLICABLE[name](hk.b_evidence())
    in_ = replace(hk.b_input(), evidence=(hk.sign_evidence(2, "test-issuer-key-1", e),))
    with hk.raises(Code.MISSING_FIELD):
        hk.b_holder(hk.memory_key(1)).present(in_, ck.at(ck.B4_TIME))


def isolation(value: str) -> Claim:
    return Claim(path="/attributes/runtime/isolation", value=value)


def test_evidence_conflicts(ck: Any, hk: Any) -> None:
    now = ck.at(ck.B4_TIME)
    h = hk.b_holder(hk.memory_key(1))
    # A profile value that differs from the authoritative value conflicts.
    with hk.raises(holder.CODE_CONFLICTING_EVIDENCE):
        h.present(with_attr(hk.b_input(), runtime={"isolation": "shared"}), now)
    other = replace(hk.b_evidence(), claims=(isolation("shared"),))
    signed = hk.sign_evidence(2, "test-issuer-key-1", other)
    # Applicable evidence that disagrees conflicts.
    in_ = with_attr(hk.b_input(), runtime={})
    with hk.raises(holder.CODE_CONFLICTING_EVIDENCE):
        h.present(replace(in_, evidence=(*in_.evidence, signed)), now)
    in_ = hk.b_input()
    with hk.raises(holder.CODE_CONFLICTING_EVIDENCE):
        h.present(replace(in_, evidence=(*in_.evidence, signed)), now)


def test_malformed_artifacts(ck: Any, hk: Any) -> None:
    now = ck.at(ck.B4_TIME)
    h = hk.b_holder(hk.memory_key(1))
    in_ = hk.b_input()
    with hk.raises(Code.INVALID_MESSAGE):
        h.present(replace(in_, reputation=in_.evidence[0]), now)  # evidence in the snapshot slot
    with hk.raises(Code.INVALID_MESSAGE):
        h.present(replace(in_, evidence=("not.a.jws",)), now)
    e = replace(hk.b_evidence(), pact_version="0.2")
    signed = hk.sign_evidence(2, "test-issuer-key-1", e)
    with hk.raises(Code.INVALID_MESSAGE, "unsupported-version"):
        h.present(replace(in_, evidence=(signed,)), now)


PROFILE: dict[str, tuple[Callable[[AgentProfile], AgentProfile], str]] = {
    "holder_jkt": (lambda p: replace(p, holder_jkt="A" * 43), Code.INVALID_PROOF),
    "agent": (
        lambda p: replace(p, agent_id="https://identity.example/agents/other"),
        Code.CONTEXT_MISMATCH,
    ),
    "tenant": (lambda p: replace(p, tenant_id="globex"), Code.CONTEXT_MISMATCH),
    "expired": (
        lambda p: replace(p, created_at=1792080000 - 7200, expires_at=1792080000),
        holder.CODE_EXPIRED,
    ),
    "future": (
        lambda p: replace(p, created_at=1792080060, expires_at=1792083600),
        Code.INVALID_MESSAGE,
    ),
    "lifetime": (
        lambda p: replace(p, created_at=1792080000 - 60, expires_at=1792080000 - 60 + 86401),
        Code.INVALID_MESSAGE,
    ),
}


@pytest.mark.parametrize("name", sorted(PROFILE))
def test_profile_checks(ck: Any, hk: Any, name: str) -> None:
    # The profile view must name the holder's agent, key and tenant and be current, with a
    # lifetime of at most 24 hours (draft 8.1, 11.2, Appendix A.2).
    edit, code = PROFILE[name]
    in_ = hk.b_input()
    in_ = replace(in_, profile=edit(in_.profile))
    with hk.raises(code):
        hk.b_holder(hk.memory_key(1)).present(in_, ck.at(ck.B4_TIME))


def test_profile_of_24_hours(ck: Any, hk: Any) -> None:
    in_ = hk.b_input()
    t = ck.B4_TIME
    in_ = replace(in_, profile=replace(in_.profile, created_at=t - 60, expires_at=t - 60 + 86400))
    hk.b_holder(hk.memory_key(1)).present(in_, ck.at(t))


SNAPSHOT: dict[str, Callable[[ReputationSnapshot], ReputationSnapshot]] = {
    "issuer": lambda s: replace(s, iss="https://reputation.example/other"),
    "holder": lambda s: replace(s, holder_jkt="A" * 43),
    "audience": lambda s: replace(s, aud="https://gateway.example/other"),
    "subject": lambda s: replace(s, sub="https://identity.example/agents/other"),
    "env": lambda s: replace(s, environment_id="https://gateway.example/environments/other"),
    "expired": lambda s: replace(s, iat=1792079700, nbf=1792079700, exp=1792080000),
}


@pytest.mark.parametrize("name", sorted(SNAPSHOT))
def test_snapshot_selection(ck: Any, hk: Any, name: str) -> None:
    # A snapshot from a service the rule does not allow, or bound to another holder key,
    # audience or realm, or expired, does not back a reputation rule (draft 15.2).
    in_ = replace(
        hk.b_input(), reputation=hk.sign_snapshot_with(jws.TYP_REPUTATION, SNAPSHOT[name])
    )
    with hk.raises(Code.MISSING_FIELD):
        hk.b_holder(hk.memory_key(1)).present(in_, ck.at(ck.B4_TIME))


def test_snapshot_typ(ck: Any, hk: Any) -> None:
    in_ = replace(hk.b_input(), reputation=hk.sign_snapshot_with(jws.TYP_REPUTATION, lambda s: s))
    hk.b_holder(hk.memory_key(1)).present(in_, ck.at(ck.B4_TIME))
    # One under another typ is refused (draft 7.2).
    in_ = replace(in_, reputation=hk.sign_snapshot_with(jws.TYP_EVIDENCE, lambda s: s))
    with hk.raises(Code.INVALID_MESSAGE):
        hk.b_holder(hk.memory_key(1)).present(in_, ck.at(ck.B4_TIME))
