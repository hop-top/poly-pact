"""Verification of requirement contracts. Port of go/contract/verify_test.go.

The helpers (Appendix B.4 context, keys, payload editing) are the ``ck``
fixture of conftest.py. The tests read spec/v1.0/fixtures and the draft: they fail
when the tree is absent under PACT_REQUIRE_VECTORS=1 (make py-test) and skip
otherwise (a mirror checkout).
"""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Callable
from datetime import timedelta
from typing import Any

import pytest

from hop_top_pact import contract
from hop_top_pact.adapter import Code, Realm
from hop_top_pact.core import jws
from hop_top_pact.core.clock import ClockError, ClockErrorKind

Edit = Callable[[dict[str, Any]], None]


def test_appendix_b4_verifies(ck: Any) -> None:
    # The signed contract of the admission/valid case, whose payload is the
    # Appendix B.4 contract, verifies under the publisher key at the B.4 time and
    # passes the contract-validity and active-policy checks against the B.4 context.
    compact = ck.compact_of(ck.VALID_CONTRACT)
    c = ck.b4_verifier().verify(compact, ck.at(ck.B4_TIME))
    want = ck.canonical(ck.draft_block("B.4"))
    assert ck.canonical(ck.segment(compact, 1)) == want, "fixture payload is not the B.4 contract"
    assert c.compact == compact
    digest = base64.urlsafe_b64encode(hashlib.sha256(compact.encode()).digest()).rstrip(b"=")
    assert c.digest == digest.decode(), "digest is not the artifact_digest"
    c.check(ck.b4_expect())
    c.check_active(ck.b4_policy())
    assert c.nonce_record() == contract.NonceRecord(
        nonce="N8WrKpg8XNb9Wh_QuWlHbw",
        agent_id=ck.B4_AGENT,
        holder_jkt=ck.B4_HOLDER_JKT,
        realm=ck.B4_REALM,
        operation_digest=ck.B4_OP_DIGEST,
        requirements_digest=c.digest,
    )
    assert c.claims.sub == ck.B4_AGENT
    assert c.claims.mode == "enforced"


TAMPERS: dict[str, Edit] = {
    "max_age_seconds": lambda m: m["field_rules"][3].__setitem__("max_age_seconds", 3600),
    "allowed_issuers": lambda m: m["field_rules"][3].__setitem__(
        "allowed_issuers", ["https://attacker.example/issuer"]
    ),
    "rule removed": lambda m: m.__setitem__("field_rules", m["field_rules"][:4]),
    "context check removed": lambda m: m.__setitem__("context_checks", m["context_checks"][:3]),
    "selected_set": lambda m: m.__setitem__("selected_set", "established"),
}


def test_weaker_set_swapped_in_fails_the_signature(ck: Any) -> None:
    # Rules edited after signing fail the publisher signature (INVALID_PROOF): the
    # agent swapped in another set (selection/agent-requests-weaker-set).
    edited = ck.compact_of("selection/agent-requests-weaker-set/signed/contract.jws")
    with ck.raises(Code.INVALID_PROOF):
        ck.b4_verifier().verify(edited, ck.at(ck.B4_TIME + 10))


@pytest.mark.parametrize("name", sorted(TAMPERS))
def test_tampered_rules_rejected(ck: Any, name: str) -> None:
    # ... or changed one member of one rule.
    compact = ck.compact_of(ck.VALID_CONTRACT)
    with ck.raises(Code.INVALID_PROOF):
        ck.b4_verifier().verify(ck.tampered(compact, TAMPERS[name]), ck.at(ck.B4_TIME))


def test_publisher_authority(ck: Any) -> None:
    # Only a key of the trust record that iss names verifies a contract. Another
    # trusted key, or an iss without a trust record, is INVALID_PROOF.
    compact = ck.compact_of(ck.VALID_CONTRACT)
    skew = timedelta(seconds=5)
    verifiers = {
        "no publishers": contract.Verifier(publishers={}, skew=skew),
        "iss not configured": contract.Verifier(
            publishers={"https://trust.example/issuers/payroll": ck.fixture_key_set("issuer")},
            skew=skew,
        ),
        "other key for iss": contract.Verifier(
            publishers={ck.B4_PUBLISHER: ck.fixture_key_set("validator")}, skew=skew
        ),
    }
    for v in verifiers.values():
        with ck.raises(Code.INVALID_PROOF):
            v.verify(compact, ck.at(ck.B4_TIME))
    # A contract signed by the adversarial key under the publisher's kid.
    forged = ck.resign(ck.segment(compact, 0), ck.segment(compact, 1), ck.scalar_key(3))
    with ck.raises(Code.INVALID_PROOF):
        ck.b4_verifier().verify(forged, ck.at(ck.B4_TIME))


@pytest.mark.parametrize(
    ("name", "agent", "audience", "tenant", "env"),
    [
        ("wrong-audience", None, "https://gateway.example/payroll", None, None),
        ("wrong-tenant", None, None, "globex", None),
        ("wrong-environment", None, None, None, "https://gateway.example/environments/payroll"),
    ],
)
def test_wrong_audience_and_realm(
    ck: Any, name: str, agent: str | None, audience: str | None, tenant: str | None, env: str | None
) -> None:
    # The admission cases whose gateway differs from the one the contract names fail
    # the contract-validity check with CONTEXT_MISMATCH (spec/v1.0/fixtures/admission/README.md).
    c = ck.b4_verifier().verify(
        ck.compact_of(f"admission/{name}/signed/contract.jws"), ck.at(ck.B4_TIME)
    )
    expect = contract.Expect(
        agent_id=agent or ck.B4_AGENT,
        audience=audience or ck.B4_GATEWAY,
        realm=Realm(tenant_id=tenant or ck.B4_TENANT, environment_id=env or ck.B4_ENV),
    )
    with ck.raises(Code.CONTEXT_MISMATCH):
        c.check(expect)
    c.check(ck.b4_expect())  # the contract's own context


@pytest.mark.parametrize(
    "expect",
    [
        contract.Expect(
            agent_id="https://identity.example/agents/other",
            audience="https://gateway.example/finance",
            realm=Realm(
                tenant_id="acme", environment_id="https://gateway.example/environments/finance"
            ),
        ),
        contract.Expect(
            audience="https://gateway.example/finance",
            realm=Realm(
                tenant_id="acme", environment_id="https://gateway.example/environments/finance"
            ),
        ),
        contract.Expect(
            agent_id="https://identity.example/agents/invoice-assistant",
            realm=Realm(
                tenant_id="acme", environment_id="https://gateway.example/environments/finance"
            ),
        ),
        contract.Expect(
            agent_id="https://identity.example/agents/invoice-assistant",
            audience="https://gateway.example/finance",
        ),
        contract.Expect(
            agent_id="https://identity.example/agents/invoice-assistant",
            audience="https://gateway.example/finance/",
            realm=Realm(
                tenant_id="acme", environment_id="https://gateway.example/environments/finance"
            ),
        ),
    ],
    ids=["other agent", "empty agent", "empty audience", "empty realm", "audience suffix"],
)
def test_check_context_mismatch(ck: Any, expect: contract.Expect) -> None:
    # An empty field of the expectation matches nothing.
    c = ck.b4_verifier().verify(ck.compact_of(ck.VALID_CONTRACT), ck.at(ck.B4_TIME))
    with ck.raises(Code.CONTEXT_MISMATCH):
        c.check(expect)


def test_unsupported_extension(ck: Any) -> None:
    # admission/unknown-required-extension carries an extension the gateway does not
    # support: contract-validity is UNSUPPORTED_REQUIREMENT, unless it supports it.
    c = ck.b4_verifier().verify(
        ck.compact_of("admission/unknown-required-extension/signed/contract.jws"),
        ck.at(ck.B4_TIME),
    )
    with ck.raises(Code.UNSUPPORTED_REQUIREMENT):
        c.check(ck.b4_expect())
    supported = contract.Expect(
        agent_id=ck.B4_AGENT,
        audience=ck.B4_GATEWAY,
        realm=ck.B4_REALM,
        supported_extensions=("https://extensions.example/pact/geo-fence-v1",),
    )
    c.check(supported)
    # A context mismatch is reported before the unsupported extension.
    other = contract.Expect(
        agent_id=ck.B4_AGENT, audience="https://gateway.example/payroll", realm=ck.B4_REALM
    )
    with ck.raises(Code.CONTEXT_MISMATCH):
        c.check(other)


@pytest.mark.parametrize(
    ("name", "base", "artifact"),
    [
        ("policy-revision-changed", "finance-base-4", None),
        ("selector-rolled-back", None, "rzz4zv_9KiTRHF7_aQVAYUILJEYi0VlrBJDdRRgzCzg"),
    ],
)
def test_requirements_changed(ck: Any, name: str, base: str | None, artifact: str | None) -> None:
    # The selection cases whose active policy changed after issuance fail the
    # active-policy check with REQUIREMENTS_CHANGED.
    c = ck.b4_verifier().verify(
        ck.compact_of(f"selection/{name}/signed/contract.jws"), ck.at(ck.B4_TIME + 10)
    )
    active = contract.Policy(
        base_revision=base or ck.B4_BASE,
        learning_policy_digest=ck.B4_POLICY_DIGEST,
        learning_artifact_digest=artifact or ck.B4_ARTIFACT_DIGEST,
    )
    with ck.raises(contract.CODE_REQUIREMENTS_CHANGED):
        c.check_active(active)
    c.check_active(ck.b4_policy())  # the pinned policy


def test_requirements_changed_on_policy_digest(ck: Any) -> None:
    c = ck.b4_verifier().verify(ck.compact_of(ck.VALID_CONTRACT), ck.at(ck.B4_TIME))
    p = contract.Policy(
        base_revision=ck.B4_BASE,
        learning_policy_digest=ck.B4_ARTIFACT_DIGEST,
        learning_artifact_digest=ck.B4_ARTIFACT_DIGEST,
    )
    with ck.raises(contract.CODE_REQUIREMENTS_CHANGED):
        c.check_active(p)
    with ck.raises(contract.CODE_REQUIREMENTS_CHANGED):
        c.check_active(contract.Policy())  # an empty field matches nothing


def test_expired_contract(ck: Any) -> None:
    # B.4 has exp 1792080060. There is no grace period: at exp, and at exp plus the
    # skew, it is EXPIRED (draft 7.5, 12.2).
    compact = ck.compact_of(ck.VALID_CONTRACT)
    v = ck.b4_verifier()
    v.verify(compact, ck.at(1792080059))
    v.verify(compact, ck.at(1792080059, 999999))
    for now in (1792080060, 1792080065, 1792090000):
        with ck.raises(contract.CODE_EXPIRED):
            v.verify(compact, ck.at(now))


def test_codes(ck: Any) -> None:
    # Every error carries its draft 13.4 code and says which package raised it.
    for code, want in {
        Code.INVALID_MESSAGE: "INVALID_MESSAGE",
        Code.INVALID_PROOF: "INVALID_PROOF",
        Code.CONTEXT_MISMATCH: "CONTEXT_MISMATCH",
        Code.UNSUPPORTED_REQUIREMENT: "UNSUPPORTED_REQUIREMENT",
        contract.CODE_REQUIREMENTS_CHANGED: "REQUIREMENTS_CHANGED",
        contract.CODE_EXPIRED: "EXPIRED",
        contract.CODE_REPLAY: "REPLAY",
        Code.DEPENDENCY_UNAVAILABLE: "DEPENDENCY_UNAVAILABLE",
        contract.CODE_SECURITY_HOLD: "SECURITY_HOLD",
        Code.UNSUPPORTED_PURPOSE: "UNSUPPORTED_PURPOSE",
    }.items():
        e = contract.ContractError(code)
        assert e.code == want
        assert str(e).startswith("contract: ")
    with pytest.raises(contract.ContractError) as ei:
        ck.b4_verifier().verify(ck.compact_of(ck.VALID_CONTRACT), ck.at(1792080060))
    assert ei.value.code == "EXPIRED"
    assert isinstance(ei.value.__cause__, ClockError)
    assert ei.value.__cause__.kind == ClockErrorKind.EXPIRED


def test_time_rules(ck: Any) -> None:
    # nbf and iat later than now plus skew, a lifetime over 60 s (draft 9.1, 20.1) and
    # nbf not before exp (Appendix A.2) are invalid.
    compact = ck.compact_of(ck.VALID_CONTRACT)
    v = ck.b4_verifier()
    # iat = nbf = 1792080000; skew 5 s.
    v.verify(compact, ck.at(ck.B4_TIME - 5))  # issued at now plus skew
    with ck.raises(Code.INVALID_MESSAGE):
        v.verify(compact, ck.at(ck.B4_TIME - 6))

    def lifetime(m: dict[str, Any]) -> None:
        m["exp"] = 1792080061

    def nbf_at_exp(m: dict[str, Any]) -> None:
        # nbf <= now+skew and now < exp hold; only nbf < exp fails.
        m["iat"], m["nbf"], m["exp"] = 1792079990, 1792080003, 1792080003

    def exp_at_iat(m: dict[str, Any]) -> None:
        m["exp"] = 1792080000

    def nbf_future(m: dict[str, Any]) -> None:
        m["nbf"] = 1792080006

    for now, edit in (
        (ck.B4_TIME, lifetime),
        (ck.B4_TIME, nbf_at_exp),
        (ck.B4_TIME - 3, exp_at_iat),
        (ck.B4_TIME, nbf_future),
    ):
        with ck.raises(Code.INVALID_MESSAGE):
            v.verify(ck.resigned(compact, edit), ck.at(now))

    for skew in (timedelta(seconds=6), timedelta(seconds=-1)):
        bad = contract.Verifier(publishers=v.publishers, skew=skew)
        with pytest.raises(ValueError, match="skew"):
            bad.verify(compact, ck.at(ck.B4_TIME))


def rule_edit(i: int, member: str, value: object) -> Edit:
    def edit(m: dict[str, Any]) -> None:
        m["field_rules"][i][member] = value

    return edit


def self_edit(i: int, **members: object) -> Edit:
    def edit(m: dict[str, Any]) -> None:
        r = m["field_rules"][i]
        r.update(source="self", allowed_issuers=[], max_age_seconds=0, status_max_age_seconds=0)
        r.update(members)

    return edit


INVALID: dict[str, Edit] = {
    "unknown member": lambda m: m.__setitem__("max_uses", 2),
    "pact_version": lambda m: m.__setitem__("pact_version", "0.2"),
    "missing nonce": lambda m: m.pop("nonce"),
    "short nonce": lambda m: m.__setitem__("nonce", "N8WrKpg8XNb9Wh_QuWlHb"),
    "nonce not base64url": lambda m: m.__setitem__("nonce", "N8WrKpg8XNb9Wh/QuWlHbw"),
    "short jti": lambda m: m.__setitem__("jti", "zIMh1jdcSU0EP90CYPIbw"),
    "empty sub": lambda m: m.__setitem__("sub", ""),
    "relative aud": lambda m: m.__setitem__("aud", "gateway.example/finance"),
    "empty tenant": lambda m: m.__setitem__("tenant_id", ""),
    "empty contract_id": lambda m: m.__setitem__("contract_id", ""),
    "empty base_revision": lambda m: m.__setitem__("base_revision", ""),
    "empty selected_set": lambda m: m.__setitem__("selected_set", ""),
    "holder_jkt": lambda m: m.__setitem__("holder_jkt", "xx0BcA"),
    "operation_digest": lambda m: m.__setitem__(
        "operation_digest", "R5nfhv7g_o93VPHK6a2o56-MyyGy75GQwXxDM4M3cn="
    ),
    "mode": lambda m: m.__setitem__("mode", "permissive"),
    "no context checks": lambda m: m.__setitem__("context_checks", []),
    "duplicate context check": lambda m: m.__setitem__(
        "context_checks", ["security-hold-v1", "security-hold-v1"]
    ),
    "field_rules null": lambda m: m.__setitem__("field_rules", None),
    "field_rules absent": lambda m: m.pop("field_rules"),
    "allowed_issuers absent": lambda m: m["field_rules"][0].pop("allowed_issuers"),
    "schema absent": lambda m: m["field_rules"][0].pop("schema"),
    "schema null": rule_edit(0, "schema", None),
    "duplicate rule_id": rule_edit(1, "rule_id", "principal"),
    "empty rule_id": rule_edit(0, "rule_id", ""),
    "path not a pointer": rule_edit(0, "path", "attributes/environment/principal_id"),
    "path bad escape": rule_edit(0, "path", "/attributes/a~2b"),
    "schema string": rule_edit(0, "schema", "string"),
    "source": rule_edit(0, "source", "agent"),
    "comparison": rule_edit(0, "comparison", "contains"),
    "native with issuers": rule_edit(
        0, "allowed_issuers", ["https://trust.example/issuers/finance"]
    ),
    "native without path": rule_edit(0, "native_path", None),
    "native_path not pointer": rule_edit(0, "native_path", "principal/id"),
    "evidence without issuers": rule_edit(3, "allowed_issuers", []),
    "evidence with path": rule_edit(3, "native_path", "/principal/id"),
    "duplicate issuers": rule_edit(
        3,
        "allowed_issuers",
        ["https://trust.example/issuers/finance", "https://trust.example/issuers/finance"],
    ),
    "relative issuer": rule_edit(3, "allowed_issuers", ["trust.example"]),
    "negative age": rule_edit(3, "max_age_seconds", -1),
    "self with issuers": self_edit(3, allowed_issuers=["https://trust.example/issuers/finance"]),
    "self with native_path": self_edit(0),
    "self subset": self_edit(3, comparison="subset"),
    "self with age": self_edit(3, max_age_seconds=30),
    "self with status age": self_edit(3, status_max_age_seconds=1),
}


@pytest.mark.parametrize("name", sorted(INVALID))
def test_invalid_contracts(ck: Any, name: str) -> None:
    # A contract signed by the publisher that breaks the schema or Appendix A.2 is
    # INVALID_MESSAGE.
    compact = ck.compact_of(ck.VALID_CONTRACT)
    with ck.raises(Code.INVALID_MESSAGE):
        ck.b4_verifier().verify(ck.resigned(compact, INVALID[name]), ck.at(ck.B4_TIME))


def test_valid_variants_accepted(ck: Any) -> None:
    compact = ck.compact_of(ck.VALID_CONTRACT)
    v = ck.b4_verifier()
    now = ck.at(ck.B4_TIME)
    v.verify(ck.resigned(compact, self_edit(3)), now)  # a valid self rule
    v.verify(ck.resigned(compact, rule_edit(0, "schema", True)), now)  # a boolean schema
    v.verify(ck.resigned(compact, rule_edit(0, "schema", False)), now)


def test_other_typ_is_invalid_message(ck: Any) -> None:
    # The evidence typ under the publisher key.
    compact = ck.compact_of(ck.VALID_CONTRACT)
    ev = jws.sign(
        jws.Header(typ=jws.TYP_EVIDENCE, kid="test-issuer-key-1"),
        ck.segment(compact, 1),
        ck.scalar_key(2),
    )
    with ck.raises(Code.INVALID_MESSAGE):
        ck.b4_verifier().verify(ev, ck.at(ck.B4_TIME))


@pytest.mark.parametrize("name", ["empty", "two segments", "not base64"])
def test_malformed_jws(ck: Any, name: str) -> None:
    compact = ck.compact_of(ck.VALID_CONTRACT)
    s = {
        "empty": "",
        "two segments": ".".join(compact.split(".")[:2]),
        "not base64": "!" + compact,
    }[name]
    with ck.raises(Code.INVALID_MESSAGE):
        ck.b4_verifier().verify(s, ck.at(ck.B4_TIME))


def test_payload_is_the_b4_contract_json(ck: Any) -> None:
    compact = ck.compact_of(ck.VALID_CONTRACT)
    assert json.loads(ck.segment(compact, 1)) == json.loads(ck.draft_block("B.4"))
