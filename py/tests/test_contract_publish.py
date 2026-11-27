"""Issuance of requirement contracts. Port of go/contract/publish_test.go.

The Go test of a cancelled context has no counterpart: the calls take no
context argument (docs/sdk/parity-ledger.md, deviation adapter calls). A
FieldRule holds allowed_issuers as a tuple, which cannot be nil, so the "nil
issuers" case has none either.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import replace
from datetime import datetime, timedelta
from typing import Any, cast

import pytest

from hop_top_pact import contract
from hop_top_pact.adapter import AgentBinding, BindingStatus, Code, Principal
from hop_top_pact.core import strictjson
from hop_top_pact.core.enums import Mode
from hop_top_pact.core.types import ContractRequest, RequirementContract

RANDOM_ID = re.compile(r"^[A-Za-z0-9_-]{22}$")
NativeEdit = Callable[
    [ContractRequest, contract.Authenticated], tuple[ContractRequest, contract.Authenticated]
]
ReqEdit = Callable[[contract.Requirements], contract.Requirements]


def test_issue_appendix_b4(ck: Any) -> None:
    # The B.2 intent, the B.3 operation and the B.4 requirements, issued at the B.4
    # time, give the B.4 contract: every claim but the random jti, contract_id and
    # nonce is the B.4 value.
    store = contract.MemoryReplay()
    c = ck.new_publisher(store).issue(
        ck.b4_request(), ck.b4_auth(), ck.b4_requirements(), ck.at(ck.B4_TIME)
    )
    want = strictjson.decode(ck.draft_block("B.4"), RequirementContract)
    got = c.claims
    ids = {"jti": got.jti, "nonce": got.nonce, "contract_id": got.contract_id}
    for name, i in ids.items():
        assert RANDOM_ID.match(i), f"{name} {i!r} is not 128 bits of base64url"
    assert len(set(ids.values())) == 3, "jti, nonce and contract_id are not distinct"
    assert replace(got, jti=want.jti, nonce=want.nonce, contract_id=want.contract_id) == want
    # The payload of the JWS is the claims.
    assert strictjson.decode(ck.segment(c.compact, 1), RequirementContract) == c.claims


def test_round_trip(ck: Any) -> None:
    # An issued contract verifies, passes the contract-validity and active-policy
    # checks, and its nonce is registered: consumed once, then REPLAY.
    store = contract.MemoryReplay()
    issued = ck.new_publisher(store).issue(
        ck.b4_request(), ck.b4_auth(), ck.b4_requirements(), ck.at(ck.B4_TIME)
    )
    now = ck.at(ck.B4_TIME + 10)
    got = ck.b4_verifier().verify(issued.compact, now)
    assert got == issued
    got.check(ck.b4_expect())
    got.check_active(ck.b4_policy())
    r = got.nonce_record()
    assert r == contract.NonceRecord(
        nonce=issued.claims.nonce,
        agent_id=ck.B4_AGENT,
        holder_jkt=ck.B4_HOLDER_JKT,
        realm=ck.B4_REALM,
        operation_digest=ck.B4_OP_DIGEST,
        requirements_digest=issued.digest,
    )
    until = ck.at(ck.B4_TIME + 75)
    store.consume(r, now, until)
    with ck.raises(contract.CODE_REPLAY):
        store.consume(r, now, until)
    with ck.raises(contract.CODE_REPLAY):
        store.consume(r, ck.at(ck.B4_TIME + 20), until)

    # Two contracts never share a nonce.
    again = ck.new_publisher(store).issue(
        ck.b4_request(), ck.b4_auth(), ck.b4_requirements(), ck.at(ck.B4_TIME)
    )
    assert again.claims.nonce != issued.claims.nonce
    assert again.claims.jti != issued.claims.jti


@pytest.mark.parametrize(
    ("lifetime", "exp"),
    [
        (timedelta(0), 60),
        (timedelta(seconds=30), 30),
        (timedelta(seconds=60), 60),
        (timedelta(seconds=1), 1),
    ],
)
def test_issue_lifetime(ck: Any, lifetime: timedelta, exp: int) -> None:
    # exp is iat plus the lifetime, 60 s by default, never more (draft 9.1, 20.1).
    p = ck.new_publisher(contract.MemoryReplay())
    p.lifetime = lifetime
    c = p.issue(ck.b4_request(), ck.b4_auth(), ck.b4_requirements(), ck.at(ck.B4_TIME, 900000))
    assert (c.claims.iat, c.claims.nbf, c.claims.exp) == (
        ck.B4_TIME,
        ck.B4_TIME,
        ck.B4_TIME + exp,
    )


@pytest.mark.parametrize(
    "lifetime",
    [
        timedelta(seconds=61),
        timedelta(hours=1),
        timedelta(seconds=-1),
        timedelta(milliseconds=1500),
        timedelta(milliseconds=1),
    ],
)
def test_issue_lifetime_refused(ck: Any, lifetime: timedelta) -> None:
    p = ck.new_publisher(contract.MemoryReplay())
    p.lifetime = lifetime
    with pytest.raises(ValueError, match="lifetime"):
        p.issue(ck.b4_request(), ck.b4_auth(), ck.b4_requirements(), ck.at(ck.B4_TIME))


def with_realm(**kw: Any) -> NativeEdit:
    return lambda req, a: (
        req,
        replace(a, principal=replace(a.principal, realm=replace(a.principal.realm, **kw))),
    )


def with_binding(binding: AgentBinding | None = None, **kw: Any) -> NativeEdit:
    return lambda req, a: (
        req,
        replace(a, binding=binding if binding is not None else replace(a.binding, **kw)),
    )


def with_request(**kw: Any) -> NativeEdit:
    return lambda req, a: (replace(req, **kw), a)


def with_operation(**kw: Any) -> NativeEdit:
    return lambda req, a: (replace(req, operation=replace(req.operation, **kw)), a)


NATIVE_CONTEXT: list[tuple[str, NativeEdit, str]] = [
    ("no principal", lambda req, a: (req, replace(a, principal=Principal())), Code.INVALID_PROOF),
    ("principal in other tenant", with_realm(tenant_id="globex"), Code.CONTEXT_MISMATCH),
    (
        "principal in other environment",
        with_realm(environment_id="https://gateway.example/environments/payroll"),
        Code.CONTEXT_MISMATCH,
    ),
    ("binding unknown", with_binding(status=BindingStatus.UNKNOWN), Code.INVALID_PROOF),
    ("binding absent", with_binding(AgentBinding()), Code.INVALID_PROOF),
    ("binding revoked", with_binding(status=BindingStatus.REVOKED), Code.INVALID_PROOF),
    (
        "binding compromised",
        with_binding(status=BindingStatus.COMPROMISED),
        contract.CODE_SECURITY_HOLD,
    ),
    (
        "agent enrolled for another workload",
        with_binding(AgentBinding(status=BindingStatus.UNKNOWN, enrolled_elsewhere=True)),
        Code.CONTEXT_MISMATCH,
    ),
    (
        "request names another agent",
        with_request(agent_id="https://identity.example/agents/other"),
        Code.INVALID_PROOF,
    ),
    (
        "request names another key",
        with_request(holder_jkt="ahxE1XEYqxvLIZy3r4nx9RE4E0683KndykyuZTK9xQg"),
        Code.INVALID_PROOF,
    ),
    (
        "operation of another principal",
        with_operation(principal_id="https://identity.example/principals/bob"),
        Code.CONTEXT_MISMATCH,
    ),
    (
        "operation in another environment",
        with_operation(environment_id="https://gateway.example/environments/payroll"),
        Code.CONTEXT_MISMATCH,
    ),
    (
        "request extension",
        with_request(extensions={"https://extensions.example/x": True}),
        Code.UNSUPPORTED_REQUIREMENT,
    ),
]


@pytest.mark.parametrize(
    ("name", "edit", "code"), NATIVE_CONTEXT, ids=[n for n, _, _ in NATIVE_CONTEXT]
)
def test_issue_requires_native_context(ck: Any, name: str, edit: NativeEdit, code: str) -> None:
    # No contract without native authentication and a trustworthy agent/key binding
    # for the agent and key the request names, in the publisher's realm (draft 9.1,
    # 11.1 step 1); nothing is registered.
    store = Counting()
    req, auth = edit(ck.b4_request(), ck.b4_auth())
    with ck.raises(code):
        ck.new_publisher(store).issue(req, auth, ck.b4_requirements(), ck.at(ck.B4_TIME))
    assert store.registered == 0


def with_rule(i: int, **kw: Any) -> ReqEdit:
    def edit(r: contract.Requirements) -> contract.Requirements:
        rules = list(r.field_rules)
        rules[i] = replace(rules[i], **kw)
        return replace(r, field_rules=tuple(rules))

    return edit


REQUIREMENTS: list[tuple[str, ReqEdit]] = [
    ("weaker set without selection check", lambda r: replace(r, selected_set="established")),
    ("no conservative set", lambda r: replace(r, conservative_set="")),
    ("no selected set", lambda r: replace(r, selected_set="", conservative_set="")),
    ("no base revision", lambda r: replace(r, policy=replace(r.policy, base_revision=""))),
    (
        "bad learning digest",
        lambda r: replace(r, policy=replace(r.policy, learning_policy_digest="x")),
    ),
    ("no context checks", lambda r: replace(r, context_checks=())),
    ("no mode", lambda r: replace(r, mode=cast(Mode, ""))),
    ("duplicate rule", lambda r: replace(r, field_rules=(*r.field_rules, r.field_rules[0]))),
    ("evidence rule without issuer", with_rule(3, allowed_issuers=())),
]


@pytest.mark.parametrize(("name", "edit"), REQUIREMENTS, ids=[n for n, _ in REQUIREMENTS])
def test_issue_requirements_refused(ck: Any, name: str, edit: ReqEdit) -> None:
    # The publisher signs only a complete, valid effective set (draft 9.2, 9.4,
    # Appendix A.2).
    r = edit(ck.b4_requirements())
    with ck.raises(Code.INVALID_MESSAGE):
        ck.new_publisher(contract.MemoryReplay()).issue(
            ck.b4_request(), ck.b4_auth(), r, ck.at(ck.B4_TIME)
        )


def test_issue_requirements_accepted(ck: Any) -> None:
    def issue(r: contract.Requirements) -> contract.Contract:
        c: contract.Contract = ck.new_publisher(contract.MemoryReplay()).issue(
            ck.b4_request(), ck.b4_auth(), r, ck.at(ck.B4_TIME)
        )
        return c

    # A weaker set that lists the selection check is issued.
    r = ck.b4_requirements()
    issue(
        replace(
            r,
            selected_set="established",
            context_checks=(*r.context_checks, contract.SELECTION_CONSISTENCY_CHECK),
        )
    )
    # No field rules is a valid set (minItems 0); the payload has an array.
    c = issue(replace(r, field_rules=()))
    assert ck.b4_verifier().verify(c.compact, ck.at(ck.B4_TIME)).claims.field_rules == ()
    assert b'"field_rules":[]' in ck.segment(c.compact, 1)
    # Bound extensions are signed into the contract.
    ext = {"pact-transport-profile-v1": {"transport_profile": "https", "version": "0.1"}}
    c = issue(replace(r, extensions=ext))
    v = ck.b4_verifier().verify(c.compact, ck.at(ck.B4_TIME))
    with ck.raises(Code.UNSUPPORTED_REQUIREMENT):
        v.check(ck.b4_expect())
    v.check(replace(ck.b4_expect(), supported_extensions=("pact-transport-profile-v1",)))
    assert v.transport() == contract.TRANSPORT_HTTPS


@pytest.mark.parametrize(
    "edit",
    [
        lambda p: setattr(p, "issuer", ""),
        lambda p: setattr(p, "audience", ""),
        lambda p: setattr(p, "realm", replace(p.realm, tenant_id="")),
        lambda p: setattr(p, "signer", None),
        lambda p: setattr(p, "replay", None),
    ],
    ids=["no issuer", "no audience", "no tenant", "no signer", "no store"],
)
def test_issue_publisher_config(ck: Any, edit: Callable[[contract.Publisher], None]) -> None:
    # A publisher without identity, signer or store issues nothing.
    p = ck.new_publisher(contract.MemoryReplay())
    edit(p)
    with pytest.raises(ValueError, match="publisher"):
        p.issue(ck.b4_request(), ck.b4_auth(), ck.b4_requirements(), ck.at(ck.B4_TIME))


class Counting(contract.MemoryReplay):
    """A MemoryReplay that counts the nonces registered."""

    def __init__(self, max_records: int = 0) -> None:
        super().__init__(max_records)
        self.registered = 0

    def register(self, r: contract.NonceRecord, now: datetime, until: datetime) -> None:
        self.registered += 1
        super().register(r, now, until)


class FailingStore:
    def __init__(self, err: Exception) -> None:
        self.err = err

    def register(self, r: contract.NonceRecord, now: datetime, until: datetime) -> None:
        raise self.err

    def consume(self, r: contract.NonceRecord, now: datetime, until: datetime) -> None:
        raise self.err


class FuncSigner:
    def __init__(self, f: Callable[[bytes], str]) -> None:
        self.f = f

    def sign_contract(self, payload: bytes) -> str:
        return self.f(payload)


def test_issue_fails_closed(ck: Any) -> None:
    # An unavailable store or a failing signer issues no contract
    # (DEPENDENCY_UNAVAILABLE), and a signer that signs other bytes is refused.
    def issue(p: contract.Publisher) -> contract.Contract:
        return p.issue(ck.b4_request(), ck.b4_auth(), ck.b4_requirements(), ck.at(ck.B4_TIME))

    with ck.raises(Code.DEPENDENCY_UNAVAILABLE):
        issue(ck.new_publisher(FailingStore(RuntimeError("store down"))))
    # A store that reports the nonce as known.
    with ck.raises(contract.CODE_REPLAY):
        issue(ck.new_publisher(FailingStore(contract.ContractError(contract.CODE_REPLAY))))
    p = ck.new_publisher(contract.MemoryReplay(1))
    issue(p)
    with ck.raises(Code.DEPENDENCY_UNAVAILABLE):
        issue(p)

    def hsm_down(_: bytes) -> str:
        raise RuntimeError("hsm down")

    p = ck.new_publisher(contract.MemoryReplay())
    p.signer = FuncSigner(hsm_down)
    with ck.raises(Code.DEPENDENCY_UNAVAILABLE):
        issue(p)

    other = ck.compact_of(ck.VALID_CONTRACT)
    p.signer = FuncSigner(lambda _: other)
    with pytest.raises(ValueError, match="other bytes"):
        issue(p)
    p.signer = FuncSigner(lambda _: "not-a-jws")
    with pytest.raises(ValueError, match="compact JWS"):
        issue(p)


def test_issue_registers_the_nonce_it_signed(ck: Any) -> None:
    store = contract.MemoryReplay()
    c = ck.new_publisher(store).issue(
        ck.b4_request(), ck.b4_auth(), ck.b4_requirements(), ck.at(ck.B4_TIME)
    )
    store.consume(c.nonce_record(), ck.at(ck.B4_TIME), ck.at(ck.B4_TIME + 65))
    with ck.raises(contract.CODE_REPLAY):
        store.consume(c.nonce_record(), ck.at(ck.B4_TIME), ck.at(ck.B4_TIME + 65))


def test_issue_refusal_codes(ck: Any) -> None:
    # The issuance refusals of draft 9.1 and 10.1: a compromised binding is
    # SECURITY_HOLD, an unrecognized purpose UNSUPPORTED_PURPOSE, each a transport
    # error that issues no contract and registers no nonce.
    store = Counting()
    auth = ck.b4_auth()
    auth = replace(auth, binding=replace(auth.binding, status=BindingStatus.COMPROMISED))
    with ck.raises("SECURITY_HOLD"):
        ck.new_publisher(store).issue(
            ck.b4_request(), auth, ck.b4_requirements(), ck.at(ck.B4_TIME)
        )
    p = ck.new_publisher(store)
    p.purposes = ("https://policies.example/purposes/other/v1",)
    with ck.raises("UNSUPPORTED_PURPOSE"):
        p.issue(ck.b4_request(), ck.b4_auth(), ck.b4_requirements(), ck.at(ck.B4_TIME))
    assert store.registered == 0, "nonces registered by refused requests"
    # The installed purpose of B.2 is issued for.
    p.purposes = (*p.purposes, "https://policies.example/purposes/invoice-summary/v1")
    p.issue(ck.b4_request(), ck.b4_auth(), ck.b4_requirements(), ck.at(ck.B4_TIME))


def test_request_type_is_the_wire_type(ck: Any) -> None:
    assert isinstance(ck.b4_request(), ContractRequest)
