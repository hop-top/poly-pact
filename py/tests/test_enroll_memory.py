"""The in-memory enrollment registry.

Port of go/adapter/enroll/memory/registry_test.go: identity mapping IM-11
(resolution results), IM-18 (selection by the presented agent) and IM-19
(dedicated workloads by default) of spec/v1.0/profiles/identity-mapping.md, and
draft 6.1, 6.4 and 17.1. Go's TestCanceledContext has no counterpart: the
Python calls take no context.
"""

from __future__ import annotations

import base64
import hashlib
import threading
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from hop_top_pact.adapter import (
    AgentBinding,
    AgentID,
    BindingResolver,
    BindingStatus,
    Realm,
    UnsupportedRequirement,
    Workload,
)
from hop_top_pact.adapter.enroll import (
    Actor,
    ActorKind,
    AuditAction,
    AuditResult,
    EnrollError,
    EnrollErrorKind,
    Registry,
    Resolver,
)
from hop_top_pact.adapter.enroll_memory import (
    DEFAULT_SOURCE_ID,
    Enrollment,
    MemoryRegistry,
    Option,
    with_clock,
    with_shared_workloads,
    with_source_id,
)
from hop_top_pact.core.clock import FakeClock, SystemClock

REALM = Realm(tenant_id="tenant-1", environment_id="prod")
OTHER_TENANT = Realm(tenant_id="tenant-2", environment_id="prod")
OTHER_ENV = Realm(tenant_id="tenant-1", environment_id="staging")

ADMIN = Actor(kind=ActorKind.ADMIN, id="admin-1", realm=REALM)
ISSUER = Actor(kind=ActorKind.AUTHORIZED_ISSUER, id="issuer-1", realm=REALM)

AGENT_A = "https://agents.example/a"
AGENT_B = "https://agents.example/b"

WORKLOAD_A = "acct:1001"
WORKLOAD_B = "acct:1002"
SHARED = "acct:shared"

START = datetime.fromtimestamp(1_700_000_000, UTC)


def jkt(label: str) -> str:
    """A valid 43-character thumbprint derived from label."""
    sum_ = hashlib.sha256(label.encode()).digest()
    return base64.urlsafe_b64encode(sum_).rstrip(b"=").decode()


class Fixture:
    def __init__(self, *opts: Option) -> None:
        self.clk = FakeClock(START)
        self.reg = MemoryRegistry(with_clock(self.clk), with_source_id("test-source"), *opts)

    def enroll(self, agent: str, wl: Workload, key: str) -> None:
        self.reg.enroll(
            ADMIN, Enrollment(agent_id=agent, operator_id="op-1", workload=wl, holder_jkt=key)
        )

    def lookup(self, r: Realm, wl: Workload, agent: AgentID) -> AgentBinding:
        return self.reg.lookup(r, wl, agent)

    def want_binding(self, wl: Workload, agent: AgentID, status: BindingStatus, key: str) -> None:
        b = self.lookup(REALM, wl, agent)
        assert (b.status, b.holder_jkt) == (status, key), (wl, agent)


def kind_of(fn: Callable[[], object]) -> EnrollErrorKind | None:
    try:
        fn()
    except EnrollError as e:
        return e.kind
    return None


def test_registry_satisfies_the_protocols() -> None:
    reg = MemoryRegistry()
    _r: Registry = reg  # checked by mypy
    _b: BindingResolver = Resolver(registry=reg)
    assert isinstance(reg, Registry)


def test_lookup_active() -> None:
    f = Fixture()
    f.enroll(AGENT_A, WORKLOAD_A, jkt("a1"))
    got = f.lookup(REALM, WORKLOAD_A, AGENT_A)
    assert (got.agent_id, got.operator_id, got.holder_jkt) == (AGENT_A, "op-1", jkt("a1"))
    assert got.status == BindingStatus.ACTIVE
    assert (got.observed_at, got.status_checked_at) == (START, START)
    assert got.source_id == "test-source"
    assert got.source_ref != "", "want an opaque row reference"


def test_lookup_keeps_observation_time() -> None:
    """Draft 17.1 invariant 2: a read confirms the status now; it never restamps
    the original observation."""
    f = Fixture()
    f.enroll(AGENT_A, WORKLOAD_A, jkt("a1"))
    f.clk.advance(timedelta(seconds=90))
    got = f.lookup(REALM, WORKLOAD_A, AGENT_A)
    assert got.observed_at == START
    assert got.status_checked_at == START + timedelta(seconds=90)


def test_source_ref_is_stable_per_enrollment() -> None:
    f = Fixture()
    f.enroll(AGENT_A, WORKLOAD_A, jkt("a1"))
    f.enroll(AGENT_B, WORKLOAD_B, jkt("b1"))
    before = f.lookup(REALM, WORKLOAD_A, AGENT_A).source_ref
    f.reg.rotate(ADMIN, AGENT_A, jkt("a2"))
    assert f.lookup(REALM, WORKLOAD_A, AGENT_A).source_ref == before
    assert f.lookup(REALM, WORKLOAD_B, AGENT_B).source_ref != before


def test_lookup_not_enrolled() -> None:
    f = Fixture()
    f.enroll(AGENT_A, WORKLOAD_A, jkt("a1"))
    f.clk.advance(timedelta(minutes=1))
    got = f.reg.lookup(REALM, "acct:9999", AGENT_A)  # an absent binding is UNKNOWN, not an error
    assert got.status == BindingStatus.UNKNOWN
    assert (got.agent_id, got.operator_id, got.holder_jkt) == ("", "", "")
    assert got.observed_at is None, "nothing was observed"
    assert got.status_checked_at == f.clk.now()
    assert got.source_id == "test-source"


@pytest.mark.parametrize(
    ("r", "wl", "agent"),
    [
        pytest.param(OTHER_TENANT, "User:Alice", AGENT_A, id="other tenant"),
        pytest.param(OTHER_ENV, "User:Alice", AGENT_A, id="other environment"),
        pytest.param(Realm(), "User:Alice", AGENT_A, id="zero realm"),
        pytest.param(REALM, "user:alice", AGENT_A, id="other case"),
        pytest.param(REALM, "User:Alice ", AGENT_A, id="trailing space"),
        pytest.param(REALM, "", AGENT_A, id="empty workload"),
        pytest.param(REALM, "User:Alice", "https://agents.example/A", id="agent in other case"),
        pytest.param(REALM, "User:Alice", AGENT_A + "/", id="agent with trailing slash"),
        pytest.param(REALM, "User:Alice", "", id="empty agent"),
    ],
)
def test_lookup_distinguishes_realm_and_workload(r: Realm, wl: Workload, agent: AgentID) -> None:
    """The same workload text in another tenant or environment, and a near-miss
    spelling of the workload or of the agent ID, is another identity (draft
    8.5, 17.2)."""
    f = Fixture()
    f.enroll(AGENT_A, "User:Alice", jkt("a1"))
    got = f.lookup(r, wl, agent)
    assert (got.status, got.agent_id) == (BindingStatus.UNKNOWN, "")
    f.want_binding("User:Alice", AGENT_A, BindingStatus.ACTIVE, jkt("a1"))


def test_lookup_enrolled_elsewhere() -> None:
    """IM-11: an UNKNOWN answer reports whether the agent ID is enrolled for
    another workload of the realm, in any status (draft 17.1). A binding on the
    workload never carries the report, and an enrollment in another tenant or
    environment never sets it."""
    agent_d = "https://agents.example/d"
    f = Fixture()
    f.enroll(AGENT_A, SHARED, jkt("a1"))
    f.enroll(AGENT_B, WORKLOAD_B, jkt("b1"))
    f.reg.revoke(ADMIN, AGENT_B)
    other = Actor(kind=ActorKind.ADMIN, id="admin-2", realm=OTHER_ENV)
    f.reg.enroll(
        other,
        Enrollment(agent_id=agent_d, operator_id="op-1", workload=WORKLOAD_A, holder_jkt=jkt("d1")),
    )
    unknown = BindingStatus.UNKNOWN
    rows = [
        ("binding on the workload", REALM, SHARED, AGENT_A, BindingStatus.ACTIVE, False),
        (
            "revoked binding on the workload",
            REALM,
            WORKLOAD_B,
            AGENT_B,
            BindingStatus.REVOKED,
            False,
        ),
        ("agent of another workload", REALM, WORKLOAD_A, AGENT_A, unknown, True),
        ("revoked agent of another workload", REALM, SHARED, AGENT_B, unknown, True),
        ("agent not enrolled", REALM, SHARED, "https://agents.example/c", unknown, False),
        ("agent of another environment only", REALM, SHARED, agent_d, unknown, False),
        ("another environment, same workload text", REALM, WORKLOAD_A, agent_d, unknown, False),
        (
            "agent of the realm, asked in another tenant",
            OTHER_TENANT,
            WORKLOAD_A,
            AGENT_A,
            unknown,
            False,
        ),
        ("no agent named", REALM, SHARED, "", unknown, False),
    ]
    for name, r, wl, agent, status, elsewhere in rows:
        got = f.lookup(r, wl, agent)
        assert (got.status, got.enrolled_elsewhere) == (status, elsewhere), name
    f.reg.mark_compromised(ADMIN, AGENT_A)
    got = f.lookup(REALM, WORKLOAD_A, AGENT_A)
    assert (got.status, got.enrolled_elsewhere) == (unknown, True), "compromised, other workload"


GOOD = Enrollment(agent_id=AGENT_A, operator_id="op-1", workload=WORKLOAD_A, holder_jkt=jkt("a1"))


@pytest.mark.parametrize(
    ("actor", "e", "want"),
    [
        pytest.param(
            Actor(kind=ActorKind.AGENT, id=AGENT_A, realm=REALM),
            GOOD,
            EnrollErrorKind.NOT_AUTHORIZED,
            id="agent enrolling itself",
        ),
        pytest.param(Actor(), GOOD, EnrollErrorKind.NOT_AUTHORIZED, id="empty actor"),
        pytest.param(
            ADMIN,
            replace(GOOD, agent_id="agent-a"),
            EnrollErrorKind.INVALID,
            id="relative agent id",
        ),
        pytest.param(
            ADMIN, replace(GOOD, agent_id=""), EnrollErrorKind.INVALID, id="empty agent id"
        ),
        pytest.param(
            ADMIN,
            replace(GOOD, agent_id=AGENT_A + "#x"),
            EnrollErrorKind.INVALID,
            id="agent id with fragment",
        ),
        pytest.param(
            ADMIN,
            replace(GOOD, agent_id=AGENT_A + "#"),
            EnrollErrorKind.INVALID,
            id="agent id with empty fragment",
        ),
        pytest.param(
            ADMIN,
            replace(GOOD, agent_id="https://agents.example/a b"),
            EnrollErrorKind.INVALID,
            id="agent id with space",
        ),
        pytest.param(
            ADMIN, replace(GOOD, operator_id=""), EnrollErrorKind.INVALID, id="empty operator"
        ),
        pytest.param(
            ADMIN, replace(GOOD, workload=""), EnrollErrorKind.INVALID, id="empty workload"
        ),
        pytest.param(
            ADMIN, replace(GOOD, holder_jkt="abc"), EnrollErrorKind.INVALID, id="short key"
        ),
        pytest.param(
            ADMIN,
            replace(GOOD, holder_jkt=jkt("a1") + "="),
            EnrollErrorKind.INVALID,
            id="padded key",
        ),
    ],
)
def test_enroll_requires_authority_and_valid_input(
    actor: Actor, e: Enrollment, want: EnrollErrorKind
) -> None:
    f = Fixture()
    assert kind_of(lambda: f.reg.enroll(actor, e)) == want
    assert f.lookup(REALM, WORKLOAD_A, AGENT_A).status == BindingStatus.UNKNOWN


def test_enroll_conflicts() -> None:
    f = Fixture()
    f.enroll(AGENT_A, WORKLOAD_A, jkt("a1"))
    # Same agent_id again, even with a new key and workload.
    again = Enrollment(
        agent_id=AGENT_A, operator_id="op-2", workload=WORKLOAD_B, holder_jkt=jkt("a9")
    )
    assert kind_of(lambda: f.reg.enroll(ADMIN, again)) == EnrollErrorKind.ALREADY_ENROLLED
    # A holder key already bound to another agent of the realm.
    shared_key = Enrollment(
        agent_id=AGENT_B, operator_id="op-1", workload=WORKLOAD_B, holder_jkt=jkt("a1")
    )
    assert kind_of(lambda: f.reg.enroll(ADMIN, shared_key)) == EnrollErrorKind.KEY_REUSE
    f.want_binding(WORKLOAD_A, AGENT_A, BindingStatus.ACTIVE, jkt("a1"))
    assert f.lookup(REALM, WORKLOAD_B, AGENT_B).status == BindingStatus.UNKNOWN


def test_enroll_is_realm_scoped() -> None:
    """The same agent_id and the same key in another realm are separate
    enrollments, and an admin acts only in its own realm."""
    f = Fixture()
    f.enroll(AGENT_A, WORKLOAD_A, jkt("a1"))
    other = Actor(kind=ActorKind.ADMIN, id="admin-2", realm=OTHER_TENANT)
    f.reg.enroll(
        other,
        Enrollment(agent_id=AGENT_A, operator_id="op-9", workload=WORKLOAD_A, holder_jkt=jkt("a1")),
    )
    got = f.lookup(OTHER_TENANT, WORKLOAD_A, AGENT_A)
    assert (got.operator_id, got.status) == ("op-9", BindingStatus.ACTIVE)
    assert f.lookup(REALM, WORKLOAD_A, AGENT_A).operator_id == "op-1"


@pytest.mark.parametrize(
    "actor",
    [
        pytest.param(
            Actor(kind=ActorKind.AGENT, id=AGENT_A, realm=REALM), id="agent with the old key"
        ),
        pytest.param(
            Actor(kind=ActorKind.AGENT, id="admin-1", realm=REALM), id="agent claiming admin id"
        ),
        pytest.param(Actor(), id="zero actor"),
        pytest.param(Actor(kind="OPERATOR", id="op-1", realm=REALM), id="undefined kind"),
        pytest.param(Actor(kind=ActorKind.ADMIN, realm=REALM), id="admin without id"),
        pytest.param(Actor(kind=ActorKind.ADMIN, id="admin-1"), id="admin without realm"),
    ],
)
def test_rotate_requires_admin_or_issuer(actor: Actor) -> None:
    """The first required case: rotation by a non-admin is rejected and leaves the
    binding untouched (draft 6.4)."""
    f = Fixture()
    f.enroll(AGENT_A, WORKLOAD_A, jkt("a1"))
    assert (
        kind_of(lambda: f.reg.rotate(actor, AGENT_A, jkt("a2"))) == EnrollErrorKind.NOT_AUTHORIZED
    )
    f.want_binding(WORKLOAD_A, AGENT_A, BindingStatus.ACTIVE, jkt("a1"))


@pytest.mark.parametrize("actor", [ADMIN, ISSUER], ids=["admin", "authorized issuer"])
def test_rotate_by_admin_and_issuer(actor: Actor) -> None:
    f = Fixture()
    f.enroll(AGENT_A, WORKLOAD_A, jkt("a1"))
    f.clk.advance(timedelta(hours=1, minutes=1))
    f.reg.rotate(actor, AGENT_A, jkt("a2"))
    got = f.lookup(REALM, WORKLOAD_A, AGENT_A)
    assert (got.holder_jkt, got.status, got.agent_id, got.operator_id) == (
        jkt("a2"),
        BindingStatus.ACTIVE,
        AGENT_A,
        "op-1",
    )
    assert got.observed_at == START + timedelta(hours=1, minutes=1), "the rotation time"


@pytest.mark.parametrize(
    ("key", "want"),
    [
        pytest.param("not-a-thumbprint", EnrollErrorKind.INVALID, id="malformed"),
        pytest.param("", EnrollErrorKind.INVALID, id="empty"),
        pytest.param(jkt("a2"), EnrollErrorKind.KEY_REUSE, id="current key"),
        pytest.param(jkt("a1"), EnrollErrorKind.KEY_REUSE, id="retired key"),
        pytest.param(jkt("b1"), EnrollErrorKind.KEY_REUSE, id="another agent's key"),
    ],
)
def test_rotate_rejects_bad_keys(key: str, want: EnrollErrorKind) -> None:
    f = Fixture()
    f.enroll(AGENT_A, WORKLOAD_A, jkt("a1"))
    f.enroll(AGENT_B, WORKLOAD_B, jkt("b1"))
    f.reg.rotate(ADMIN, AGENT_A, jkt("a2"))
    assert kind_of(lambda: f.reg.rotate(ADMIN, AGENT_A, key)) == want
    f.want_binding(WORKLOAD_A, AGENT_A, BindingStatus.ACTIVE, jkt("a2"))


def test_rotate_unknown_agent() -> None:
    f = Fixture()
    f.enroll(AGENT_A, WORKLOAD_A, jkt("a1"))
    assert kind_of(lambda: f.reg.rotate(ADMIN, AGENT_B, jkt("b1"))) == EnrollErrorKind.NOT_FOUND
    # An admin of another tenant has no authority over this realm's agent.
    foreign = Actor(kind=ActorKind.ADMIN, id="admin-2", realm=OTHER_TENANT)
    assert kind_of(lambda: f.reg.rotate(foreign, AGENT_A, jkt("a2"))) == EnrollErrorKind.NOT_FOUND
    f.want_binding(WORKLOAD_A, AGENT_A, BindingStatus.ACTIVE, jkt("a1"))


@pytest.mark.parametrize("actor", [ADMIN, ISSUER], ids=["admin", "authorized issuer"])
def test_mark_compromised(actor: Actor) -> None:
    f = Fixture()
    f.enroll(AGENT_A, WORKLOAD_A, jkt("a1"))
    f.clk.advance(timedelta(hours=1))
    f.reg.mark_compromised(actor, AGENT_A)
    got = f.lookup(REALM, WORKLOAD_A, AGENT_A)
    assert got.status == BindingStatus.COMPROMISED
    assert (got.agent_id, got.holder_jkt) == (AGENT_A, jkt("a1")), "still names the agent and key"
    assert got.observed_at == START + timedelta(hours=1), "the marking time"


@pytest.mark.parametrize(
    "actor",
    [
        pytest.param(Actor(kind=ActorKind.AGENT, id=AGENT_A, realm=REALM), id="agent"),
        pytest.param(Actor(), id="zero"),
        pytest.param(Actor(kind=ActorKind.ADMIN, realm=REALM), id="admin no id"),
        pytest.param(Actor(kind=ActorKind.ADMIN, id="admin-1"), id="admin no realm"),
    ],
)
def test_mark_compromised_requires_authority(actor: Actor) -> None:
    f = Fixture()
    f.enroll(AGENT_A, WORKLOAD_A, jkt("a1"))
    assert kind_of(lambda: f.reg.mark_compromised(actor, AGENT_A)) == EnrollErrorKind.NOT_AUTHORIZED
    f.want_binding(WORKLOAD_A, AGENT_A, BindingStatus.ACTIVE, jkt("a1"))


def test_mark_compromised_unknown_agent() -> None:
    f = Fixture()
    f.enroll(AGENT_A, WORKLOAD_A, jkt("a1"))
    foreign = Actor(kind=ActorKind.ADMIN, id="admin-2", realm=OTHER_TENANT)
    not_found = EnrollErrorKind.NOT_FOUND
    assert kind_of(lambda: f.reg.mark_compromised(ADMIN, AGENT_B)) == not_found, "unknown agent"
    assert kind_of(lambda: f.reg.mark_compromised(foreign, AGENT_A)) == not_found, "foreign admin"
    f.want_binding(WORKLOAD_A, AGENT_A, BindingStatus.ACTIVE, jkt("a1"))


def test_compromised_never_recovers() -> None:
    """The second required case (draft 6.4): no call sequence, whoever makes it,
    returns a compromised binding to ACTIVE through lookup, and the original
    observation time of the marking survives."""
    f = Fixture()
    f.enroll(AGENT_A, WORKLOAD_A, jkt("a1"))
    f.clk.advance(timedelta(hours=1))
    marked_at = f.clk.now()
    f.reg.mark_compromised(ADMIN, AGENT_A)
    f.clk.advance(timedelta(hours=1))
    agent = Actor(kind=ActorKind.AGENT, id=AGENT_A, realm=REALM)

    def enroll_again(key: str) -> None:
        f.reg.enroll(
            ADMIN,
            Enrollment(agent_id=AGENT_A, operator_id="op-1", workload=WORKLOAD_A, holder_jkt=key),
        )

    steps: list[tuple[str, Callable[[], None], EnrollErrorKind | None]] = [
        (
            "rotate by admin",
            lambda: f.reg.rotate(ADMIN, AGENT_A, jkt("a2")),
            EnrollErrorKind.COMPROMISED,
        ),
        (
            "rotate by issuer",
            lambda: f.reg.rotate(ISSUER, AGENT_A, jkt("a3")),
            EnrollErrorKind.COMPROMISED,
        ),
        (
            "rotate by the agent",
            lambda: f.reg.rotate(agent, AGENT_A, jkt("a4")),
            EnrollErrorKind.NOT_AUTHORIZED,
        ),
        ("revoke", lambda: f.reg.revoke(ADMIN, AGENT_A), EnrollErrorKind.COMPROMISED),
        (
            "enroll again, new key",
            lambda: enroll_again(jkt("a5")),
            EnrollErrorKind.ALREADY_ENROLLED,
        ),
        (
            "enroll again, same key",
            lambda: enroll_again(jkt("a1")),
            EnrollErrorKind.ALREADY_ENROLLED,
        ),
        ("mark again", lambda: f.reg.mark_compromised(ADMIN, AGENT_A), None),
    ]
    for name, do, want in steps:
        assert kind_of(do) == want, name
        got = f.lookup(REALM, WORKLOAD_A, AGENT_A)
        assert (got.status, got.holder_jkt, got.agent_id) == (
            BindingStatus.COMPROMISED,
            jkt("a1"),
            AGENT_A,
        ), name
        assert got.observed_at == marked_at, name


def test_revoke() -> None:
    f = Fixture()
    f.enroll(AGENT_A, WORKLOAD_A, jkt("a1"))
    f.clk.advance(timedelta(hours=1))
    agent = Actor(kind=ActorKind.AGENT, id=AGENT_A, realm=REALM)
    assert kind_of(lambda: f.reg.revoke(agent, AGENT_A)) == EnrollErrorKind.NOT_AUTHORIZED
    f.want_binding(WORKLOAD_A, AGENT_A, BindingStatus.ACTIVE, jkt("a1"))

    f.reg.revoke(ADMIN, AGENT_A)
    got = f.lookup(REALM, WORKLOAD_A, AGENT_A)
    assert (got.status, got.agent_id, got.holder_jkt) == (BindingStatus.REVOKED, AGENT_A, jkt("a1"))

    # A revoked binding is not rotated back to life, and revoking again is a no-op.
    assert kind_of(lambda: f.reg.rotate(ADMIN, AGENT_A, jkt("a2"))) == EnrollErrorKind.REVOKED
    f.reg.revoke(ADMIN, AGENT_A)
    again = Enrollment(
        agent_id=AGENT_A, operator_id="op-1", workload=WORKLOAD_A, holder_jkt=jkt("a3")
    )
    assert kind_of(lambda: f.reg.enroll(ADMIN, again)) == EnrollErrorKind.ALREADY_ENROLLED
    f.want_binding(WORKLOAD_A, AGENT_A, BindingStatus.REVOKED, jkt("a1"))

    # A revoked binding can still be found compromised, and then stays so.
    f.reg.mark_compromised(ADMIN, AGENT_A)
    f.want_binding(WORKLOAD_A, AGENT_A, BindingStatus.COMPROMISED, jkt("a1"))


def test_revoke_unknown_agent() -> None:
    f = Fixture()
    assert kind_of(lambda: f.reg.revoke(ADMIN, AGENT_A)) == EnrollErrorKind.NOT_FOUND


def test_shared_workload() -> None:
    """IM-18 (draft 5 invariant 3, 6.1 and 17.1): a credential shared by two
    agents names the account, never an agent; each agent has its own row, and
    lookup selects the row of the agent the request names among the rows of the
    workload, never a row of another workload or of another agent."""
    agent_d = "https://agents.example/d"
    f = Fixture(with_shared_workloads())
    f.enroll(AGENT_A, SHARED, jkt("a1"))
    f.enroll(AGENT_B, SHARED, jkt("b1"))
    f.enroll(agent_d, WORKLOAD_A, jkt("d1"))

    for agent, key in [(AGENT_A, jkt("a1")), (AGENT_B, jkt("b1"))]:
        got = f.lookup(REALM, SHARED, agent)
        assert (got.status, got.agent_id, got.holder_jkt) == (BindingStatus.ACTIVE, agent, key)

    # The agent ID selects only among the rows of the workload; the workload
    # alone names no agent.
    for name, got in {
        "agent enrolled only on another workload": f.lookup(REALM, SHARED, agent_d),
        "agent of the shared workload, other one": f.lookup(REALM, WORKLOAD_A, AGENT_A),
        "agent not enrolled": f.lookup(REALM, SHARED, "https://agents.example/c"),
        "no agent named": f.lookup(REALM, SHARED, ""),
    }.items():
        assert (got.status, got.agent_id, got.holder_jkt) == (BindingStatus.UNKNOWN, "", ""), name

    # Compromise of one agent does not touch the other.
    f.reg.mark_compromised(ADMIN, AGENT_A)
    got = f.lookup(REALM, SHARED, AGENT_A)
    assert (got.status, got.holder_jkt) == (BindingStatus.COMPROMISED, jkt("a1"))
    got = f.lookup(REALM, SHARED, AGENT_B)
    assert (got.status, got.holder_jkt) == (BindingStatus.ACTIVE, jkt("b1"))

    # Revoking B answers REVOKED for B, and A stays COMPROMISED.
    f.reg.revoke(ADMIN, AGENT_B)
    got = f.lookup(REALM, SHARED, AGENT_B)
    assert (got.status, got.agent_id) == (BindingStatus.REVOKED, AGENT_B)
    got = f.lookup(REALM, SHARED, AGENT_A)
    assert (got.status, got.agent_id) == (BindingStatus.COMPROMISED, AGENT_A)


def test_revoked_rows_do_not_shadow_the_binding() -> None:
    """IM-18: on an account whose first agent was revoked, the agent enrolled
    after it resolves ACTIVE and the revoked agent stays REVOKED; neither answers
    for the other."""
    f = Fixture()
    f.enroll(AGENT_A, WORKLOAD_A, jkt("a1"))
    f.reg.revoke(ADMIN, AGENT_A)
    f.enroll(AGENT_B, WORKLOAD_A, jkt("b1"))
    got = f.lookup(REALM, WORKLOAD_A, AGENT_B)
    assert (got.agent_id, got.status, got.holder_jkt) == (AGENT_B, BindingStatus.ACTIVE, jkt("b1"))
    got = f.lookup(REALM, WORKLOAD_A, AGENT_A)
    assert (got.agent_id, got.status, got.holder_jkt) == (AGENT_A, BindingStatus.REVOKED, jkt("a1"))


def test_dedicated_workload_refuses_a_second_enrollment() -> None:
    """IM-19: by default a workload serves one agent, so enroll refuses a record
    for a workload that a record in force already names. Only records in force
    count: a revoked record does not, a compromised one does. The refusal is
    audited, and the workload of another realm is another workload."""
    agent_c = "https://agents.example/c"
    f = Fixture()
    f.enroll(AGENT_A, WORKLOAD_A, jkt("a1"))

    second = Enrollment(
        agent_id=AGENT_B, operator_id="op-1", workload=WORKLOAD_A, holder_jkt=jkt("b1")
    )
    assert kind_of(lambda: f.reg.enroll(ADMIN, second)) == EnrollErrorKind.WORKLOAD_IN_USE
    last = f.reg.audit()[-1]
    assert (last.result, last.agent_id, last.workload) == (
        AuditResult.REJECTED,
        AGENT_B,
        WORKLOAD_A,
    )
    f.want_binding(WORKLOAD_A, AGENT_A, BindingStatus.ACTIVE, jkt("a1"))
    got = f.lookup(REALM, WORKLOAD_A, AGENT_B)
    assert (got.status, got.agent_id) == (BindingStatus.UNKNOWN, "")

    # The key of the refused request was not used, so a later enrollment may
    # take it; another workload of the realm is free.
    f.enroll(AGENT_B, WORKLOAD_B, jkt("b1"))
    # The same workload text in another realm is another workload.
    other = Actor(kind=ActorKind.ADMIN, id="admin-2", realm=OTHER_ENV)
    f.reg.enroll(
        other,
        Enrollment(agent_id=agent_c, operator_id="op-1", workload=WORKLOAD_A, holder_jkt=jkt("c1")),
    )

    # A compromised record stays in force.
    f.reg.mark_compromised(ADMIN, AGENT_A)
    third = Enrollment(
        agent_id=agent_c, operator_id="op-1", workload=WORKLOAD_A, holder_jkt=jkt("c2")
    )
    assert kind_of(lambda: f.reg.enroll(ADMIN, third)) == EnrollErrorKind.WORKLOAD_IN_USE

    # A revoked record does not count.
    f.reg.revoke(ADMIN, AGENT_B)
    f.enroll(agent_c, WORKLOAD_B, jkt("c3"))
    f.want_binding(WORKLOAD_B, agent_c, BindingStatus.ACTIVE, jkt("c3"))


@pytest.mark.parametrize("shared", [False, True], ids=["dedicated", "shared"])
def test_dedicated_workload_configuration_error(shared: bool) -> None:
    """IM-19: a workload whose agent was revoked takes a new agent, and the old
    record becomes in force again when it is marked compromised. The workload
    then has two records in force, the configuration error: whichever agent ID
    the request names, lookup returns no binding and raises
    UnsupportedRequirement (draft 17.1). A registry that supports shared
    workloads selects instead."""
    f = Fixture(with_shared_workloads()) if shared else Fixture()
    f.enroll(AGENT_A, WORKLOAD_A, jkt("a1"))
    f.reg.revoke(ADMIN, AGENT_A)
    f.enroll(AGENT_B, WORKLOAD_A, jkt("b1"))
    f.want_binding(WORKLOAD_A, AGENT_B, BindingStatus.ACTIVE, jkt("b1"))
    f.want_binding(WORKLOAD_A, AGENT_A, BindingStatus.REVOKED, jkt("a1"))

    f.reg.mark_compromised(ADMIN, AGENT_A)
    if shared:
        f.want_binding(WORKLOAD_A, AGENT_B, BindingStatus.ACTIVE, jkt("b1"))
        f.want_binding(WORKLOAD_A, AGENT_A, BindingStatus.COMPROMISED, jkt("a1"))
        return
    r: BindingResolver = Resolver(registry=f.reg)
    for agent in [AGENT_A, AGENT_B, "https://agents.example/c", ""]:
        with pytest.raises(UnsupportedRequirement):
            r.resolve_agent_binding(REALM, WORKLOAD_A, agent)
    # Another workload of the realm is not affected.
    f.enroll("https://agents.example/c", WORKLOAD_B, jkt("c1"))
    f.want_binding(WORKLOAD_B, "https://agents.example/c", BindingStatus.ACTIVE, jkt("c1"))


def test_audit_log() -> None:
    f = Fixture()
    assert f.reg.audit() == []
    agent = Actor(kind=ActorKind.AGENT, id=AGENT_A, realm=REALM)

    def attempt(fn: Callable[[], None]) -> None:
        kind_of(fn)

    f.enroll(AGENT_A, WORKLOAD_A, jkt("a1"))  # 1 applied
    f.clk.advance(timedelta(minutes=1))
    attempt(lambda: f.reg.rotate(agent, AGENT_A, jkt("a2")))  # 2 denied: no authority
    attempt(lambda: f.reg.rotate(ADMIN, AGENT_A, jkt("a2")))  # 3 applied
    attempt(lambda: f.reg.rotate(ISSUER, AGENT_A, jkt("a1")))  # 4 rejected: retired key
    attempt(lambda: f.reg.mark_compromised(ISSUER, AGENT_A))  # 5 applied
    attempt(lambda: f.reg.mark_compromised(ADMIN, AGENT_A))  # 6 unchanged: already compromised
    attempt(lambda: f.reg.rotate(ADMIN, AGENT_A, jkt("a3")))  # 7 rejected: compromised
    attempt(lambda: f.reg.revoke(ADMIN, AGENT_B))  # 8 rejected: not enrolled

    log = f.reg.audit()
    want = [
        (AuditAction.ENROLL, ActorKind.ADMIN, AuditResult.APPLIED),
        (AuditAction.ROTATE, ActorKind.AGENT, AuditResult.DENIED),
        (AuditAction.ROTATE, ActorKind.ADMIN, AuditResult.APPLIED),
        (AuditAction.ROTATE, ActorKind.AUTHORIZED_ISSUER, AuditResult.REJECTED),
        (AuditAction.MARK_COMPROMISED, ActorKind.AUTHORIZED_ISSUER, AuditResult.APPLIED),
        (AuditAction.MARK_COMPROMISED, ActorKind.ADMIN, AuditResult.UNCHANGED),
        (AuditAction.ROTATE, ActorKind.ADMIN, AuditResult.REJECTED),
        (AuditAction.REVOKE, ActorKind.ADMIN, AuditResult.REJECTED),
    ]
    assert len(log) == len(want)
    for i, (w, e) in enumerate(zip(want, log, strict=True)):
        assert e.seq == i + 1
        assert (e.action, e.actor.kind, e.result) == w, i
        assert e.actor.realm == REALM, i
        refused = e.result in (AuditResult.DENIED, AuditResult.REJECTED)
        assert refused == (e.reason != ""), i

    # Details of the entries that carry a key.
    e = log[0]
    assert (e.agent_id, e.workload, e.new_jkt, e.old_jkt, e.at) == (
        AGENT_A,
        WORKLOAD_A,
        jkt("a1"),
        "",
        START,
    )
    e = log[2]
    assert (e.agent_id, e.old_jkt, e.new_jkt, e.actor.id, e.at) == (
        AGENT_A,
        jkt("a1"),
        jkt("a2"),
        "admin-1",
        START + timedelta(minutes=1),
    )
    # A denied rotation records what was asked for, not what the binding held.
    e = log[1]
    assert (e.old_jkt, e.new_jkt) == ("", jkt("a2"))

    # The returned log is a copy.
    log[0] = replace(log[0], agent_id="tampered")
    log.clear()
    assert f.reg.audit()[0].agent_id == AGENT_A


def test_audit_log_records_nothing_for_reads() -> None:
    f = Fixture()
    f.enroll(AGENT_A, WORKLOAD_A, jkt("a1"))
    f.lookup(REALM, WORKLOAD_A, AGENT_A)
    f.lookup(REALM, WORKLOAD_A, AGENT_B)
    assert len(f.reg.audit()) == 1, "only the enrollment"


def test_concurrent_use() -> None:
    """The registry is safe for concurrent use: whatever the interleaving of 40
    rotations, 40 reads and one compromise mark, the end state is COMPROMISED
    and every attempt is in the log."""
    f = Fixture()
    f.enroll(AGENT_A, WORKLOAD_A, jkt("a0"))
    rotations = 40
    errors: list[BaseException] = []
    barrier = threading.Barrier(2 * rotations + 1)

    def rotate(i: int) -> None:
        barrier.wait()
        try:
            f.reg.rotate(ADMIN, AGENT_A, jkt(f"a-{i}"))
        except EnrollError as e:
            if e.kind != EnrollErrorKind.COMPROMISED:
                errors.append(e)
        except BaseException as e:
            errors.append(e)

    def read() -> None:
        barrier.wait()
        try:
            f.reg.lookup(REALM, WORKLOAD_A, AGENT_A)
        except BaseException as e:
            errors.append(e)

    def mark() -> None:
        barrier.wait()
        try:
            f.reg.mark_compromised(ISSUER, AGENT_A)
        except BaseException as e:
            errors.append(e)

    threads = [threading.Thread(target=rotate, args=(i,)) for i in range(rotations)]
    threads += [threading.Thread(target=read) for _ in range(rotations)]
    threads.append(threading.Thread(target=mark))
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    assert f.lookup(REALM, WORKLOAD_A, AGENT_A).status == BindingStatus.COMPROMISED
    log = f.reg.audit()
    assert len(log) == 1 + rotations + 1
    assert [e.seq for e in log] == list(range(1, len(log) + 1)), "no gaps, no duplicates"


@pytest.mark.parametrize(
    ("agent_id", "ok"),
    [
        ("https://agents.example/a", True),
        ("https://agents.example/a%20b?x=1", True),
        ("urn:uuid:6e8bc430-9c3a-11d9-9669-0800200c9a66", True),
        ("did:web:example.com", True),
        ("spiffe://example.org/ns/prod/sa/runner", True),
        ("agent-a", False),
        ("/agents/a", False),
        ("1http://agents.example/a", False),
        ("://agents.example/a", False),
        ("https:", False),
        ("https://agents.example/a%2", False),
        ("https://agents.example/a%zz", False),
        ("https://agents.example/é", False),
        ("https://agents.example/a b", False),
        ("https://agents.example/a#frag", False),
        (" https://agents.example/a", False),
    ],
)
def test_enroll_agent_id_forms(agent_id: str, ok: bool) -> None:
    """agent_id is an absolute URI (draft 6.1); a native workload identifier, a
    gateway-assigned URI and a DID are all valid."""
    f = Fixture()
    e = Enrollment(agent_id=agent_id, operator_id="op-1", workload=WORKLOAD_A, holder_jkt=jkt("k"))
    assert kind_of(lambda: f.reg.enroll(ADMIN, e)) == (None if ok else EnrollErrorKind.INVALID)


def test_options_and_keyword_arguments() -> None:
    """New's options become keyword arguments; the Option values apply after
    them, in order."""
    clk = FakeClock(START)
    by_kw = MemoryRegistry(clock=clk, source_id="kw-source", shared_workloads=True)
    by_opt = MemoryRegistry(with_clock(clk), with_source_id("kw-source"), with_shared_workloads())
    for reg in (by_kw, by_opt):
        for agent, key in [(AGENT_A, jkt("a1")), (AGENT_B, jkt("b1"))]:
            reg.enroll(
                ADMIN,
                Enrollment(agent_id=agent, operator_id="op-1", workload=SHARED, holder_jkt=key),
            )
        got = reg.lookup(REALM, SHARED, AGENT_B)
        assert (got.status, got.source_id, got.status_checked_at) == (
            BindingStatus.ACTIVE,
            "kw-source",
            START,
        )
    later = MemoryRegistry(with_source_id("second"), source_id="first")
    assert later.lookup(REALM, SHARED, AGENT_A).source_id == "second"
    default = MemoryRegistry()
    got = default.lookup(REALM, SHARED, AGENT_A)
    assert got.source_id == DEFAULT_SOURCE_ID == "enroll-memory"
    assert got.status_checked_at is not None
    assert abs(got.status_checked_at - SystemClock().now()) < timedelta(minutes=1)
