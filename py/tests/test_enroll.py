"""Who may change an enrollment, and the Resolver over a Registry.

Port of go/adapter/enroll/enroll_test.go. Go's sentinel errors are the kinds
of EnrollError.
"""

from __future__ import annotations

import pytest

from hop_top_pact.adapter import (
    AgentBinding,
    AgentID,
    BindingResolver,
    BindingStatus,
    Code,
    DependencyUnavailable,
    Realm,
    Workload,
    code_of,
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
from hop_top_pact.errors import PactError

REALM = Realm(tenant_id="tenant-1", environment_id="prod")


@pytest.mark.parametrize(
    ("kind", "want"),
    [
        (ActorKind.ADMIN, True),
        (ActorKind.AUTHORIZED_ISSUER, True),
        (ActorKind.AGENT, True),
        ("", False),
        ("admin", False),
        ("ROOT", False),
    ],
)
def test_actor_kind_valid(kind: str, want: bool) -> None:
    assert ActorKind.is_valid(kind) is want


def test_enumerations_spell_the_go_values() -> None:
    assert [k.value for k in ActorKind] == ["ADMIN", "AUTHORIZED_ISSUER", "AGENT"]
    assert [a.value for a in AuditAction] == ["ENROLL", "ROTATE", "REVOKE", "MARK_COMPROMISED"]
    assert [r.value for r in AuditResult] == ["APPLIED", "UNCHANGED", "DENIED", "REJECTED"]
    assert [k.value for k in EnrollErrorKind] == [
        "NOT_AUTHORIZED",
        "NOT_FOUND",
        "ALREADY_ENROLLED",
        "COMPROMISED",
        "REVOKED",
        "KEY_REUSE",
        "INVALID",
        "WORKLOAD_IN_USE",
    ]
    assert issubclass(EnrollError, PactError)


@pytest.mark.parametrize(
    ("name", "actor", "ok"),
    [
        ("admin", Actor(kind=ActorKind.ADMIN, id="a1", realm=REALM), True),
        ("authorized issuer", Actor(kind=ActorKind.AUTHORIZED_ISSUER, id="i1", realm=REALM), True),
        (
            "agent itself",
            Actor(kind=ActorKind.AGENT, id="https://agents.example/a", realm=REALM),
            False,
        ),
        ("empty kind", Actor(id="a1", realm=REALM), False),
        ("undefined kind", Actor(kind="OWNER", id="a1", realm=REALM), False),
        ("lower-case kind", Actor(kind="admin", id="a1", realm=REALM), False),
        ("admin without id", Actor(kind=ActorKind.ADMIN, realm=REALM), False),
        ("admin without realm", Actor(kind=ActorKind.ADMIN, id="a1"), False),
        (
            "admin without tenant",
            Actor(kind=ActorKind.ADMIN, id="a1", realm=Realm(environment_id="prod")),
            False,
        ),
        (
            "admin without environment",
            Actor(kind=ActorKind.ADMIN, id="a1", realm=Realm(tenant_id="tenant-1")),
            False,
        ),
    ],
)
def test_check_authority(name: str, actor: Actor, ok: bool) -> None:
    """Who may change an enrollment: the draft 6.1 and 6.4 actors (a native
    authenticated administrative workflow and an authorized identity-binding or
    rotation issuer), scoped to one realm and attributable."""
    if ok:
        actor.check_authority()
        return
    with pytest.raises(EnrollError) as e:
        actor.check_authority()
    assert e.value.kind == EnrollErrorKind.NOT_AUTHORIZED, name


class StubRegistry:
    """Records the arguments of lookup and returns canned results."""

    def __init__(self, binding: AgentBinding | None = None, err: Exception | None = None) -> None:
        self.binding = binding or AgentBinding()
        self.err = err
        self.got: tuple[Realm, Workload, AgentID] | None = None

    def lookup(self, realm: Realm, workload: Workload, agent_id: AgentID) -> AgentBinding:
        self.got = (realm, workload, agent_id)
        if self.err is not None:
            raise self.err
        return self.binding

    def rotate(self, admin: Actor, agent_id: str, new_jkt: str) -> None:
        raise NotImplementedError

    def mark_compromised(self, authority: Actor, agent_id: str) -> None:
        raise NotImplementedError


def test_resolver_delegates_to_lookup() -> None:
    want = AgentBinding(
        agent_id="https://agents.example/a",
        operator_id="op-1",
        holder_jkt="0123456789012345678901234567890123456789012",
        status=BindingStatus.COMPROMISED,
    )
    stub = StubRegistry(binding=want)
    _reg: Registry = stub  # checked by mypy
    r: BindingResolver = Resolver(registry=stub)
    got = r.resolve_agent_binding(REALM, "acct:1", "https://agents.example/a")
    assert got == want
    assert stub.got == (REALM, "acct:1", "https://agents.example/a")


def test_resolver_keeps_dependency_error() -> None:
    stub = StubRegistry(err=DependencyUnavailable("store down"))
    with pytest.raises(DependencyUnavailable) as e:
        Resolver(registry=stub).resolve_agent_binding(REALM, "acct:1", "https://agents.example/a")
    assert code_of(e.value) == Code.DEPENDENCY_UNAVAILABLE
