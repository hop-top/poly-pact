"""The enrollment registry behind resolve_agent_binding. Mirrors hop.top/pact-go/adapter/enroll.

The record that binds a stable agent_id to an authenticated workload in a
realm, with its operator and its holder key (draft 6.1, 6.2), and the
lifecycle operations on that record (draft 6.4). The module holds the
Registry contract, the Actor that may change a binding, EnrollError, the
AuditEntry every change leaves, and Resolver, which exposes a Registry as
the BindingResolver an adapter needs. adapter.enroll_memory is the in-memory
backend.

Who may change a binding
------------------------

Enrollment, rotation and the compromise mark are native administrative
operations (draft 6.1). The only trusted actors are ADMIN, a native
authenticated administrative workflow, and AUTHORIZED_ISSUER, an
identity-binding or rotation issuer the gateway's administrators configured.
The agent holding the old key is an AGENT actor and has no authority: proof
by the old key alone never rotates a key and never recovers a compromised
identity. An actor's authority is scoped to the one realm named in
Actor.realm.

Binding status
--------------

lookup selects the record by the agent_id the request names, among the
records of the authenticated workload in the realm, and reports the status
of its AgentBinding:

- ACTIVE: enrolled and in force.
- REVOKED: withdrawn. It is not rotated or enrolled back to life.
- COMPROMISED: marked by an authority. It is terminal: no Registry method
  returns it to ACTIVE or REVOKED. Clearing the security hold and enrolling
  the agent again is a remediation process outside this module, and the
  remediated agent is enrolled under a new agent_id.
- UNKNOWN: no current binding can be established. It covers an agent_id with
  no record on the workload, including one enrolled only for another
  workload, so that a workload alone, or a credential that several agents
  share, never selects an agent. enrolled_elsewhere then says whether the
  agent_id is enrolled for another workload of the realm (draft 17.1).

Dedicated workloads
-------------------

By default a workload serves one agent (identity mapping IM-19): a registry
refuses to enroll an agent for a workload that an enrollment in force
already names, with WORKLOAD_IN_USE, and lookup reports a workload with more
than one enrollment in force as a configuration error, UnsupportedRequirement
with no binding (draft 17.1). An enrollment is in force unless it is
revoked; a compromised one is in force, so that a compromise is never hidden
behind a newer record. A backend may support workloads shared by several
agents as an option, for a profile that supports them.

The mapping rules these types implement are in
spec/v1.0/profiles/identity-mapping.md.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Protocol, runtime_checkable

from hop_top_pact.adapter._types import AgentBinding, AgentID, Realm, Workload
from hop_top_pact.errors import PactError

__all__ = [
    "Actor",
    "ActorKind",
    "AuditAction",
    "AuditEntry",
    "AuditResult",
    "EnrollError",
    "EnrollErrorKind",
    "Registry",
    "Resolver",
]


class ActorKind(StrEnum):
    """The capacity in which an Actor acts on an enrollment."""

    ADMIN = "ADMIN"
    """A native authenticated administrative workflow: an administrator of the
    realm acting through the environment's existing admin controls (draft 6.1,
    6.4). A trusted enrollment actor."""
    AUTHORIZED_ISSUER = "AUTHORIZED_ISSUER"
    """An identity-binding or rotation issuer that the gateway's administrators
    configured for the realm (draft 4.2, 6.1, 6.4). A trusted enrollment actor."""
    AGENT = "AGENT"
    """The agent itself, or anyone presenting its key. Self-registration proves
    neither organizational identity nor entitlement (draft 6.1), so an AGENT has
    no authority over any binding."""

    @classmethod
    def is_valid(cls, s: str) -> bool:
        """Report whether s is a defined value."""
        return s in cls._value2member_map_


class EnrollErrorKind(StrEnum):
    """Why a Registry refused a request: the Go sentinels Err* of the enroll package."""

    NOT_AUTHORIZED = "NOT_AUTHORIZED"
    """The actor is not a trusted enrollment actor for its realm. It is raised
    before the registry looks at the target, so it never reveals whether an
    agent is enrolled."""
    NOT_FOUND = "NOT_FOUND"
    """The agent_id is not enrolled in the actor's realm."""
    ALREADY_ENROLLED = "ALREADY_ENROLLED"
    """The agent_id is already enrolled in the realm, in any status. An agent_id
    is enrolled once; a replacement identity is a new agent_id."""
    COMPROMISED = "COMPROMISED"
    """The binding is marked compromised and cannot be changed by rotation or
    revocation (draft 6.4)."""
    REVOKED = "REVOKED"
    """The binding is revoked and cannot be rotated."""
    KEY_REUSE = "KEY_REUSE"
    """The holder key is, or ever was, enrolled in the realm. A key is enrolled
    at most once, so rotation cannot restore a retired key and two agents never
    share one."""
    INVALID = "INVALID"
    """An argument is malformed, such as a thumbprint that is not 43 base64url
    characters or an agent_id that is not an absolute URI."""
    WORKLOAD_IN_USE = "WORKLOAD_IN_USE"
    """The workload already has an enrollment in force in the realm, and the
    registry does not support workloads shared by several agents. A record is in
    force unless it is revoked; a compromised record is in force
    (spec/v1.0/profiles/identity-mapping.md, IM-18, IM-19)."""


_TEXT = {
    EnrollErrorKind.NOT_AUTHORIZED: "actor is not a trusted enrollment actor",
    EnrollErrorKind.NOT_FOUND: "agent is not enrolled in the realm",
    EnrollErrorKind.ALREADY_ENROLLED: "agent_id is already enrolled in the realm",
    EnrollErrorKind.COMPROMISED: "binding is marked compromised",
    EnrollErrorKind.REVOKED: "binding is revoked",
    EnrollErrorKind.KEY_REUSE: "holder key was already enrolled in the realm",
    EnrollErrorKind.INVALID: "invalid argument",
    EnrollErrorKind.WORKLOAD_IN_USE: "workload already has an enrollment in force",
}


class EnrollError(PactError):
    """A Registry refused a request for kind; detail says what was found."""

    def __init__(self, kind: EnrollErrorKind, detail: str = "") -> None:
        self.kind = kind
        self.detail = detail
        super().__init__(str(self))

    def __str__(self) -> str:
        s = "enroll: " + _TEXT[self.kind]
        if self.detail:
            s += ": " + self.detail
        return s


@dataclass(frozen=True, slots=True, kw_only=True)
class Actor:
    """Who asks a Registry to change a binding.

    kind is the capacity in which the actor acts, an ActorKind value. id
    identifies the actor for the audit log, an administrator account or an
    issuer identifier, and is never interpreted. realm is the realm the
    actor's authority covers, and so the realm whose bindings the call
    addresses; an actor has no authority outside it.
    """

    kind: str = ""
    id: str = ""
    realm: Realm = field(default_factory=Realm)

    def check_authority(self) -> None:
        """Return when the actor is a trusted enrollment actor for its realm: kind is
        ADMIN or AUTHORIZED_ISSUER, id is set so that the change is attributable,
        and realm names a tenant and an environment. Otherwise raise EnrollError
        NOT_AUTHORIZED."""
        if self.kind not in (ActorKind.ADMIN, ActorKind.AUTHORIZED_ISSUER):
            raise EnrollError(
                EnrollErrorKind.NOT_AUTHORIZED,
                f"actor kind {self.kind!r} is not a trusted enrollment actor",
            )
        if self.id == "":
            raise EnrollError(EnrollErrorKind.NOT_AUTHORIZED, "the actor is not attributable")
        if self.realm.tenant_id == "" or self.realm.environment_id == "":
            raise EnrollError(EnrollErrorKind.NOT_AUTHORIZED, "the actor has no realm")


@runtime_checkable
class Registry(Protocol):
    """The enrollment registry of draft 6.1 and 6.4: it answers whether an agent is
    bound to a workload and with which holder key, and it applies rotation and
    the compromise mark. Enrolling an agent is a native administrative operation
    that each backend exposes in its own terms."""

    def lookup(self, realm: Realm, workload: Workload, agent_id: AgentID) -> AgentBinding:
        """The binding of the agent to the workload in the realm, with the semantics
        of BindingResolver: the agent ID selects among the records of the
        workload only. A binding that is compromised or revoked is returned
        with that status, never as active. An agent with no record on the
        workload in the realm, which includes one enrolled only for another
        workload, gets status UNKNOWN with no identity; enrolled_elsewhere then
        reports whether the agent is enrolled for another workload of the
        realm, and an enrollment in another realm never sets it. A source that
        cannot answer raises DependencyUnavailable.

        Unless the registry supports workloads shared by several agents, a
        workload serves one agent, and a workload with more than one enrollment
        in force in the realm is a configuration error: lookup returns no
        binding and raises UnsupportedRequirement, whichever agent ID it is
        given (draft 17.1, identity mapping IM-19).
        """
        ...

    def rotate(self, admin: Actor, agent_id: str, new_jkt: str) -> None:
        """Replace the holder key of the agent with new_jkt, in admin.realm. admin
        must be an ADMIN or an AUTHORIZED_ISSUER (Actor.check_authority); proof
        by the old key never suffices. The old key stops being the enrolled key
        at once. Raises EnrollError COMPROMISED or REVOKED for a binding in that
        state, KEY_REUSE for a key that was ever enrolled in the realm, INVALID
        for a malformed thumbprint and NOT_FOUND for an agent that is not
        enrolled."""
        ...

    def mark_compromised(self, authority: Actor, agent_id: str) -> None:
        """Mark the binding of the agent compromised, in authority.realm. authority
        must be an ADMIN or an AUTHORIZED_ISSUER. The mark is terminal and a
        repeat is a no-op. Raises EnrollError NOT_FOUND for an agent that is not
        enrolled."""
        ...


@dataclass(frozen=True, slots=True)
class Resolver:
    """Exposes a Registry as the BindingResolver of draft 17.1."""

    registry: Registry

    def resolve_agent_binding(
        self, realm: Realm, workload: Workload, agent: AgentID
    ) -> AgentBinding:
        """registry.lookup for the realm, workload and agent."""
        return self.registry.lookup(realm, workload, agent)


class AuditAction(StrEnum):
    """The change an AuditEntry records."""

    ENROLL = "ENROLL"
    ROTATE = "ROTATE"
    REVOKE = "REVOKE"
    MARK_COMPROMISED = "MARK_COMPROMISED"


class AuditResult(StrEnum):
    """What became of the request an AuditEntry records."""

    APPLIED = "APPLIED"
    """The change was made."""
    UNCHANGED = "UNCHANGED"
    """The binding was already in the requested state."""
    DENIED = "DENIED"
    """The actor has no authority, and nothing else was examined."""
    REJECTED = "REJECTED"
    """The actor has authority and the request was refused, for example for an
    unknown agent, a compromised binding or a reused key."""


@dataclass(frozen=True, slots=True, kw_only=True)
class AuditEntry:
    """One attempt to change a binding. A registry appends an entry for every
    attempt, including denied and rejected ones, and never edits or removes one;
    a rotation entry is the retained rotation event of draft 6.4.

    seq numbers the entries of one registry from 1, without gaps. at is when
    the registry handled the request. actor is who asked, as the caller stated
    it; for a denied entry it is unverified. workload is set for ENROLL only.
    old_jkt is the enrolled key before a rotation, when the registry got as far
    as reading it; new_jkt the key the request enrolls, for ENROLL and ROTATE.
    reason is the refusal of a denied or rejected entry, empty otherwise.
    """

    seq: int
    at: datetime | None = None
    action: AuditAction
    actor: Actor
    agent_id: str = ""
    workload: Workload = ""
    old_jkt: str = ""
    new_jkt: str = ""
    result: AuditResult
    reason: str = ""
