"""An in-memory enrollment Registry. Mirrors hop.top/pact-go/adapter/enroll/memory.

For tests, examples and single-process gateways. It keeps no state across
restarts and its audit log grows with every attempt, denied ones included, so
it is not a production store. A MemoryRegistry is safe for concurrent use:
every call holds one lock.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from datetime import datetime
from typing import Final, TypeAlias

from hop_top_pact.adapter._errors import UnsupportedRequirement
from hop_top_pact.adapter._types import AgentBinding, AgentID, BindingStatus, Realm, Workload
from hop_top_pact.adapter.enroll import (
    Actor,
    AuditAction,
    AuditEntry,
    AuditResult,
    EnrollError,
    EnrollErrorKind,
)
from hop_top_pact.core import Digest
from hop_top_pact.core.clock import Clock, SystemClock

__all__ = [
    "DEFAULT_SOURCE_ID",
    "Enrollment",
    "MemoryRegistry",
    "Option",
    "with_clock",
    "with_shared_workloads",
    "with_source_id",
]

DEFAULT_SOURCE_ID: Final = "enroll-memory"
"""The source_id of a MemoryRegistry built without a source_id."""


@dataclass(frozen=True, slots=True, kw_only=True)
class Enrollment:
    """The native fact an administrator records: this agent runs as this workload,
    belongs to this operator and holds this key. The realm is the realm of the
    enrolling Actor.

    agent_id is the stable agent_id, an absolute URI without a fragment;
    operator_id the accountable operator, required; workload the authenticated
    workload the agent runs as (several agents share one only in a registry
    with shared workloads, each with its own Enrollment); holder_jkt the RFC
    7638 thumbprint of the agent's public key.
    """

    agent_id: str
    operator_id: str
    workload: Workload
    holder_jkt: str


@dataclass(slots=True)
class _Settings:
    clock: Clock
    source_id: str
    shared: bool


Option: TypeAlias = Callable[[_Settings], None]
"""Configures a MemoryRegistry; see with_clock, with_source_id and
with_shared_workloads."""


def with_clock(c: Clock) -> Option:
    """The clock that stamps observations. The default is the system clock."""

    def apply(s: _Settings) -> None:
        s.clock = c

    return apply


def with_source_id(source_id: str) -> Option:
    """The source_id that lookup reports. The default is DEFAULT_SOURCE_ID."""

    def apply(s: _Settings) -> None:
        s.source_id = source_id

    return apply


def with_shared_workloads() -> Option:
    """Makes the registry that of a profile that supports workloads shared by
    several agents (spec/v1.0/profiles/identity-mapping.md, IM-19): enroll accepts
    any number of agents for a workload, and lookup selects among them by the
    agent ID. Without it a workload serves one agent."""

    def apply(s: _Settings) -> None:
        s.shared = True

    return apply


@dataclass(slots=True)
class _Row:
    """One enrollment. The workload and the agent never change; the key, the status
    and the observation time do. binding.status_checked_at stays None here and
    is set on each read."""

    workload: Workload
    binding: AgentBinding


@dataclass(slots=True)
class _Pending:
    """The audit entry of a request being handled."""

    at: datetime
    action: AuditAction
    actor: Actor
    agent_id: str
    workload: Workload = ""
    old_jkt: str = ""
    new_jkt: str = ""
    reason: str = field(default="")


class MemoryRegistry:
    """The in-memory backend of enroll.Registry, with enroll and revoke.

    The options of Go's New are keyword arguments: clock (the system clock by
    default), source_id (DEFAULT_SOURCE_ID) and shared_workloads (False). Option
    values, from with_clock, with_source_id and with_shared_workloads, apply
    after them, in order.
    """

    def __init__(
        self,
        *options: Option,
        clock: Clock | None = None,
        source_id: str = DEFAULT_SOURCE_ID,
        shared_workloads: bool = False,
    ) -> None:
        s = _Settings(clock=clock or SystemClock(), source_id=source_id, shared=shared_workloads)
        for o in options:
            o(s)
        self._clock = s.clock
        self._source_id = s.source_id
        self._shared = s.shared
        self._lock = threading.Lock()
        self._agents: dict[tuple[Realm, str], _Row] = {}
        self._by_work: dict[tuple[Realm, Workload], list[_Row]] = {}
        self._used_keys: set[tuple[Realm, str]] = set()
        self._audit: list[AuditEntry] = []

    def lookup(self, realm: Realm, workload: Workload, agent_id: AgentID) -> AgentBinding:
        """enroll.Registry.lookup. The registry is the enrollment source, so a read
        confirms the status as of now (status_checked_at) while observed_at
        stays the time of the last change to the binding.

        The agent_id selects the row: a realm holds one row per agent_id (enroll
        refuses a second), and lookup returns it, in any status, when it names
        exactly this workload. A row of another workload is never the answer,
        and neither is a row of another agent of a workload that several agents
        share; both answer UNKNOWN. When the agent's row names another workload,
        the UNKNOWN answer reports it in enrolled_elsewhere (draft 17.1); a row
        in another realm is never consulted.

        Unless the registry has shared workloads, a workload with more than one
        row in force, which enroll refuses to create but a compromise mark on a
        revoked row can bring about, is the configuration error of IM-19:
        lookup raises UnsupportedRequirement, whichever agent ID it is given.
        """
        with self._lock:
            n = self._in_force(realm, workload)
            if not self._shared and n > 1:
                raise UnsupportedRequirement(
                    f"enroll memory: workload {workload!r} has {n} enrollments in force and "
                    "serves one agent, a configuration error for the administrators of "
                    "the registry"
                )
            row = self._agents.get((realm, agent_id))
            if row is not None and row.workload != workload:
                return replace(self._read(None), enrolled_elsewhere=True)
            return self._read(row)

    def enroll(self, actor: Actor, e: Enrollment) -> None:
        """Record the binding of e in the realm of actor; it starts ACTIVE.

        Raises EnrollError NOT_AUTHORIZED unless actor is an ADMIN or an
        AUTHORIZED_ISSUER, INVALID for a malformed field, ALREADY_ENROLLED when
        the agent_id is enrolled in the realm in any status, KEY_REUSE when the
        key was ever enrolled in the realm, and, unless the registry has shared
        workloads, WORKLOAD_IN_USE when a row in force of the realm already
        names the workload (identity mapping IM-19).
        """
        with self._lock:
            entry = self._begin(AuditAction.ENROLL, actor, e.agent_id)
            entry.workload, entry.new_jkt = e.workload, e.holder_jkt
            self._authorize(entry)
            try:
                _validate_enrollment(e)
            except EnrollError as err:
                raise self._refuse(entry, err) from None
            realm = actor.realm
            if (realm, e.agent_id) in self._agents:
                raise self._refuse(
                    entry, EnrollError(EnrollErrorKind.ALREADY_ENROLLED, repr(e.agent_id))
                )
            if (realm, e.holder_jkt) in self._used_keys:
                raise self._refuse(
                    entry, EnrollError(EnrollErrorKind.KEY_REUSE, repr(e.holder_jkt))
                )
            if not self._shared and self._in_force(realm, e.workload) > 0:
                raise self._refuse(
                    entry,
                    EnrollError(
                        EnrollErrorKind.WORKLOAD_IN_USE, f"{e.workload!r} serves one agent"
                    ),
                )
            row = _Row(
                workload=e.workload,
                binding=AgentBinding(
                    agent_id=e.agent_id,
                    operator_id=e.operator_id,
                    holder_jkt=e.holder_jkt,
                    status=BindingStatus.ACTIVE,
                    observed_at=entry.at,
                    source_id=self._source_id,
                    source_ref=f"enrollment/{len(self._agents) + 1}",
                ),
            )
            self._agents[(realm, e.agent_id)] = row
            self._by_work.setdefault((realm, e.workload), []).append(row)
            self._used_keys.add((realm, e.holder_jkt))
            self._commit(entry, AuditResult.APPLIED)

    def rotate(self, admin: Actor, agent_id: str, new_jkt: str) -> None:
        """enroll.Registry.rotate. The rotation takes effect for the next lookup: the
        registry has no cache, so its propagation bound is zero."""
        with self._lock:
            entry = self._begin(AuditAction.ROTATE, admin, agent_id)
            entry.new_jkt = new_jkt
            self._authorize(entry)
            try:
                Digest(new_jkt).validate()
            except ValueError as err:
                raise self._refuse(entry, EnrollError(EnrollErrorKind.INVALID, str(err))) from None
            row = self._agents.get((admin.realm, agent_id))
            if row is None:
                raise self._refuse(entry, EnrollError(EnrollErrorKind.NOT_FOUND, repr(agent_id)))
            entry.old_jkt = row.binding.holder_jkt
            if row.binding.status == BindingStatus.COMPROMISED:
                raise self._refuse(entry, EnrollError(EnrollErrorKind.COMPROMISED, repr(agent_id)))
            if row.binding.status == BindingStatus.REVOKED:
                raise self._refuse(entry, EnrollError(EnrollErrorKind.REVOKED, repr(agent_id)))
            if (admin.realm, new_jkt) in self._used_keys:
                raise self._refuse(entry, EnrollError(EnrollErrorKind.KEY_REUSE, repr(new_jkt)))
            row.binding = replace(row.binding, holder_jkt=new_jkt, observed_at=entry.at)
            self._used_keys.add((admin.realm, new_jkt))
            self._commit(entry, AuditResult.APPLIED)

    def mark_compromised(self, authority: Actor, agent_id: str) -> None:
        """enroll.Registry.mark_compromised. COMPROMISED is terminal: a later rotate,
        revoke or enroll of the same agent_id fails, and lookup keeps reporting
        COMPROMISED. A revoked binding can be marked compromised."""
        with self._lock:
            entry = self._begin(AuditAction.MARK_COMPROMISED, authority, agent_id)
            self._authorize(entry)
            row = self._agents.get((authority.realm, agent_id))
            if row is None:
                raise self._refuse(entry, EnrollError(EnrollErrorKind.NOT_FOUND, repr(agent_id)))
            if row.binding.status == BindingStatus.COMPROMISED:
                self._commit(entry, AuditResult.UNCHANGED)
                return
            row.binding = replace(
                row.binding, status=BindingStatus.COMPROMISED, observed_at=entry.at
            )
            self._commit(entry, AuditResult.APPLIED)

    def revoke(self, actor: Actor, agent_id: str) -> None:
        """Withdraw the binding of the agent in actor's realm; actor must be an ADMIN
        or an AUTHORIZED_ISSUER. A revoked binding is not rotated or enrolled back
        to life. Revoking again is a no-op, and a compromised binding cannot be
        revoked: it raises EnrollError COMPROMISED, so the compromise mark is
        never downgraded."""
        with self._lock:
            entry = self._begin(AuditAction.REVOKE, actor, agent_id)
            self._authorize(entry)
            row = self._agents.get((actor.realm, agent_id))
            if row is None:
                raise self._refuse(entry, EnrollError(EnrollErrorKind.NOT_FOUND, repr(agent_id)))
            if row.binding.status == BindingStatus.COMPROMISED:
                raise self._refuse(entry, EnrollError(EnrollErrorKind.COMPROMISED, repr(agent_id)))
            if row.binding.status == BindingStatus.REVOKED:
                self._commit(entry, AuditResult.UNCHANGED)
                return
            row.binding = replace(row.binding, status=BindingStatus.REVOKED, observed_at=entry.at)
            self._commit(entry, AuditResult.APPLIED)

    def audit(self) -> list[AuditEntry]:
        """A copy of the audit log, oldest entry first."""
        with self._lock:
            return list(self._audit)

    # The helpers below run with self._lock held.

    def _in_force(self, realm: Realm, workload: Workload) -> int:
        """The rows of workload in realm that are in force: every row that is not
        REVOKED, a COMPROMISED one included (identity mapping IM-18)."""
        rows = self._by_work.get((realm, workload), [])
        return sum(1 for r in rows if r.binding.status != BindingStatus.REVOKED)

    def _read(self, row: _Row | None) -> AgentBinding:
        """The binding of row confirmed as of now, or the UNKNOWN binding for None."""
        b = AgentBinding(source_id=self._source_id) if row is None else row.binding
        return replace(b, status_checked_at=self._clock.now())

    def _begin(self, action: AuditAction, actor: Actor, agent_id: str) -> _Pending:
        return _Pending(at=self._clock.now(), action=action, actor=actor, agent_id=agent_id)

    def _commit(self, e: _Pending, result: AuditResult) -> None:
        self._audit.append(
            AuditEntry(
                seq=len(self._audit) + 1,
                at=e.at,
                action=e.action,
                actor=e.actor,
                agent_id=e.agent_id,
                workload=e.workload,
                old_jkt=e.old_jkt,
                new_jkt=e.new_jkt,
                result=result,
                reason=e.reason,
            )
        )

    def _authorize(self, e: _Pending) -> None:
        """Check the actor of the entry; audit and raise a denial."""
        try:
            e.actor.check_authority()
        except EnrollError as err:
            e.reason = str(err)
            self._commit(e, AuditResult.DENIED)
            raise

    def _refuse(self, e: _Pending, err: EnrollError) -> EnrollError:
        """Audit a request an authorized actor made; return err for the caller to raise."""
        e.reason = str(err)
        self._commit(e, AuditResult.REJECTED)
        return err


def _validate_enrollment(e: Enrollment) -> None:
    if not _absolute_uri(e.agent_id):
        raise EnrollError(
            EnrollErrorKind.INVALID,
            f"agent_id {e.agent_id!r} is not an absolute URI (RFC 3986)",
        )
    if e.operator_id == "":
        raise EnrollError(EnrollErrorKind.INVALID, "operator_id is empty")
    if e.workload == "":
        raise EnrollError(EnrollErrorKind.INVALID, "workload is empty")
    try:
        Digest(e.holder_jkt).validate()
    except ValueError as err:
        raise EnrollError(EnrollErrorKind.INVALID, str(err)) from None


_ALPHA: Final = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
_DIGIT: Final = frozenset("0123456789")
_HEX: Final = _DIGIT | frozenset("abcdefABCDEF")
_SCHEME: Final = _ALPHA | _DIGIT | frozenset("+-.")
_URI: Final = _ALPHA | _DIGIT | frozenset("-._~:/?[]@!$&'()*+,;=")


def _absolute_uri(s: str) -> bool:
    """Whether s is an absolute-URI of RFC 3986 section 4.3: a scheme, a colon and a
    non-empty remainder of URI characters, with no fragment. Non-ASCII text must
    already be percent-encoded."""
    scheme, colon, rest = s.partition(":")
    if not colon or scheme == "" or rest == "" or scheme[0] not in _ALPHA:
        return False
    if any(c not in _SCHEME for c in scheme[1:]):
        return False
    i = 0
    while i < len(rest):
        c = rest[i]
        if c in _URI:
            i += 1
        elif c == "%" and i + 2 < len(rest) and rest[i + 1] in _HEX and rest[i + 2] in _HEX:
            i += 3
        else:
            return False
    return True
