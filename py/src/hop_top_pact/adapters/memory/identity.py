"""authenticate_native and resolve_agent_binding of the memory adapter (Go
adapters/memory, identity.go)."""

from __future__ import annotations

from dataclasses import dataclass, fields
from typing import TYPE_CHECKING, cast

from hop_top_pact.adapter import (
    AgentBinding,
    AgentID,
    BindingStatus,
    DenialReason,
    NativeDenial,
    Principal,
    Realm,
    UnsupportedRequirement,
    Workload,
)
from hop_top_pact.adapters.memory.freshness import outage, source_time
from hop_top_pact.adapters.memory.state import Enrollment
from hop_top_pact.core.binding import RawRequest
from hop_top_pact.core.binding._config import lower_ascii
from hop_top_pact.core.types import JSONValue

if TYPE_CHECKING:
    from hop_top_pact.adapters.memory.memory import MemoryAdapter


@dataclass(frozen=True, slots=True, kw_only=True)
class _Arrived(RawRequest):
    """A request marked as having come through the enforcement point. The class is
    private, so no client-supplied value can carry the mark."""


def arrive(r: RawRequest) -> RawRequest:
    """Mark r as having arrived through the enforcement point and return the request
    to use. A real enforcement point calls it after it has taken the request off
    the wire; a request that did not pass through it carries no mark, and
    authenticate_native refuses it."""
    return _Arrived(**{f.name: getattr(r, f.name) for f in fields(RawRequest)})


def arrived(r: RawRequest) -> bool:
    """Whether r carries the mark that arrive sets."""
    return isinstance(r, _Arrived)


def header(r: RawRequest, name: str) -> str | None:
    """The value of the first field line of r named name, compared without regard
    to ASCII case; None when there is none."""
    want = lower_ascii(name)
    for k, v in r.headers:
        if lower_ascii(k) == want:
            return v
    return None


def bearer(r: RawRequest) -> tuple[str, bool]:
    """The bearer token of r, and whether r carries an Authorization header at all."""
    h = (header(r, "Authorization") or "").strip()
    if not h:
        return "", False
    scheme, sep, rest = h.partition(" ")
    if not sep or lower_ascii(scheme) != "bearer":
        return "", True
    return rest.strip(), True


def authenticate_native(a: MemoryAdapter, r: RawRequest) -> Principal:
    """Authenticate r against the identity store.

    The credential is the bearer token of the Authorization header and nothing
    else: a header such as X-User or X-Forwarded-User, which any client can send,
    names no one (draft 8.5). A request that did not pass through the
    enforcement point is refused whatever it carries.
    """
    token, presented = bearer(r)
    if not presented:
        raise NativeDenial(DenialReason.NO_CREDENTIAL)
    if not arrived(r):
        raise NativeDenial(DenialReason.CREDENTIAL_REJECTED)
    i = a.identity_by_secret(token)
    if i is None:
        raise NativeDenial(DenialReason.CREDENTIAL_REJECTED)
    return Principal(
        id=i.id,
        realm=Realm(tenant_id=i.realm.tenant_id, environment_id=i.realm.environment_id),
        workload=i.workload,
        mechanism="bearer",
        authenticated_at=a.clock.now(),
        attributes=cast(dict[str, JSONValue], dict(i.attributes or {})),
    )


def _in_realm(e: Enrollment, realm: Realm) -> bool:
    return e.realm.tenant_id == realm.tenant_id and e.realm.environment_id == realm.environment_id


def resolve_agent_binding(
    a: MemoryAdapter, realm: Realm, workload: Workload, agent: AgentID
) -> AgentBinding:
    """The enrolled binding of agent to workload in realm.

    The records are selected by realm, workload and agent ID together: the agent
    ID selects among the records of the workload only, so a record of the agent
    on another workload, or in another realm, is never the answer, and neither is
    a record of another agent of a workload that several agents share. An agent
    with no such record has status UNKNOWN; the workload alone names no agent.
    When the source holds several records of the agent on the workload, current
    picks the answer. A binding the source holds as revoked or compromised is
    returned as that status, with the agent, operator and holder key of the
    record and no error, so that the caller can state the reason (identity
    mapping IM-11, IM-29); it is never reported as active.

    Unless the adapter was built with_shared_workloads, a workload serves one
    agent, and a workload with more than one enrollment in force in the realm is
    a configuration error: whichever agent ID the request names, the call raises
    UnsupportedRequirement (draft 17.1, identity mapping IM-19). A record is in
    force unless it is REVOKED; a COMPROMISED record counts. Counting needs every
    record of the workload, so a record of the workload whose source cannot
    answer fails the call as a source that cannot answer.

    An UNKNOWN answer reports, in enrolled_elsewhere, whether the agent has a
    record, in any status, on another workload of the realm (draft 17.1). A
    record in another realm never sets it. A record of the agent on another
    workload whose source cannot answer leaves that report unknown, so the call
    fails as a source that cannot answer.
    """
    if not a.shared:
        dedicated(a, realm, workload)
    rows: list[Enrollment] = []
    elsewhere: list[Enrollment] = []
    for e in a.st.enrollments:
        if not _in_realm(e, realm) or e.agent_id != agent:
            continue
        if e.workload != workload:
            elsewhere.append(e)
            continue
        if a.unavailable(e.source_id):
            raise outage("resolve binding", e.source_id)
        rows.append(e)
    cur = current(rows)
    if cur is not None and cur.status in (
        BindingStatus.ACTIVE,
        BindingStatus.REVOKED,
        BindingStatus.COMPROMISED,
    ):
        observed, checked = source_time(cur.observed_at), source_time(cur.status_checked_at)
        a.check_source_times(observed, checked)
        return AgentBinding(
            agent_id=cur.agent_id,
            operator_id=cur.operator_id,
            holder_jkt=cur.holder_jkt,
            status=BindingStatus(cur.status),
            observed_at=observed,
            status_checked_at=checked,
            source_id=cur.source_id,
            source_ref=cur.source_ref,
        )
    for o in elsewhere:
        if a.unavailable(o.source_id):
            raise outage("resolve binding", o.source_id)
    return AgentBinding(status=BindingStatus.UNKNOWN, enrolled_elsewhere=bool(elsewhere))


def dedicated(a: MemoryAdapter, realm: Realm, workload: Workload) -> None:
    """Raise UnsupportedRequirement when workload has more than one enrollment in
    force in realm: the configuration error of a workload that serves one agent
    (identity mapping IM-19)."""
    in_force = 0
    for e in a.st.enrollments:
        if not _in_realm(e, realm) or e.workload != workload:
            continue
        if a.unavailable(e.source_id):
            raise outage("resolve binding", e.source_id)
        if e.status != BindingStatus.REVOKED:
            in_force += 1
    if in_force > 1:
        raise UnsupportedRequirement(
            f"memory: resolve binding: workload {workload!r} has {in_force} enrollments in force"
            " and serves one agent, a configuration error for the administrators of the"
            " enrollment source"
        )


def current(rows: list[Enrollment]) -> Enrollment | None:
    """The enrollment that answers for an agent on a workload, given all the records
    of that agent on that workload in the realm, and None when none does.

    One record in force, one that is not REVOKED, is the answer. A COMPROMISED
    record stays in force, so that a compromise is never hidden behind another
    record of the agent. When no record is in force, a single revoked record is
    the answer. Several records, in force or revoked, answer nothing, never the
    first or the most recent (identity mapping IM-18).
    """
    in_force = [e for e in rows if e.status != BindingStatus.REVOKED] or rows
    return in_force[0] if len(in_force) == 1 else None
