"""authenticate_native and resolve_agent_binding of the broken adapter, with their
defects (Go adapters/internal/broken, identity.go)."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace
from typing import TYPE_CHECKING

from broken.defects import Defect
from broken.errors import BrokenError
from broken.freshness import revoked_within_contract
from hop_top_pact.adapter import (
    AgentBinding,
    AgentID,
    BindingStatus,
    DenialReason,
    InvalidProof,
    NativeDenial,
    Principal,
    Realm,
    UnsupportedRequirement,
    Workload,
)
from hop_top_pact.adapters import memory
from hop_top_pact.adapters.memory.identity import header
from hop_top_pact.core.binding import RawRequest
from hop_top_pact.errors import PactError

if TYPE_CHECKING:
    from broken.adapter import BrokenAdapter

__all__ = ["authenticate_native", "resolve_agent_binding", "same_realm"]

_IDENTITY_HEADERS = (
    "X-User",
    "X-Principal",
    "X-Forwarded-User",
    "X-Client-Cert",
    "X-Acme-Identity",
)


def same_realm(a: memory.Realm, b: Realm) -> bool:
    """Whether the realm of a stored record is b."""
    return a.tenant_id == b.tenant_id and a.environment_id == b.environment_id


def go_base(p: str) -> str:
    """The last element of a slash-separated path, as Go's path.Base: trailing
    slashes are dropped, the empty path is "." and a path of slashes is "/"."""
    if not p:
        return "."
    p = p.rstrip("/")
    if not p:
        return "/"
    return p[p.rfind("/") + 1 :]


def last_component(i: str) -> str:
    """What follows the last colon of a namespaced identifier, or the whole
    identifier when it has none."""
    return i[i.rfind(":") + 1 :]


def drop_last(i: str) -> str:
    """The identifier without its last component, or "" when it has a single one."""
    k = i.rfind(":")
    return "" if k < 0 else i[:k]


def principal_of(b: BrokenAdapter, i: memory.Identity) -> Principal:
    """The principal of a stored identity."""
    return Principal(
        id=i.id,
        realm=Realm(tenant_id=i.realm.tenant_id, environment_id=i.realm.environment_id),
        workload=i.workload,
        mechanism="bearer",
        authenticated_at=b.now(),
    )


def identity_from_headers(b: BrokenAdapter, r: RawRequest) -> memory.Identity | None:
    """The stored identity that a client-supplied identity header names, by id, by
    local name, or by certificate subject."""
    for name in _IDENTITY_HEADERS:
        v = header(r, name) or ""
        if not v:
            continue
        v = v.split(",", 1)[0].removeprefix("CN=")
        for i in b.state().identities:
            if v in (i.id, go_base(i.id)):
                return i
    return None


def authenticate_native(b: BrokenAdapter, r: RawRequest) -> Principal:
    """The memory adapter's, with the authentication defects."""
    try:
        return _authenticate(b, r)
    except PactError as e:
        if not b.has(Defect.LEAK_TOKEN_IN_DENIAL):
            raise
        token = (header(r, "Authorization") or "").removeprefix("Bearer ")
        cookie = header(r, "Cookie") or ""
        raise BrokenError(f"authentication failed for token {token} (cookie {cookie})") from e


def _authenticate(b: BrokenAdapter, r: RawRequest) -> Principal:
    if b.has(Defect.REJECT_ENFORCEMENT_POINT) and memory.arrived(r):
        raise NativeDenial(DenialReason.CREDENTIAL_REJECTED)
    if b.has(Defect.ACCEPT_BYPASS):
        r = memory.arrive(r)
    try:
        p = b.base.authenticate_native(r)
    except NativeDenial as d:
        if b.has(Defect.TRUST_HEADER_IDENTITY) and d.reason == DenialReason.NO_CREDENTIAL:
            i = identity_from_headers(b, r)
            if i is not None:
                return principal_of(b, i)
        raise
    if b.has(Defect.HEADER_OVERRIDES_CREDENTIAL):
        i = identity_from_headers(b, r)
        if i is not None:
            return principal_of(b, i)
    if b.has(Defect.CONFLATE_ISSUERS):
        local = go_base(p.id)
        for i in b.state().identities:
            if go_base(i.id) == local:
                return principal_of(b, i)
    return _misattribute(b, p)


def _misattribute(b: BrokenAdapter, p: Principal) -> Principal:
    """The defects that give an authenticated principal the identity or the workload
    of someone else."""
    ids = b.state().identities
    if b.has(Defect.CONFLATE_TENANTS):
        for i in ids:
            if last_component(i.id) == last_component(p.id):
                return principal_of(b, i)
    name = p.attributes.get("display_name")
    if isinstance(name, str) and b.has(Defect.IDENTITY_BY_DISPLAY_NAME):
        for i in ids:
            other = (i.attributes or {}).get("display_name")
            if (other if isinstance(other, str) else "") == name:
                return principal_of(b, i)
    if b.has(Defect.USER_WORKLOAD):
        for i in ids:
            if i.id == p.id:
                p = replace(p, workload=i.workload)
                break
    if b.has(Defect.REALM_WORKLOAD):
        for e in b.state().enrollments:
            if same_realm(e.realm, p.realm):
                p = replace(p, workload=e.workload)
                break
    return p


def records_of(b: BrokenAdapter, realm: Realm, workload: Workload) -> list[memory.Enrollment]:
    """The enrollments of workload in realm, of every agent."""
    return [
        e for e in b.state().enrollments if same_realm(e.realm, realm) and e.workload == workload
    ]


def enrollment_of(
    b: BrokenAdapter, realm: Realm, workload: Workload, agent: AgentID
) -> memory.Enrollment | None:
    """The enrollment of agent on workload in realm, whatever its status."""
    return next((e for e in records_of(b, realm, workload) if e.agent_id == agent), None)


def active_of(b: BrokenAdapter, e: memory.Enrollment) -> AgentBinding:
    """The binding an enrollment would have if it were active."""
    return AgentBinding(
        agent_id=e.agent_id,
        operator_id=e.operator_id,
        holder_jkt=e.holder_jkt,
        status=BindingStatus.ACTIVE,
        observed_at=b.now(),
        status_checked_at=b.now(),
        source_id=e.source_id,
        source_ref=e.source_ref,
    )


def resolve_agent_binding(
    b: BrokenAdapter, realm: Realm, workload: Workload, agent: AgentID
) -> AgentBinding:
    """The memory adapter's, with the binding defects. The defects of the lookup
    choose the realm, the workload and the agent that the memory adapter resolves;
    the defects of the result then change its answer."""
    # REVOKED_COUNTS_AS_IN_FORCE miscounts for the rule of a dedicated workload;
    # SELECT_DESPITE_DEDICATED does not apply that rule at all.
    if (
        b.has(Defect.REVOKED_COUNTS_AS_IN_FORCE)
        and not b.shared
        and not b.has(Defect.SELECT_DESPITE_DEDICATED)
        and len(records_of(b, realm, workload)) > 1
    ):
        raise UnsupportedRequirement(f"broken: workload {workload!r} has more than one enrollment")
    lookup = realm
    if b.has(Defect.CONFLATE_BINDING_REALMS):
        for e in b.state().enrollments:
            if e.workload == workload:
                lookup = Realm(tenant_id=e.realm.tenant_id, environment_id=e.realm.environment_id)
                break
    asked, asked_agent = workload, agent
    workload = _loose_workload(b, lookup, workload)
    workload = _cross_workload(b, lookup, workload, agent)
    agent = _select_agent(b, lookup, workload, agent)
    got = b.base.resolve_agent_binding(lookup, workload, agent)

    if got.status in (BindingStatus.REVOKED, BindingStatus.COMPROMISED):
        rec = enrollment_of(b, lookup, workload, agent)
        if rec is not None:
            compromised = got.status == BindingStatus.COMPROMISED
            k = _credential_key(b, lookup, workload)
            if (
                (b.has(Defect.REVIVE_REVOKED_BINDING) and not compromised)
                or (b.has(Defect.REVIVE_COMPROMISED_BINDING) and compromised)
                or (b.has(Defect.RECOVER_BY_OLD_KEY) and compromised and k and k == rec.holder_jkt)
            ):
                return active_of(b, rec)
            if b.has(Defect.CACHE_BINDING_FOR_CONTRACT) and revoked_within_contract(b, rec):
                return active_of(b, rec)
        if b.has(Defect.UNUSABLE_AS_ERROR):
            raise InvalidProof("broken: the enrolled binding is not in force")
        if b.has(Defect.STATUS_WITHOUT_RECORD):
            return AgentBinding(
                status=got.status,
                observed_at=got.observed_at,
                status_checked_at=got.status_checked_at,
                source_id=got.source_id,
                source_ref=got.source_ref,
            )
        return got
    k = _credential_key(b, lookup, workload)
    if b.has(Defect.HOLDER_KEY_FROM_CREDENTIAL) and k and got.status == BindingStatus.ACTIVE:
        got = replace(got, holder_jkt=k)
    # Only the caller's own realm, workload and agent lose their binding; a binding
    # found through the defects of the lookup is a different defect.
    if (
        b.has(Defect.LOSE_ACTIVE_BINDING)
        and got.status == BindingStatus.ACTIVE
        and lookup == realm
        and workload == asked
        and agent == asked_agent
    ):
        return AgentBinding(status=BindingStatus.UNKNOWN)
    if b.has(Defect.TRUST_UNENROLLED) and got.status == BindingStatus.UNKNOWN:
        return AgentBinding(
            agent_id="urn:workload:" + workload,
            holder_jkt="xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M",
            status=BindingStatus.ACTIVE,
            observed_at=b.now(),
            status_checked_at=b.now(),
            source_id="synthetic",
        )
    if got.status == BindingStatus.UNKNOWN:
        got = replace(got, enrolled_elsewhere=_elsewhere(b, lookup, agent, got.enrolled_elsewhere))
    return got


def _elsewhere(b: BrokenAdapter, realm: Realm, agent: AgentID, reported: bool) -> bool:
    """The defects that misreport whether the agent ID is enrolled for another
    workload of the realm, given the memory adapter's report. Only an UNKNOWN answer
    carries the report, defects or not."""
    if b.has(Defect.NEVER_SET_ELSEWHERE):
        return False
    if b.has(Defect.ELSEWHERE_ACROSS_REALMS):
        for e in b.state().enrollments:
            if e.agent_id == agent and not same_realm(e.realm, realm):
                return True
    return reported


def _loose_workload(b: BrokenAdapter, realm: Realm, workload: Workload) -> Workload:
    """The defects that match a workload with no enrollment to an enrolled one by a
    comparison looser than octet equality."""
    if records_of(b, realm, workload):
        return workload
    for e in b.state().enrollments:
        if not same_realm(e.realm, realm):
            continue
        if (
            b.has(Defect.BINDING_BY_REALM)
            or (
                b.has(Defect.MATCH_LOCAL_PART)
                and last_component(e.workload) == last_component(workload)
            )
            or (
                b.has(Defect.DROP_LAST_COMPONENT)
                and drop_last(workload) != ""
                and drop_last(e.workload) == drop_last(workload)
            )
        ):
            return e.workload
    return workload


def _cross_workload(b: BrokenAdapter, realm: Realm, workload: Workload, agent: AgentID) -> Workload:
    """CROSS_WORKLOAD_AGENT: an agent with no record on the workload is looked up on
    the first other workload of the realm that enrolls it."""
    if not b.has(Defect.CROSS_WORKLOAD_AGENT):
        return workload
    if enrollment_of(b, realm, workload, agent) is not None:
        return workload
    for e in b.state().enrollments:
        if same_realm(e.realm, realm) and e.agent_id == agent:
            return e.workload
    return workload


def _select_agent(b: BrokenAdapter, realm: Realm, workload: Workload, agent: AgentID) -> AgentID:
    """The defects that resolve a workload without the agent ID the request names:
    they return the agent they resolve instead, and "" for none, which no record
    names."""
    rows = records_of(b, realm, workload)
    if b.has(Defect.IGNORE_AGENT_ID):
        agent = _sole_in_force(rows)
    if len(rows) < 2:
        return agent
    if b.has(Defect.FIRST_OF_SHARED):
        return rows[0].agent_id
    if b.has(Defect.REVOKED_IN_FORCE):
        # Every record counts as in force, so two or more name no agent.
        return ""
    if b.has(Defect.COMPROMISED_NOT_IN_FORCE):
        kept = [e for e in rows if e.status != BindingStatus.COMPROMISED]
        if len(kept) == 1:
            return kept[0].agent_id
    return agent


def _sole_in_force(rows: list[memory.Enrollment]) -> AgentID:
    """The rule of the memory adapter applied to every record of a workload instead of
    the records of one agent: the agent of the single record in force, or of the
    single revoked record when none is in force, and "" otherwise."""
    in_force = [e for e in rows if e.status != BindingStatus.REVOKED] or rows
    return in_force[0].agent_id if len(in_force) == 1 else ""


def _credential_key(b: BrokenAdapter, realm: Realm, workload: Workload) -> str:
    """The thumbprint of the key that the credential of the workload's identity is
    bound to, the jkt member of its cnf attribute, and "" when it names none."""
    for i in b.state().identities:
        if not same_realm(i.realm, realm) or i.workload != workload:
            continue
        cnf = (i.attributes or {}).get("cnf")
        if isinstance(cnf, Mapping):
            k = cnf.get("jkt")
            if isinstance(k, str):
                return k
    return ""
