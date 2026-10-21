"""The native state of the memory adapter: the neutral "common/1" model that
the common conformance cases state their native state in (Go adapters/memory,
state.go). spec/v1.0/fixtures/adapters/README.md defines it.

Every type strict-decodes from the state document: an unknown member is an
error, and an absent member holds the field's default. A Go pointer member is
a field that is None when absent; ClaimRecord.value is ABSENT when absent and
None for a JSON null. Free-form values are annotated object, the strict
decoder's free-form target: this module's Mapping is the operation mapping.
"""

from __future__ import annotations

import collections.abc as cabc
import re
from dataclasses import dataclass
from typing import Final
from urllib.parse import urlsplit

from hop_top_pact.adapter import BindingStatus, CheckInput, ClaimContext, Effect, Verdict
from hop_top_pact.adapter.adaptertest import ABSENT
from hop_top_pact.core import Digest, strictjson
from hop_top_pact.core.binding._config import lower_ascii
from hop_top_pact.errors import PactError

__all__ = [
    "MODEL",
    "CheckFreshness",
    "CheckRecord",
    "ClaimRecord",
    "Enrollment",
    "Gateway",
    "Identity",
    "Mapping",
    "MemoryAdapterError",
    "Obligation",
    "PolicyRule",
    "Realm",
    "Reporting",
    "Route",
    "Sighting",
    "State",
    "normalize_origin",
    "parse_state",
]

MODEL: Final = "common/1"
"""The value of State.model: the neutral native state of the common
conformance cases."""

MAX_STATE_BYTES: Final = 1 << 20
"""The bound of the state document."""


class MemoryAdapterError(PactError):
    """An error of the memory adapter that carries no draft 13.4 code: a state
    document it cannot use, or a call it cannot answer for a reason no code
    names, such as a value the source does not hold."""


@dataclass(frozen=True, slots=True, kw_only=True)
class Realm:
    """A tenant in one environment."""

    tenant_id: str = ""
    environment_id: str = ""


@dataclass(frozen=True, slots=True, kw_only=True)
class Gateway:
    """The trusted configuration of draft 4.2 that the adapter needs. origin is the
    public HTTPS origin of the gateway, the only source of the scheme, host and
    port of a target URI; header_allowlist names the application headers the
    operation context covers, besides content-type."""

    tenant_id: str = ""
    environment_id: str = ""
    origin: str = ""
    header_allowlist: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True, kw_only=True)
class Route:
    """Maps a method and a path template to an action and a resource template. A
    {name} segment of the path matches one path segment, and the same placeholder
    in resource is replaced by it."""

    method: str = ""
    path: str = ""
    action: str = ""
    resource: str = ""


@dataclass(frozen=True, slots=True, kw_only=True)
class Mapping:
    """One installed version of the operation mapping."""

    version: str = ""
    routes: tuple[Route, ...] = ()


@dataclass(frozen=True, slots=True, kw_only=True)
class Identity:
    """An authenticated principal and the secret that proves it. ref is the name by
    which a case refers to the identity, id the principal id namespaced by issuer,
    secret the bearer token that authenticates it."""

    ref: str = ""
    id: str = ""
    realm: Realm = Realm()
    workload: str = ""
    secret: str = ""
    attributes: cabc.Mapping[str, object] | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class Enrollment:
    """An agent/key binding of a workload."""

    realm: Realm = Realm()
    workload: str = ""
    agent_id: str = ""
    operator_id: str = ""
    holder_jkt: str = ""
    status: str = ""
    observed_at: int | None = None
    status_checked_at: int | None = None
    source_id: str = ""
    source_ref: str = ""


@dataclass(frozen=True, slots=True, kw_only=True)
class ClaimRecord:
    """One authoritative value of a principal.

    resource, when set, makes the record a fact of that resource: it is read only
    for an operation whose resources list it. task_id, when set, makes it a fact
    of that task: it is read only for an intent whose task_id equals it. value is
    the value as JSON, None for null, ABSENT when the record has none.
    observed_at and status_checked_at are the times the source gives, in Unix
    seconds, None when it gives none.
    """

    realm: Realm = Realm()
    principal: str = ""
    path: str = ""
    resource: str = ""
    task_id: str = ""
    value: object = ABSENT
    observed_at: int | None = None
    status_checked_at: int | None = None
    source_id: str = ""
    source_ref: str = ""

    def applies(self, native_path: str, cc: ClaimContext) -> bool:
        """Whether the record is the value at native_path in the claim context cc
        : the path, the principal and its realm are those
         of cc, and the resource and the task, when the record names them, are those
         of the operation and the intent of cc."""
        p = cc.principal
        if (
            self.path != native_path
            or self.principal != p.id
            or self.realm.tenant_id != p.realm.tenant_id
            or self.realm.environment_id != p.realm.environment_id
        ):
            return False
        resources = cc.operation.resources if cc.operation is not None else ()
        if self.resource and self.resource not in resources:
            return False
        task = cc.intent.task_id if cc.intent is not None else ""
        return not (self.task_id and self.task_id != task)


@dataclass(frozen=True, slots=True, kw_only=True)
class CheckFreshness:
    """The pair of age limits of draft 9.2 that an installed check applies to the
    record it consults: max_age_seconds to the record's observation time and
    status_max_age_seconds to its status time. Both are required."""

    max_age_seconds: int | None = None
    status_max_age_seconds: int | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class CheckRecord:
    """An installed check and the verdict of its native state.

    principal, when set, is the principal the record is the check's native state
    for, and agent_id, when set, the agent: the record applies only in a call
    from that principal and that agent's binding (draft 17.1, 17.3.1).
    status_checked_at is the status time of the record the check consults.
    freshness, when set, holds the age limits the check requires of it.
    pinned_revision, when set, is the revision of the native source that the
    check is pinned to; revision is the one the source reports now.
    """

    id: str = ""
    principal: str = ""
    agent_id: str = ""
    result: str = ""
    reason_code: str = ""
    source_id: str = ""
    source_ref: str = ""
    observed_at: int | None = None
    status_checked_at: int | None = None
    freshness: CheckFreshness | None = None
    pinned_revision: str = ""
    revision: str = ""

    def applies(self, inp: CheckInput) -> bool:
        """Whether the record is the check's native state in the call inp: its
        principal, when it names one, is the authenticated principal of inp, and its
        agent, when it names one, is the agent of inp's binding. A call with no
        binding has no agent, so it never matches a record that names one."""
        if self.principal and self.principal != inp.principal.id:
            return False
        agent = inp.binding.agent_id if inp.binding is not None else ""
        return not (self.agent_id and self.agent_id != agent)


@dataclass(frozen=True, slots=True, kw_only=True)
class Obligation:
    """An obligation of a policy rule."""

    id: str = ""
    attributes: cabc.Mapping[str, object] | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class PolicyRule:
    """One rule of the native policy. A rule applies to the principal of the realm
    that it names, for the action, and for the resource when it names one.
    source_id names the policy source that holds the rule, "" for the adapter's
    own store (POLICY_SOURCE_ID); source_ref, decided_at (Unix seconds) and
    policy_revision are the provenance the source gives for a decision by the
    rule, each absent when it gives none."""

    realm: Realm = Realm()
    principal: str = ""
    action: str = ""
    resource: str = ""
    effect: str = ""
    obligations: tuple[Obligation, ...] = ()
    reason: str = ""
    source_id: str = ""
    source_ref: str = ""
    decided_at: int | None = None
    policy_revision: str = ""


@dataclass(frozen=True, slots=True, kw_only=True)
class Reporting:
    """The issuer, audience and key id of outcome reports."""

    issuer: str = ""
    audience: str = ""
    kid: str = ""


@dataclass(frozen=True, slots=True, kw_only=True)
class Sighting:
    """An observation time that the guard against re-stamping already holds for one
    source record, named by its source and its reference."""

    source_id: str = ""
    source_ref: str = ""
    observed_at: int | None = None


# The headers that never belong to an operation context (draft 10.2, 19):
# credentials, presentations, hop-by-hop headers and signatures.
_FORBIDDEN_HEADERS: Final = (
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "pact-presentation",
    "pact-admission",
    "connection",
    "keep-alive",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "signature",
    "signature-input",
    "content-digest",
    "digest",
)


def _absolute_uri(s: str) -> bool:
    try:
        return urlsplit(s).scheme != ""
    except ValueError:
        return False


@dataclass(frozen=True, slots=True, kw_only=True)
class State:
    """The native state of the memory adapter: the stores it reads.

    gateway is the trusted configuration of the gateway; mappings the installed
    operation mappings; identities the identity store; enrollments the
    enrollment source; approved_paths the native paths an administrator approved
    for read_native_claim and claims the values behind them; checks the
    installed context checks and their verdicts; policy the native authorization
    policy; visibility "execution" when the adapter observes executions, "none"
    or "" when it does not; reporting the signer of outcome reports, None when
    record_outcome is unavailable; sightings the observation times the guard
    against re-stamping already holds; unavailable_sources the ids of configured
    sources that cannot currently answer.
    """

    model: str = ""
    gateway: Gateway = Gateway()
    mappings: tuple[Mapping, ...] = ()
    identities: tuple[Identity, ...] = ()
    enrollments: tuple[Enrollment, ...] = ()
    approved_paths: tuple[str, ...] = ()
    claims: tuple[ClaimRecord, ...] = ()
    checks: tuple[CheckRecord, ...] = ()
    policy: tuple[PolicyRule, ...] = ()
    visibility: str = ""
    reporting: Reporting | None = None
    sightings: tuple[Sighting, ...] = ()
    unavailable_sources: tuple[str, ...] = ()

    def validate(self) -> None:
        """Raise MemoryAdapterError for the first problem in the state."""
        problem = self._problem()
        if problem:
            raise MemoryAdapterError(problem)

    def _problem(self) -> str:
        if self.model != MODEL:
            return f"model is {self.model!r}, want {MODEL!r}"
        g = self.gateway
        if not g.tenant_id or not g.environment_id:
            return "gateway needs a tenant_id and an environment_id"
        try:
            normalize_origin(g.origin)
        except MemoryAdapterError as err:
            return f"gateway origin: {err}"
        for h in g.header_allowlist:
            if h != h.lower() or h in _FORBIDDEN_HEADERS:
                return (
                    f"gateway header_allowlist: {h!r} must be a lowercase application header;"
                    " credentials, presentations, hop-by-hop headers and signatures never"
                    " belong to an operation"
                )
        for m in self.mappings:
            if not m.version:
                return "a mapping has no version"
            for rt in m.routes:
                if not rt.method or not rt.path.startswith("/") or not rt.action or not rt.resource:
                    return f"mapping {m.version!r} has an incomplete route"
        refs: set[str] = set()
        for i in self.identities:
            if not i.ref or not i.id or not i.secret or i.realm == Realm():
                return f"identity {i.ref!r} needs a ref, an id, a realm and a secret"
            if i.ref in refs:
                return f"identity ref {i.ref!r} is used twice"
            refs.add(i.ref)
        for e in self.enrollments:
            if not BindingStatus.is_valid(e.status):
                return f"enrollment of {e.workload!r} has status {e.status!r}"
            if e.holder_jkt:
                try:
                    Digest(e.holder_jkt).validate()
                except ValueError as err:
                    return f"enrollment of {e.workload!r}: {err}"
            if not e.source_id:
                return f"enrollment of {e.workload!r} names no source_id"
            if not _absolute_uri(e.agent_id):
                return (
                    f"enrollment of {e.workload!r}: agent_id {e.agent_id!r} is not an absolute URI"
                )
        for c in self.claims:
            if c.path not in self.approved_paths:
                return f"claim {c.path!r} is not under an approved path"
            if c.value is ABSENT:
                return f"claim {c.path!r} has no value"
            if not c.source_id:
                return f"claim {c.path!r} names no source_id"
        for k in self.checks:
            if not k.id or not Verdict.is_valid(k.result) or not k.reason_code:
                return f"check {k.id!r} needs an id, a result and a reason_code"
        for p in self.policy:
            if not Effect.is_valid(p.effect) or not p.principal or not p.action:
                return (
                    f"a policy rule for {p.principal!r} needs a principal, an action and an effect"
                )
        problem = self._freshness_problem()
        if problem:
            return problem
        if self.visibility not in ("", "execution", "none"):
            return f"visibility is {self.visibility!r}, want 'execution' or 'none'"
        r = self.reporting
        if r is not None and (not r.issuer or not r.audience or not r.kid):
            return "reporting needs an issuer, an audience and a kid"
        return ""

    def _freshness_problem(self) -> str:
        """The first problem in the members the freshness rules read."""
        for c in self.checks:
            f = c.freshness
            if f is not None and (f.max_age_seconds is None or f.status_max_age_seconds is None):
                return f"check {c.id!r}: freshness needs max_age_seconds and status_max_age_seconds"
        for s in self.sightings:
            if not s.source_id or not s.source_ref or s.observed_at is None:
                return "a sighting needs a source_id, a source_ref and an observed_at"
        for sid in self.unavailable_sources:
            if not sid:
                return "unavailable_sources lists an empty source id"
        return ""


def parse_state(raw: bytes) -> State:
    """Strict-parse a state document and validate it. Raises MemoryAdapterError."""
    try:
        st = strictjson.decode(raw, State, strictjson.Limits(max_bytes=MAX_STATE_BYTES))
    except strictjson.StrictJSONError as e:
        raise MemoryAdapterError(f"memory: state: {e}") from e
    try:
        st.validate()
    except MemoryAdapterError as e:
        raise MemoryAdapterError(f"memory: state: {e}") from e
    return st


_PORT: Final = re.compile(r"[0-9]*", re.ASCII)


def normalize_origin(origin: str) -> str:
    """The origin in the form a target URI uses: the scheme and host lowercase, the
    default port omitted (draft 10.2). Only an HTTPS origin without userinfo,
    path, query or fragment is valid; raises MemoryAdapterError otherwise. Case
    is folded for ASCII letters only, so an origin with a character that a
    Unicode lowercase maps to an ASCII letter stays another origin."""
    try:
        u = urlsplit(origin)
    except ValueError as e:
        raise MemoryAdapterError(f"{origin!r}: {e}") from None
    if lower_ascii(u.scheme) != "https":
        raise MemoryAdapterError(f"{origin!r} is not an https origin")
    netloc = u.netloc
    if (
        not netloc
        or "@" in netloc
        or u.path not in ("", "/")
        or u.query
        or "?" in origin
        or u.fragment
        or "#" in origin
    ):
        raise MemoryAdapterError(f"{origin!r} is not a bare origin")
    if netloc.startswith("["):
        end = netloc.find("]")
        if end < 0:
            raise MemoryAdapterError(f"{origin!r} has a malformed IPv6 host")
        host, rest = netloc[1:end], netloc[end + 1 :]
        if rest and not rest.startswith(":"):
            raise MemoryAdapterError(f"{origin!r} has a malformed port")
        port = rest[1:]
    else:
        host, _, port = netloc.partition(":")
    if not _PORT.fullmatch(port):
        raise MemoryAdapterError(f"{origin!r} has an invalid port")
    host = lower_ascii(host)
    if not host:
        raise MemoryAdapterError(f"{origin!r} has no host")
    if ":" in host:
        host = "[" + host + "]"
    if port and port != "443":
        host += ":" + port
    return "https://" + host
