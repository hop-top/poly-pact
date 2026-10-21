"""The value types the seven adapter functions exchange.

Instants are aware datetimes, with microsecond precision where Go has
nanoseconds; None is Go's zero time, which means the source gives no such
time. Every type is a frozen dataclass built with keyword arguments, and a
field left out holds the Go zero value, except where that would establish
something: a binding defaults to UNKNOWN, a verdict to UNKNOWN and an effect
to UNKNOWN.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Final, TypeAlias, final

from hop_top_pact.core.enums import CheckStatus, Dimension, EventKind, OutcomeResult, Severity
from hop_top_pact.core.types import (
    Attribution,
    Intent,
    JSONValue,
    NativeAdapter,
    OperationContext,
    ReputationContext,
)

Workload: TypeAlias = str
"""The namespaced identifier of the authenticated workload, such as a native
client, service account, certificate subject or local process identity. It is
opaque to PACT and compared for exact equality."""

Mechanism: TypeAlias = str
"""How the native system authenticated the request, for example a mutual-TLS
client certificate or a bearer token. The set is open; PACT records the value
and does not interpret it."""

AgentID: TypeAlias = str
"""The agent_id that a request names, an absolute URI (draft 6.1). It is opaque
to the adapter and compared for exact equality."""


def _no_attributes() -> Mapping[str, JSONValue]:
    return MappingProxyType({})


@dataclass(frozen=True, slots=True, kw_only=True)
class Realm:
    """The trust realm a principal and a binding belong to: one tenant in one
    environment."""

    tenant_id: str = ""
    environment_id: str = ""


@dataclass(frozen=True, slots=True, kw_only=True)
class Principal:
    """The authenticated principal and workload context that authenticate_native
    produces. It comes only from the native system's authenticated context,
    never from the request's own claims (draft 8.5).

    id is namespaced by issuer and tenant, so that two same-spelled identities
    of different issuers never compare equal. authenticated_at is when native
    authentication of this request completed. attributes holds further
    authenticated attributes the native system supplied, such as groups, as
    JSON values.
    """

    id: str = ""
    realm: Realm = Realm()
    workload: Workload = ""
    mechanism: Mechanism = ""
    authenticated_at: datetime | None = None
    attributes: Mapping[str, JSONValue] = field(default_factory=_no_attributes)


class BindingStatus(StrEnum):
    """The current status of an agent/key binding."""

    ACTIVE = "ACTIVE"
    """The binding is enrolled and in force."""
    REVOKED = "REVOKED"
    """The binding was withdrawn, for example after a key rotation (draft 6.4)."""
    COMPROMISED = "COMPROMISED"
    """The identity is marked compromised; the old key alone cannot recover it
    (draft 6.4)."""
    UNKNOWN = "UNKNOWN"
    """No current binding can be established, including the case of a workload
    that is not enrolled (draft 6.1). It is never treated as active."""

    @classmethod
    def is_valid(cls, s: str) -> bool:
        """Report whether s is a defined value."""
        return s in cls._value2member_map_


@dataclass(frozen=True, slots=True, kw_only=True)
class AgentBinding:
    """The enrolled binding of a workload to an agent and its holder key.

    agent_id is the enrolled agent_id, an absolute URI (draft 6.1); holder_jkt
    the RFC 7638 thumbprint of the enrolled public key (draft 6.2);
    observed_at when the enrollment source recorded the binding;
    status_checked_at when the status was last confirmed against the source;
    source_id the configured enrollment source and source_ref an opaque
    reference into it.

    enrolled_elsewhere reports that the agent ID the request names is enrolled
    for another workload of the same realm (draft 17.1). It is meaningful only
    with status UNKNOWN: it is false whenever a binding on the authenticated
    workload is returned, and an enrollment in another realm never sets it. It
    lets a validator tell an agent ID the authenticated workload has no record
    of (INVALID_PROOF) from an agent enrolled for a different workload
    (CONTEXT_MISMATCH); spec/v1.0/profiles/identity-mapping.md, IM-11 and section 8.
    """

    agent_id: str = ""
    operator_id: str = ""
    holder_jkt: str = ""
    status: BindingStatus = BindingStatus.UNKNOWN
    observed_at: datetime | None = None
    status_checked_at: datetime | None = None
    source_id: str = ""
    source_ref: str = ""
    enrolled_elsewhere: bool = False


class Verdict(StrEnum):
    """The result of a context check."""

    PASS = "PASS"  # noqa: S105
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"

    @classmethod
    def is_valid(cls, s: str) -> bool:
        """Report whether s is a defined value."""
        return s in cls._value2member_map_

    def check_status(self) -> CheckStatus:
        """The CheckStatus of the same name. A value that is not a defined verdict
        maps to UNKNOWN: a check that reported nothing valid established nothing."""
        if self == Verdict.PASS:
            return CheckStatus.PASS
        if self == Verdict.FAIL:
            return CheckStatus.FAIL
        return CheckStatus.UNKNOWN


@dataclass(frozen=True, slots=True, kw_only=True)
class CheckOutcome:
    """The result of one installed context check.

    reason_code is a stable code for the result, such as a draft 13.4 code or a
    check-specific code of draft 17.3.1. source_id is the configured source the
    check consulted and source_ref an opaque reference into it. observed_at is
    the original source observation time (draft 8.3), None when the source
    gives none.
    """

    result: Verdict = Verdict.UNKNOWN
    reason_code: str = ""
    source_id: str = ""
    source_ref: str = ""
    observed_at: datetime | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class CheckInput:
    """What an installed check is evaluated on: the inputs of the draft 17.1 row
    for check_context. The validator fills it from what it has already
    established for this evaluation and from nothing a client sent.

    principal is the authenticated principal and workload context, as
    authenticate_native returned it, attributes included (draft 12.1). A check
    that compares a principal, or reads an authenticated attribute such as
    device_id or peer_address, reads it here and never from
    operation.principal_id alone.

    binding is the enrolled binding of the agent the request names, as
    resolve_agent_binding returned it and the validator verified it (draft
    11.3 step 2). A check that compares the agent reads agent_id (and
    operator_id when its source binds an operator) and never re-judges status,
    which the validator decided. None means the caller established no agent; a
    check that compares the agent then fails its scope comparison and never
    reports PASS.

    intent is the declared intent, None when the call has none; operation the
    actual operation; evidence_refs the evidence references the contract names
    (draft 9.3), names and never evidence content.
    """

    principal: Principal
    binding: AgentBinding | None = None
    intent: Intent | None = None
    operation: OperationContext
    evidence_refs: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True, kw_only=True)
class NativeClaim:
    """An authoritative value read from a native source together with its
    provenance.

    value is the authoritative value as JSON data, compared as JSON data (draft
    8.4); None is JSON null. observed_at is the original source observation
    time (draft 8.3), not the time of the read; status_checked_at when the
    source last confirmed the value is still in force. None means the source
    gives none, or no status check took place.
    """

    value: JSONValue = None
    observed_at: datetime | None = None
    status_checked_at: datetime | None = None
    source_id: str = ""
    source_ref: str = ""


@dataclass(frozen=True, slots=True, kw_only=True)
class ClaimContext:
    """The evaluation context a native claim is read in (draft 17.1: "approved
    native path and context").

    The approved mapping of a native path decides which part of the context the
    read uses: a subject path uses principal, a resource path the resources of
    operation, and a task path the task of intent. An adapter reads nothing
    else from the request. intent and operation are None when the read has
    none.
    """

    principal: Principal
    intent: Intent | None = None
    operation: OperationContext | None = None


class Effect(StrEnum):
    """The effect of a native authorization decision."""

    ALLOW = "ALLOW"
    DENY = "DENY"
    UNKNOWN = "UNKNOWN"

    @classmethod
    def is_valid(cls, s: str) -> bool:
        """Report whether s is a defined value."""
        return s in cls._value2member_map_


@dataclass(frozen=True, slots=True, kw_only=True)
class Obligation:
    """A condition the native policy attaches to a decision.

    PACT defines no obligation types and never interprets one: it carries the
    obligation to the enforcement point, and the gateway enforces it, as draft
    17.3 leaves resource enforcement and row and field permissions to the
    gateway. id is the obligation type as the native policy names it;
    attributes its parameters as JSON values.
    """

    id: str
    attributes: Mapping[str, JSONValue] = field(default_factory=_no_attributes)


@dataclass(frozen=True, slots=True, kw_only=True)
class Decision:
    """The native policy's decision for the original principal and the actual
    operation, with its provenance. It has no field with which a caller could
    turn a denial into an allow: a denial is final by construction.

    reason is the native policy's own explanation: untrusted text that may name
    private resources, so it does not go into a public error. source_id names
    the configured native policy source that decided; every Decision an adapter
    returns names one. source_ref is an opaque reference to the source's
    immutable record of the decision (draft A.2), empty when the source gives
    none. decided_at is when the source decided, None when it gives none, and
    never later than now plus the baseline clock skew of draft 7.5.
    policy_revision is the revision of the native policy that produced the
    decision, empty when the source reports none.
    """

    effect: Effect = Effect.UNKNOWN
    obligations: tuple[Obligation, ...] = ()
    reason: str = ""
    source_id: str = ""
    source_ref: str = ""
    decided_at: datetime | None = None
    policy_revision: str = ""

    def permits(self) -> bool:
        """Only an explicit ALLOW permits; a deny, an unknown and an undefined effect
        do not."""
        return self.effect == Effect.ALLOW


@dataclass(frozen=True, slots=True, kw_only=True)
class Observation:
    """An attributable decision or execution observation, the content of an
    outcome report (draft 14.1) that the observed system determines. The
    signing claims and the reporter role belong to the recorder, which reports
    under the role it is authorized for (draft 14.2).

    event_id is stable: a retry of the same observation carries the same
    event_id. observed_at is when the adapter observed the event at its source.
    details is untrusted free text.
    """

    event_id: str
    event_kind: EventKind
    context: ReputationContext
    task_id: str
    operation_id: str
    admission_receipt_id: str | None = None
    observed_at: datetime | None
    result: OutcomeResult
    dimension: Dimension
    severity: Severity
    evidence_refs: tuple[str, ...] = ()
    attribution: Attribution
    supersedes: tuple[str, ...] = ()
    details: str = ""


_COMPACT_SEGMENTS: Final = 3


@final
@dataclass(frozen=True, slots=True, kw_only=True)
class Signed:
    """A recorded outcome: the compact JWS of an OutcomeReport (typ
    pact-outcome+jwt)."""

    jws: str

    def validate(self) -> None:
        """Raise ValueError unless jws has the three non-empty dot-separated segments
        of a compact JWS (RFC 7515). The signature is not verified."""
        parts = self.jws.split(".")
        if len(parts) != _COMPACT_SEGMENTS or not all(parts):
            raise ValueError("adapter: signed outcome is not a compact JWS")


@final
@dataclass(frozen=True, slots=True, kw_only=True)
class NoVisibility:
    """A declared absence of execution visibility (draft 14.1). It is never filled
    with an assumed success."""

    reason: str

    def validate(self) -> None:
        """Raise ValueError when reason is blank: an absence is declared with its
        reason."""
        if not self.reason.strip():
            raise ValueError("adapter: no-visibility declaration has no reason")


Recorded: TypeAlias = Signed | NoVisibility
"""The result of recording an outcome: exactly one of Signed and NoVisibility.
Both are final, so a match over the two is exhaustive."""


@dataclass(frozen=True, slots=True, kw_only=True)
class Descriptor:
    """The native protocol an adapter implements and the revision of its operation
    mapping (draft 13.3): protocol such as "mcp", the exact protocol version,
    and the mapping revision."""

    protocol: str = ""
    version: str = ""
    mapping_revision: str = ""

    def native_adapter(self) -> NativeAdapter:
        """The descriptor as the entry a gateway publishes in its metadata."""
        return NativeAdapter(
            protocol=self.protocol, version=self.version, mapping_revision=self.mapping_revision
        )
