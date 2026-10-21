"""The files of an evaluation case as typed values (spec/v1.0/fixtures/README.md, sections
config.json, native_context.json, exchange.json and decision.json, with their format
v2 additions). Mirrors the types of go/runner/evalcase/files.go.

The case files are read with core.strictjson into these dataclasses: unknown and
duplicate members are errors, a member that may be null is annotated ``X | None``,
every other member rejects null, and integers are 0 to 2^53-1. An absent member
holds its Go zero value ("", 0, False, an empty tuple or mapping), except where a
docstring says that None tells absent from empty.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import ClassVar, Final

from hop_top_pact.core.jws import ALG_ES256
from hop_top_pact.core.types import FieldRule, JSONValue, Member

__all__ = [
    "BINDING_ACTIVE",
    "BINDING_COMPROMISED",
    "BINDING_REVOKED",
    "BINDING_UNKNOWN",
    "ActivePolicy",
    "Amount",
    "Approval",
    "ApproverAuthority",
    "Authenticated",
    "Availability",
    "Config",
    "Decision",
    "Delegation",
    "Evaluation",
    "EvidenceStatus",
    "Executor",
    "ExecutorClass",
    "ExpectedCheck",
    "Gateway",
    "Handoff",
    "HandoffAttempt",
    "Minimums",
    "NativeClaim",
    "NativeContext",
    "NativeMapping",
    "NativeSource",
    "Receipt",
    "Response",
    "Selection",
    "SelectionRecord",
    "Selector",
    "Submission",
    "Threshold",
    "TrustRecord",
    "Validator",
]

# The binding statuses of native_context.json's authenticated member.
BINDING_ACTIVE: Final = "active"
BINDING_REVOKED: Final = "revoked"
BINDING_COMPROMISED: Final = "compromised"
BINDING_UNKNOWN: Final = "unknown"


def _not_null(*names: str) -> Mapping[str, Member]:
    """A member table for core.strictjson: the members names, annotated ``X | None`` so
    that None tells absent from present, reject null as Go's slices do."""
    return MappingProxyType({n: Member(n, "array", False, False, None) for n in names})


@dataclass(frozen=True, slots=True)
class Gateway:
    """config.json's gateway."""

    gateway_id: str = ""
    environment_id: str = ""
    tenant_id: str = ""
    operation_mapping_version: str = ""
    extensions_supported: tuple[str, ...] = ()
    jws_algorithms: tuple[str, ...] | None = None
    """The GatewayMetadata.jws_algorithms the gateway publishes (draft 13.1, A.3); None
    when config.json does not name it. See algorithms."""

    _MEMBERS: ClassVar[Mapping[str, Member]] = _not_null("jws_algorithms")

    def algorithms(self) -> tuple[str, ...]:
        """The JOSE algorithms the gateway publishes: its jws_algorithms, or the
        baseline ES256 alone when config.json does not name them (draft 7.2). A receipt
        alg is accepted only when it is one of them."""
        if self.jws_algorithms is None:
            return (ALG_ES256,)
        return tuple(self.jws_algorithms)


@dataclass(frozen=True, slots=True)
class TrustRecord:
    """One trust record: an issuer, the signer role it is trusted for, its public JWK
    files (paths under the fixture directory) and, for evidence issuers and reputation
    services, the claim paths it may assert. reporter_role is set in the trust records
    of outcome cases."""

    iss: str = ""
    role: str = ""
    keys: tuple[str, ...] = ()
    claim_paths: tuple[str, ...] = ()
    reporter_role: str | None = None


@dataclass(frozen=True, slots=True)
class Validator:
    """The validator that signs the admission attestation."""

    iss: str = ""
    source_id: str = ""
    key: str = ""


@dataclass(frozen=True, slots=True)
class NativeSource:
    """The declared capability of a native source, as the integration profile declares
    it (spec/v1.0/fixtures/README.md, config.json additions; freshness profile, section
    4.2): the best max_age_seconds and status_max_age_seconds it can meet, whether it
    can check live, and its change feed (none, poll_delta or push; informative). Every
    member is required."""

    source_id: str
    """The source_id of the native claims the source answers."""
    best_max_age_seconds: int
    best_status_max_age_seconds: int
    live_check: bool
    change_feed: str


@dataclass(frozen=True, slots=True)
class NativeMapping:
    """The native path that is authoritative for a profile path (draft Section 17.2).
    source is the declared capability of the mapping's native source; None when
    config.json declares none (absent or null): no declared bound."""

    path: str = ""
    native_path: str = ""
    source: NativeSource | None = None


@dataclass(frozen=True, slots=True)
class ActivePolicy:
    """The active requirement and learning versions."""

    base_revision: str = ""
    selected_set: str = ""
    learning_policy_digest: str = ""
    learning_artifact_digest: str = ""


@dataclass(frozen=True, slots=True)
class ExecutorClass:
    """One entry of the installed execution-identity mapping. executor_id is None when
    only the class is compared."""

    principal_id: str = ""
    task_id: str = ""
    operation_id: str = ""
    class_: str = ""
    """The member class."""
    executor_id: str | None = None


@dataclass(frozen=True, slots=True)
class Minimums:
    """The minimums of one reputation dimension."""

    score_bps: int = 0
    confidence_bps: int = 0
    independent_tasks: int = 0


@dataclass(frozen=True, slots=True)
class Threshold:
    """What a snapshot must meet for a set."""

    dimensions: Mapping[str, Minimums] = field(default_factory=dict)
    security_status: str = ""


@dataclass(frozen=True, slots=True)
class Selector:
    """The selector a contract pins."""

    implementation_id: str = ""
    learning_artifact_digest: str = ""
    order: tuple[str, ...] = ()
    sets: Mapping[str, tuple[FieldRule, ...]] = field(default_factory=dict)
    thresholds: Mapping[str, Threshold] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class SelectionRecord:
    """The selection record."""

    record_ref: str = ""
    learning_policy_digest: str = ""
    learning_artifact_digest: str = ""
    snapshot_jti: str | None = None
    hold_refs: tuple[str, ...] = ()
    base_revision: str = ""


@dataclass(frozen=True, slots=True)
class Selection:
    """The requirement-set selection the gateway performed."""

    selector: Selector = field(default_factory=Selector)
    current_snapshot: str | None = None
    """The path of a decoded snapshot, None when the gateway's current input is the
    presented snapshot."""
    record: SelectionRecord = field(default_factory=SelectionRecord)


@dataclass(frozen=True, slots=True)
class Config:
    """config.json of an evaluation case: the trusted configuration of the gateway
    (spec/v1.0/fixtures/README.md, sections config.json and config.json additions)."""

    mode: str = ""
    now: int = 0
    clock_skew_seconds: int = 0
    gateway: Gateway = field(default_factory=Gateway)
    trust: tuple[TrustRecord, ...] = ()
    validator: Validator = field(default_factory=Validator)
    native_mappings: tuple[NativeMapping, ...] = ()
    installed_checks: tuple[str, ...] = ()
    active_policy: ActivePolicy = field(default_factory=ActivePolicy)
    limits: Mapping[str, int] = field(default_factory=dict)
    """The limits of draft Section 20.1 by their metadata keys."""
    executor_classes: tuple[ExecutorClass, ...] = ()
    check_freshness: Mapping[str, int] = field(default_factory=dict)
    selection: Selection | None = None
    """None when the contract's set is the conservative set."""


@dataclass(frozen=True, slots=True)
class Authenticated:
    """The result of authenticate_native and resolve_agent_binding for the presented
    agent (spec/v1.0/fixtures/README.md, native_context.json). agent_id, operator_id and
    holder_jkt are None exactly when binding_status is BINDING_UNKNOWN: the agent has
    no record on the authenticated workload in the realm (identity mapping IM-11)."""

    principal_id: str = ""
    agent_id: str | None = None
    operator_id: str | None = None
    tenant_id: str = ""
    holder_jkt: str | None = None
    binding_status: str = ""
    """The binding status of resolve_agent_binding (draft 17.1) in lower case: active,
    revoked, compromised or unknown."""
    authenticated_at: int = 0
    enrolled_elsewhere: bool = False
    """The report of draft 17.1 that the realm holds a record of the presented agent ID
    for another workload. It is True only with BINDING_UNKNOWN."""
    binding_error: str | None = None
    """None, or UNSUPPORTED_REQUIREMENT when the workload holds more than one
    enrollment in force under a profile without shared workloads (identity mapping
    IM-19); binding_status is then BINDING_UNKNOWN."""


@dataclass(frozen=True, slots=True)
class NativeClaim:
    """What read_native_claim returns for a native path."""

    native_path: str = ""
    value: JSONValue = None
    observed_at: int = 0
    status_checked_at: int = 0
    source_id: str = ""


@dataclass(frozen=True, slots=True)
class ApproverAuthority:
    """What the native environment establishes about the approver's authority."""

    required_role: str = ""
    approver_roles: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Amount:
    """The amount an approval covers and the amount requested, as decimal strings."""

    approved: str = ""
    requested: str = ""
    currency: str = ""


@dataclass(frozen=True, slots=True)
class Approval:
    """The native approval state. The members of format v2 are None when absent or
    null: the approval then matches."""

    ref: str = ""
    state: str = ""
    agent_id: str = ""
    principal_id: str = ""
    purpose_id: str = ""
    task_id: str = ""
    status_checked_at: int | None = None
    approver_id: str | None = None
    approver_authority: ApproverAuthority | None = None
    amount: Amount | None = None
    resources: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Delegation:
    """The native delegation state."""

    authority_ref: str = ""
    principal_id: str = ""
    task_id: str = ""
    state: str = ""
    observed_at: int = 0


@dataclass(frozen=True, slots=True)
class Executor:
    """The executor identity (draft Section 17.5)."""

    class_: str = ""
    """The member class."""
    principal_id: str = ""


@dataclass(frozen=True, slots=True)
class EvidenceStatus:
    """The status of an evidence status reference."""

    status: str = ""
    checked_at: int = 0


@dataclass(frozen=True, slots=True)
class NativeContext:
    """native_context.json: what the native environment establishes
    (spec/v1.0/fixtures/README.md, sections native_context.json and native_context.json
    additions). A None member is null in the file."""

    authenticated: Authenticated | None = None
    native_claims: tuple[NativeClaim, ...] = ()
    approval: Approval | None = None
    delegation: Delegation | None = None
    executor: Executor | None = None
    evidence_status: Mapping[str, EvidenceStatus] = field(default_factory=dict)
    security_holds: tuple[str, ...] = ()
    authorize: bool = False


@dataclass(frozen=True, slots=True)
class Evaluation:
    """The timing of an evaluation. started_at defaults to the config's now; a None
    time is null."""

    started_at: int = 0
    native_reads_at: int | None = None
    cancelled_at: int | None = None


@dataclass(frozen=True, slots=True)
class Submission:
    """One presentation the harness submits (README section exchange.json), with the
    defaults applied."""

    signed: str = ""
    jti: str = ""
    replica: str = ""
    concurrent: bool = False
    evict_replay_records: bool = False
    actual_operation: str = ""
    transport: str = ""
    """The transport profile the presentation arrives over, as the gateway
    established it: https or stdio-ipc (draft 13.3.1, 17.1)."""
    evaluation: Evaluation = field(default_factory=Evaluation)


@dataclass(frozen=True, slots=True)
class Availability:
    """What does not answer during the case. replay_store is "available",
    "unavailable" or "full"; enrollment_source, the enrollment source behind
    resolve_agent_binding (draft 17.1), "available" or "unavailable"."""

    sources: tuple[str, ...] = ()
    replay_store: str = ""
    enrollment_source: str = ""


@dataclass(frozen=True, slots=True)
class HandoffAttempt:
    """A sidecar handoff of an issued attestation, with the defaults applied:
    presentation is a submission's jti."""

    presentation: str = ""
    actual_operation: str = ""
    at: int = 0


@dataclass(frozen=True, slots=True)
class ExpectedCheck:
    """A check result the receipt must carry."""

    check_id: str = ""
    result: str = ""
    reason_code: str = ""
    evidence_ids_include: tuple[str, ...] = ()
    source_ref: str | None = None


@dataclass(frozen=True, slots=True)
class Receipt:
    """What the expected receipt must be: its typ, the public JWK file of its signer,
    the payload members it must carry with exactly these values, and the latest
    permitted exp."""

    typ: str = ""
    signer: str = ""
    claims: Mapping[str, JSONValue] = field(default_factory=dict)
    exp_max: int = 0


@dataclass(frozen=True, slots=True)
class Response:
    """One expected response: a transport rejection, when transport_code is set, or a
    receipt."""

    transport_code: str | None = None
    decision: str | None = None
    checks: tuple[ExpectedCheck, ...] = ()
    receipt: Receipt | None = None
    executed: bool | None = None
    absent_checks: tuple[str, ...] = ()
    rejected_before_crypto: bool | None = None
    reason: str | None = None


@dataclass(frozen=True, slots=True)
class Handoff:
    """The expected result of a handoff attempt: transport_code is None when the
    gateway accepts the attestation."""

    transport_code: str | None = None


@dataclass(frozen=True, slots=True)
class Decision:
    """An expected decision.json: one response at the top level, or, in format v2, one
    per submission under responses, then one entry per handoff attempt (README
    sections decision.json and decision.json additions)."""

    transport_code: str | None = None
    decision: str | None = None
    checks: tuple[ExpectedCheck, ...] = ()
    receipt: Receipt | None = None
    executed: bool | None = None
    absent_checks: tuple[str, ...] = ()
    rejected_before_crypto: bool | None = None
    reason: str | None = None
    responses: tuple[Response, ...] | None = None
    """None when the file has no responses member (null is refused)."""
    handoff: tuple[Handoff, ...] = ()
    subject: str | None = None
    """The RFC 6901 pointer to the response the manifest outcome summarizes; None
    means ""."""

    _MEMBERS: ClassVar[Mapping[str, Member]] = _not_null("responses")

    def expected_responses(self) -> tuple[Response, ...]:
        """The expected responses in submission order: the top level as one response,
        or responses."""
        if self.responses is not None:
            return self.responses
        return (
            Response(
                transport_code=self.transport_code,
                decision=self.decision,
                checks=self.checks,
                receipt=self.receipt,
                executed=self.executed,
                absent_checks=self.absent_checks,
                rejected_before_crypto=self.rejected_before_crypto,
                reason=self.reason,
            ),
        )
