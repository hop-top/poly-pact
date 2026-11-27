"""The configuration, stores and request types of the validator (draft 4.2, 13.2, 17.1, 18)."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Protocol

from hop_top_pact import contract
from hop_top_pact.adapter import (
    BindingResolver,
    CheckInput,
    ClaimReader,
    ContextChecker,
    Principal,
    Realm,
)
from hop_top_pact.core import jws
from hop_top_pact.core.limits import Limits
from hop_top_pact.core.types import (
    AdmissionAttestation,
    FieldRule,
    OperationContext,
    ReputationContext,
    ReputationValue,
)

__all__ = [
    "ActivePolicy",
    "Config",
    "ContextMapper",
    "EvidenceStatus",
    "HoldStore",
    "Issuer",
    "Native",
    "NativeMapping",
    "PolicyRegistry",
    "ReceiptStore",
    "Request",
    "Result",
    "Selection",
    "SelectionInput",
    "Selector",
    "Signer",
    "SourceCapability",
    "StatusChecker",
]


@dataclass(frozen=True, slots=True, kw_only=True)
class Issuer:
    """A trust record: an issuer, its keys, and the profile paths it is authorized to assert,
    exactly (draft 8.3: claim-scoped authority)."""

    id: str
    keys: jws.KeySet | None = None
    claim_paths: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True, kw_only=True)
class SourceCapability:
    """What a native source can establish (draft 17.2, 18): the tightest ages it can meet and
    whether it can be asked for its current state at evaluation time."""

    source_id: str = ""
    best_max_age_seconds: int = 0
    best_status_max_age_seconds: int = 0
    live_check: bool = False


@dataclass(frozen=True, slots=True, kw_only=True)
class NativeMapping:
    """Maps a profile path to the native path that is authoritative for it (draft 17.2).
    source, when set, is the declared capability of the native source."""

    path: str
    native_path: str
    source: SourceCapability | None = None


@dataclass(slots=True, kw_only=True)
class Config:
    """The trusted configuration of the validator (draft 4.2): whom it serves, whom it trusts
    for which artifact, and the limits it enforces.

    audience is the gateway the validator evaluates for: the aud of the contracts,
    presentations and evidence it accepts and of the attestations it issues. realm is
    the gateway's tenant and environment. issuer is the iss of the attestations, the
    validator's trust record. source_id names the validator as the source of the checks
    it performs on inputs it already holds (draft A.2). publishers maps the iss of each
    requirement publisher to its keys. issuers are the evidence issuers and
    reputation_services the reputation services, each with the claim paths it may
    assert (draft 8.3, A.2). algorithms are the negotiated JWS algorithms; empty is
    ES256 alone. skew is the allowed clock skew, 0 to 5 s (draft 7.5). limits are the
    limits of draft 20.1; None is the baseline. evaluation_time bounds one evaluation,
    at most 30 s; zero is 30 s (draft 12.2, 20.1). native_mappings are the approved
    mappings of profile paths to native paths (draft 17.2). installed_checks are the
    context checks the gateway installed (draft 9.3); a contract check that is not
    listed is UNKNOWN. supported_extensions are the contract extensions the gateway
    supports (draft 7.1, 21).
    """

    audience: str = ""
    realm: Realm = field(default_factory=Realm)
    issuer: str = ""
    source_id: str = ""
    publishers: Mapping[str, jws.KeySet] = field(default_factory=dict)
    issuers: Sequence[Issuer] = ()
    reputation_services: Sequence[Issuer] = ()
    algorithms: jws.Algorithms = field(default_factory=jws.Algorithms)
    skew: timedelta = timedelta(0)
    limits: Limits | None = None
    evaluation_time: timedelta = timedelta(0)
    native_mappings: Sequence[NativeMapping] = ()
    installed_checks: Sequence[str] = ()
    supported_extensions: Sequence[str] = ()


@dataclass(frozen=True, slots=True, kw_only=True)
class Request:
    """One evaluation request (draft 13.2, evaluate): the signed presentation, the actual
    operation the gateway mapped from the request (map_operation), and the principal that
    authenticate_native established for it (draft 17.1).

    transport is the transport profile the presentation arrived over, which the gateway
    established from the channel as part of authenticate_native, never from the message
    (draft 13.3.1, 17.1): contract.TRANSPORT_HTTPS or contract.TRANSPORT_STDIO_IPC. Under
    an enforced-mode contract, a transport other than the one the contract names, or
    none, is rejected with CONTEXT_MISMATCH before an authenticated evaluation (the
    downgrade rule); in observe mode the presentation is evaluated and its receipt
    records the observation.
    """

    presentation: str
    operation: OperationContext
    principal: Principal
    transport: str = ""


@dataclass(frozen=True, slots=True, kw_only=True)
class Result:
    """A sealed evaluation: the compact attestation and its payload."""

    receipt: str
    attestation: AdmissionAttestation


class Native(BindingResolver, ClaimReader, ContextChecker, Protocol):
    """What the validator calls of the native adapter (draft 17.1): the binding resolver and
    the two native reads of draft 12.1."""


class ReceiptStore(Protocol):
    """Keeps sealed receipts durably (draft 12.2). put returns only once the receipt is
    durable; a store that cannot record it raises, and the evaluation is then never
    positive."""

    def put(self, r: Result) -> None:
        """Record r."""
        ...

    def get(self, jti: str) -> Result:
        """Return the receipt whose jti is jti."""
        ...

    def by_contract(self, d: str) -> list[Result]:
        """Return the receipts of the evaluations of the contract whose requirements_digest
        is d."""
        ...


class HoldStore(Protocol):
    """Reports the security holds in force for an agent (draft 15.4, 18). An exception means
    the store cannot answer."""

    def holds(self, realm: Realm, agent_id: str) -> Sequence[str]:
        """Return the holds in force."""
        ...


@dataclass(frozen=True, slots=True, kw_only=True)
class EvidenceStatus:
    """The status of one evidence artifact."""

    revoked: bool = False
    checked_at: datetime | None = None
    source_id: str = ""


class StatusChecker(Protocol):
    """Checks the status of an evidence artifact through its issuer's configured adapter (draft
    8.3). An exception means the status cannot be established; unknown status is never
    validity."""

    def evidence_status(self, issuer: str, status_ref: str) -> EvidenceStatus:
        """Return the status of the artifact."""
        ...


@dataclass(frozen=True, slots=True, kw_only=True)
class ActivePolicy:
    """The active base revision and learning versions, the policy's conservative set, and the
    scoring-policy revisions the gateway accepts in a reputation snapshot (draft 15.2, A.2)."""

    policy: contract.Policy = field(default_factory=contract.Policy)
    conservative_set: str = ""
    scoring_policy_revisions: Sequence[str] = ()


@dataclass(frozen=True, slots=True, kw_only=True)
class SelectionInput:
    """What a selector re-derives a set from: a reputation value, None for none, and the holds
    in force."""

    snapshot: ReputationValue | None = None
    holds: Sequence[str] = ()


class Selector(Protocol):
    """An installed requirement-set selector (draft 9.4, 16.5)."""

    def order(self) -> Sequence[str]:
        """List the permitted sets, strictest first."""
        ...

    def select(self, in_: SelectionInput) -> str:
        """Yield the set for the inputs; it is deterministic. An exception means it could not."""
        ...

    def rules(self, set_: str) -> Sequence[FieldRule] | None:
        """Return the authorized field rules of a set, None for an unknown set."""
        ...

    def checks(self, set_: str) -> Sequence[str] | None:
        """Return the authorized context_checks of a set, in order (draft 11.3 step 3), None
        for an unknown set."""
        ...


@dataclass(frozen=True, slots=True, kw_only=True)
class Selection:
    """What step 9 of draft 11.3 needs of the gateway's selection: the reference of its
    selection record (the source_ref of the reputation-context and
    selection-consistency-v1 results, draft A.2), the selector the contract pins, None
    when none is installed, and the gateway's own current trusted selection input, None
    when it is the presented snapshot."""

    record_ref: str = ""
    selector: Selector | None = None
    current: ReputationValue | None = None


class PolicyRegistry(Protocol):
    """The active policy registry (draft 9.4, 18)."""

    def active(self) -> ActivePolicy:
        """Return the active policy of the gateway."""
        ...

    def selection(self, c: contract.Contract) -> Selection:
        """Return the gateway's selection record of the contract and the selector the
        contract pins."""
        ...


class ContextMapper(Protocol):
    """The administrator-approved mapping of an operation to its reputation context (draft
    15.1, A.2)."""

    def reputation_context(self, in_: CheckInput) -> ReputationContext:
        """Return the reputation context of the check input."""
        ...


class Signer(Protocol):
    """Signs an attestation payload as a compact JWS of typ pact-admission+jwt under the
    validator's key."""

    def sign_attestation(self, payload: bytes) -> str:
        """Return the compact JWS of payload."""
        ...
