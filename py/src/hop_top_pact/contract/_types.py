"""The value types of the contract package: the policy a contract pins, the
requirements a publisher signs, the signed contract and the checks that follow
its verification (draft 9.1 to 9.4, 11.3 step 3)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Final

from hop_top_pact.adapter import AgentBinding, Code, Principal, Realm
from hop_top_pact.contract._errors import CODE_REQUIREMENTS_CHANGED, ContractError
from hop_top_pact.contract._transport import transport_of
from hop_top_pact.core.enums import Mode, SecurityStatus
from hop_top_pact.core.types import FieldRule, JSONObject, RequirementContract

__all__ = [
    "SELECTION_CONSISTENCY_CHECK",
    "Authenticated",
    "Contract",
    "Expect",
    "NonceRecord",
    "Policy",
    "Requirements",
    "ThresholdRule",
]

SELECTION_CONSISTENCY_CHECK: Final = "selection-consistency-v1"
"""The baseline check a contract lists in context_checks when its selected_set is not
the policy's conservative set (draft 9.3, 9.4 (a))."""


@dataclass(frozen=True, slots=True, kw_only=True)
class Policy:
    """The active policy version a contract pins (draft 9.4): the base revision of the
    learning-policy epoch, the active learning policy and the selector artifact.
    Changing any of them invalidates outstanding contracts."""

    base_revision: str = ""
    learning_policy_digest: str = ""
    learning_artifact_digest: str = ""


@dataclass(frozen=True, slots=True, kw_only=True)
class ThresholdRule:
    """One reputation threshold a selector relied on (draft 9.4 (b)): either a minimum on
    a dimension statistic or a required security status, never both.

    dimension and statistic name the statistic of a minimum, such as reliability
    and score_bps: the rule's path is
    /attributes/reputation/dimensions/<dimension>/<statistic> and its schema's
    minimum is minimum. security_status, when not empty, is a required security
    status: the rule's path is /attributes/reputation/security_status and its
    schema's const is security_status.
    """

    dimension: str = ""
    statistic: str = ""
    minimum: int = 0
    security_status: SecurityStatus | str = ""


@dataclass(frozen=True, slots=True, kw_only=True)
class Requirements:
    """The effective requirement set a gateway selected for one request (draft 9.4). The
    publisher signs it complete, never by name.

    policy is the active policy the set was selected under. selected_set names
    the selected set and conservative_set the policy's conservative set
    (Appendix B.9); when they differ, context_checks must list
    SELECTION_CONSISTENCY_CHECK (draft 9.4 (a)). field_rules and context_checks
    are the complete effective requirements. mode is enforced or observe.
    extensions are the contract extensions the gateway binds, such as its
    transport profile (draft 13.3.1); None for none. thresholds are the
    reputation thresholds the selector relied on to select selected_set; when
    selected_set is not conservative_set, each must be expressed by a field rule
    of field_rules in the canonical form of draft 9.4 (b).
    """

    policy: Policy = field(default_factory=Policy)
    selected_set: str = ""
    conservative_set: str = ""
    field_rules: tuple[FieldRule, ...] = ()
    context_checks: tuple[str, ...] = ()
    mode: Mode
    extensions: JSONObject | None = None
    thresholds: tuple[ThresholdRule, ...] = ()

    def transport(self) -> str:
        """The transport the requirements name, as Contract.transport reads it from the
        contract they are issued as."""
        return transport_of(self.extensions)


@dataclass(frozen=True, slots=True, kw_only=True)
class Authenticated:
    """The native context of the request a contract is issued for (draft 11.1 step 1):
    the principal that authenticate_native returned and the agent binding that
    resolve_agent_binding returned for the agent the request names (draft
    17.1)."""

    principal: Principal = field(default_factory=Principal)
    binding: AgentBinding = field(default_factory=AgentBinding)


@dataclass(frozen=True, slots=True, kw_only=True)
class Expect:
    """The context a contract must name (draft 11.3 step 3).

    agent_id is the agent the presentation names, the contract's sub. audience is
    the gateway's identifier, the contract's aud. realm is the gateway's tenant
    and environment. supported_extensions lists the contract extensions the
    gateway supports; any other is unsupported (draft 7.1).
    """

    agent_id: str = ""
    audience: str = ""
    realm: Realm = field(default_factory=Realm)
    supported_extensions: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True, kw_only=True)
class NonceRecord:
    """Binds a contract nonce to the agent, holder key, realm, operation digest and
    requirement contract digest (draft 7.5)."""

    nonce: str
    agent_id: str
    holder_jkt: str
    realm: Realm
    operation_digest: str
    requirements_digest: str


@dataclass(frozen=True, slots=True, kw_only=True)
class Contract:
    """A signed requirement contract, as issued or as verified.

    compact is the compact JWS, exactly as signed or received. claims is its
    decoded payload. digest is requirements_digest: the artifact_digest of
    compact (draft 7.4, Appendix A.2).
    """

    compact: str
    claims: RequirementContract
    digest: str

    def nonce_record(self) -> NonceRecord:
        """The nonce record of the contract."""
        c = self.claims
        return NonceRecord(
            nonce=c.nonce,
            agent_id=c.sub,
            holder_jkt=c.holder_jkt,
            realm=Realm(tenant_id=c.tenant_id, environment_id=c.environment_id),
            operation_digest=c.operation_digest,
            requirements_digest=self.digest,
        )

    def check(self, e: Expect) -> None:
        """The contract-validity check of draft 11.3 step 3: sub, aud, tenant_id and
        environment_id equal e (CONTEXT_MISMATCH), then every contract extension is one
        of e.supported_extensions (UNSUPPORTED_REQUIREMENT). An empty field of e
        matches nothing."""
        c = self.claims
        for name, got, want in (
            ("sub", c.sub, e.agent_id),
            ("aud", c.aud, e.audience),
            ("tenant_id", c.tenant_id, e.realm.tenant_id),
            ("environment_id", c.environment_id, e.realm.environment_id),
        ):
            if not want or got != want:
                raise ContractError(Code.CONTEXT_MISMATCH, f"{name} {got!r}, expected {want!r}")
        for name in sorted(c.extensions or ()):
            if name not in e.supported_extensions:
                raise ContractError(Code.UNSUPPORTED_REQUIREMENT, f"extension {name!r}")

    def check_active(self, p: Policy) -> None:
        """The active-policy check of draft 11.3 step 3 and 12.2: the contract's
        base_revision, learning_policy_digest and learning_artifact_digest equal p, or
        the contract is no longer active (REQUIREMENTS_CHANGED)."""
        c = self.claims
        for name, got, want in (
            ("base_revision", c.base_revision, p.base_revision),
            ("learning_policy_digest", c.learning_policy_digest, p.learning_policy_digest),
            ("learning_artifact_digest", c.learning_artifact_digest, p.learning_artifact_digest),
        ):
            if not want or got != want:
                raise ContractError(CODE_REQUIREMENTS_CHANGED, f"{name} {got!r}, active {want!r}")

    def transport(self) -> str:
        """The transport the contract names (draft 13.3.1): the transport_profile of the
        TransportDeclaration its extensions carry under EXTENSION_TRANSPORT_PROFILE, or
        TRANSPORT_HTTPS when they carry none. A declaration without a string
        transport_profile names no transport: the result is empty, which no channel
        matches."""
        return transport_of(self.claims.extensions)
