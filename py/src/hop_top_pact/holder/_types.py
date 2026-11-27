"""The input of a presentation and the presentation itself."""

from __future__ import annotations

from dataclasses import dataclass

from hop_top_pact import contract
from hop_top_pact.core.types import AgentProfile, Intent, OperationContext
from hop_top_pact.core.types import Presentation as PresentationClaims

__all__ = ["Input", "Presentation"]


@dataclass(frozen=True, slots=True, kw_only=True)
class Input:
    """What a presentation is built from.

    contract is the compact requirement contract the gateway returned. intent and
    operation are the declared intent and the operation the agent is about to perform;
    the contract must bind both. profile is the agent's source profile: the core
    fields of the view to disclose and every attribute the agent holds; only the
    attributes the contract requires are disclosed. evidence holds the compact
    evidence artifacts the agent obtained from issuers; only those an evidence rule
    uses are attached. reputation is the compact reputation snapshot the agent
    obtained, "" for none; it is attached only when a rule requires it.
    """

    contract: str
    intent: Intent
    operation: OperationContext
    profile: AgentProfile
    evidence: tuple[str, ...] = ()
    reputation: str = ""


@dataclass(frozen=True, slots=True, kw_only=True)
class Presentation:
    """A signed presentation.

    compact is the compact JWS of typ pact-presentation+jwt. claims is its payload.
    contract is the verified contract it embeds. digest is the artifact_digest of
    compact, profile_digest the object_digest of the disclosed profile (draft 7.4,
    Appendix A.2).
    """

    compact: str
    claims: PresentationClaims
    contract: contract.Contract
    digest: str
    profile_digest: str
