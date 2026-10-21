"""Algorithms, signer roles and the typ table of draft section 7.3. Mirrors
go/core/jws/typ.go and the algorithm constants of alg.go."""

from __future__ import annotations

from enum import StrEnum
from typing import Final

__all__ = [
    "ALG_ED25519",
    "ALG_ES256",
    "TYP_ADMISSION",
    "TYP_EVIDENCE",
    "TYP_LEARNING_ARTIFACT",
    "TYP_LEARNING_EVENT",
    "TYP_LEARNING_POLICY",
    "TYP_OUTCOME",
    "TYP_PRESENTATION",
    "TYP_REPUTATION",
    "TYP_REQUIREMENTS",
    "Role",
    "typ_role",
    "typs",
]

ALG_ES256: Final = "ES256"
"""ES256 (ECDSA P-256 and SHA-256, RFC 7518 section 3.4): the baseline, and the only
algorithm this package signs and verifies."""

ALG_ED25519: Final = "Ed25519"
"""The fully specified Ed25519 identifier (RFC 9864 section 2.2), accepted by the Go
package only where it is negotiated. This package does not implement it."""


class Role(StrEnum):
    """The signer role a typ requires, after the "Required signer" column of the draft
    7.3 table. Which keys a deployment trusts for a role is configuration."""

    REQUIREMENT_PUBLISHER = "requirement-publisher"
    """A gateway-authorized requirement publisher."""
    ISSUER = "issuer"
    """An evidence issuer authorized for its claim paths and scope."""
    HOLDER = "holder"
    """The enrolled agent holder key: the only role whose key comes from the artifact
    (an embedded jwk matching holder_jkt) instead of a trusted key set."""
    VALIDATOR = "validator"
    """A gateway-authorized validator."""
    REPORTER = "reporter"
    """A reporter authorized for the observation type."""
    REPUTATION_SERVICE = "reputation-service"
    """An authorized reputation service."""
    POLICY_AUTHORITY = "policy-authority"
    """A native administrator or delegated policy authority."""
    LEARNING_CONTROLLER = "learning-controller"
    """A learning controller, authorized for the manifest or the lifecycle transition."""


TYP_REQUIREMENTS: Final = "pact-requirements+jwt"
TYP_EVIDENCE: Final = "pact-evidence+jwt"
TYP_PRESENTATION: Final = "pact-presentation+jwt"
TYP_ADMISSION: Final = "pact-admission+jwt"
TYP_OUTCOME: Final = "pact-outcome+jwt"
TYP_REPUTATION: Final = "pact-reputation+jwt"
TYP_LEARNING_POLICY: Final = "pact-learning-policy+jwt"
TYP_LEARNING_ARTIFACT: Final = "pact-learning-artifact+jwt"
TYP_LEARNING_EVENT: Final = "pact-learning-event+jwt"

# The draft 7.3 table, in its order.
_TYP_TABLE: Final = (
    (TYP_REQUIREMENTS, Role.REQUIREMENT_PUBLISHER),
    (TYP_EVIDENCE, Role.ISSUER),
    (TYP_PRESENTATION, Role.HOLDER),
    (TYP_ADMISSION, Role.VALIDATOR),
    (TYP_OUTCOME, Role.REPORTER),
    (TYP_REPUTATION, Role.REPUTATION_SERVICE),
    (TYP_LEARNING_POLICY, Role.POLICY_AUTHORITY),
    (TYP_LEARNING_ARTIFACT, Role.LEARNING_CONTROLLER),
    (TYP_LEARNING_EVENT, Role.LEARNING_CONTROLLER),
)


def typ_role(typ: str) -> Role | None:
    """Return the signer role the draft 7.3 table requires for typ, or None when typ is
    not in the table. typ is compared exactly: case and an "application/" prefix matter."""
    for t, role in _TYP_TABLE:
        if t == typ:
            return role
    return None


def typs() -> tuple[str, ...]:
    """Return the typ values of the draft 7.3 table, in its order."""
    return tuple(t for t, _ in _TYP_TABLE)
