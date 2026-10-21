"""Baseline size and count limits (draft section 20.1). Mirrors the limits of hop.top/pact-go/core.

Limits are the resource limits a validator enforces on untrusted input.
defaults() returns the baseline. A deployment may configure tighter values;
check() rejects a larger one, because larger limits need a negotiated profile
and a resource-budget review. Section 20.1 also fixes lifetimes, the clock
skew and the evaluation time; those are in hop_top_pact.core.clock.

The nesting depth is enforced while decoding, by strictjson. The validate_*
functions check the rest on decoded objects, and presentation_json,
artifact_json and profile_json give the decoder the matching bounds. The byte
limits apply to the received bytes, so a function that takes a size wants
the length of the bytes that were decoded, not of a re-encoding.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from hop_top_pact.core import strictjson
from hop_top_pact.core.types import Intent, OperationContext, Presentation, RequirementContract
from hop_top_pact.errors import PactError

__all__ = [
    "KEY_MAX_ARTIFACT_PAYLOAD_BYTES",
    "KEY_MAX_DESCRIPTION_BYTES",
    "KEY_MAX_EVIDENCE_ARTIFACTS",
    "KEY_MAX_FIELD_RULES",
    "KEY_MAX_JSON_DEPTH",
    "KEY_MAX_PRESENTATION_BYTES",
    "KEY_MAX_PROFILE_BYTES",
    "KEY_MAX_RESOURCES",
    "LimitError",
    "LimitErrorKind",
    "Limits",
    "artifact_json",
    "check",
    "defaults",
    "presentation_json",
    "profile_json",
    "validate_artifact_size",
    "validate_contract",
    "validate_intent",
    "validate_operation",
    "validate_presentation",
    "validate_profile_size",
]

# The keys of the baseline limits that section 20.1 names in
# GatewayMetadata.limits. A LimitError carries one of them.
KEY_MAX_PRESENTATION_BYTES: Final = "max_presentation_bytes"
KEY_MAX_ARTIFACT_PAYLOAD_BYTES: Final = "max_artifact_payload_bytes"
KEY_MAX_PROFILE_BYTES: Final = "max_profile_bytes"
KEY_MAX_EVIDENCE_ARTIFACTS: Final = "max_evidence_artifacts"
KEY_MAX_FIELD_RULES: Final = "max_field_rules"
KEY_MAX_JSON_DEPTH: Final = "max_json_depth"
KEY_MAX_RESOURCES: Final = "max_resources"
KEY_MAX_DESCRIPTION_BYTES: Final = "max_description_bytes"

# The baseline values of section 20.1.
_BASELINE_PRESENTATION_BYTES: Final = 256 << 10
_BASELINE_ARTIFACT_PAYLOAD_BYTES: Final = 32 << 10
_BASELINE_PROFILE_BYTES: Final = 32 << 10
_BASELINE_EVIDENCE_ARTIFACTS: Final = 32
_BASELINE_FIELD_RULES: Final = 128
_BASELINE_DEPTH: Final = 16
_BASELINE_RESOURCES: Final = 256
_BASELINE_DESCRIPTION_BYTES: Final = 4096


class LimitErrorKind(StrEnum):
    """Why a limit check failed (Go: ErrLimitExceeded, ErrLimitsInvalid, ErrNilObject)."""

    LIMIT_EXCEEDED = "LIMIT_EXCEEDED"
    """An object is larger or has more members than a limit allows."""
    LIMITS_INVALID = "LIMITS_INVALID"
    """A Limits value is not positive or is looser than the baseline."""
    NIL_OBJECT = "NIL_OBJECT"
    """A validate function was given None."""


_MESSAGES: Final = {
    LimitErrorKind.LIMIT_EXCEEDED: "core: limit exceeded",
    LimitErrorKind.LIMITS_INVALID: "core: invalid limits",
    LimitErrorKind.NIL_OBJECT: "core: nil object",
}


class LimitError(PactError):
    """A limit check failed, naming the limit.

    key is the section 20.1 metadata key of the limit, such as
    "max_json_depth". max is what the limit allows: the configured value for
    LIMIT_EXCEEDED, the baseline for LIMITS_INVALID. got is the offending
    value: the measured quantity, or the configured limit that is out of
    range. A NIL_OBJECT error names the missing object in detail instead.
    """

    def __init__(
        self, kind: LimitErrorKind, key: str = "", max: int = 0, got: int = 0, detail: str = ""
    ) -> None:
        self.kind = kind
        self.key = key
        self.max = max
        self.got = got
        self.detail = detail
        super().__init__(str(self))

    def __str__(self) -> str:
        head = _MESSAGES[self.kind]
        if self.kind is LimitErrorKind.NIL_OBJECT:
            return f"{head}: {self.detail}"
        if self.kind is LimitErrorKind.LIMITS_INVALID:
            return f"{head}: {self.key} is {self.got}, must be 1..{self.max}"
        return f"{head}: {self.key} is {self.got}, at most {self.max}"


@dataclass(frozen=True, slots=True)
class Limits:
    """The limits a deployment enforces; defaults() gives the baseline.

    presentation_bytes is the largest decoded presentation, embedded
    artifacts included; artifact_payload_bytes the largest decoded payload of
    one signed evidence or reputation artifact; profile_bytes the largest
    profile JSON; evidence_artifacts the most evidence artifacts in a
    presentation; field_rules the most field rules in a contract; depth the
    deepest JSON nesting, the outermost object or array having depth 1;
    resources the most resources in an operation; description_bytes the
    longest human-readable description in UTF-8 bytes.
    """

    presentation_bytes: int
    artifact_payload_bytes: int
    profile_bytes: int
    evidence_artifacts: int
    field_rules: int
    depth: int
    resources: int
    description_bytes: int


def defaults() -> Limits:
    """Return the baseline limits of draft section 20.1."""
    return Limits(
        presentation_bytes=_BASELINE_PRESENTATION_BYTES,
        artifact_payload_bytes=_BASELINE_ARTIFACT_PAYLOAD_BYTES,
        profile_bytes=_BASELINE_PROFILE_BYTES,
        evidence_artifacts=_BASELINE_EVIDENCE_ARTIFACTS,
        field_rules=_BASELINE_FIELD_RULES,
        depth=_BASELINE_DEPTH,
        resources=_BASELINE_RESOURCES,
        description_bytes=_BASELINE_DESCRIPTION_BYTES,
    )


def check(limits: Limits) -> None:
    """Raise LimitError (LIMITS_INVALID) unless every limit is 1 to its baseline.

    Equal and tighter values pass. All zeros do not, so a forgotten field is
    an error and not an unlimited input.
    """
    for key, value, ceiling in (
        (KEY_MAX_PRESENTATION_BYTES, limits.presentation_bytes, _BASELINE_PRESENTATION_BYTES),
        (
            KEY_MAX_ARTIFACT_PAYLOAD_BYTES,
            limits.artifact_payload_bytes,
            _BASELINE_ARTIFACT_PAYLOAD_BYTES,
        ),
        (KEY_MAX_PROFILE_BYTES, limits.profile_bytes, _BASELINE_PROFILE_BYTES),
        (KEY_MAX_EVIDENCE_ARTIFACTS, limits.evidence_artifacts, _BASELINE_EVIDENCE_ARTIFACTS),
        (KEY_MAX_FIELD_RULES, limits.field_rules, _BASELINE_FIELD_RULES),
        (KEY_MAX_JSON_DEPTH, limits.depth, _BASELINE_DEPTH),
        (KEY_MAX_RESOURCES, limits.resources, _BASELINE_RESOURCES),
        (KEY_MAX_DESCRIPTION_BYTES, limits.description_bytes, _BASELINE_DESCRIPTION_BYTES),
    ):
        if value < 1 or value > ceiling:
            raise LimitError(LimitErrorKind.LIMITS_INVALID, key, ceiling, value)


def _exceeds(key: str, got: int, most: int) -> None:
    if got > most:
        raise LimitError(LimitErrorKind.LIMIT_EXCEEDED, key, most, got)


def validate_presentation(limits: Limits, p: Presentation | None, size: int) -> None:
    """Check a decoded presentation; size is its length in bytes, embedded artifacts included.

    It checks the size, the number of evidence artifacts, and, through
    validate_operation and validate_intent, the resources and the
    description, and raises LimitError for the first limit exceeded. The
    profile inside a presentation has its own byte limit; check it with
    validate_profile_size on the bytes it was decoded from.
    """
    if p is None:
        raise LimitError(LimitErrorKind.NIL_OBJECT, detail="presentation")
    _exceeds(KEY_MAX_PRESENTATION_BYTES, size, limits.presentation_bytes)
    _exceeds(KEY_MAX_EVIDENCE_ARTIFACTS, len(p.evidence), limits.evidence_artifacts)
    validate_operation(limits, p.operation)
    validate_intent(limits, p.intent)


def validate_contract(limits: Limits, c: RequirementContract | None) -> None:
    """Check the number of field rules in a decoded contract."""
    if c is None:
        raise LimitError(LimitErrorKind.NIL_OBJECT, detail="requirement contract")
    _exceeds(KEY_MAX_FIELD_RULES, len(c.field_rules), limits.field_rules)


def validate_operation(limits: Limits, op: OperationContext | None) -> None:
    """Check the number of resources in a decoded operation."""
    if op is None:
        raise LimitError(LimitErrorKind.NIL_OBJECT, detail="operation")
    _exceeds(KEY_MAX_RESOURCES, len(op.resources), limits.resources)


def validate_intent(limits: Limits, intent: Intent | None) -> None:
    """Check the length of a decoded intent's description in UTF-8 bytes, not characters."""
    if intent is None:
        raise LimitError(LimitErrorKind.NIL_OBJECT, detail="intent")
    _exceeds(
        KEY_MAX_DESCRIPTION_BYTES, len(intent.description.encode("utf-8")), limits.description_bytes
    )


def validate_artifact_size(limits: Limits, size: int) -> None:
    """Check the decoded payload size in bytes of one signed evidence or reputation artifact."""
    _exceeds(KEY_MAX_ARTIFACT_PAYLOAD_BYTES, size, limits.artifact_payload_bytes)


def validate_profile_size(limits: Limits, size: int) -> None:
    """Check the size in bytes of a profile's JSON."""
    _exceeds(KEY_MAX_PROFILE_BYTES, size, limits.profile_bytes)


def presentation_json(limits: Limits) -> strictjson.Limits:
    """Return the strictjson limits for decoding a presentation: presentation_bytes, depth."""
    return strictjson.Limits(max_bytes=limits.presentation_bytes, max_depth=limits.depth)


def artifact_json(limits: Limits) -> strictjson.Limits:
    """Return the strictjson limits for one artifact payload: artifact_payload_bytes, depth."""
    return strictjson.Limits(max_bytes=limits.artifact_payload_bytes, max_depth=limits.depth)


def profile_json(limits: Limits) -> strictjson.Limits:
    """Return the strictjson limits for decoding a profile: profile_bytes, depth."""
    return strictjson.Limits(max_bytes=limits.profile_bytes, max_depth=limits.depth)
