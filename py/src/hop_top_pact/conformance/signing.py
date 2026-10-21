"""signing.json, the generator contract of a signed directory (spec/v1.0/fixtures/README.md,
section Generator contract: signing.json). Mirrors go/runner/evalcase/signing.go."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Final

from hop_top_pact.conformance.errors import CaseError, q
from hop_top_pact.core import strictjson
from hop_top_pact.core.jws import TYP_PRESENTATION, typ_role
from hop_top_pact.runner.manifest import PATH_PATTERN

__all__ = [
    "ABSENT",
    "FIXED_TIME",
    "PRESENTATION_LIFETIME",
    "Artifact",
    "Presentation",
    "Signing",
    "parse_signing",
]

FIXED_TIME: Final = 1792080000
"""The default iat, and so nbf, of every generated artifact: the sample time of draft
Appendix B, 2026-10-15T16:00:00Z."""

PRESENTATION_LIFETIME: Final = 60
"""The default exp - iat of a generated presentation, the most draft Section 7.5
allows."""


class _Absent:
    """The type of ABSENT."""

    __slots__ = ()

    def __repr__(self) -> str:
        return "ABSENT"


# A relative path inside the case, as the manifest's paths (ASCII classes, as Go's RE2
# reads them).
PATH_RE: Final = re.compile(PATH_PATTERN, re.ASCII)

ABSENT: Final = _Absent()
"""The value of Presentation.reputation when signing.json has no such member."""


@dataclass(frozen=True, slots=True)
class Artifact:
    """One service-signed artifact: its decoded payload, the signed file, its typ, the
    role of its signing key in KEYS_FILE, and the claims its payload must carry."""

    decoded: str = ""
    signed: str = ""
    typ: str = ""
    signer: str = ""
    jti: str = ""
    iat: int | None = None
    """Defaults to FIXED_TIME."""
    nbf: int | None = None
    """Defaults to the iat."""
    exp: int | None = None
    """Checked only when set."""
    digests: Mapping[str, str] = field(default_factory=dict)
    """Maps an RFC 6901 pointer into the decoded payload to the signed file of an
    earlier entry whose artifact_digest the member gets."""
    payload_signed: str | None = None
    """When set, the decoded file the signature covers; the compact JWS still carries
    decoded, so it does not verify by design."""


@dataclass(frozen=True, slots=True)
class Presentation:
    """A presentation, which has no decoded file: the generator builds its payload from
    the case files."""

    signed: str = ""
    signer: str = ""
    jti: str = ""
    iat: int | None = None
    """Defaults to FIXED_TIME."""
    nbf: int | None = None
    """Defaults to the iat."""
    exp: int | None = None
    """Defaults to iat + PRESENTATION_LIFETIME."""
    contract: str | None = None
    """Defaults to signed/contract.jws."""
    evidence: tuple[str, ...] | None = None
    """Defaults to the evidence artifacts in order."""
    reputation: object = ABSENT
    """ABSENT, the default: the reputation artifact, or null when there is none; None
    (null): no reputation; otherwise the member as written, which must be the path of
    a reputation artifact."""
    profile: str | None = None
    intent: str | None = None
    operation: str | None = None


@dataclass(frozen=True, slots=True)
class Signing:
    """A directory's signing.json: the artifacts the generator signs, in order, then the
    presentations it builds and signs."""

    artifacts: tuple[Artifact, ...] = ()
    presentations: tuple[Presentation, ...] = ()


@dataclass(frozen=True, slots=True)
class _SigningFile:
    artifacts: tuple[Artifact, ...] | None = None
    presentations: tuple[Presentation, ...] = ()


def parse_signing(data: bytes) -> Signing:
    """Read a signing.json strictly and check it; raise CaseError or StrictJSONError."""
    raw = strictjson.decode(data, _SigningFile)
    if raw.artifacts is None:
        raise CaseError("artifacts is required")
    s = Signing(artifacts=raw.artifacts, presentations=raw.presentations)
    _validate(s)
    return s


def _paths(where: str, *ps: str) -> None:
    for p in ps:
        if not PATH_RE.fullmatch(p):
            raise CaseError(f"{where}: {q(p)} is not a relative path inside the case")


def _validate(s: Signing) -> None:
    seen: set[str] = set()
    for i, a in enumerate(s.artifacts):
        where = f"artifacts[{i}]"
        if not (a.decoded and a.signed and a.typ and a.signer and a.jti):
            raise CaseError(f"{where}: decoded, signed, typ, signer and jti are required")
        _paths(where, a.decoded, a.signed)
        if a.payload_signed is not None:
            _paths(where, a.payload_signed)
        if typ_role(a.typ) is None or a.typ == TYP_PRESENTATION:
            raise CaseError(
                f"{where}: typ {q(a.typ)} is not a typ of draft Section 7.3"
                " for a service-signed artifact"
            )
        for ptr, p in a.digests.items():
            if not ptr.startswith("/"):
                raise CaseError(f"{where}: digests: {q(ptr)} is not a JSON Pointer to a member")
            if p not in seen:
                raise CaseError(
                    f"{where}: digests {ptr}: {p} is not the signed file of an earlier entry"
                )
        if a.signed in seen:
            raise CaseError(f"{where}: signed file {a.signed} is named twice")
        seen.add(a.signed)
    for i, pr in enumerate(s.presentations):
        where = f"presentations[{i}]"
        if not (pr.signed and pr.signer and pr.jti):
            raise CaseError(f"{where}: signed, signer and jti are required")
        _paths(where, pr.signed)
        if pr.signed in seen:
            raise CaseError(f"{where}: signed file {pr.signed} is named twice")
        seen.add(pr.signed)
