"""The errors of the holder package and their draft 13.4 codes."""

from __future__ import annotations

from typing import Final

from hop_top_pact.adapter import Code
from hop_top_pact.errors import PactError

__all__ = ["CODE_CONFLICTING_EVIDENCE", "CODE_EXPIRED", "HolderError"]

# The codes of the draft 13.4 table that this package returns and that adapter.Code has
# no member for.
CODE_CONFLICTING_EVIDENCE: Final = "CONFLICTING_EVIDENCE"
CODE_EXPIRED: Final = "EXPIRED"

_UNSUPPORTED_VERSION: Final = "unsupported-version"

_TEXTS: Final = {
    Code.INVALID_MESSAGE.value: "invalid message or configuration",
    Code.INVALID_PROOF.value: "publisher signature or holder key binding failed",
    Code.CONTEXT_MISMATCH.value: "agent, gateway, realm, intent or operation differs",
    Code.UNSUPPORTED_REQUIREMENT.value: "unsupported extension or algorithm",
    Code.MISSING_FIELD.value: "required field or evidence missing",
    CODE_CONFLICTING_EVIDENCE: "profile and authoritative values conflict",
    CODE_EXPIRED: "contract or profile expired",
    Code.DEPENDENCY_UNAVAILABLE.value: "key source or random source unavailable",
}


class HolderError(PactError):
    """An error of the holder package, with the draft 13.4 code it maps to.

    code is one of INVALID_MESSAGE (an input that is not a valid artifact of its type,
    a profile whose lifetime breaks draft 8.1, a presentation over a draft 20.1 limit, or
    a holder configuration error), INVALID_PROOF (the publisher's signature does not
    verify, the key of the key source is not the holder_jkt of the contract or profile,
    or the key source produced a signature its public key does not verify; draft 6.2,
    11.2), CONTEXT_MISMATCH (the contract names another agent, gateway or realm, binds
    another operation or intent than the one the agent is about to perform, or, in
    enforced mode, names another transport than the holder's; or the profile names
    another agent or tenant; draft 10.3, 11.2, 13.3.1), UNSUPPORTED_REQUIREMENT (the
    contract carries an extension the holder does not support, which defers, or the
    key's algorithm is not negotiated; draft 7.1, 21), MISSING_FIELD (a field a rule
    requires has no value the holder may disclose, or an evidence rule has no
    applicable evidence or snapshot; the holder never replaces a missing authoritative
    value with a self-asserted one; draft 8.6, 9.2), CONFLICTING_EVIDENCE (the profile
    value of an evidence rule differs from every applicable authoritative value, or
    applicable evidence disagrees; draft 8.4), EXPIRED (the contract or the profile has
    expired, with no grace period; draft 7.5) or DEPENDENCY_UNAVAILABLE (the key source
    or the random source failed).

    kind is "unsupported-version" for a gateway, contract or embedded artifact that
    names no wire version this holder implements (the holder never downgrades, draft
    21); its code is INVALID_MESSAGE, the 13.4 code of an unsupported structure. It is
    empty for every other error. An error of the contract package is translated to
    the code it carries, its text kept, with the original as __cause__.
    """

    def __init__(self, code: str, detail: str = "", kind: str = "") -> None:
        self.code = str(code)
        self.detail = detail
        self.kind = kind
        text = "unsupported wire version" if kind == _UNSUPPORTED_VERSION else None
        text = text or _TEXTS.get(self.code, "holder error")
        super().__init__("holder: " + text + (": " + detail if detail else ""))

    def prefixed(self, prefix: str) -> HolderError:
        """A copy of the error whose detail starts with prefix, with this error as cause."""
        e = HolderError(self.code, f"{prefix}: {self.detail}", self.kind)
        e.__cause__ = self
        return e


def unsupported_version(detail: str) -> HolderError:
    """The error of a wire version the holder does not implement."""
    return HolderError(Code.INVALID_MESSAGE, detail, _UNSUPPORTED_VERSION)
