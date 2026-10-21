"""The adapter errors, their draft 13.4 codes, and the native denial."""

from __future__ import annotations

from enum import StrEnum
from typing import ClassVar, Final

from hop_top_pact.errors import PactError


class Code(StrEnum):
    """A stable error code of the draft 13.4 table."""

    INVALID_MESSAGE = "INVALID_MESSAGE"
    INVALID_PROOF = "INVALID_PROOF"
    CONTEXT_MISMATCH = "CONTEXT_MISMATCH"
    DEPENDENCY_UNAVAILABLE = "DEPENDENCY_UNAVAILABLE"
    UNSUPPORTED_REQUIREMENT = "UNSUPPORTED_REQUIREMENT"
    UNSUPPORTED_PURPOSE = "UNSUPPORTED_PURPOSE"
    MISSING_FIELD = "MISSING_FIELD"


class AdapterError(PactError):
    """An error of the adapter contract, with the draft 13.4 code it maps to.

    An implementation raises one of the seven subclasses, the Go sentinel
    errors, with an optional detail and, for an underlying failure, ``raise
    ... from cause``. A caller matches with isinstance or reads the code with
    code_of.
    """

    code: ClassVar[Code]
    """The draft 13.4 code, set by each subclass."""
    text: ClassVar[str] = "adapter error"

    def __init__(self, detail: str = "") -> None:
        self.detail = detail
        super().__init__(self._message())

    def _message(self) -> str:
        s = "adapter: " + self.text
        if self.detail:
            s += ": " + self.detail
        return s

    def __str__(self) -> str:
        return self._message()


class InvalidMessage(AdapterError):
    """A request or message has a form the contract does not accept
    (INVALID_MESSAGE, HTTP 400): invalid JSON, schema or signature format, or an
    unsupported structure. map_operation raises it for an actual request that
    violates a rule of the baseline HTTP mapping (draft 10.2, 13.4): among them a
    fragment or userinfo in the target, an ambiguous encoding, of which draft
    10.2 gives the definition and the list, and an HTTP content encoding."""

    code = Code.INVALID_MESSAGE
    text = "request or message is malformed or has an unsupported structure"


class InvalidProof(AdapterError):
    """Native authentication, a signature, or a holder binding failed
    (INVALID_PROOF). NativeDenial is an InvalidProof."""

    code = Code.INVALID_PROOF
    text = "native authentication or holder binding failed"


class ContextMismatch(AdapterError):
    """The principal, audience, realm, intent or actual operation differs from what
    was bound (CONTEXT_MISMATCH)."""

    code = Code.CONTEXT_MISMATCH
    text = "principal, realm, intent or operation differs"


class DependencyUnavailable(AdapterError):
    """A required source cannot currently answer (DEPENDENCY_UNAVAILABLE). The
    affected check is UNKNOWN and the admission decision is DEFERRED; it is never
    a pass and never a failure."""

    code = Code.DEPENDENCY_UNAVAILABLE
    text = "required verification cannot currently be completed"


class UnsupportedRequirement(AdapterError):
    """A required field rule, extension, mapping or context check has no installed
    meaning here (UNSUPPORTED_REQUIREMENT). resolve_agent_binding raises it for a
    workload with more than one enrollment in force when the profile in use does
    not support workloads shared by several agents (draft 17.1)."""

    code = Code.UNSUPPORTED_REQUIREMENT
    text = "required rule, mapping or check is unsupported"


class UnsupportedPurpose(AdapterError):
    """A purpose identifier has no installed meaning (UNSUPPORTED_PURPOSE)."""

    code = Code.UNSUPPORTED_PURPOSE
    text = "purpose has no installed meaning"


class MissingField(AdapterError):
    """The source answers, and it holds no value at the native path for the
    principal (MISSING_FIELD). An absent value fails the rule that requires it
    (draft 9.2); it is not an outage. A source whose record of the principal is
    gone, such as a deleted provisioned user, answers no fact with it."""

    code = Code.MISSING_FIELD
    text = "the source holds no value at the native path"


def code_of(err: BaseException | None) -> Code | None:
    """Return the draft 13.4 code of err or of the first AdapterError in its cause
    chain, or None.

    The chain is followed through __cause__, else __context__, of PactError
    instances only, as the package's other *_of functions do.
    """
    seen: set[int] = set()
    while isinstance(err, PactError) and id(err) not in seen:
        if isinstance(err, AdapterError):
            return err.code
        seen.add(id(err))
        err = err.__cause__ if err.__cause__ is not None else err.__context__
    return None


class DenialReason(StrEnum):
    """The public reason of a NativeDenial. The set is closed and each value is
    something the caller already knows about its own request, so a denial never
    discloses whether an account, a tenant or an issuer exists (draft 13.4)."""

    NO_CREDENTIAL = "NO_CREDENTIAL"
    """The request carried no credential."""
    CREDENTIAL_REJECTED = "CREDENTIAL_REJECTED"
    """A credential was presented and not accepted, whether it was malformed,
    expired, revoked, unknown or unverifiable."""

    @classmethod
    def is_valid(cls, s: str) -> bool:
        """Report whether s is a defined value."""
        return s in cls._value2member_map_


_DENIED: Final = "native authentication denied: "


class NativeDenial(InvalidProof):
    """What authenticate_native raises when the native system evaluated the request
    and did not authenticate it.

    reason is the public reason; a value outside DenialReason is reported as
    CREDENTIAL_REJECTED, so that free text an adapter puts in it is never shown:
    str(), repr() and args carry the public reason only. A denial carries no
    detail; an adapter logs internal detail itself.
    """

    def __init__(self, reason: str = "") -> None:
        self.reason = reason
        super().__init__()

    def public_reason(self) -> DenialReason:
        """reason when it is a defined value, else CREDENTIAL_REJECTED."""
        if DenialReason.is_valid(self.reason):
            return DenialReason(self.reason)
        return DenialReason.CREDENTIAL_REJECTED

    def _message(self) -> str:
        return "adapter: " + _DENIED + self.public_reason().value

    def __repr__(self) -> str:
        return f"NativeDenial({self.public_reason().value!r})"
