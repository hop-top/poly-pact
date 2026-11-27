"""Transport errors: the draft 13.4 codes the validator returns and their problem details."""

from __future__ import annotations

from typing import Final

from hop_top_pact.adapter import AdapterError, Code
from hop_top_pact.contract import (
    CODE_EXPIRED,
    CODE_REPLAY,
    CODE_REQUIREMENTS_CHANGED,
    CODE_SECURITY_HOLD,
    ContractError,
)
from hop_top_pact.core.types import Problem
from hop_top_pact.errors import PactError
from hop_top_pact.holder import HolderError

__all__ = ["problem_of"]

CODE_INVALID_MESSAGE: Final = str(Code.INVALID_MESSAGE)
CODE_INVALID_PROOF: Final = str(Code.INVALID_PROOF)
CODE_CONTEXT_MISMATCH: Final = str(Code.CONTEXT_MISMATCH)


class Rejection(PactError):
    """The error of a request rejected before an authenticated evaluation (draft 12.2): it
    carries its draft 13.4 code."""

    def __init__(self, code: str, text: str) -> None:
        self.code = code
        self.text = text
        super().__init__(f"validator: {code}: {text}")


def reject(code: str, text: str) -> Rejection:
    """A Rejection of code, INVALID_MESSAGE when code is empty."""
    return Rejection(str(code) or CODE_INVALID_MESSAGE, text)


def code_of(err: BaseException | None) -> str | None:
    """The draft 13.4 code of err or of the first error in its cause chain that carries
    one, or None. It reads what adapter.CodeOf reads in Go: the code of an AdapterError, a
    ContractError, a HolderError and a Rejection, following __cause__, else
    __context__."""
    seen: set[int] = set()
    while err is not None and id(err) not in seen:
        if isinstance(err, AdapterError | ContractError | HolderError | Rejection):
            return str(err.code)
        seen.add(id(err))
        err = err.__cause__ if err.__cause__ is not None else err.__context__
    return None


# The HTTP status of each code of the draft 13.4 table.
_STATUSES: Final = {
    CODE_INVALID_MESSAGE: 400,
    CODE_INVALID_PROOF: 401,
    CODE_REPLAY: 409,
    CODE_CONTEXT_MISMATCH: 403,
    CODE_REQUIREMENTS_CHANGED: 409,
    str(Code.UNSUPPORTED_REQUIREMENT): 422,
    str(Code.UNSUPPORTED_PURPOSE): 422,
    str(Code.MISSING_FIELD): 403,
    str(Code.DEPENDENCY_UNAVAILABLE): 503,
    CODE_EXPIRED: 410,
    CODE_SECURITY_HOLD: 403,
}

# The non-disclosing titles of the codes (draft 13.4: public errors avoid disclosing
# private membership or issuer details).
_TITLES: Final = {
    CODE_INVALID_MESSAGE: "Invalid message",
    CODE_INVALID_PROOF: "Invalid proof",
    CODE_REPLAY: "Replay",
    CODE_CONTEXT_MISMATCH: "Context mismatch",
    CODE_REQUIREMENTS_CHANGED: "Requirements changed",
    str(Code.UNSUPPORTED_REQUIREMENT): "Unsupported requirement",
    str(Code.UNSUPPORTED_PURPOSE): "Unsupported purpose",
    str(Code.MISSING_FIELD): "Missing field",
    str(Code.DEPENDENCY_UNAVAILABLE): "Dependency unavailable",
    CODE_EXPIRED: "Expired",
    CODE_SECURITY_HOLD: "Security hold",
}


def problem_of(err: BaseException | None, request_id: str) -> Problem | None:
    """Return the RFC 9457 problem details of the transport error err carries (draft 13.4),
    with the non-sensitive request_id, and None when err carries no code of the draft 13.4
    table. The detail of err is not copied: a public error discloses only its code."""
    code = code_of(err)
    if code is None or code not in _STATUSES:
        return None
    return Problem(
        type="about:blank",
        title=_TITLES[code],
        status=_STATUSES[code],
        code=code,
        request_id=request_id,
    )
