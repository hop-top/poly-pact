"""The errors of the contract package and their draft 13.4 codes."""

from __future__ import annotations

from typing import Final

from hop_top_pact.adapter import Code
from hop_top_pact.errors import PactError

__all__ = [
    "CODE_EXPIRED",
    "CODE_REPLAY",
    "CODE_REQUIREMENTS_CHANGED",
    "CODE_SECURITY_HOLD",
    "ContractError",
]

# The codes of the draft 13.4 table that this package returns and that
# adapter.Code has no member for.
CODE_REPLAY: Final = "REPLAY"
CODE_REQUIREMENTS_CHANGED: Final = "REQUIREMENTS_CHANGED"
CODE_EXPIRED: Final = "EXPIRED"
CODE_SECURITY_HOLD: Final = "SECURITY_HOLD"

_TEXTS: Final = {
    Code.INVALID_MESSAGE.value: "malformed or invalid requirement contract",
    Code.INVALID_PROOF.value: (
        "publisher signature, native authentication or agent/key binding failed"
    ),
    CODE_SECURITY_HOLD: "agent binding is marked compromised",
    Code.UNSUPPORTED_PURPOSE.value: "purpose has no installed meaning",
    Code.CONTEXT_MISMATCH.value: "subject, audience, realm or bound context differs",
    Code.UNSUPPORTED_REQUIREMENT.value: "unsupported extension",
    CODE_REQUIREMENTS_CHANGED: "contract is no longer active",
    CODE_EXPIRED: "contract expired",
    CODE_REPLAY: "nonce already consumed or not issued",
    Code.DEPENDENCY_UNAVAILABLE.value: "replay store or signer unavailable",
}


class ContractError(PactError):
    """An error of the contract package, with the draft 13.4 code it maps to.

    code is one of INVALID_MESSAGE (a contract that is not a valid
    RequirementContract: schema, Appendix A.2, a lifetime over 60 s, iat or nbf
    after now plus the skew, a JWS of another typ or of a malformed form, or
    requirements a publisher cannot issue), INVALID_PROOF (the publisher's
    signature does not verify under the keys of the trust record iss names, or
    there is no native authentication, no binding of the named agent to the
    authenticated workload, or a revoked binding or one of another key to issue a
    contract for; draft 9.1), SECURITY_HOLD (the agent binding a contract request
    names is marked compromised; draft 6.4, 9.1), UNSUPPORTED_PURPOSE (the
    purpose a contract request's intent names has no installed meaning; draft
    10.1), CONTEXT_MISMATCH (the subject, audience or realm differs from the one
    expected, or a nonce record differs from the registered one),
    UNSUPPORTED_REQUIREMENT (the contract carries an extension the verifier does
    not support; draft 7.1), REQUIREMENTS_CHANGED (the contract pins a base
    revision or learning version that is no longer active; draft 9.4, 12.2),
    EXPIRED (now is at or after the contract's exp, with no grace period; draft
    7.5, 12.2), REPLAY (the nonce was already consumed, or was never registered;
    draft 7.5) or DEPENDENCY_UNAVAILABLE (the replay store is full or
    unavailable, or the signer failed; it defers and never admits, draft 7.5).

    detail says what was found; the underlying failure, if any, is __cause__.
    A caller reads err.code, or compares it with the adapter.Code members and the
    CODE_* constants of this module: the code is a plain string, because
    adapter.Code has no member for the four codes above.
    """

    def __init__(self, code: str, detail: str = "") -> None:
        self.code = str(code)
        self.detail = detail
        text = _TEXTS.get(self.code, "contract error")
        super().__init__("contract: " + text + (": " + detail if detail else ""))
