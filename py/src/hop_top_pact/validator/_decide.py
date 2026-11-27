"""The admission decision of draft 11.4 and the reason codes the validator records."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Final

from hop_top_pact.core.enums import CheckStatus, Decision, TerminalReason
from hop_top_pact.core.types import CheckResult

__all__ = ["decide"]

# Reason codes the validator records (draft 12.1, 13.4, 17.3.1).
REASON_SATISFIED: Final = "REQUIREMENT_SATISFIED"
REASON_NOT_EVALUATED: Final = "NOT_EVALUATED"
REASON_SELECTION_INPUT_CHANGED: Final = "SELECTION_INPUT_CHANGED"
REASON_REQUIREMENTS_CHANGED: Final = "REQUIREMENTS_CHANGED"
REASON_INVALID_CLAIM: Final = "INVALID_CLAIM"
REASON_MISSING_FIELD: Final = "MISSING_FIELD"
REASON_CONFLICTING_EVIDENCE: Final = "CONFLICTING_EVIDENCE"
REASON_REVOKED_EVIDENCE: Final = "REVOKED_EVIDENCE"
REASON_STALE_EVIDENCE: Final = "STALE_EVIDENCE"
REASON_SECURITY_HOLD: Final = "SECURITY_HOLD"
REASON_CONTEXT_MISMATCH: Final = "CONTEXT_MISMATCH"
REASON_INVALID_PROOF: Final = "INVALID_PROOF"
REASON_UNSUPPORTED: Final = "UNSUPPORTED_REQUIREMENT"
REASON_UNAVAILABLE: Final = "DEPENDENCY_UNAVAILABLE"


def decide(checks: Sequence[CheckResult], terminal: TerminalReason) -> Decision:
    """Return the admission decision of draft 11.4 for the results of the required checks of
    one evaluation that ended with terminal:

    - a cancelled or expired evaluation is DEFERRED, whatever its results (draft 12.2);
    - a FAIL is INADMISSIBLE, even beside UNKNOWN results, except the FAIL results that
      mean the contract, not the agent, is stale (SELECTION_INPUT_CHANGED and
      REQUIREMENTS_CHANGED), which are DEFERRED;
    - otherwise an UNKNOWN, or a result that is not one of the four defined values, is
      DEFERRED;
    - ADMISSIBLE needs at least one result and every result PASS or NOT_APPLICABLE
      (Appendix A.2).
    """
    if terminal != TerminalReason.COMPLETED or not checks:
        return Decision.DEFERRED
    failed = deferred = False
    for c in checks:
        if c.result in (CheckStatus.PASS, CheckStatus.NOT_APPLICABLE):
            continue
        if c.result == CheckStatus.FAIL:
            if stale_contract(c.reason_code):
                deferred = True
            else:
                failed = True
        else:
            deferred = True
    if failed:
        return Decision.INADMISSIBLE
    if deferred:
        return Decision.DEFERRED
    return Decision.ADMISSIBLE


def stale_contract(reason: str) -> bool:
    """Report the FAIL reason codes that draft 11.4 maps to DEFERRED: the contract is stale,
    so a new one is the remedy."""
    return reason in (REASON_SELECTION_INPUT_CHANGED, REASON_REQUIREMENTS_CHANGED)
