package validator

import "hop.top/pact-go/core"

// Reason codes the validator records (draft 12.1, 13.4, 17.3.1).
const (
	reasonSatisfied             = "REQUIREMENT_SATISFIED"
	reasonNotEvaluated          = "NOT_EVALUATED"
	reasonSelectionInputChanged = "SELECTION_INPUT_CHANGED"
	reasonRequirementsChanged   = "REQUIREMENTS_CHANGED"
	reasonInvalidClaim          = "INVALID_CLAIM"
	reasonMissingField          = "MISSING_FIELD"
	reasonConflictingEvidence   = "CONFLICTING_EVIDENCE"
	reasonRevokedEvidence       = "REVOKED_EVIDENCE"
	reasonStaleEvidence         = "STALE_EVIDENCE"
	reasonSecurityHold          = "SECURITY_HOLD"
	reasonContextMismatch       = "CONTEXT_MISMATCH"
	reasonInvalidProof          = "INVALID_PROOF"
	reasonUnsupported           = "UNSUPPORTED_REQUIREMENT"
	reasonUnavailable           = "DEPENDENCY_UNAVAILABLE"
)

// Decide returns the admission decision of draft 11.4 for the results of
// the required checks of one evaluation that ended with terminal:
//
//   - a cancelled or expired evaluation is DEFERRED, whatever its results
//     (draft 12.2);
//   - a FAIL is INADMISSIBLE, even beside UNKNOWN results, except the FAIL
//     results that mean the contract, not the agent, is stale
//     (SELECTION_INPUT_CHANGED and REQUIREMENTS_CHANGED), which are DEFERRED;
//   - otherwise an UNKNOWN, or a result that is not one of the four defined
//     values, is DEFERRED;
//   - ADMISSIBLE needs at least one result and every result PASS or
//     NOT_APPLICABLE (Appendix A.2).
func Decide(checks []core.CheckResult, terminal core.TerminalReason) core.Decision {
	if terminal != core.TerminalCompleted || len(checks) == 0 {
		return core.DecisionDeferred
	}
	failed, deferred := false, false
	for _, c := range checks {
		switch c.Result {
		case core.CheckPass, core.CheckNotApplicable:
		case core.CheckFail:
			if staleContract(c.ReasonCode) {
				deferred = true
			} else {
				failed = true
			}
		default:
			deferred = true
		}
	}
	switch {
	case failed:
		return core.DecisionInadmissible
	case deferred:
		return core.DecisionDeferred
	}
	return core.DecisionAdmissible
}

// staleContract reports the FAIL reason codes that draft 11.4 maps to
// DEFERRED: the contract is stale, so a new one is the remedy.
func staleContract(reason string) bool {
	return reason == reasonSelectionInputChanged || reason == reasonRequirementsChanged
}
