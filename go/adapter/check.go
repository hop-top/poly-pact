package adapter

import (
	"context"
	"slices"
	"time"

	"hop.top/pact-go/core"
)

// Verdict is the result of a context check.
type Verdict string

const (
	VerdictPass    Verdict = "PASS"
	VerdictFail    Verdict = "FAIL"
	VerdictUnknown Verdict = "UNKNOWN"
)

var verdictValues = []Verdict{VerdictPass, VerdictFail, VerdictUnknown}

// Valid reports whether v is a defined value.
func (v Verdict) Valid() bool { return slices.Contains(verdictValues, v) }

// CheckStatus returns the [core.CheckStatus] with the same name. A value that
// is not a defined verdict maps to [core.CheckUnknown]: a check that reported
// nothing valid established nothing.
func (v Verdict) CheckStatus() core.CheckStatus {
	switch v {
	case VerdictPass:
		return core.CheckPass
	case VerdictFail:
		return core.CheckFail
	default:
		return core.CheckUnknown
	}
}

// CheckOutcome is the result of one installed context check.
type CheckOutcome struct {
	// Result is PASS, FAIL or UNKNOWN.
	Result Verdict
	// ReasonCode is a stable code for the result, such as a draft 13.4 code
	// or a check-specific code of draft 17.3.1.
	ReasonCode string
	// SourceID identifies the configured source the check consulted.
	SourceID string
	// SourceRef is an opaque reference into that source; empty when none.
	SourceRef string
	// ObservedAt is the original source observation time (draft 8.3); the zero
	// time means the source gives none.
	ObservedAt time.Time
}

// CheckInput is what an installed check is evaluated on: the inputs of the
// draft 17.1 row for check_context. The validator fills it from what it has
// already established for this evaluation and from nothing a client sent.
type CheckInput struct {
	// Principal is the authenticated principal and workload context, as
	// AuthenticateNative returned it, Attributes included (draft 12.1: the
	// principal of the receipt). A check that compares a principal, or reads
	// an authenticated attribute such as device_id or peer_address, reads it
	// here and never from Operation.PrincipalID alone.
	Principal Principal
	// Binding is the enrolled binding of the agent the request names, as
	// ResolveAgentBinding returned it and the validator verified it (draft
	// 11.3 step 2). A check that compares the agent reads AgentID (and
	// OperatorID when its source binds an operator) and never re-judges
	// Status, which the validator decided. A zero Binding means the caller
	// established no agent; a check that compares the agent then fails its
	// scope comparison and never reports PASS.
	Binding AgentBinding
	// Intent is the declared intent.
	Intent core.Intent
	// Operation is the actual operation.
	Operation core.OperationContext
	// EvidenceRefs are the evidence references the contract names (draft
	// 9.3). They are names, never evidence content.
	EvidenceRefs []string
}

// ContextChecker is the draft 17.1 function check_context.
type ContextChecker interface {
	// CheckContext runs the installed, versioned check named by checkID on
	// in: the authenticated principal, the agent binding, the declared intent,
	// the actual operation and the evidence references, which are the inputs
	// draft 17.1 lists. A check compares an agent or a principal against
	// in.Binding and in.Principal, never against a value the presentation,
	// the profile or an evidence artifact carries; a check that needs neither
	// ignores them.
	//
	// It has no error result. A check it did not perform returns UNKNOWN, never
	// PASS (draft 17.2): an unknown checkID with ReasonCode
	// UNSUPPORTED_REQUIREMENT, a source that cannot answer with ReasonCode
	// DEPENDENCY_UNAVAILABLE. The validator records UNKNOWN as DEFERRED.
	CheckContext(ctx context.Context, checkID string, in CheckInput) CheckOutcome
}
