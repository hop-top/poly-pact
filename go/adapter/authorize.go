package adapter

import (
	"context"
	"slices"
	"time"

	"hop.top/pact-go/core"
)

// Effect is the effect of a native authorization decision.
type Effect string

const (
	EffectAllow   Effect = "ALLOW"
	EffectDeny    Effect = "DENY"
	EffectUnknown Effect = "UNKNOWN"
)

var effectValues = []Effect{EffectAllow, EffectDeny, EffectUnknown}

// Valid reports whether e is a defined value.
func (e Effect) Valid() bool { return slices.Contains(effectValues, e) }

// Obligation is a condition the native policy attaches to a decision.
//
// PACT defines no obligation types and never interprets one: it carries the
// obligation to the enforcement point, and the gateway enforces it, as draft
// 17.3 leaves resource enforcement and row and field permissions to the
// gateway. A profile that relies on particular obligation types names them.
type Obligation struct {
	// ID is the obligation type, as the native policy names it.
	ID string
	// Attributes holds the obligation's parameters as JSON-compatible values.
	Attributes map[string]any
}

// Decision is the native policy's decision for the original principal and the
// actual operation, with its provenance. It has no field with which a caller
// could turn a denial into an allow: a denial is final by construction.
type Decision struct {
	Effect      Effect
	Obligations []Obligation
	// Reason is the native policy's own explanation. It is untrusted text and
	// may name private resources, so it does not go into a public error.
	Reason string
	// SourceID identifies the configured native policy source that decided.
	// Every Decision an adapter returns names one.
	SourceID string
	// SourceRef is an opaque reference to the source's immutable record of the
	// decision (draft A.2), such as a decision log id; empty when the source
	// gives none.
	SourceRef string
	// DecidedAt is when the source decided; the zero time means the source
	// gives none. It is never later than now plus the baseline clock skew of
	// draft 7.5.
	DecidedAt time.Time
	// PolicyRevision is the revision of the native policy that produced the
	// decision, as the source reports it; empty when the source reports none.
	PolicyRevision string
}

// Permits reports whether the decision allows the operation. Only an explicit
// [EffectAllow] does; a deny, an unknown, the zero value and an undefined
// effect do not.
func (d Decision) Permits() bool { return d.Effect == EffectAllow }

// NativeAuthorizer is the draft 17.1 function authorize_native.
type NativeAuthorizer interface {
	// AuthorizeNative returns the environment's existing policy decision for
	// the original authenticated principal p and the actual operation. It never
	// substitutes a connector or service identity for p (draft 4.3). A native
	// exception changes only this result (draft 17.3); PACT evidence of an
	// exception neither grants nor implies one.
	//
	// Native authorization never sees the PACT contract: draft 17.1 gives it
	// the original principal and the actual operation only. A caller whose
	// contract pins a policy version compares Decision.PolicyRevision with the
	// installed check version the contract names; on a mismatch it does not
	// use the decision and answers REQUIREMENTS_CHANGED (draft 13.4), so that a
	// new contract is obtained.
	//
	// A policy that cannot decide returns an error that wraps
	// [ErrDependencyUnavailable], or a Decision with [EffectUnknown].
	AuthorizeNative(ctx context.Context, p Principal, op core.OperationContext) (Decision, error)
}
