package adapter

import (
	"context"
	"errors"
	"strings"
	"time"

	"hop.top/pact-go/core"
)

// Observation is an attributable decision or execution observation, the
// content of an outcome report (draft 14.1) that the observed system
// determines. The signing claims and the reporter role belong to the
// recorder, which reports under the role it is authorized for (draft 14.2).
type Observation struct {
	// EventID is the stable identifier of this observation. A retry of the
	// same observation carries the same EventID.
	EventID string
	// EventKind is the kind of the event.
	EventKind core.EventKind
	// Context is the agent, realm and reputation context of the event.
	Context core.ReputationContext
	// TaskID is the authoritative native task.
	TaskID string
	// OperationID is the operation the event concerns.
	OperationID string
	// AdmissionReceiptID is the admission receipt, when one exists.
	AdmissionReceiptID *string
	// ObservedAt is when the adapter observed the event at its source.
	ObservedAt time.Time
	// Result is the result the observation supports.
	Result core.OutcomeResult
	// Dimension is the reputation dimension the event counts toward.
	Dimension core.Dimension
	// Severity is the severity of the event.
	Severity core.Severity
	// EvidenceRefs references the evidence behind the observation.
	EvidenceRefs []string
	// Attribution ties the event to a native task and a cause.
	Attribution core.Attribution
	// Supersedes references the events a correction replaces.
	Supersedes []string
	// Details is untrusted free text.
	Details string
}

// Recorded is the result of recording an outcome: exactly one of [Signed] and
// [NoVisibility]. Only this package can implement it, so a type switch over
// these two values is exhaustive. Return the value, not a pointer.
type Recorded interface {
	// Validate reports whether the variant is well formed.
	Validate() error
	isRecorded()
}

// Signed is a recorded outcome: the compact JWS of a [core.OutcomeReport]
// (typ pact-outcome+jwt).
type Signed struct {
	JWS string
}

// NoVisibility is a declared absence of execution visibility (draft 14.1). It
// is never filled with an assumed success.
type NoVisibility struct {
	// Reason says why the adapter cannot observe the execution.
	Reason string
}

func (Signed) isRecorded()       {}
func (NoVisibility) isRecorded() {}

// Validate reports an error unless JWS has the three non-empty dot-separated
// segments of a compact JWS (RFC 7515). It does not verify the signature.
func (s Signed) Validate() error {
	parts := strings.Split(s.JWS, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return errors.New("adapter: signed outcome is not a compact JWS")
	}
	return nil
}

// Validate reports an error when Reason is blank: an absence must be declared
// with its reason.
func (n NoVisibility) Validate() error {
	if strings.TrimSpace(n.Reason) == "" {
		return errors.New("adapter: no-visibility declaration has no reason")
	}
	return nil
}

// OutcomeRecorder is the draft 17.1 function record_outcome.
type OutcomeRecorder interface {
	// RecordOutcome records the observation as a signed [core.OutcomeReport] and
	// returns [Signed], or returns [NoVisibility] when the adapter has no
	// visibility of the event. Missing visibility is declared, never assumed to
	// be success (draft 14.1).
	//
	// On a nil error the result is non-nil. A recorder that cannot reach its
	// signer or store returns an error that wraps [ErrDependencyUnavailable].
	RecordOutcome(ctx context.Context, o Observation) (Recorded, error)
}
