package ssf

import (
	"context"
	"time"
)

// The kinds of Record.
const (
	// KindApplied: an event changed the account state of a principal.
	KindApplied = "applied"
	// KindStaleEvent: an event older than the state it would replace was not applied.
	KindStaleEvent = "stale-event"
	// KindNoEffect: a valid event that invalidates nothing, such as a new credential.
	KindNoEffect = "no-effect"
	// KindUnknownSubject: the subject resolved to no principal; Reason says why.
	KindUnknownSubject = "unknown-subject"
	// KindUnsupportedEvent: an event type the receiver does not map.
	KindUnsupportedEvent = "unsupported-event"
	// KindDiscarded: an event dropped for a critical subject member.
	KindDiscarded = "discarded"
	// KindReplay: a SET already applied arrived again and was not applied again.
	KindReplay = "replay"
	// KindRejected: a SET was refused; Reason is an error code.
	KindRejected = "rejected"
	// KindHoldCandidate: a hold candidate was raised.
	KindHoldCandidate = "hold-candidate"
	// KindVerification: a verification event arrived.
	KindVerification = "verification"
	// KindStreamUpdated: a stream-updated event arrived; Reason is the stream status.
	KindStreamUpdated = "stream-updated"
)

// Record is one decision of the receiver, for the operator. It never carries
// a subject identifier (SSF 1.0 section 10.1), only the subject format.
type Record struct {
	// Kind is one of the Kind constants.
	Kind string
	// At is the receiver's time of the decision.
	At time.Time
	// Issuer and JTI identify the SET, when it was authenticated.
	Issuer string
	JTI    string
	// EventType is the event the decision is about.
	EventType string
	// Principal is the principal the event resolved to, if any.
	Principal string
	// SubjectFormat is the format of the subject that decided the outcome.
	SubjectFormat string
	// Reason qualifies the kind.
	Reason string
}

// Telemetry receives the receiver's decisions. Observe must not block.
type Telemetry interface {
	Observe(Record)
}

// HoldCandidate asks a security authority to consider a security hold for a
// principal. It is not a hold: a hold is a separate, attributable security
// decision (draft Sections 6.4, 14.4 and 15.4), and an event from an identity provider
// is evidence for it, nothing more. A sink is called once per event and again
// when a delivery is retried, so it must be idempotent on Issuer and JTI.
type HoldCandidate struct {
	Principal string
	Issuer    string
	JTI       string
	EventType string
	EventTime time.Time
}

// HoldSink receives the hold candidates of the event types in Config.HoldOn.
type HoldSink interface {
	Candidate(ctx context.Context, c HoldCandidate) error
}
