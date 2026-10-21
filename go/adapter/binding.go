package adapter

import (
	"context"
	"slices"
	"time"

	"hop.top/pact-go/core"
)

// BindingStatus is the current status of an agent/key binding.
type BindingStatus string

const (
	// BindingActive: the binding is enrolled and in force.
	BindingActive BindingStatus = "ACTIVE"
	// BindingRevoked: the binding was withdrawn, for example after a key
	// rotation (draft 6.4).
	BindingRevoked BindingStatus = "REVOKED"
	// BindingCompromised: the identity is marked compromised; the old key
	// alone cannot recover it (draft 6.4).
	BindingCompromised BindingStatus = "COMPROMISED"
	// BindingUnknown: no current binding can be established, including the case
	// of a workload that is not enrolled (draft 6.1). It is never treated as
	// active.
	BindingUnknown BindingStatus = "UNKNOWN"
)

var bindingStatusValues = []BindingStatus{BindingActive, BindingRevoked, BindingCompromised, BindingUnknown}

// Valid reports whether s is a defined value.
func (s BindingStatus) Valid() bool { return slices.Contains(bindingStatusValues, s) }

// AgentBinding is the enrolled binding of a workload to an agent and its
// holder key.
type AgentBinding struct {
	// AgentID is the enrolled agent_id, an absolute URI (draft 6.1).
	AgentID string
	// OperatorID is the operator the agent is bound to.
	OperatorID string
	// HolderJKT is the RFC 7638 thumbprint of the enrolled public key
	// (draft 6.2).
	HolderJKT core.Digest
	// Status is the current status of the binding.
	Status BindingStatus
	// ObservedAt is when the enrollment source recorded the binding.
	ObservedAt time.Time
	// StatusCheckedAt is when the status was last confirmed against the
	// source.
	StatusCheckedAt time.Time
	// SourceID identifies the configured enrollment source.
	SourceID string
	// SourceRef is an opaque reference into that source; empty when none.
	SourceRef string
	// EnrolledElsewhere reports that the agent ID the request names is
	// enrolled for another workload of the same realm, the same tenant and
	// environment (draft 17.1). It is meaningful only with Status
	// [BindingUnknown]: it is false whenever a binding on the authenticated
	// workload is returned, and an enrollment in another realm never sets it.
	// It lets a validator tell an agent ID the authenticated workload has no
	// record of (INVALID_PROOF) from an agent enrolled for a different
	// workload (CONTEXT_MISMATCH); spec/v1.0/profiles/identity-mapping.md, IM-11
	// and section 8.
	EnrolledElsewhere bool
}

// AgentID is the agent_id that a request names, an absolute URI (draft 6.1).
// It is opaque to the adapter and compared for exact equality.
type AgentID string

// BindingResolver is the draft 17.1 function resolve_agent_binding.
type BindingResolver interface {
	// ResolveAgentBinding returns the enrolled binding of agent to the
	// authenticated workload in the realm, from the configured enrollment
	// source. The realm and workload are the Realm and Workload of the
	// authenticated [Principal]; agent is the agent ID the request names.
	//
	// The agent ID only selects among the enrollments of the workload: it
	// never selects an enrollment of another workload, and a workload alone
	// never names an agent. The holder-key proof then binds the request to the
	// selected enrollment (draft 6.2). When the profile in use does not support
	// workloads shared by several agents, a workload with more than one
	// enrollment in force is a configuration error: the function returns no
	// binding and an error that wraps [ErrUnsupportedRequirement], whichever
	// agent ID it is given. An enrollment is in force unless it is revoked; a
	// compromised one is in force (spec/v1.0/profiles/identity-mapping.md, IM-18,
	// IM-19).
	//
	// A binding the source holds as revoked or compromised is returned with
	// Status [BindingRevoked] or [BindingCompromised], the AgentID, OperatorID
	// and HolderJKT of its record, and a nil error, so that a caller can state
	// the reason (spec/v1.0/profiles/identity-mapping.md, IM-11); it is never
	// reported as active. A source that cannot answer returns an error that
	// wraps [ErrDependencyUnavailable]. A source that answers that no such
	// enrollment exists returns Status [BindingUnknown], not an error, with
	// EnrolledElsewhere set when the agent ID is enrolled for another workload
	// of the realm.
	ResolveAgentBinding(ctx context.Context, realm Realm, workload Workload, agent AgentID) (AgentBinding, error)
}
