package enroll

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/core"
)

// ActorKind is the capacity in which an [Actor] acts on an enrollment.
type ActorKind string

const (
	// Admin is a native authenticated administrative workflow: an administrator
	// of the realm acting through the environment's existing admin controls
	// (draft 6.1, 6.4). It is a trusted enrollment actor.
	Admin ActorKind = "ADMIN"
	// AuthorizedIssuer is an identity-binding or rotation issuer that the
	// gateway's administrators configured for the realm (draft 4.2, 6.1, 6.4).
	// It is a trusted enrollment actor.
	AuthorizedIssuer ActorKind = "AUTHORIZED_ISSUER"
	// Agent is the agent itself, or anyone presenting its key. Self-registration
	// proves neither organizational identity nor entitlement (draft 6.1), so an
	// Agent has no authority over any binding.
	Agent ActorKind = "AGENT"
)

var actorKindValues = []ActorKind{Admin, AuthorizedIssuer, Agent}

// Valid reports whether k is a defined value.
func (k ActorKind) Valid() bool { return slices.Contains(actorKindValues, k) }

// Actor is who asks a [Registry] to change a binding.
type Actor struct {
	// Kind is the capacity in which the actor acts.
	Kind ActorKind
	// ID identifies the actor for the audit log: an administrator account, an
	// issuer identifier. It is never interpreted.
	ID string
	// Realm is the realm the actor's authority covers, and so the realm whose
	// bindings the call addresses. An actor has no authority outside it.
	Realm adapter.Realm
}

// CheckAuthority returns nil when a is a trusted enrollment actor for its
// realm: Kind is [Admin] or [AuthorizedIssuer], ID is set so that the change is
// attributable, and Realm names a tenant and an environment. Otherwise it
// returns an error that wraps [ErrNotAuthorized].
func (a Actor) CheckAuthority() error {
	switch {
	case a.Kind != Admin && a.Kind != AuthorizedIssuer:
		return fmt.Errorf("%w: actor kind %q is not a trusted enrollment actor", ErrNotAuthorized, a.Kind)
	case a.ID == "":
		return fmt.Errorf("%w: the actor is not attributable", ErrNotAuthorized)
	case a.Realm.TenantID == "" || a.Realm.EnvironmentID == "":
		return fmt.Errorf("%w: the actor has no realm", ErrNotAuthorized)
	}
	return nil
}

// The errors a [Registry] returns. Callers match them with errors.Is.
var (
	// ErrNotAuthorized: the actor is not a trusted enrollment actor for its
	// realm. It is returned before the registry looks at the target, so it
	// never reveals whether an agent is enrolled.
	ErrNotAuthorized = errors.New("enroll: actor is not a trusted enrollment actor")
	// ErrNotFound: the agent_id is not enrolled in the actor's realm.
	ErrNotFound = errors.New("enroll: agent is not enrolled in the realm")
	// ErrAlreadyEnrolled: the agent_id is already enrolled in the realm, in any
	// status. An agent_id is enrolled once; a replacement identity is a new
	// agent_id.
	ErrAlreadyEnrolled = errors.New("enroll: agent_id is already enrolled in the realm")
	// ErrCompromised: the binding is marked compromised and cannot be changed
	// by rotation or revocation (draft 6.4).
	ErrCompromised = errors.New("enroll: binding is marked compromised")
	// ErrRevoked: the binding is revoked and cannot be rotated.
	ErrRevoked = errors.New("enroll: binding is revoked")
	// ErrKeyReuse: the holder key is, or ever was, enrolled in the realm. A key
	// is enrolled at most once, so rotation cannot restore a retired key and
	// two agents never share one.
	ErrKeyReuse = errors.New("enroll: holder key was already enrolled in the realm")
	// ErrInvalid: an argument is malformed, such as a thumbprint that is not 43
	// base64url characters or an agent_id that is not an absolute URI.
	ErrInvalid = errors.New("enroll: invalid argument")
	// ErrWorkloadInUse: the workload already has an enrollment in force in the
	// realm, and the registry does not support workloads shared by several
	// agents. A record is in force unless it is revoked; a compromised record
	// is in force (spec/v1.0/profiles/identity-mapping.md, IM-18, IM-19).
	ErrWorkloadInUse = errors.New("enroll: workload already has an enrollment in force")
)

// Registry is the enrollment registry of draft 6.1 and 6.4: it answers whether
// an agent is bound to a workload and with which holder key, and it applies
// rotation and the compromise mark. Enrolling an agent is a native
// administrative operation that each backend exposes in its own terms.
type Registry interface {
	// Lookup returns the binding of the agent to the workload in the realm,
	// with the semantics of [adapter.BindingResolver]: the agent ID selects
	// among the records of the workload only. It returns the binding with
	// Status [adapter.BindingCompromised] or [adapter.BindingRevoked] when the
	// binding is in that state; it never reports such a binding as active. It
	// returns Status [adapter.BindingUnknown], with no identity and a nil
	// error, when the agent has no record on the workload in the realm, which
	// includes an agent enrolled only for another workload; EnrolledElsewhere
	// then reports whether the agent is enrolled for another workload of the
	// realm, and an enrollment in another realm never sets it. A source that
	// cannot answer returns an error that wraps
	// [adapter.ErrDependencyUnavailable].
	//
	// Unless the registry supports workloads shared by several agents, a
	// workload serves one agent, and a workload with more than one enrollment
	// in force in the realm is a configuration error: Lookup returns no
	// binding and an error that wraps [adapter.ErrUnsupportedRequirement],
	// whichever agent ID it is given (draft 17.1, identity mapping IM-19).
	Lookup(ctx context.Context, realm adapter.Realm, workload adapter.Workload, agentID adapter.AgentID) (adapter.AgentBinding, error)

	// Rotate replaces the holder key of the agent with newJKT, in admin.Realm.
	// admin must be an [Admin] or an [AuthorizedIssuer] ([Actor.CheckAuthority]);
	// proof by the old key never suffices. The old key stops being the enrolled
	// key at once. It fails with [ErrCompromised] or [ErrRevoked] for a binding
	// in that state, [ErrKeyReuse] for a key that was ever enrolled in the
	// realm, [ErrInvalid] for a malformed thumbprint and [ErrNotFound] for an
	// agent that is not enrolled.
	Rotate(ctx context.Context, admin Actor, agentID string, newJKT core.Digest) error

	// MarkCompromised marks the binding of the agent compromised, in
	// authority.Realm. authority must be an [Admin] or an [AuthorizedIssuer].
	// The mark is terminal and a repeat is a no-op. It fails with
	// [ErrNotFound] for an agent that is not enrolled.
	MarkCompromised(ctx context.Context, authority Actor, agentID string) error
}

// Resolver exposes a [Registry] as the [adapter.BindingResolver] of draft 17.1.
type Resolver struct {
	Registry Registry
}

// ResolveAgentBinding returns Registry.Lookup for the realm, workload and agent.
func (r Resolver) ResolveAgentBinding(ctx context.Context, realm adapter.Realm, workload adapter.Workload, agent adapter.AgentID) (adapter.AgentBinding, error) {
	return r.Registry.Lookup(ctx, realm, workload, agent)
}

// AuditAction is the change an [AuditEntry] records.
type AuditAction string

// The changes a registry records.
const (
	ActionEnroll          AuditAction = "ENROLL"
	ActionRotate          AuditAction = "ROTATE"
	ActionRevoke          AuditAction = "REVOKE"
	ActionMarkCompromised AuditAction = "MARK_COMPROMISED"
)

// AuditResult is what became of the request an [AuditEntry] records.
type AuditResult string

const (
	// ResultApplied: the change was made.
	ResultApplied AuditResult = "APPLIED"
	// ResultUnchanged: the binding was already in the requested state.
	ResultUnchanged AuditResult = "UNCHANGED"
	// ResultDenied: the actor has no authority, and nothing else was examined.
	ResultDenied AuditResult = "DENIED"
	// ResultRejected: the actor has authority and the request was refused, for
	// example for an unknown agent, a compromised binding or a reused key.
	ResultRejected AuditResult = "REJECTED"
)

// AuditEntry is one attempt to change a binding. A registry appends an entry for
// every attempt, including denied and rejected ones, and never edits or removes
// one; a rotation entry is the retained rotation event of draft 6.4.
type AuditEntry struct {
	// Seq numbers the entries of one registry from 1, without gaps.
	Seq uint64
	// At is when the registry handled the request.
	At time.Time
	// Action is the requested change.
	Action AuditAction
	// Actor is who asked, as the caller stated it. For a denied entry it is
	// unverified.
	Actor Actor
	// AgentID is the agent the request addressed.
	AgentID string
	// Workload is the enrolled workload; set for ActionEnroll only.
	Workload adapter.Workload
	// OldJKT is the enrolled key before a rotation, when the registry got as far
	// as reading it; empty otherwise.
	OldJKT core.Digest
	// NewJKT is the key the request enrolls: set for ActionEnroll and
	// ActionRotate.
	NewJKT core.Digest
	// Result is what became of the request.
	Result AuditResult
	// Reason is the refusal for a denied or rejected entry; empty otherwise.
	Reason string
}
