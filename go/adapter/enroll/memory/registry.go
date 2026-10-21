// Package memory is an in-memory [enroll.Registry] for tests, examples and
// single-process gateways. It keeps no state across restarts and its audit log
// grows with every attempt, denied ones included, so it is not a production
// store.
package memory

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/enroll"
	"hop.top/pact-go/core"
	"hop.top/pact-go/core/clock"
)

// DefaultSourceID is the SourceID of a Registry built without [WithSourceID].
const DefaultSourceID = "enroll-memory"

// Enrollment is the native fact an administrator records: this agent runs as
// this workload, belongs to this operator and holds this key. The realm is the
// realm of the enrolling [enroll.Actor].
type Enrollment struct {
	// AgentID is the stable agent_id, an absolute URI without a fragment.
	AgentID string
	// OperatorID is the accountable operator. It is required.
	OperatorID string
	// Workload is the authenticated workload the agent runs as. Several agents
	// may share one workload only in a registry built [WithSharedWorkloads];
	// each then has its own Enrollment.
	Workload adapter.Workload
	// HolderJKT is the RFC 7638 thumbprint of the agent's public key.
	HolderJKT core.Digest
}

// Option configures a [Registry].
type Option func(*Registry)

// WithClock sets the clock that stamps observations. The default is the system
// clock.
func WithClock(c clock.Clock) Option { return func(r *Registry) { r.clock = c } }

// WithSourceID sets the SourceID that Lookup reports. The default is
// [DefaultSourceID].
func WithSourceID(id string) Option { return func(r *Registry) { r.sourceID = id } }

// WithSharedWorkloads makes the registry that of a profile that supports
// workloads shared by several agents (spec/v1.0/profiles/identity-mapping.md,
// IM-19): Enroll accepts any number of agents for a workload, and Lookup
// selects among them by the agent ID. Without it a workload serves one agent.
func WithSharedWorkloads() Option { return func(r *Registry) { r.shared = true } }

// Registry is the in-memory backend. It is safe for concurrent use.
type Registry struct {
	clock    clock.Clock
	sourceID string
	shared   bool

	mu       sync.Mutex
	agents   map[agentKey]*row
	byWork   map[workKey][]*row
	usedKeys map[keyKey]struct{}
	audit    []enroll.AuditEntry
}

type (
	agentKey struct {
		realm   adapter.Realm
		agentID string
	}
	workKey struct {
		realm    adapter.Realm
		workload adapter.Workload
	}
	keyKey struct {
		realm adapter.Realm
		jkt   core.Digest
	}
)

// row is one enrollment. The workload and the agent never change; the key, the
// status and the observation time do. binding.StatusCheckedAt stays zero here
// and is set on each read.
type row struct {
	workload adapter.Workload
	binding  adapter.AgentBinding
}

// New returns an empty Registry.
func New(opts ...Option) *Registry {
	r := &Registry{
		clock:    clock.SystemClock{},
		sourceID: DefaultSourceID,
		agents:   make(map[agentKey]*row),
		byWork:   make(map[workKey][]*row),
		usedKeys: make(map[keyKey]struct{}),
	}
	for _, o := range opts {
		o(r)
	}
	return r
}

// Lookup implements [enroll.Registry]. The registry is the enrollment source,
// so a read confirms the status as of now (StatusCheckedAt) while ObservedAt
// stays the time of the last change to the binding.
//
// The agent_id selects the row: a realm holds one row per agent_id (Enroll
// refuses a second), and Lookup returns it, in any status, when it names
// exactly this workload. A row of another workload is never the answer, and
// neither is a row of another agent of a workload that several agents share;
// both answer UNKNOWN. When the agent's row names another workload, the
// UNKNOWN answer reports it in EnrolledElsewhere (draft 17.1); a row in
// another realm is never consulted.
//
// Unless the registry was built [WithSharedWorkloads], a workload with more
// than one row in force, which Enroll refuses to create but a compromise mark
// on a revoked row can bring about, is the configuration error of IM-19:
// Lookup returns no binding and an error that wraps
// [adapter.ErrUnsupportedRequirement], whichever agent ID it is given.
func (r *Registry) Lookup(ctx context.Context, realm adapter.Realm, workload adapter.Workload, agentID adapter.AgentID) (adapter.AgentBinding, error) {
	if err := unavailable(ctx); err != nil {
		return adapter.AgentBinding{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if n := r.inForce(realm, workload); !r.shared && n > 1 {
		return adapter.AgentBinding{}, fmt.Errorf("enroll memory: workload %q has %d enrollments in force and serves one agent, a configuration error for the administrators of the registry: %w",
			workload, n, adapter.ErrUnsupportedRequirement)
	}
	rw := r.agents[agentKey{realm, string(agentID)}]
	if rw != nil && rw.workload != workload {
		b := r.read(nil)
		b.EnrolledElsewhere = true
		return b, nil
	}
	return r.read(rw), nil
}

// inForce counts the rows of workload in realm that are in force: every row
// that is not REVOKED, a COMPROMISED one included (identity mapping IM-18).
// The caller holds r.mu.
func (r *Registry) inForce(realm adapter.Realm, workload adapter.Workload) int {
	n := 0
	for _, rw := range r.byWork[workKey{realm, workload}] {
		if rw.binding.Status != adapter.BindingRevoked {
			n++
		}
	}
	return n
}

// read returns the binding of rw confirmed as of now, or the UNKNOWN binding
// for a nil row. The caller holds r.mu.
func (r *Registry) read(rw *row) adapter.AgentBinding {
	b := adapter.AgentBinding{Status: adapter.BindingUnknown, SourceID: r.sourceID}
	if rw != nil {
		b = rw.binding
	}
	b.StatusCheckedAt = r.clock.Now()
	return b
}

// Enroll records the binding of enrollment e in the realm of actor. The binding
// starts ACTIVE. It fails with [enroll.ErrNotAuthorized] unless actor is an
// [enroll.Admin] or an [enroll.AuthorizedIssuer], [enroll.ErrInvalid] for a
// malformed field, [enroll.ErrAlreadyEnrolled] when the agent_id is enrolled in
// the realm in any status, [enroll.ErrKeyReuse] when the key was ever
// enrolled in the realm, and, unless the registry was built
// [WithSharedWorkloads], [enroll.ErrWorkloadInUse] when a row in force of the
// realm already names the workload (identity mapping IM-19).
func (r *Registry) Enroll(ctx context.Context, actor enroll.Actor, e Enrollment) error {
	if err := unavailable(ctx); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	entry := r.begin(enroll.ActionEnroll, actor, e.AgentID)
	entry.Workload, entry.NewJKT = e.Workload, e.HolderJKT
	if err := r.authorize(entry); err != nil {
		return err
	}
	if err := validateEnrollment(e); err != nil {
		return r.refuse(entry, err)
	}
	ak := agentKey{actor.Realm, e.AgentID}
	if r.agents[ak] != nil {
		return r.refuse(entry, fmt.Errorf("%w: %q", enroll.ErrAlreadyEnrolled, e.AgentID))
	}
	kk := keyKey{actor.Realm, e.HolderJKT}
	if _, used := r.usedKeys[kk]; used {
		return r.refuse(entry, fmt.Errorf("%w: %q", enroll.ErrKeyReuse, e.HolderJKT))
	}
	wk := workKey{actor.Realm, e.Workload}
	if !r.shared && r.inForce(actor.Realm, e.Workload) > 0 {
		return r.refuse(entry, fmt.Errorf("%w: %q serves one agent", enroll.ErrWorkloadInUse, e.Workload))
	}

	rw := &row{
		workload: e.Workload,
		binding: adapter.AgentBinding{
			AgentID:    e.AgentID,
			OperatorID: e.OperatorID,
			HolderJKT:  e.HolderJKT,
			Status:     adapter.BindingActive,
			ObservedAt: entry.At,
			SourceID:   r.sourceID,
			SourceRef:  fmt.Sprintf("enrollment/%d", len(r.agents)+1),
		},
	}
	r.agents[ak] = rw
	r.byWork[wk] = append(r.byWork[wk], rw)
	r.usedKeys[kk] = struct{}{}
	r.commit(entry, enroll.ResultApplied)
	return nil
}

// Rotate implements [enroll.Registry]. The rotation takes effect for the next
// Lookup: the registry has no cache, so its propagation bound is zero.
func (r *Registry) Rotate(ctx context.Context, admin enroll.Actor, agentID string, newJKT core.Digest) error {
	if err := unavailable(ctx); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	entry := r.begin(enroll.ActionRotate, admin, agentID)
	entry.NewJKT = newJKT
	if err := r.authorize(entry); err != nil {
		return err
	}
	if err := newJKT.Validate(); err != nil {
		return r.refuse(entry, fmt.Errorf("%w: %w", enroll.ErrInvalid, err))
	}
	rw := r.agents[agentKey{admin.Realm, agentID}]
	if rw == nil {
		return r.refuse(entry, fmt.Errorf("%w: %q", enroll.ErrNotFound, agentID))
	}
	entry.OldJKT = rw.binding.HolderJKT
	switch rw.binding.Status {
	case adapter.BindingCompromised:
		return r.refuse(entry, fmt.Errorf("%w: %q", enroll.ErrCompromised, agentID))
	case adapter.BindingRevoked:
		return r.refuse(entry, fmt.Errorf("%w: %q", enroll.ErrRevoked, agentID))
	}
	kk := keyKey{admin.Realm, newJKT}
	if _, used := r.usedKeys[kk]; used {
		return r.refuse(entry, fmt.Errorf("%w: %q", enroll.ErrKeyReuse, newJKT))
	}

	rw.binding.HolderJKT = newJKT
	rw.binding.ObservedAt = entry.At
	r.usedKeys[kk] = struct{}{}
	r.commit(entry, enroll.ResultApplied)
	return nil
}

// MarkCompromised implements [enroll.Registry]. Compromised is terminal: a
// later Rotate, Revoke or Enroll of the same agent_id fails, and Lookup keeps
// reporting COMPROMISED. A revoked binding can be marked compromised.
func (r *Registry) MarkCompromised(ctx context.Context, authority enroll.Actor, agentID string) error {
	if err := unavailable(ctx); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	entry := r.begin(enroll.ActionMarkCompromised, authority, agentID)
	if err := r.authorize(entry); err != nil {
		return err
	}
	rw := r.agents[agentKey{authority.Realm, agentID}]
	if rw == nil {
		return r.refuse(entry, fmt.Errorf("%w: %q", enroll.ErrNotFound, agentID))
	}
	if rw.binding.Status == adapter.BindingCompromised {
		r.commit(entry, enroll.ResultUnchanged)
		return nil
	}
	rw.binding.Status = adapter.BindingCompromised
	rw.binding.ObservedAt = entry.At
	r.commit(entry, enroll.ResultApplied)
	return nil
}

// Revoke withdraws the binding of the agent in actor's realm; actor must be an
// [enroll.Admin] or an [enroll.AuthorizedIssuer]. A revoked binding is not
// rotated or enrolled back to life. Revoking again is a no-op, and a
// compromised binding cannot be revoked: it fails with [enroll.ErrCompromised],
// so the compromise mark is never downgraded.
func (r *Registry) Revoke(ctx context.Context, actor enroll.Actor, agentID string) error {
	if err := unavailable(ctx); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	entry := r.begin(enroll.ActionRevoke, actor, agentID)
	if err := r.authorize(entry); err != nil {
		return err
	}
	rw := r.agents[agentKey{actor.Realm, agentID}]
	if rw == nil {
		return r.refuse(entry, fmt.Errorf("%w: %q", enroll.ErrNotFound, agentID))
	}
	switch rw.binding.Status {
	case adapter.BindingCompromised:
		return r.refuse(entry, fmt.Errorf("%w: %q", enroll.ErrCompromised, agentID))
	case adapter.BindingRevoked:
		r.commit(entry, enroll.ResultUnchanged)
		return nil
	}
	rw.binding.Status = adapter.BindingRevoked
	rw.binding.ObservedAt = entry.At
	r.commit(entry, enroll.ResultApplied)
	return nil
}

// Audit returns a copy of the audit log, oldest entry first.
func (r *Registry) Audit() []enroll.AuditEntry {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.audit)
}

// unavailable reports a canceled or expired context as a source that cannot
// answer.
func unavailable(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("%w: %w", adapter.ErrDependencyUnavailable, err)
	}
	return nil
}

// begin starts the audit entry of a request. The caller holds r.mu.
func (r *Registry) begin(action enroll.AuditAction, actor enroll.Actor, agentID string) enroll.AuditEntry {
	return enroll.AuditEntry{At: r.clock.Now(), Action: action, Actor: actor, AgentID: agentID}
}

// commit appends the entry with its result. The caller holds r.mu.
func (r *Registry) commit(e enroll.AuditEntry, result enroll.AuditResult) {
	e.Seq = uint64(len(r.audit)) + 1
	e.Result = result
	r.audit = append(r.audit, e)
}

// authorize checks the actor of the entry and audits a denial. The caller holds
// r.mu.
func (r *Registry) authorize(e enroll.AuditEntry) error {
	err := e.Actor.CheckAuthority()
	if err == nil {
		return nil
	}
	e.Reason = err.Error()
	r.commit(e, enroll.ResultDenied)
	return err
}

// refuse audits a request an authorized actor made and returns err. The caller
// holds r.mu.
func (r *Registry) refuse(e enroll.AuditEntry, err error) error {
	e.Reason = err.Error()
	r.commit(e, enroll.ResultRejected)
	return err
}

func validateEnrollment(e Enrollment) error {
	if !absoluteURI(e.AgentID) {
		return fmt.Errorf("%w: agent_id %q is not an absolute URI (RFC 3986)", enroll.ErrInvalid, e.AgentID)
	}
	if e.OperatorID == "" {
		return fmt.Errorf("%w: operator_id is empty", enroll.ErrInvalid)
	}
	if e.Workload == "" {
		return fmt.Errorf("%w: workload is empty", enroll.ErrInvalid)
	}
	if err := e.HolderJKT.Validate(); err != nil {
		return fmt.Errorf("%w: %w", enroll.ErrInvalid, err)
	}
	return nil
}

// absoluteURI reports whether s is an absolute-URI of RFC 3986 section 4.3: a
// scheme, a colon and a non-empty remainder of URI characters, with no
// fragment. Non-ASCII text must already be percent-encoded.
func absoluteURI(s string) bool {
	scheme, rest, ok := strings.Cut(s, ":")
	if !ok || scheme == "" || rest == "" || !isAlpha(scheme[0]) {
		return false
	}
	for i := 1; i < len(scheme); i++ {
		if c := scheme[i]; !isAlpha(c) && !isDigit(c) && c != '+' && c != '-' && c != '.' {
			return false
		}
	}
	for i := 0; i < len(rest); i++ {
		c := rest[i]
		switch {
		case isAlpha(c), isDigit(c), strings.IndexByte("-._~:/?[]@!$&'()*+,;=", c) >= 0:
		case c == '%' && i+2 < len(rest) && isHex(rest[i+1]) && isHex(rest[i+2]):
			i += 2
		default:
			return false
		}
	}
	return true
}

func isAlpha(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }
func isDigit(c byte) bool { return c >= '0' && c <= '9' }
func isHex(c byte) bool   { return isDigit(c) || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' }
