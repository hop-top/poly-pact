package task

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/core"
	"hop.top/pact-go/core/clock"
	"hop.top/pact-go/core/digest"
)

// IdempotencyStore holds the idempotency keys of the logical operations of
// the tasks (MO-26 to MO-30). It is written before the request is sent and is
// shared by every replica of the gateway, as the ledger is (MO-17).
type IdempotencyStore interface {
	// Bind binds key, in the task of k, to the logical operation opID whose
	// fingerprint is fp. When the key is already bound in that task it binds
	// nothing and returns the operation and the fingerprint it is bound to,
	// so that the caller tells a repeat (MO-28) from a conflict (MO-29). The
	// same key in another task is another binding.
	Bind(ctx context.Context, k Key, key string, fp core.Digest, opID string) (boundOp string, boundFP core.Digest, err error)
}

// NewMemoryIdempotencyStore returns an in-memory [IdempotencyStore].
func NewMemoryIdempotencyStore() IdempotencyStore {
	return &memoryKeys{bound: map[keyRef]keyBinding{}}
}

type keyRef struct {
	k   Key
	key string
}

type keyBinding struct {
	op string
	fp core.Digest
}

type memoryKeys struct {
	mu    sync.Mutex
	bound map[keyRef]keyBinding
}

func (m *memoryKeys) Bind(_ context.Context, k Key, key string, fp core.Digest, opID string) (string, core.Digest, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if b, ok := m.bound[keyRef{k, key}]; ok {
		return b.op, b.fp, nil
	}
	m.bound[keyRef{k, key}] = keyBinding{opID, fp}
	return "", "", nil
}

// Config configures a [Memory] ledger.
type Config struct {
	// Registry is the native task registry.
	Registry Registry
	// Clock is the clock of the deadline (MO-23).
	Clock clock.Clock
	// Pager checks next links before they are recorded; without one no
	// continuation is recorded.
	Pager Pager
	// Keys holds the idempotency keys; nil means an in-memory store.
	Keys IdempotencyStore
}

// Memory is the in-memory [TaskLedger]. It is safe for concurrent use.
type Memory struct {
	cfg Config

	mu      sync.Mutex
	entries map[Key]*entry
	conts   map[string]continuation
	seq     uint64
}

// entry is the ledger entry of a task.
type entry struct {
	key     Key
	state   State
	binding Binding
	budget  Budget
	ops     []*record
	byID    map[string]*record
	// byFP is the latest record of each logical write without a client key,
	// by fingerprint (MO-27, MO-28); byKey that of each client key (MO-29).
	byFP  map[core.Digest]*record
	byKey map[string]*record
}

// record is an operation record with what the ledger needs to settle it.
type record struct {
	op      Operation
	route   Route
	agent   adapter.AgentID
	bodyLen int64
	// reconciled is true for a Failed that reconciliation established
	// (MO-32, MO-38).
	reconciled bool
}

// continuation is the record of a page token (RB-57, MO-56).
type continuation struct {
	key     Key
	binding Binding
	route   string
	version string
}

// NewMemory returns an in-memory ledger.
func NewMemory(cfg Config) *Memory {
	if cfg.Keys == nil {
		cfg.Keys = NewMemoryIdempotencyStore()
	}
	if cfg.Clock == nil {
		cfg.Clock = clock.SystemClock{}
	}
	return &Memory{cfg: cfg, entries: map[Key]*entry{}, conts: map[string]continuation{}}
}

func refuse(l Label) error { return &Refusal{Label: l} }

// unavailable wraps err as DEPENDENCY_UNAVAILABLE unless it already is.
func unavailable(what string, err error) error {
	if errors.Is(err, adapter.ErrDependencyUnavailable) {
		return fmt.Errorf("task: %s: %w", what, err)
	}
	return fmt.Errorf("task: %s: %w: %w", what, adapter.ErrDependencyUnavailable, err)
}

// Resolve implements [TaskLedger.Resolve]: a client value that the registry
// resolves, for the principal and the agent, to exactly one reference gives
// that reference; anything else is task-mismatch (MO-3).
func (m *Memory) Resolve(ctx context.Context, req Request) (Key, error) {
	if m.cfg.Registry == nil {
		return Key{}, fmt.Errorf("task: no registry: %w", adapter.ErrDependencyUnavailable)
	}
	realm := req.Principal.Realm
	refs, err := m.cfg.Registry.Resolve(ctx, realm, req.Principal.ID, req.AgentID, req.TaskID)
	if err != nil {
		return Key{}, unavailable("the registry cannot resolve the task", err)
	}
	if len(refs) != 1 || refs[0] == "" {
		return Key{}, refuse(LabelTaskMismatch)
	}
	return Key{Realm: realm, Task: refs[0]}, nil
}

// deadlineOf is the earlier of the registry's deadline and the expiry of the
// authority (MO-23).
func deadlineOf(rec Record) time.Time {
	d := rec.Limits.Deadline
	if !rec.AuthorityExpires.IsZero() && rec.AuthorityExpires.Before(d) {
		d = rec.AuthorityExpires
	}
	return d
}

// terminalLabel is the refusal label of a terminal task state (MO-50).
func terminalLabel(s State) Label {
	switch s {
	case StateCompleted:
		return LabelTaskCompleted
	case StateCancelled:
		return LabelTaskCancelled
	}
	return LabelDeadlineElapsed
}

// configured reports whether every dimension of the limits is set (MO-15).
func configured(l Limits) bool {
	return l.MaxOperations.kind != limitUnset && l.MaxPages.kind != limitUnset && l.MaxBytes.kind != limitUnset && !l.Deadline.IsZero()
}

// past reports whether n more would take the counter past the bounded limit.
func past(l Limit, counter, n int64) bool {
	v, bounded := l.Value()
	return bounded && counter+n > v
}

// fingerprint is the object_digest of the logical operation (MO-27).
func fingerprint(ref Ref, op core.OperationContext) (core.Digest, error) {
	return digest.ObjectDigest(map[string]any{
		"task": string(ref), "principal_id": op.PrincipalID, "action": op.Action, "resources": op.Resources,
		"method": op.Method, "target_uri": op.TargetURI, "body_digest": op.BodyDigest, "headers": op.Headers,
	})
}

// randomID is a random identifier of 128 bits in the UUID version 4 form
// (MO-30).
func randomID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// randomToken is a gateway page token of 32 random octets.
func randomToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// Reserve implements [TaskLedger.Reserve]. The tests run in the order of
// profile section 3.3: the task state and the registry (MO-6, MO-8, MO-49,
// MO-62), the binding (MO-7), the deadline (MO-23), the continuation
// (MO-56), the fingerprint (MO-27 to MO-33), then the budget (MO-19, MO-61).
// A refusal changes no counter and makes no entry (MO-6, MO-17).
func (m *Memory) Reserve(ctx context.Context, req Request) (Reservation, error) {
	k, err := m.Resolve(ctx, req)
	if err != nil {
		return Reservation{}, err
	}
	switch req.Route.Class {
	case ClassRead, ClassKeyedWrite, ClassLedgerWrite:
	default:
		return Reservation{}, fmt.Errorf("task: route %q has no executor class: %w", req.Route.ID, adapter.ErrDependencyUnavailable)
	}
	if req.BodyLength < 0 {
		return Reservation{}, fmt.Errorf("task: negative body length: %w", adapter.ErrInvalidMessage)
	}
	fp, err := fingerprint(k.Task, req.Operation)
	if err != nil {
		return Reservation{}, fmt.Errorf("task: fingerprint: %w", adapter.ErrInvalidMessage)
	}
	rec, err := m.cfg.Registry.Lookup(ctx, k.Realm, k.Task)
	switch {
	case errors.Is(err, ErrNoRecord):
		rec = Record{}
	case err != nil:
		return Reservation{}, unavailable("the registry cannot answer", err)
	}
	now := m.cfg.Clock.Now()

	m.mu.Lock()
	defer m.mu.Unlock()
	e := m.entries[k]
	// The task state and the registry. A terminal entry is immutable: the
	// first terminal state wins (MO-49).
	if e != nil && e.state != StateActive {
		return Reservation{}, refuse(terminalLabel(e.state))
	}
	if errors.Is(err, ErrNoRecord) {
		return Reservation{}, refuse(LabelTaskUnknown)
	}
	switch rec.State {
	case StateActive:
	case StateCompleted, StateCancelled, StateExpired:
		if e != nil {
			e.state = rec.State
		}
		return Reservation{}, refuse(terminalLabel(rec.State))
	default:
		return Reservation{}, fmt.Errorf("task: the registry reports the state %q: %w", rec.State, adapter.ErrDependencyUnavailable)
	}
	if !configured(rec.Limits) {
		return Reservation{}, fmt.Errorf("task: a limit of %s is not set (MO-15): %w", k.Task, adapter.ErrDependencyUnavailable)
	}
	deadline := deadlineOf(rec)
	if e == nil && !now.Before(deadline) {
		return Reservation{}, refuse(LabelDeadlineElapsed)
	}
	// The binding.
	bind := Binding{PrincipalID: req.Principal.ID, AgentID: req.AgentID, Workload: req.Principal.Workload}
	if e != nil && e.binding != bind {
		return Reservation{}, refuse(LabelTaskMismatch)
	}
	// The deadline.
	if e != nil && !now.Before(deadline) {
		e.state = StateExpired
		return Reservation{}, refuse(LabelDeadlineElapsed)
	}
	// The continuation.
	if req.Continuation != "" {
		c, ok := m.conts[req.Continuation]
		if !ok || c.key != k || c.binding != bind || c.route != req.Route.ID || c.version != req.Route.Version {
			return Reservation{}, fmt.Errorf("task: the continuation is not one of this task, principal, agent, row and mapping version (MO-56, RB-58): %w", adapter.ErrContextMismatch)
		}
	}
	limits := rec.Limits
	if e != nil {
		e.budget.Limits = limits
	}
	// The fingerprint.
	var prev *record
	clientKey := ""
	if req.Route.Class != ClassRead {
		clientKey = req.Operation.Headers["idempotency-key"]
		if e != nil {
			if clientKey != "" {
				prev = e.byKey[clientKey]
				if prev != nil && prev.op.Fingerprint != fp {
					return Reservation{}, refuse(LabelIdempotencyConflict)
				}
			} else {
				prev = e.byFP[fp]
			}
		}
		if prev != nil {
			switch prev.op.State {
			case OpSucceeded:
				return Reservation{Key: k, Operation: prev.op, BytesLeft: bytesLeft(limits, e.budget.Bytes)}, nil
			case OpReserved, OpAccepted:
				return Reservation{}, &Refusal{Label: LabelOperationInFlight, Operation: prev.op}
			case OpUnknown:
				return Reservation{}, &Refusal{Label: LabelOutcomeUnknown, Operation: prev.op}
			}
			// Failed or Released: a new logical operation (MO-22, MO-32).
		}
	}
	// The budget.
	var ops, pages, bytes int64
	if e != nil {
		ops, pages, bytes = e.budget.Operations, e.budget.Pages, e.budget.Bytes
	}
	body := int64(0)
	if req.Route.Class != ClassRead {
		body = req.BodyLength
	}
	if past(limits.MaxOperations, ops, 1) || (req.Route.Page && past(limits.MaxPages, pages, 1)) || past(limits.MaxBytes, bytes, body) {
		return Reservation{}, refuse(LabelBudgetExhausted)
	}
	// The idempotency key: the client key, the key of a logical operation
	// that reconciliation found not applied, or one drawn now (MO-29, MO-30,
	// MO-32).
	m.seq++
	id := fmt.Sprintf("operation-%d", m.seq)
	key := clientKey
	switch {
	case key != "":
	case req.Route.Class == ClassKeyedWrite && prev != nil && (prev.reconciled || prev.op.State == OpReleased):
		key = prev.op.IdempotencyKey
	case req.Route.Class == ClassKeyedWrite:
		if key, err = randomID(); err != nil {
			return Reservation{}, fmt.Errorf("task: no idempotency key: %w", adapter.ErrDependencyUnavailable)
		}
	}
	if key != "" && prev == nil {
		boundOp, boundFP, err := m.cfg.Keys.Bind(ctx, k, key, fp, id)
		switch {
		case err != nil:
			return Reservation{}, unavailable("the idempotency store cannot answer", err)
		case boundOp != "" && boundFP != fp:
			return Reservation{}, refuse(LabelIdempotencyConflict)
		case boundOp != "":
			// Bound by another replica: the record is not here, so the
			// operation may be in flight.
			return Reservation{}, refuse(LabelOperationInFlight)
		}
	}
	if e == nil {
		// The entry is made at the first reservation, from the registry
		// record (MO-6, MO-7).
		e = &entry{key: k, state: StateActive, binding: bind, budget: Budget{Limits: limits},
			byID: map[string]*record{}, byFP: map[core.Digest]*record{}, byKey: map[string]*record{}}
		m.entries[k] = e
	}
	r := &record{
		op:    Operation{ID: id, OperationID: req.Operation.OperationID, Fingerprint: fp, IdempotencyKey: key, State: OpReserved, Attempts: 1},
		route: req.Route, agent: req.AgentID, bodyLen: body,
	}
	e.ops = append(e.ops, r)
	e.byID[id] = r
	switch {
	case req.Route.Class == ClassRead:
	case clientKey != "":
		e.byKey[clientKey] = r
	default:
		e.byFP[fp] = r
	}
	e.budget.Operations++
	if req.Route.Page {
		e.budget.Pages++
	}
	e.budget.Bytes += body
	return Reservation{Key: k, Operation: r.op, Send: true, BytesLeft: bytesLeft(limits, e.budget.Bytes)}, nil
}

// bytesLeft is the remaining max_bytes, or -1 for an unlimited dimension.
func bytesLeft(l Limits, bytes int64) int64 {
	n, bounded := l.MaxBytes.Value()
	if !bounded {
		return -1
	}
	return max(n-bytes, 0)
}

// Entry implements [TaskLedger.Entry].
func (m *Memory) Entry(_ context.Context, k Key) (Entry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e := m.entries[k]
	if e == nil {
		return Entry{}, ErrNoEntry
	}
	out := Entry{Key: e.key, State: e.state, Binding: e.binding, Budget: e.budget}
	for _, r := range e.ops {
		out.Operations = append(out.Operations, r.op)
	}
	return out, nil
}
