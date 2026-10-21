package task_test

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/task"
	"hop.top/pact-go/core"
	"hop.top/pact-go/core/clock"
)

// clientKeyed is a test-only broken ledger: it reconciles the client
// task_id with the registry, reads the record, the binding, the deadline and
// the limits as the profile says, and has one defect, the one profile
// section 15.1 names: it keys its entries, counters and continuations on the
// client task_id instead of the native task reference.
type clientKeyed struct {
	mu      sync.Mutex
	reg     task.Registry
	clk     clock.Clock
	pager   task.Pager
	order   []mutantKey
	entries map[mutantKey]*mutantEntry
	opsOf   map[string]mutantKey
	conts   map[string]mutantCont
	seq     int
}

type mutantKey struct {
	realm  adapter.Realm
	client string
}

type mutantEntry struct {
	ref     task.Ref
	state   task.State
	binding task.Binding
	budget  task.Budget
	ops     []*task.Operation
	routes  map[string]task.Route
}

type mutantCont struct {
	key   mutantKey
	bind  task.Binding
	route string
}

func clientKeyedLedger(w *world) task.TaskLedger {
	return &clientKeyed{
		reg: w.reg, clk: w.clk, pager: graphPager{},
		entries: map[mutantKey]*mutantEntry{}, opsOf: map[string]mutantKey{}, conts: map[string]mutantCont{},
	}
}

func refuse(l task.Label) error { return &task.Refusal{Label: l} }

func (m *clientKeyed) Resolve(ctx context.Context, r task.Request) (task.Key, error) {
	refs, err := m.reg.Resolve(ctx, r.Principal.Realm, r.Principal.ID, r.AgentID, r.TaskID)
	if err != nil {
		return task.Key{}, err
	}
	if len(refs) != 1 {
		return task.Key{}, refuse(task.LabelTaskMismatch)
	}
	return task.Key{Realm: r.Principal.Realm, Task: refs[0]}, nil
}

func deadlineOf(rec task.Record) task.Record {
	if !rec.AuthorityExpires.IsZero() && rec.AuthorityExpires.Before(rec.Limits.Deadline) {
		rec.Limits.Deadline = rec.AuthorityExpires
	}
	return rec
}

// over reports whether one more would pass the bounded limit l.
func over(l task.Limit, n int64) bool {
	n2, bounded := l.Value()
	return bounded && n+1 > n2
}

func (m *clientKeyed) Reserve(ctx context.Context, r task.Request) (task.Reservation, error) {
	k, err := m.Resolve(ctx, r)
	if err != nil {
		return task.Reservation{}, err
	}
	rec, err := m.reg.Lookup(ctx, k.Realm, k.Task)
	if errors.Is(err, task.ErrNoRecord) {
		return task.Reservation{}, refuse(task.LabelTaskUnknown)
	}
	if err != nil {
		return task.Reservation{}, err
	}
	rec = deadlineOf(rec)
	m.mu.Lock()
	defer m.mu.Unlock()
	mk := mutantKey{k.Realm, r.TaskID} // the defect: the client value is the key
	e := m.entries[mk]
	if e == nil {
		switch rec.State { // a terminal task with no entry (MO-62)
		case task.StateCompleted:
			return task.Reservation{}, refuse(task.LabelTaskCompleted)
		case task.StateCancelled:
			return task.Reservation{}, refuse(task.LabelTaskCancelled)
		}
		e = &mutantEntry{ref: k.Task, state: task.StateActive, routes: map[string]task.Route{}}
		m.entries[mk] = e
		m.order = append(m.order, mk)
	}
	if e.state == task.StateActive {
		switch {
		case rec.State == task.StateCancelled || rec.State == task.StateCompleted:
			e.state = rec.State
		case !m.clk.Now().Before(rec.Limits.Deadline):
			e.state = task.StateExpired
		}
	}
	switch e.state {
	case task.StateCancelled:
		return task.Reservation{}, refuse(task.LabelTaskCancelled)
	case task.StateCompleted:
		return task.Reservation{}, refuse(task.LabelTaskCompleted)
	case task.StateExpired:
		return task.Reservation{}, refuse(task.LabelDeadlineElapsed)
	}
	bind := task.Binding{PrincipalID: r.Principal.ID, AgentID: r.AgentID, Workload: r.Principal.Workload}
	if e.budget.Operations > 0 && e.binding != bind {
		return task.Reservation{}, refuse(task.LabelTaskMismatch)
	}
	if r.Continuation != "" {
		c, ok := m.conts[r.Continuation]
		if !ok || c.key != mk || c.bind != bind || c.route != r.Route.ID {
			return task.Reservation{}, fmt.Errorf("mutant: continuation: %w", adapter.ErrContextMismatch)
		}
	}
	e.budget.Limits = rec.Limits
	if over(rec.Limits.MaxOperations, e.budget.Operations) || (r.Route.Page && over(rec.Limits.MaxPages, e.budget.Pages)) {
		return task.Reservation{}, refuse(task.LabelBudgetExhausted)
	}
	e.binding = bind
	e.budget.Operations++
	m.seq++
	op := &task.Operation{ID: fmt.Sprintf("mutant-%d", m.seq), OperationID: r.Operation.OperationID, State: task.OpReserved, Attempts: 1}
	if r.Route.Page {
		e.budget.Pages++
	}
	e.routes[op.ID] = r.Route
	e.ops = append(e.ops, op)
	m.opsOf[op.ID] = mk
	left := int64(-1)
	if n, bounded := rec.Limits.MaxBytes.Value(); bounded {
		left = n - e.budget.Bytes
	}
	return task.Reservation{Key: k, Operation: *op, Send: true, BytesLeft: left}, nil
}

func (m *clientKeyed) Record(_ context.Context, res task.Reservation, out task.Result) (task.Settled, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	mk, ok := m.opsOf[res.Operation.ID]
	if !ok {
		return task.Settled{}, errors.New("mutant: no such operation")
	}
	e := m.entries[mk]
	var op *task.Operation
	for _, o := range e.ops {
		if o.ID == res.Operation.ID {
			op = o
		}
	}
	switch {
	case !out.Sent:
		op.State = task.OpReleased
		e.budget.Operations--
		if e.routes[op.ID].Page {
			e.budget.Pages--
		}
		return task.Settled{Operation: *op}, nil
	case out.Status == 0:
		op.State = task.OpUnknown
		return task.Settled{Operation: *op}, nil
	}
	op.State = task.OpSucceeded
	if res.BytesLeft >= 0 && out.Bytes > res.BytesLeft {
		return task.Settled{Operation: *op}, refuse(task.LabelBudgetExhausted)
	}
	e.budget.Bytes += out.Bytes
	st := task.Settled{Operation: *op, Report: &adapter.Observation{
		EventID: "mutant-event-" + op.ID, EventKind: core.EventExecution, TaskID: mk.client,
		OperationID: op.OperationID, Result: core.OutcomeSuccess, Dimension: core.DimensionReliability,
	}}
	if out.NextLink != "" && m.pager.CheckNext(out.NextLink) == nil {
		m.seq++
		st.PageToken = fmt.Sprintf("mutant-page-%d", m.seq)
		m.conts[st.PageToken] = mutantCont{key: mk, bind: e.binding, route: e.routes[op.ID].ID}
	}
	return st, nil
}

func (m *clientKeyed) Observe(context.Context, task.Key, string, task.Status) (task.Settled, error) {
	return task.Settled{}, errors.New("mutant: no status reads")
}

// Entry returns the entry most recently made for the reference.
func (m *clientKeyed) Entry(_ context.Context, k task.Key) (task.Entry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := len(m.order) - 1; i >= 0; i-- {
		mk := m.order[i]
		e := m.entries[mk]
		if mk.realm != k.Realm || e.ref != k.Task {
			continue
		}
		out := task.Entry{Key: k, State: e.state, Binding: e.binding, Budget: e.budget}
		for _, o := range e.ops {
			out.Operations = append(out.Operations, *o)
		}
		return out, nil
	}
	return task.Entry{}, task.ErrNoEntry
}
