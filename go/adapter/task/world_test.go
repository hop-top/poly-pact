package task_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/task"
	"hop.top/pact-go/core"
	"hop.top/pact-go/core/clock"
	"hop.top/pact-go/core/digest"
)

// The realms, principals and agents of the cases.
var (
	realm      = adapter.Realm{TenantID: "northstar", EnvironmentID: "https://gateway.northstar.example/environments/tasks"}
	otherRealm = adapter.Realm{TenantID: "southwind", EnvironmentID: "https://gateway.southwind.example/environments/tasks"}

	t0 = time.Date(2026, 10, 18, 9, 0, 0, 0, time.UTC)

	maya = adapter.Principal{
		ID: "https://idp.northstar.example/users/maya", Realm: realm,
		Workload: "client:task-gateway", Mechanism: "bearer", AuthenticatedAt: t0,
	}
	omar = adapter.Principal{
		ID: "https://idp.northstar.example/users/omar", Realm: realm,
		Workload: "client:task-gateway", Mechanism: "bearer", AuthenticatedAt: t0,
	}
	mayaSouth = adapter.Principal{
		ID: "https://idp.southwind.example/users/maya", Realm: otherRealm,
		Workload: "client:task-gateway", Mechanism: "bearer", AuthenticatedAt: t0,
	}

	agent      = adapter.AgentID("https://agents.northstar.example/assistant")
	otherAgent = adapter.AgentID("https://agents.northstar.example/planner")
)

// The native task references of the worked tables (profile section 13).
const (
	refMailbox   task.Ref = "native-task:mailbox-summary-0731"     // I02
	refMailbox2  task.Ref = "native-task:mailbox-summary-0801"     // a second I02 task
	refRenewal   task.Ref = "crm-task:renewal-C-481"               // I03
	refQueue     task.Ref = "native-task:queue-summary-run-0412"   // I08
	refQueueNext task.Ref = "native-task:queue-summary-run-0413"   // I08
	refRestart   task.Ref = "native-task:incident-1177-vm-restart" // I14
	refOrder     task.Ref = "native-task:purchase-order-0098"      // U06
	refOrder2    task.Ref = "native-task:purchase-order-0099"      // U06
)

// The routes of the cases (profile section 6.1).
var (
	mailPages  = task.Route{ID: "GD1", Version: "1", Class: task.ClassRead, Page: true}
	queuePages = task.Route{ID: "queue-list", Version: "1", Class: task.ClassRead, Page: true}
	crmRead    = task.Route{ID: "crm-read", Version: "1", Class: task.ClassRead}
	orderWrite = task.Route{ID: "order", Version: "1", Class: task.ClassKeyedWrite, Definitive: []int{400, 422}}
	vmRestart  = task.Route{ID: "vm-restart", Version: "1", Class: task.ClassLedgerWrite, Definitive: []int{400, 404}}
)

// The targets of the routes.
const (
	mailInbox   = "https://gateway.northstar.example/mail/messages?folder=inbox"
	mailSent    = "https://gateway.northstar.example/mail/messages?folder=sent"
	queueList   = "https://gateway.northstar.example/queues/support/items"
	crmTarget   = "https://gateway.northstar.example/crm/customers/C-481"
	orderTarget = "https://gateway.northstar.example/procurement/orders"
	vmTarget    = "https://gateway.northstar.example/compute/vm-web-07/restart"

	azureOps      = "https://management.azure.com/subscriptions/0b5d7c1e-4f0a-4c39-9b8e-2f3d6c1a9e77/"
	asyncHandle   = azureOps + "providers/Microsoft.Compute/locations/westeurope/operations/7c1d?api-version=2025-04-01"
	foreignHandle = "https://status.contoso-ops.example/operations/7c1d"
	graphMessages = "https://graph.microsoft.com/v1.0/me/messages?"
)

// registry is the fake native task registry.
type registry struct {
	mu      sync.Mutex
	aliases map[aliasKey][]task.Ref
	records map[recordKey]task.Record
	down    bool
}

type aliasKey struct {
	realm     adapter.Realm
	principal string
	agent     adapter.AgentID
	value     string
}

type recordKey struct {
	realm adapter.Realm
	ref   task.Ref
}

// alias makes value name refs for the principal and the agent.
func (r *registry) alias(p adapter.Principal, a adapter.AgentID, value string, refs ...task.Ref) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.aliases[aliasKey{p.Realm, p.ID, a, value}] = refs
}

// put stores a record.
func (r *registry) put(rlm adapter.Realm, rec task.Record) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.records[recordKey{rlm, rec.Ref}] = rec
}

// update changes a stored record.
func (r *registry) update(rlm adapter.Realm, ref task.Ref, f func(*task.Record)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	rec := r.records[recordKey{rlm, ref}]
	f(&rec)
	r.records[recordKey{rlm, ref}] = rec
}

func (r *registry) setDown(down bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.down = down
}

func (r *registry) Resolve(_ context.Context, rlm adapter.Realm, principalID string, a adapter.AgentID, value string) ([]task.Ref, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.down {
		return nil, fmt.Errorf("fake registry: %w", adapter.ErrDependencyUnavailable)
	}
	return slices.Clone(r.aliases[aliasKey{rlm, principalID, a, value}]), nil
}

func (r *registry) Lookup(_ context.Context, rlm adapter.Realm, ref task.Ref) (task.Record, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.down {
		return task.Record{}, fmt.Errorf("fake registry: %w", adapter.ErrDependencyUnavailable)
	}
	rec, ok := r.records[recordKey{rlm, ref}]
	if !ok {
		return task.Record{}, task.ErrNoRecord
	}
	return rec, nil
}

// statusSource is the fake native status source: it answers its script in
// order, repeats the last answer, and counts the reads.
type statusSource struct {
	mu     sync.Mutex
	script []task.Status
	err    error
	reads  int
}

func (s *statusSource) answer(err error, st ...task.Status) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.script, s.err = st, err
}

func (s *statusSource) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reads
}

func (s *statusSource) ReadStatus(context.Context, task.Key, task.Operation) (task.Status, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reads++
	if s.err != nil {
		return task.Status{}, s.err
	}
	if len(s.script) == 0 {
		return task.Status{Effect: task.EffectIndeterminate}, nil
	}
	st := s.script[0]
	if len(s.script) > 1 {
		s.script = s.script[1:]
	}
	return st, nil
}

// graphPager accepts the next links of the Graph message listing only.
type graphPager struct{}

func (graphPager) CheckNext(link string) error {
	if !strings.HasPrefix(link, graphMessages) {
		return errors.New("graph pager: the link has another origin or path")
	}
	return nil
}

// azureHandles accepts the handles of the configured subscription only.
func azureHandles(h string) error {
	if !strings.HasPrefix(h, azureOps) {
		return errors.New("tracker: the handle has another origin or path")
	}
	return nil
}

// world is the native side of one case: the registry, the native service
// that counts the requests it receives per route, the status source, and the
// clock.
type world struct {
	clk    *clock.Fake
	reg    *registry
	src    *statusSource
	sends  map[string]int
	sleeps []time.Duration
	seq    int
	// bodies is the length of the request body of each operation_id that op
	// built (MO-61).
	bodies map[string]int64
}

func newWorld() *world {
	return &world{
		clk:    clock.NewFake(t0),
		reg:    &registry{aliases: map[aliasKey][]task.Ref{}, records: map[recordKey]task.Record{}},
		src:    &statusSource{},
		sends:  map[string]int{},
		bodies: map[string]int64{},
	}
}

// factory builds the ledger under test for a world.
type factory func(w *world) task.TaskLedger

func memoryLedger(w *world) task.TaskLedger {
	return task.NewMemory(task.Config{Registry: w.reg, Clock: w.clk, Pager: graphPager{}})
}

// lim builds the limits of a task; -1 is an explicit unlimited dimension.
func lim(ops, pages, bytes int64, deadline time.Duration) task.Limits {
	l := func(n int64) task.Limit {
		if n < 0 {
			return task.Unbounded()
		}
		return task.Bounded(n)
	}
	return task.Limits{MaxOperations: l(ops), MaxPages: l(pages), MaxBytes: l(bytes), Deadline: t0.Add(deadline)}
}

// active registers an Active task of the realm for maya and the agent under
// the client value alias, and returns its ledger key.
func (w *world) active(ref task.Ref, alias string, l task.Limits) task.Key {
	w.reg.put(realm, task.Record{Ref: ref, State: task.StateActive, Limits: l})
	w.reg.alias(maya, agent, alias, ref)
	return task.Key{Realm: realm, Task: ref}
}

// op builds the operation context of a fresh contract: a new operation_id
// every time (MO-20).
func (w *world) op(method, target, body string, headers map[string]string) core.OperationContext {
	w.seq++
	if headers == nil {
		headers = map[string]string{}
	}
	id := fmt.Sprintf("op-%03d", w.seq)
	w.bodies[id] = int64(len(body))
	return core.OperationContext{
		OperationID:   id,
		EnvironmentID: realm.EnvironmentID,
		PrincipalID:   maya.ID,
		Action:        strings.ToLower(method) + ":" + target,
		Resources:     []string{target},
		Method:        method,
		TargetURI:     target,
		BodyDigest:    digest.BytesDigest([]byte(body)),
		Headers:       headers,
	}
}

// again is the same logical operation under a fresh contract: only the
// operation_id changes (MO-20, MO-27).
func (w *world) again(op core.OperationContext) core.OperationContext {
	w.seq++
	id := fmt.Sprintf("op-%03d", w.seq)
	w.bodies[id] = w.bodies[op.OperationID]
	op.OperationID = id
	return op
}

// req builds a request of principal p. Its body length is that of the body
// op was built from, as the gateway hands it to the ledger (MO-61).
func (w *world) req(p adapter.Principal, a adapter.AgentID, taskID string, r task.Route, op core.OperationContext, cont string) task.Request {
	op.PrincipalID = p.ID
	op.EnvironmentID = p.Realm.EnvironmentID
	return task.Request{Principal: p, AgentID: a, TaskID: taskID, Operation: op, Route: r, Continuation: cont, BodyLength: w.bodies[op.OperationID]}
}

// attempt runs the gateway's order at execution (profile section 3.3) for one
// request: reserve; send when the ledger says so, which the fake native
// service counts; record how the attempt ended.
func (w *world) attempt(l task.TaskLedger, r task.Request, out task.Result) (task.Reservation, task.Settled, error) {
	ctx := context.Background()
	res, err := l.Reserve(ctx, r)
	if err != nil {
		return res, task.Settled{}, err
	}
	if !res.Send {
		return res, task.Settled{Operation: res.Operation}, nil
	}
	if out.Sent {
		w.sends[r.Route.ID]++
	}
	st, err := l.Record(ctx, res, out)
	return res, st, err
}

// tracker is the async tracker of the cases.
func (w *world) tracker(l task.TaskLedger, maxReads int) *task.AsyncTracker {
	return &task.AsyncTracker{
		Ledger: l, Source: w.src, MaxReads: maxReads, MinInterval: 20 * time.Second,
		CheckHandle: azureHandles,
		Sleep: func(_ context.Context, d time.Duration) error {
			w.sleeps = append(w.sleeps, d)
			w.clk.Advance(d)
			return nil
		},
	}
}

// The results of the fake native service.
func ok(bytes int64) task.Result { return task.Result{Sent: true, Status: 200, Bytes: bytes} }

func page(bytes int64, next string) task.Result {
	return task.Result{Sent: true, Status: 200, Bytes: bytes, NextLink: next}
}

func next(n int) string { return fmt.Sprintf("%s$skiptoken=page-%d", graphMessages, n) }

func accepted(handle string, retryAfter time.Duration) task.Result {
	return task.Result{Sent: true, Status: 202, Handle: handle, RetryAfter: retryAfter}
}

// timedOut is a request written and never answered (MO-35).
var timedOut = task.Result{Sent: true}

// notSent is a request that provably was not sent (MO-22).
var notSent = task.Result{}

// checker collects the failures of one case.
type checker struct {
	failures []string
}

func (c *checker) errorf(format string, args ...any) {
	c.failures = append(c.failures, fmt.Sprintf(format, args...))
}

// ok reports err as a failure.
func (c *checker) ok(err error, what string) bool {
	if err != nil {
		c.errorf("%s: unexpected error %v", what, err)
		return false
	}
	return true
}

// limitLabels are the labels answered with TASK_LIMIT, from rule MO-11.
var limitLabels = []task.Label{"budget-exhausted", "deadline-elapsed", "task-cancelled", "task-completed"}

// refused requires a refusal with the label; the four limit labels carry
// TASK_LIMIT and the others do not (MO-11, draft 13.4).
func (c *checker) refused(err error, want task.Label, what string) bool {
	var r *task.Refusal
	if !errors.As(err, &r) {
		c.errorf("%s: error %v, want the refusal %s", what, err, want)
		return false
	}
	if r.Label != want {
		c.errorf("%s: refusal %s, want %s", what, r.Label, want)
		return false
	}
	code, _ := adapter.CodeOf(err)
	isLimit := slices.Contains(limitLabels, want)
	switch {
	case isLimit && (!errors.Is(err, task.ErrTaskLimit) || code != "TASK_LIMIT"):
		c.errorf("%s: refusal %s has code %q, want TASK_LIMIT", what, want, code)
		return false
	case !isLimit && (errors.Is(err, task.ErrTaskLimit) || code == "TASK_LIMIT"):
		c.errorf("%s: refusal %s carries TASK_LIMIT", what, want)
		return false
	}
	return true
}

// mismatch requires CONTEXT_MISMATCH (MO-56, RB-58).
func (c *checker) mismatch(err error, what string) bool {
	code, _ := adapter.CodeOf(err)
	if !errors.Is(err, adapter.ErrContextMismatch) || code != adapter.CodeContextMismatch {
		c.errorf("%s: error %v, want CONTEXT_MISMATCH", what, err)
		return false
	}
	return true
}

// equal compares two comparable values.
func equal[T comparable](c *checker, got, want T, what string) bool {
	if got != want {
		c.errorf("%s: got %v, want %v", what, got, want)
		return false
	}
	return true
}

// budget requires the counters of the entry of k; a negative bytes is not
// compared.
func (c *checker) budget(l task.TaskLedger, k task.Key, ops, pages, bytes int64, what string) {
	e, err := l.Entry(context.Background(), k)
	if err != nil {
		c.errorf("%s: entry of %s: %v", what, k.Task, err)
		return
	}
	b := e.Budget
	if b.Operations != ops || b.Pages != pages || (bytes >= 0 && b.Bytes != bytes) {
		c.errorf("%s: counters of %s %d / %d / %d, want %d / %d / %d", what, k.Task, b.Operations, b.Pages, b.Bytes, ops, pages, bytes)
	}
}

// state requires the state of the entry of k.
func (c *checker) state(l task.TaskLedger, k task.Key, want task.State, what string) {
	e, err := l.Entry(context.Background(), k)
	if err != nil {
		c.errorf("%s: entry of %s: %v", what, k.Task, err)
		return
	}
	equal(c, e.State, want, what+": task state")
}

// opState requires the state of the operation record id of k.
func (c *checker) opState(l task.TaskLedger, k task.Key, id string, want task.OpState, what string) {
	e, err := l.Entry(context.Background(), k)
	if err != nil {
		c.errorf("%s: entry of %s: %v", what, k.Task, err)
		return
	}
	for _, op := range e.Operations {
		if op.ID == id {
			equal(c, op.State, want, what+": operation state")
			return
		}
	}
	c.errorf("%s: no operation record %q in %s", what, id, k.Task)
}

// noEntry requires that the ledger has no entry for k, or one whose counters
// are all zero (MO-6, MO-17).
func (c *checker) noEntry(l task.TaskLedger, k task.Key, what string) {
	e, err := l.Entry(context.Background(), k)
	switch {
	case errors.Is(err, task.ErrNoEntry):
	case err != nil:
		c.errorf("%s: entry of %s: %v, want ErrNoEntry", what, k.Task, err)
	case e.Budget.Operations != 0 || e.Budget.Pages != 0 || e.Budget.Bytes != 0:
		c.errorf("%s: %s has counters %+v, want none", what, k.Task, e.Budget)
	}
}

// sent requires the number of requests the native service received on a
// route.
func (c *checker) sent(w *world, route task.Route, n int, what string) {
	equal(c, w.sends[route.ID], n, what+": requests the native service received on "+route.ID)
}

// report requires the draft 14.5 row of an observation (profile section 11)
// and the native task reference as its task_id (MO-5).
func (c *checker) report(o *adapter.Observation, ref task.Ref, kind core.EventKind, result core.OutcomeResult, dim core.Dimension, what string) bool {
	if o == nil {
		c.errorf("%s: no report, want %s %s %s", what, kind, result, dim)
		return false
	}
	good := equal(c, o.EventKind, kind, what+": event_kind")
	good = equal(c, o.Result, result, what+": result") && good
	good = equal(c, o.Dimension, dim, what+": dimension") && good
	good = equal(c, o.TaskID, string(ref), what+": task_id") && good
	return good
}

// noVerdict requires that an observation is neither SUCCESS nor FAILURE:
// no completion is inferred (MO-45, MO-46).
func (c *checker) noVerdict(o *adapter.Observation, what string) {
	if o != nil && (o.Result == core.OutcomeSuccess || o.Result == core.OutcomeFailure) {
		c.errorf("%s: report %s, want no completion", what, o.Result)
	}
}
