package graph_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/task"
	"hop.top/pact-go/adapters/graph"
)

// The native tasks of the ledger tier: uTask and a second task, each with
// generous limits unless a test lowers them.
const uOtherTask = "native-task:another-task"

// taskRegistry is the fake native task registry of the ledger tier: a
// client value names one native task for every principal and agent.
type taskRegistry struct {
	mu      sync.Mutex
	aliases map[string]task.Ref
	records map[task.Ref]task.Record
}

func (r *taskRegistry) Resolve(_ context.Context, _ adapter.Realm, _ string, _ adapter.AgentID, value string) ([]task.Ref, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if ref, ok := r.aliases[value]; ok {
		return []task.Ref{ref}, nil
	}
	return nil, nil
}

func (r *taskRegistry) Lookup(_ context.Context, _ adapter.Realm, ref task.Ref) (task.Record, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	rec, ok := r.records[ref]
	if !ok {
		return task.Record{}, task.ErrNoRecord
	}
	return rec, nil
}

func (r *taskRegistry) limit(ref task.Ref, f func(*task.Limits)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	rec := r.records[ref]
	f(&rec.Limits)
	r.records[ref] = rec
}

// withLedger gives the world a task ledger with the pager of its form and
// returns the registry behind it.
func withLedger(w *unitWorld) *taskRegistry {
	l := task.Limits{MaxOperations: task.Bounded(20), MaxPages: task.Bounded(10), MaxBytes: task.Bounded(1 << 20), Deadline: w.clk.Now().Add(365 * 24 * time.Hour)}
	reg := &taskRegistry{
		aliases: map[string]task.Ref{uTask: uTask, "mail-digest": uTask, uOtherTask: uOtherTask},
		records: map[task.Ref]task.Record{
			uTask:      {Ref: uTask, State: task.StateActive, Limits: l},
			uOtherTask: {Ref: uOtherTask, State: task.StateActive, Limits: l},
		},
	}
	w.tasks = task.NewMemory(task.Config{Registry: reg, Clock: w.clk, Pager: graph.NewPager(graph.Form(w.form))})
	return reg
}

// ledgerBrokerFactory builds the adapter of a unit world with a task ledger.
func ledgerBrokerFactory(t testing.TB, w *unitWorld) (broker, error) {
	if w.tasks == nil {
		withLedger(w)
	}
	return realBrokerFactory(t, w)
}

// TestUnitWithLedger runs the whole unit tier, GRAPH-11.app-only-path among
// it, with the executor reserving every page in the task ledger and the
// ledger's pager checking every next link: the ledger changes no result of
// the Graph profile.
func TestUnitWithLedger(t *testing.T) {
	for _, c := range unitCases {
		t.Run(c.id, func(t *testing.T) {
			for _, f := range c.run(t, ledgerBrokerFactory) {
				t.Error(f)
			}
		})
	}
}

// ledgerWorld is a form D world with a ledger whose Graph answers pages
// with a next link.
func ledgerWorld(t *testing.T) (*unitWorld, *taskRegistry, broker) {
	w := newUnitWorld(t, formDelegated)
	reg := withLedger(w)
	b, err := realBrokerFactory(t, w)
	if err != nil {
		t.Fatal(err)
	}
	w.cloud.onGraph = func(c graphCall) *graphAnswer {
		return &graphAnswer{Status: 200, Body: messagesPage(c.Path, true)}
	}
	return w, reg, b
}

func entryOf(t *testing.T, w *unitWorld, ref task.Ref) task.Budget {
	t.Helper()
	e, err := w.tasks.Entry(bg(), task.Key{Realm: uRealm, Task: ref})
	if err != nil {
		t.Fatalf("entry of %s: %v", ref, err)
	}
	return e.Budget
}

// TestLedgerPagesBudget: each page reserves one operation and one page
// before token B is requested; past max_pages the page is refused with
// TASK_LIMIT, 403, and neither the token endpoint nor Graph is called
// (MO-19, MO-55, MO-57).
func TestLedgerPagesBudget(t *testing.T) {
	w, reg, b := ledgerWorld(t)
	reg.limit(uTask, func(l *task.Limits) { l.MaxPages = task.Bounded(2) })
	_, ex1, err := runDelegated(b, targetGD1, w.cloud.tokenA(uGatewayApp, "uti-0001", w.clk.Now()), uTask, nil)
	if err != nil || ex1.err != nil || ex1.pageToken == "" {
		t.Fatalf("page 1: %v %v %q", err, ex1.err, ex1.pageToken)
	}
	// The second page under another client value of the same native task
	// (MO-4, MO-56).
	_, ex2, err := runDelegated(b, uOrigin+"/mail/messages?page_token="+ex1.pageToken, w.cloud.tokenA(uGatewayApp, "uti-0002", w.clk.Now()), "mail-digest", nil)
	if err != nil || ex2.err != nil {
		t.Fatalf("page 2 under another client value of the task: %v %v", err, ex2.err)
	}
	_, ex3, err := runDelegated(b, targetGD1, w.cloud.tokenA(uGatewayApp, "uti-0003", w.clk.Now()), uTask, nil)
	if err != nil {
		t.Fatal(err)
	}
	var ref *task.Refusal
	if !errors.As(ex3.err, &ref) || ref.Label != task.LabelBudgetExhausted || ex3.code != task.CodeTaskLimit || ex3.status != http.StatusForbidden {
		t.Errorf("a new listing past max_pages: %v code %q status %d; want budget-exhausted, TASK_LIMIT, 403", ex3.err, ex3.code, ex3.status)
	}
	if n := len(w.cloud.graph()); n != 2 {
		t.Errorf("%d Graph requests, want 2", n)
	}
	if obo, _ := grants(w); obo != 2 {
		t.Errorf("%d OBO requests, want 2: a refused page requests no token", obo)
	}
	if bu := entryOf(t, w, uTask); bu.Operations != 2 || bu.Pages != 2 || bu.Bytes == 0 {
		t.Errorf("budget %+v, want 2 operations, 2 pages and the bytes of both answers", bu)
	}
}

// TestLedgerContinuationOtherNativeTask: a continuation presented under a
// client value of another native task is CONTEXT_MISMATCH with no
// reservation and no request (MO-56).
func TestLedgerContinuationOtherNativeTask(t *testing.T) {
	w, _, b := ledgerWorld(t)
	_, ex1, err := runDelegated(b, targetGD1, w.cloud.tokenA(uGatewayApp, "uti-0001", w.clk.Now()), uTask, nil)
	if err != nil || ex1.err != nil {
		t.Fatalf("page 1: %v %v", err, ex1.err)
	}
	_, ex2, err := runDelegated(b, uOrigin+"/mail/messages?page_token="+ex1.pageToken, w.cloud.tokenA(uGatewayApp, "uti-0002", w.clk.Now()), uOtherTask, nil)
	if err != nil {
		t.Fatal(err)
	}
	if ex2.code != adapter.CodeContextMismatch {
		t.Errorf("continuation under another native task: %v code %q, want CONTEXT_MISMATCH", ex2.err, ex2.code)
	}
	if _, err := w.tasks.Entry(bg(), task.Key{Realm: uRealm, Task: uOtherTask}); !errors.Is(err, task.ErrNoEntry) {
		t.Errorf("the other task has an entry: %v", err)
	}
	if n := len(w.cloud.graph()); n != 1 {
		t.Errorf("%d Graph requests, want 1", n)
	}
}

// TestLedgerBytesNotReleased: an answer past the remaining max_bytes is not
// released, its continuation is not recorded, and the reservation stays
// counted (MO-21, MO-59).
func TestLedgerBytesNotReleased(t *testing.T) {
	w, reg, b := ledgerWorld(t)
	reg.limit(uTask, func(l *task.Limits) { l.MaxBytes = task.Bounded(64) })
	_, ex, err := runDelegated(b, targetGD1, w.cloud.tokenA(uGatewayApp, "uti-0001", w.clk.Now()), uTask, nil)
	if err != nil {
		t.Fatal(err)
	}
	var ref *task.Refusal
	if !errors.As(ex.err, &ref) || ref.Label != task.LabelBudgetExhausted || ex.messages != nil || ex.pageToken != "" {
		t.Errorf("an answer past max_bytes: %v, %d octets of messages, page token %q; want budget-exhausted and nothing released", ex.err, len(ex.messages), ex.pageToken)
	}
	if bu := entryOf(t, w, uTask); bu.Operations != 1 || bu.Pages != 1 || bu.Bytes != 0 {
		t.Errorf("budget %+v, want 1 / 1 / 0", bu)
	}

	// The reader stops at the remaining bytes plus one: an answer larger
	// than any page the executor reads is still the budget's refusal, not an
	// unreadable answer.
	w.cloud.onGraph = func(c graphCall) *graphAnswer {
		page := messagesPage(c.Path, false)
		page["padding"] = strings.Repeat("x", 5<<20)
		return &graphAnswer{Status: 200, Body: page}
	}
	_, ex, err = runDelegated(b, targetGD1, w.cloud.tokenA(uGatewayApp, "uti-0002", w.clk.Now()), uTask, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !errors.As(ex.err, &ref) || ref.Label != task.LabelBudgetExhausted {
		t.Errorf("an answer of 5 MiB with 64 octets left: %v, want budget-exhausted (MO-21)", ex.err)
	}
}

// TestLedgerTokenFailureReleases: a failed OBO exchange sent nothing to
// Graph: the reservation is released and the counters restored (MO-22).
func TestLedgerTokenFailureReleases(t *testing.T) {
	w, _, b := ledgerWorld(t)
	w.cloud.onToken = oboError(400, map[string]any{"error": "invalid_grant", "error_codes": []int{50013}})
	_, ex, err := runDelegated(b, targetGD1, w.cloud.tokenA(uGatewayApp, "uti-0001", w.clk.Now()), uTask, nil)
	if err != nil || ex.err == nil {
		t.Fatalf("a failed exchange: %v %v", err, ex.err)
	}
	if bu := entryOf(t, w, uTask); bu.Operations != 0 || bu.Pages != 0 {
		t.Errorf("budget %+v, want the reservation released", bu)
	}
}

// TestPager: the pager of each form accepts only Graph's origin, the form's
// path and the pinned options (GR-24).
func TestPager(t *testing.T) {
	q := "?$select=id,subject,body&$top=10&$skip=10"
	for _, c := range []struct {
		form graph.Form
		link string
		ok   bool
	}{
		{graph.FormDelegated, "https://graph.microsoft.com/v1.0/me/messages" + q, true},
		{graph.FormDelegated, "https://graph.microsoft.com/v1.0/users/" + uMailbox + "/messages" + q, false},
		{graph.FormDelegated, "https://graph.microsoft.com.example/v1.0/me/messages" + q, false},
		{graph.FormDelegated, "https://graph.microsoft.com/v1.0/me/messages?$top=10&$skip=10", false},
		{graph.FormApplication, "https://graph.microsoft.com/v1.0/users/" + uMailbox + "/messages" + q, true},
		{graph.FormApplication, "https://graph.microsoft.com/v1.0/me/messages" + q, false},
		{graph.FormApplication, "https://graph.microsoft.com/v1.0/users/me/messages" + q, false},
		{graph.FormApplication, "https://graph.microsoft.com/v1.0/users/a/b/messages" + q, false},
		{graph.FormApplication, "https://graph.microsoft.com/v1.0/users/a%2Fb/messages" + q, false},
		{graph.FormApplication, "https://graph.microsoft.com.example/v1.0/users/" + uMailbox + "/messages" + q, false},
		{graph.FormApplication, "https://graph.microsoft.com/v1.0/users/" + uMailbox + "/messages?$top=10", false},
	} {
		err := graph.NewPager(c.form).CheckNext(c.link)
		if (err == nil) != c.ok {
			t.Errorf("%s %s: %v, want accepted %v", c.form, c.link, err, c.ok)
		}
	}
}
