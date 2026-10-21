package task_test

import (
	"errors"
	"sync"
	"testing"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/task"
	"hop.top/pact-go/core/digest"
)

// TestUnsetLimitIsConfigurationError: a dimension that is simply not set is
// a configuration error, refused with DEPENDENCY_UNAVAILABLE and no entry
// (MO-15); an explicit null is unlimited.
func TestUnsetLimitIsConfigurationError(t *testing.T) {
	w := newWorld()
	l := memoryLedger(w)
	unset := lim(5, 5, -1, time.Hour)
	unset.MaxPages = task.Limit{}
	k := w.active(refRenewal, "renewal-C-481", unset)
	_, _, err := w.attempt(l, crm(w, maya, agent, "renewal-C-481"), ok(10))
	if !errors.Is(err, adapter.ErrDependencyUnavailable) {
		t.Fatalf("unset max_pages: %v, want DEPENDENCY_UNAVAILABLE", err)
	}
	if _, err := l.Entry(bg, k); !errors.Is(err, task.ErrNoEntry) {
		t.Errorf("unset max_pages: entry %v, want none", err)
	}
	if w.sends[crmRead.ID] != 0 {
		t.Errorf("unset max_pages: %d requests sent", w.sends[crmRead.ID])
	}
}

// TestConcurrentReservations: the counters never pass the limits under
// concurrent requests (MO-17).
func TestConcurrentReservations(t *testing.T) {
	w := newWorld()
	l := memoryLedger(w)
	k := w.active(refRenewal, "renewal-C-481", lim(7, 5, -1, time.Hour))
	reqs := make([]task.Request, 40)
	for i := range reqs {
		reqs[i] = crm(w, maya, agent, "renewal-C-481")
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	granted, exhausted := 0, 0
	for _, r := range reqs {
		wg.Go(func() {
			_, err := l.Reserve(bg, r)
			var ref *task.Refusal
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				granted++
			case errors.As(err, &ref) && ref.Label == task.LabelBudgetExhausted:
				exhausted++
			default:
				t.Errorf("reserve: %v", err)
			}
		})
	}
	wg.Wait()
	if granted != 7 || exhausted != 33 {
		t.Errorf("granted %d, exhausted %d; want 7 and 33", granted, exhausted)
	}
	e, err := l.Entry(bg, k)
	if err != nil || e.Budget.Operations != 7 {
		t.Errorf("entry %+v %v, want 7 operations", e.Budget, err)
	}
}

// TestDefinitiveFailureIsNativeDenial: a status the route lists as
// definitive is Failed and reported as a native denial (MO-37, draft 14.5);
// the fingerprint is then free for a new logical operation (MO-32).
func TestDefinitiveFailureIsNativeDenial(t *testing.T) {
	w := newWorld()
	l := memoryLedger(w)
	w.active(refOrder, "purchase-0098", lim(5, 5, -1, time.Hour))
	r := order(w, `{"sku":"LAP-14","quantity":3}`)
	res, st, err := w.attempt(l, r, task.Result{Sent: true, Status: 400})
	if err != nil {
		t.Fatal(err)
	}
	c := &checker{}
	equal(c, st.Operation.State, task.OpFailed, "400: state")
	c.report(st.Report, refOrder, "AUTHORIZATION", "FAILURE", "none", "400: report")
	r.Operation = w.again(r.Operation)
	res2, _, err := w.attempt(l, r, ok(0))
	if c.ok(err, "after a definitive failure") {
		equal(c, res2.Send, true, "after a definitive failure: send")
		if res2.Operation.IdempotencyKey == res.Operation.IdempotencyKey {
			c.errorf("after a definitive failure: the key %q was reused; a definitive failure takes a new key (MO-32)", res.Operation.IdempotencyKey)
		}
	}
	for _, f := range c.failures {
		t.Error(f)
	}
}

// TestReconcileToAccepted: reconciliation that finds the operation accepted
// and running stores its handle (MO-38).
func TestReconcileToAccepted(t *testing.T) {
	w := newWorld()
	l := memoryLedger(w)
	k := w.active(refRestart, "incident-1177", lim(1, 5, -1, time.Hour))
	res, _, err := w.attempt(l, restart(w, "incident-1177"), timedOut)
	if err != nil {
		t.Fatal(err)
	}
	st, err := l.Observe(bg, k, res.Operation.ID, task.Status{Effect: task.EffectRunning, Handle: asyncHandle})
	if err != nil || st.Operation.State != task.OpAccepted || st.Operation.Handle != asyncHandle {
		t.Errorf("reconciled running: %+v %v, want Accepted with the handle", st.Operation, err)
	}
}

// TestApprovalTaskEdges: an approval record that names no task is
// MISSING_FIELD; a request whose task_id does not reconcile is
// APPROVAL_SCOPE_MISMATCH.
func TestApprovalTaskEdges(t *testing.T) {
	w := newWorld()
	l := memoryLedger(w)
	w.active(refRestart, "incident-1177", lim(1, 5, -1, time.Hour))
	o := task.CheckApprovalTask(bg, l, task.Approval{}, restart(w, "incident-1177"))
	if o.Result != adapter.VerdictFail || o.ReasonCode != "MISSING_FIELD" {
		t.Errorf("no task in the approval: %s %s", o.Result, o.ReasonCode)
	}
	o = task.CheckApprovalTask(bg, l, task.Approval{Task: refRestart}, restart(w, "no-such-task"))
	if o.Result != adapter.VerdictFail || o.ReasonCode != "APPROVAL_SCOPE_MISMATCH" {
		t.Errorf("unreconciled task_id: %s %s", o.Result, o.ReasonCode)
	}
}

// TestMemoryIdempotencyStore: a key binds once per task (MO-29).
func TestMemoryIdempotencyStore(t *testing.T) {
	s := task.NewMemoryIdempotencyStore()
	k1 := task.Key{Realm: realm, Task: refOrder}
	k2 := task.Key{Realm: realm, Task: refOrder2}
	fp1, fp2 := digest.BytesDigest([]byte("a")), digest.BytesDigest([]byte("b"))
	if op, fp, err := s.Bind(bg, k1, "order-7781", fp1, "op-1"); op != "" || fp != "" || err != nil {
		t.Fatalf("first bind: %q %q %v", op, fp, err)
	}
	if op, fp, _ := s.Bind(bg, k1, "order-7781", fp2, "op-2"); op != "op-1" || fp != fp1 {
		t.Errorf("second bind in the task: %q %q, want op-1 and its fingerprint", op, fp)
	}
	if op, _, _ := s.Bind(bg, k2, "order-7781", fp2, "op-3"); op != "" {
		t.Errorf("bind in another task: %q, want a new binding", op)
	}
}
