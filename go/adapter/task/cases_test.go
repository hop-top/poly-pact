package task_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/task"
	"hop.top/pact-go/core"
	"hop.top/pact-go/core/digest"
)

// taskCase is one planned case of profile section 15.1. Its id is the
// profile's TASK-NN.variant; rules names the rules its expected values come
// from.
type taskCase struct {
	id    string
	rules string
	run   func(c *checker, w *world, l task.TaskLedger)
}

var bg = context.Background()

// cases are the TASK-01 to TASK-09 cases. Every expected value comes from the
// rule cited with it or from the worked table of profile section 13.
var cases = []taskCase{
	// TASK-01: fresh contracts cannot reset budgets.
	{"TASK-01.max-operations", "MO-19, MO-20, MO-28, MO-34; I03 rows 1, 4, 5; I02 row 8", task01MaxOperations},
	{"TASK-01.max-bytes", "MO-17, MO-21, MO-59, MO-61; section 5.1", task01MaxBytes},
	{"TASK-01.registry-lowered-limit", "MO-18; I03 note", task01RegistryLoweredLimit},
	// TASK-02: one native request per logical operation.
	{"TASK-02.keyed-write", "MO-27, MO-28, MO-30, MO-31; U06", task02KeyedWrite},
	{"TASK-02.restart-dedupe", "MO-31, MO-33, section 3.3; I14 rows 2 to 4", task02RestartDedupe},
	{"TASK-02.key-other-payload", "MO-29", task02KeyOtherPayload},
	{"TASK-02.key-other-task", "MO-29", task02KeyOtherTask},
	// TASK-03: accepted is not completed.
	{"TASK-03.accepted-not-completed", "MO-41, MO-45, MO-47; I14 rows 3, 5", task03AcceptedNotCompleted},
	{"TASK-03.succeeded", "MO-44, MO-45, MO-47; I14 row 6a; draft 14.5", task03Succeeded},
	{"TASK-03.failed", "MO-32, MO-44; I14 row 6b; draft 14.5", task03Failed},
	{"TASK-03.cancelled", "MO-44; draft 14.5 cancelled row", task03Cancelled},
	{"TASK-03.poll-exhausted", "MO-45", task03PollExhausted},
	{"TASK-03.handle-other-origin", "MO-43", task03HandleOtherOrigin},
	{"TASK-03.tracking-forbidden", "MO-46; I14 row 6d", task03TrackingForbidden},
	// TASK-04: paging stays task-bound.
	{"TASK-04.other-task", "MO-56; I02 row 3", task04OtherTask},
	{"TASK-04.beyond-max-pages", "MO-19, MO-20, MO-55, MO-57; I02 rows 1, 2, 4 to 8", task04BeyondMaxPages},
	{"TASK-04.listing-restart", "MO-57", task04ListingRestart},
	{"TASK-04.unknown-token", "MO-56, RB-57, RB-58", task04UnknownToken},
	{"TASK-04.expired-task", "MO-50, MO-58; I08 row 5", task04ExpiredTask},
	// TASK-05: ambiguous effects are reconciled, never retried blindly.
	{"TASK-05.timeout-reconcile", "MO-32, MO-35, MO-36, MO-38; U06", task05TimeoutReconcile},
	{"TASK-05.status-indeterminate", "MO-37, MO-38", task05StatusIndeterminate},
	{"TASK-05.restart-timeout", "MO-32, MO-33, MO-35; I14 row 6c", task05RestartTimeout},
	// TASK-06: cancellation and terminal states.
	{"TASK-06.cancel-mid-task", "MO-38, MO-49, MO-50", task06CancelMidTask},
	{"TASK-06.completed-task", "MO-6, MO-49, MO-50, MO-58; I08 rows 4 to 6", task06CompletedTask},
	{"TASK-06.context-after-send", "MO-35, MO-52", task06ContextAfterSend},
	{"TASK-06.context-before-send", "MO-22, MO-52", task06ContextBeforeSend},
	{"TASK-06.fresh-contract-after-cancel", "MO-12, MO-20, MO-49", task06FreshContractAfterCancel},
	// TASK-07: the ledger key is the native task reference.
	{"TASK-07.alias-same-reference", "MO-1, MO-3, MO-4, MO-5", task07AliasSameReference},
	{"TASK-07.unknown-reference", "MO-6; I08 row 3", task07UnknownReference},
	{"TASK-07.unreconciled-id", "MO-3", task07UnreconciledID},
	{"TASK-07.terminal-no-entry", "MO-6, MO-23, MO-50, MO-62", task07TerminalNoEntry},
	{"TASK-07.other-principal", "MO-7; I03 rows 1 to 3", task07OtherPrincipal},
	{"TASK-07.swap-between-calls", "MO-4, MO-20, MO-56", task07SwapBetweenCalls},
	// TASK-08: the deadline.
	{"TASK-08.deadline-elapsed", "MO-23, MO-49", task08DeadlineElapsed},
	{"TASK-08.just-before-deadline", "MO-23", task08JustBeforeDeadline},
	{"TASK-08.status-after-deadline", "MO-23, MO-38, MO-50", task08StatusAfterDeadline},
	// TASK-09: task-scoped approval.
	{"TASK-09.approval-other-task", "MO-6, MO-9; draft 17.3.1", task09ApprovalOtherTask},
	{"TASK-09.late-approval-no-reset", "MO-12, MO-49", task09LateApprovalNoReset},
	{"TASK-09.pending-reserves-nothing", "MO-6, MO-10; I14 rows 1, 2", task09PendingReservesNothing},
}

func crm(w *world, p adapter.Principal, a adapter.AgentID, alias string) task.Request {
	return w.req(p, a, alias, crmRead, w.op("GET", crmTarget, "", nil), "")
}

func mail(w *world, alias, target, cont string) task.Request {
	return w.req(maya, agent, alias, mailPages, w.op("GET", target, "", nil), cont)
}

func restart(w *world, alias string) task.Request {
	return w.req(maya, agent, alias, vmRestart, w.op("POST", vmTarget, "", nil), "")
}

// TASK-01.max-operations: three identical reads are three operations, each
// reserved and sent, for a read is never a repeat (MO-28, MO-34); after
// max_operations a new contract for the same native task, under another
// client value that reconciles to it, is refused with budget-exhausted; no
// counter changes and the native service sees no request.
func task01MaxOperations(c *checker, w *world, l task.TaskLedger) {
	k := w.active(refRenewal, "renewal-C-481", lim(3, 5, -1, 900*time.Second))
	w.reg.alias(maya, agent, "crm:renewal/C-481", refRenewal)
	seen := map[string]bool{}
	for i := 1; i <= 3; i++ {
		res, _, err := w.attempt(l, crm(w, maya, agent, "renewal-C-481"), ok(1200))
		if !c.ok(err, "read within the budget") {
			return
		}
		equal(c, res.Send, true, "an identical read: send")
		if seen[res.Operation.ID] {
			c.errorf("read %d: answered from the record %q of an earlier read, want a new operation (MO-28)", i, res.Operation.ID)
		}
		seen[res.Operation.ID] = true
	}
	c.budget(l, k, 3, 0, 3600, "after three reads")
	_, _, err := w.attempt(l, crm(w, maya, agent, "crm:renewal/C-481"), ok(1200))
	c.refused(err, task.LabelBudgetExhausted, "fourth read: new contract, other client value of the same task")
	_, _, err = w.attempt(l, crm(w, maya, agent, "renewal-C-481"), ok(1200))
	c.refused(err, task.LabelBudgetExhausted, "fourth read: new contract, same client value")
	c.budget(l, k, 3, 0, 3600, "after the refusals")
	c.sent(w, crmRead, 3, "after the refusals")
}

// TASK-01.max-bytes: a response that would take the bytes past max_bytes is
// not released, its continuation is not recorded, and the reservation stays
// counted; a response that reaches the limit exactly is released.
func task01MaxBytes(c *checker, w *world, l task.TaskLedger) {
	k := w.active(refMailbox, "mailbox-summary", lim(12, 5, 100_000, 1800*time.Second))
	w.reg.alias(maya, agent, "mail:summary/0731", refMailbox)
	res, st, err := w.attempt(l, mail(w, "mailbox-summary", mailInbox, ""), page(40_000, next(2)))
	if !c.ok(err, "page 1") {
		return
	}
	equal(c, res.BytesLeft, 100_000, "page 1: bytes left")
	res, st, err = w.attempt(l, mail(w, "mailbox-summary", mailInbox, st.PageToken), page(40_000, next(3)))
	if !c.ok(err, "page 2") {
		return
	}
	equal(c, res.BytesLeft, 60_000, "page 2: bytes left")
	res, st, err = w.attempt(l, mail(w, "mailbox-summary", mailInbox, st.PageToken), page(20_001, next(4)))
	equal(c, res.BytesLeft, 20_000, "page 3: bytes left")
	c.refused(err, task.LabelBudgetExhausted, "page 3: 20,001 bytes with 20,000 left")
	equal(c, st.PageToken, "", "page 3: continuation of a page not released (MO-59)")
	c.budget(l, k, 3, 3, 80_000, "page 3: the reservation stays counted, the bytes are not released")

	_, _, err = w.attempt(l, mail(w, "mail:summary/0731", mailInbox, ""), page(20_000, ""))
	c.ok(err, "a first page under a fresh contract that reaches max_bytes exactly")
	c.budget(l, k, 4, 4, 100_000, "at max_bytes")
	res, _, err = w.attempt(l, mail(w, "mail:summary/0731", mailInbox, ""), page(1, ""))
	equal(c, res.BytesLeft, 0, "at max_bytes: bytes left")
	c.refused(err, task.LabelBudgetExhausted, "one byte past max_bytes")
	c.budget(l, k, 5, 5, 100_000, "after one byte past max_bytes")

	// A write: the 29 octets of its request body count against max_bytes at
	// the reservation, before the send (section 5.1, MO-61); its response has
	// no body.
	ko := w.active(refOrder, "purchase-0098", lim(5, 5, 1000, 3600*time.Second))
	ro, err := l.Reserve(bg, order(w, `{"sku":"LAP-14","quantity":3}`))
	if !c.ok(err, "an order with a body of 29 octets") {
		return
	}
	c.budget(l, ko, 1, 0, 29, "the request body of a write, at the reservation")
	w.sends[orderWrite.ID]++
	_, err = l.Record(bg, ro, ok(0))
	c.ok(err, "the order of 29 octets: record")
	c.budget(l, ko, 1, 0, 29, "the request body of a write, after the response")

	// 971 octets are left: a body of 972 is refused at the reservation and
	// sent nothing; a body of 971 reaches max_bytes exactly.
	_, _, err = w.attempt(l, order(w, bodyOf(972)), ok(0))
	c.refused(err, task.LabelBudgetExhausted, "an order whose body of 972 octets would pass max_bytes")
	c.budget(l, ko, 1, 0, 29, "after the refused order")
	c.sent(w, orderWrite, 1, "the refused order is not sent")
	_, _, err = w.attempt(l, order(w, bodyOf(971)), ok(0))
	c.ok(err, "an order whose body of 971 octets reaches max_bytes")
	c.budget(l, ko, 2, 0, 1000, "at max_bytes")
	c.sent(w, orderWrite, 2, "at max_bytes")
}

// bodyOf returns a JSON order body of exactly n octets, n at least 26.
func bodyOf(n int) string {
	return `{"sku":"LAP-14","note":"` + strings.Repeat("x", n-26) + `"}`
}

// TASK-01.registry-lowered-limit: a lower registry limit takes effect at the
// next reservation, even below a counter; a higher one only when the
// registry says so.
func task01RegistryLoweredLimit(c *checker, w *world, l task.TaskLedger) {
	k := w.active(refRenewal, "renewal-C-481", lim(3, 5, -1, 900*time.Second))
	for i := 1; i <= 2; i++ {
		if _, _, err := w.attempt(l, crm(w, maya, agent, "renewal-C-481"), ok(500)); !c.ok(err, "read within the budget") {
			return
		}
	}
	w.reg.update(realm, refRenewal, func(r *task.Record) { r.Limits.MaxOperations = task.Bounded(1) })
	_, _, err := w.attempt(l, crm(w, maya, agent, "renewal-C-481"), ok(500))
	c.refused(err, task.LabelBudgetExhausted, "third read after the registry lowered max_operations to 1")
	c.budget(l, k, 2, 0, -1, "after the lowered limit")
	w.reg.update(realm, refRenewal, func(r *task.Record) { r.Limits.MaxOperations = task.Bounded(3) })
	_, _, err = w.attempt(l, crm(w, maya, agent, "renewal-C-481"), ok(500))
	c.ok(err, "third read after the registry raised max_operations to 3")
	_, _, err = w.attempt(l, crm(w, maya, agent, "renewal-C-481"), ok(500))
	c.refused(err, task.LabelBudgetExhausted, "fourth read")
	c.budget(l, k, 3, 0, -1, "at the end")
	c.sent(w, crmRead, 3, "at the end")
}

// TASK-02.keyed-write: the same order under a second contract is one logical
// operation: exactly one native request, answered from the record. The key
// is drawn by the ledger, not derived from operation_id.
func task02KeyedWrite(c *checker, w *world, l task.TaskLedger) {
	k := w.active(refOrder, "purchase-0098", lim(5, 5, -1, 3600*time.Second))
	op := w.op("POST", orderTarget, `{"sku":"LAP-14","quantity":3}`, nil)
	res, st, err := w.attempt(l, w.req(maya, agent, "purchase-0098", orderWrite, op, ""), task.Result{Sent: true, Status: 200, NativeRef: "po-55120"})
	if !c.ok(err, "first order") {
		return
	}
	equal(c, res.Send, true, "first order: send")
	key := res.Operation.IdempotencyKey
	if key == "" || strings.Contains(key, op.OperationID) {
		c.errorf("first order: idempotency key %q, want a drawn key not derived from operation_id %q (MO-30)", key, op.OperationID)
	}
	want, err := digest.ObjectDigest(map[string]any{
		"task": string(refOrder), "principal_id": maya.ID, "action": op.Action, "resources": op.Resources,
		"method": op.Method, "target_uri": op.TargetURI, "body_digest": op.BodyDigest, "headers": op.Headers,
	})
	if c.ok(err, "fingerprint") {
		equal(c, res.Operation.Fingerprint, want, "first order: fingerprint (MO-27)")
	}
	equal(c, st.Operation.State, task.OpSucceeded, "first order: record")

	res2, _, err := w.attempt(l, w.req(maya, agent, "purchase-0098", orderWrite, w.again(op), ""), task.Result{Sent: true, Status: 200})
	if !c.ok(err, "the same order under a second contract") {
		return
	}
	equal(c, res2.Send, false, "second contract: send")
	equal(c, res2.Operation.ID, res.Operation.ID, "second contract: answered from the record of the first")
	equal(c, res2.Operation.State, task.OpSucceeded, "second contract: state")
	equal(c, res2.Operation.NativeRef, "po-55120", "second contract: native reference")
	c.sent(w, orderWrite, 1, "after the second contract")
	c.budget(l, k, 1, 0, -1, "after the second contract")
}

// TASK-02.restart-dedupe: an accepted restart asked again under contract C3
// is answered operation-in-flight, not budget-exhausted although
// max_operations is spent, because the fingerprint test comes first.
func task02RestartDedupe(c *checker, w *world, l task.TaskLedger) {
	k := w.active(refRestart, "incident-1177", lim(1, 5, -1, 3600*time.Second))
	r := restart(w, "incident-1177")
	res, st, err := w.attempt(l, r, accepted(asyncHandle, 10*time.Second))
	if !c.ok(err, "restart") {
		return
	}
	equal(c, st.Operation.State, task.OpAccepted, "restart: record")
	r.Operation = w.again(r.Operation)
	_, _, err = w.attempt(l, r, accepted(asyncHandle, 10*time.Second))
	if c.refused(err, task.LabelOperationInFlight, "restart asked again under contract C3") {
		var ref *task.Refusal
		errors.As(err, &ref)
		equal(c, ref.Operation.ID, res.Operation.ID, "contract C3: the record answered")
		equal(c, ref.Operation.State, task.OpAccepted, "contract C3: the state answered")
	}
	c.sent(w, vmRestart, 1, "after contract C3")
	c.budget(l, k, 1, 0, -1, "after contract C3")
}

// TASK-02.key-other-payload: the same client key in the same task with
// another payload is idempotency-conflict; the key is copied unchanged.
func task02KeyOtherPayload(c *checker, w *world, l task.TaskLedger) {
	k := w.active(refOrder, "purchase-0098", lim(5, 5, -1, 3600*time.Second))
	key := map[string]string{"idempotency-key": "order-7781"}
	res, _, err := w.attempt(l, w.req(maya, agent, "purchase-0098", orderWrite, w.op("POST", orderTarget, `{"sku":"LAP-14","quantity":3}`, key), ""), ok(0))
	if !c.ok(err, "first order") {
		return
	}
	equal(c, res.Operation.IdempotencyKey, "order-7781", "first order: the client key, unchanged")
	_, _, err = w.attempt(l, w.req(maya, agent, "purchase-0098", orderWrite, w.op("POST", orderTarget, `{"sku":"LAP-14","quantity":30}`, key), ""), ok(0))
	c.refused(err, task.LabelIdempotencyConflict, "the same key with another payload")
	c.sent(w, orderWrite, 1, "after the conflict")
	c.budget(l, k, 1, 0, -1, "after the conflict")
}

// TASK-02.key-other-task: the same client key in another task is another
// logical operation.
func task02KeyOtherTask(c *checker, w *world, l task.TaskLedger) {
	k1 := w.active(refOrder, "purchase-0098", lim(5, 5, -1, 3600*time.Second))
	k2 := w.active(refOrder2, "purchase-0099", lim(5, 5, -1, 3600*time.Second))
	key := map[string]string{"idempotency-key": "order-7781"}
	body := `{"sku":"LAP-14","quantity":3}`
	_, _, err := w.attempt(l, w.req(maya, agent, "purchase-0098", orderWrite, w.op("POST", orderTarget, body, key), ""), ok(0))
	if !c.ok(err, "order in task 0098") {
		return
	}
	res, _, err := w.attempt(l, w.req(maya, agent, "purchase-0099", orderWrite, w.op("POST", orderTarget, body, key), ""), ok(0))
	if !c.ok(err, "the same key in task 0099") {
		return
	}
	equal(c, res.Send, true, "task 0099: send")
	equal(c, res.Operation.IdempotencyKey, "order-7781", "task 0099: the client key")
	c.sent(w, orderWrite, 2, "two tasks")
	c.budget(l, k1, 1, 0, -1, "task 0098")
	c.budget(l, k2, 1, 0, -1, "task 0099")
}

// acceptRestart runs I14 rows 2 and 3: the restart is reserved, sent, and
// answered 202.
func acceptRestart(c *checker, w *world, l task.TaskLedger, l0 task.Limits, retryAfter time.Duration) (task.Key, task.Reservation, task.Settled, bool) {
	k := w.active(refRestart, "incident-1177", l0)
	res, st, err := w.attempt(l, restart(w, "incident-1177"), accepted(asyncHandle, retryAfter))
	if !c.ok(err, "restart answered 202") {
		return k, res, st, false
	}
	return k, res, st, equal(c, st.Operation.State, task.OpAccepted, "202: record")
}

// TASK-03.accepted-not-completed: a 202 is Accepted with an EXECUTION,
// UNKNOWN, none report; a status read of a running operation leaves it
// Accepted; the tracker waits the Retry-After first; the task stays Active.
func task03AcceptedNotCompleted(c *checker, w *world, l task.TaskLedger) {
	k, res, st, good := acceptRestart(c, w, l, lim(1, 5, -1, 3600*time.Second), 10*time.Second)
	if !good {
		return
	}
	equal(c, st.Operation.Handle, asyncHandle, "202: handle stored")
	if c.report(st.Report, refRestart, core.EventExecution, core.OutcomeUnknown, core.DimensionNone, "202: report") {
		equal(c, st.Report.OperationID, res.Operation.OperationID, "202: report operation_id")
	}
	w.src.answer(nil, task.Status{Effect: task.EffectRunning, RetryAfter: 15 * time.Second})
	st2, err := w.tracker(l, 1).Track(bg, k, res.Operation.ID)
	c.ok(err, "one status read of a running operation")
	c.noVerdict(st2.Report, "running")
	equal(c, w.src.count(), 1, "status reads")
	equal(c, slices.Equal(w.sleeps, []time.Duration{10 * time.Second}), true, "the wait before the first read is the 202's Retry-After")
	c.opState(l, k, res.Operation.ID, task.OpAccepted, "running")
	c.state(l, k, task.StateActive, "running")
	c.budget(l, k, 1, 0, -1, "status reads are not operations (MO-16)")
}

// TASK-03.succeeded: a terminal Succeeded makes the record Succeeded, with
// a separate EXECUTION, SUCCESS, reliability report; the task stays Active.
func task03Succeeded(c *checker, w *world, l task.TaskLedger) {
	k, res, st, good := acceptRestart(c, w, l, lim(1, 5, -1, 3600*time.Second), 10*time.Second)
	if !good {
		return
	}
	w.src.answer(nil, task.Status{Effect: task.EffectRunning, RetryAfter: 15 * time.Second}, task.Status{Effect: task.EffectApplied})
	st2, err := w.tracker(l, 5).Track(bg, k, res.Operation.ID)
	if !c.ok(err, "track to completion") {
		return
	}
	equal(c, w.src.count(), 2, "status reads")
	equal(c, slices.Equal(w.sleeps, []time.Duration{10 * time.Second, 15 * time.Second}), true, "waits are the Retry-After values")
	c.opState(l, k, res.Operation.ID, task.OpSucceeded, "completed")
	if c.report(st2.Report, refRestart, core.EventExecution, core.OutcomeSuccess, core.DimensionReliability, "completion report") && st.Report != nil {
		if st2.Report.EventID == "" || st2.Report.EventID == st.Report.EventID {
			c.errorf("completion report: event_id %q, want one separate from the 202's %q", st2.Report.EventID, st.Report.EventID)
		}
	}
	c.state(l, k, task.StateActive, "the completion of an operation is not the completion of the task (MO-47)")
}

// TASK-03.failed: a terminal Failed makes the record Failed with an
// EXECUTION, FAILURE, reliability report; a new restart is a new reservation
// and is budget-exhausted.
func task03Failed(c *checker, w *world, l task.TaskLedger) {
	k, res, _, good := acceptRestart(c, w, l, lim(1, 5, -1, 3600*time.Second), 10*time.Second)
	if !good {
		return
	}
	w.src.answer(nil, task.Status{Effect: task.EffectNone})
	st, err := w.tracker(l, 5).Track(bg, k, res.Operation.ID)
	if !c.ok(err, "track to failure") {
		return
	}
	c.opState(l, k, res.Operation.ID, task.OpFailed, "failed")
	if c.report(st.Report, refRestart, core.EventExecution, core.OutcomeFailure, core.DimensionReliability, "failure report") {
		equal(c, st.Report.Details != "cancelled", true, "failure report: not the cancelled row")
	}
	_, _, err = w.attempt(l, restart(w, "incident-1177"), accepted(asyncHandle, 0))
	c.refused(err, task.LabelBudgetExhausted, "a new restart after Failed with max_operations 1")
	c.sent(w, vmRestart, 1, "after the new restart")
}

// TASK-03.cancelled: a native Canceled is terminal without success and is
// reported under the cancelled-completion row of draft 14.5.
func task03Cancelled(c *checker, w *world, l task.TaskLedger) {
	k, res, _, good := acceptRestart(c, w, l, lim(1, 5, -1, 3600*time.Second), 10*time.Second)
	if !good {
		return
	}
	w.src.answer(nil, task.Status{Effect: task.EffectCancelled})
	st, err := w.tracker(l, 5).Track(bg, k, res.Operation.ID)
	if !c.ok(err, "track to cancellation") {
		return
	}
	c.opState(l, k, res.Operation.ID, task.OpFailed, "cancelled")
	if c.report(st.Report, refRestart, core.EventExecution, core.OutcomeFailure, core.DimensionReliability, "cancelled report") {
		equal(c, st.Report.Details, "cancelled", "cancelled report: details")
		equal(c, st.Report.Attribution.CausalAssessment, core.CausalUnknown, "cancelled report: causal_assessment")
	}
}

// TASK-03.poll-exhausted: max_status_reads reached leaves the record
// Accepted; with no Retry-After the tracker waits the minimum interval.
func task03PollExhausted(c *checker, w *world, l task.TaskLedger) {
	k, res, _, good := acceptRestart(c, w, l, lim(1, 5, -1, 3600*time.Second), 0)
	if !good {
		return
	}
	w.src.answer(nil, task.Status{Effect: task.EffectRunning})
	st, _ := w.tracker(l, 3).Track(bg, k, res.Operation.ID)
	equal(c, w.src.count(), 3, "status reads bounded by max_status_reads")
	equal(c, slices.Equal(w.sleeps, []time.Duration{20 * time.Second, 20 * time.Second, 20 * time.Second}), true, "waits are the minimum interval")
	c.opState(l, k, res.Operation.ID, task.OpAccepted, "exhausted")
	c.noVerdict(st.Report, "exhausted")
}

// TASK-03.handle-other-origin: a handle on another origin is not followed,
// and without a configured handle check no handle is followed.
func task03HandleOtherOrigin(c *checker, w *world, l task.TaskLedger) {
	k := w.active(refRestart, "incident-1177", lim(2, 5, -1, 3600*time.Second))
	res, _, err := w.attempt(l, restart(w, "incident-1177"), accepted(foreignHandle, 0))
	if !c.ok(err, "restart answered 202 with a foreign handle") {
		return
	}
	w.src.answer(nil, task.Status{Effect: task.EffectApplied})
	st, err := w.tracker(l, 5).Track(bg, k, res.Operation.ID)
	if err == nil {
		c.errorf("a foreign handle: Track succeeded, want an error")
	}
	c.noVerdict(st.Report, "a foreign handle")
	equal(c, w.src.count(), 0, "a foreign handle: status reads")
	c.opState(l, k, res.Operation.ID, task.OpAccepted, "a foreign handle")

	r := restart(w, "incident-1177")
	r.Operation.TargetURI += "?second"
	res, _, err = w.attempt(l, r, accepted(asyncHandle, 0))
	if !c.ok(err, "a second restart") {
		return
	}
	tr := w.tracker(l, 5)
	tr.CheckHandle = nil
	if _, err := tr.Track(bg, k, res.Operation.ID); err == nil {
		c.errorf("no handle check: Track succeeded, want an error")
	}
	equal(c, w.src.count(), 0, "no handle check: status reads")
	c.opState(l, k, res.Operation.ID, task.OpAccepted, "no handle check")
}

// TASK-03.tracking-forbidden: a handle the principal cannot read leaves the
// record Accepted with DEPENDENCY_UNAVAILABLE; no success is inferred.
func task03TrackingForbidden(c *checker, w *world, l task.TaskLedger) {
	k, res, _, good := acceptRestart(c, w, l, lim(1, 5, -1, 3600*time.Second), 10*time.Second)
	if !good {
		return
	}
	w.src.answer(errors.Join(errors.New("fake ARM: 403 AuthorizationFailed at resource group scope"), adapter.ErrDependencyUnavailable))
	st, err := w.tracker(l, 5).Track(bg, k, res.Operation.ID)
	equal(c, errors.Is(err, adapter.ErrDependencyUnavailable), true, "unreadable handle: DEPENDENCY_UNAVAILABLE")
	c.noVerdict(st.Report, "unreadable handle")
	c.opState(l, k, res.Operation.ID, task.OpAccepted, "unreadable handle")
}

// TASK-04.other-task: a continuation presented under another native task is
// CONTEXT_MISMATCH before any reservation; under its own task it is
// followed.
func task04OtherTask(c *checker, w *world, l task.TaskLedger) {
	k := w.active(refMailbox, "mailbox-summary", lim(12, 5, 1_048_576, 1800*time.Second))
	k2 := w.active(refMailbox2, "mailbox-summary-0801", lim(12, 5, 1_048_576, 1800*time.Second))
	_, st, err := w.attempt(l, mail(w, "mailbox-summary", mailInbox, ""), page(40_000, next(2)))
	if !c.ok(err, "page 1") {
		return
	}
	tok := st.PageToken
	if tok == "" {
		c.errorf("page 1: no page token for a next link the pager accepts")
		return
	}
	_, _, err = w.attempt(l, mail(w, "mailbox-summary-0801", mailInbox, tok), page(40_000, next(3)))
	c.mismatch(err, "the page-2 token under a task_id that resolves to another task")
	c.budget(l, k, 1, 1, 40_000, "after the mismatch")
	c.noEntry(l, k2, "the other task after the mismatch")
	c.sent(w, mailPages, 1, "after the mismatch")
	_, _, err = w.attempt(l, mail(w, "mailbox-summary", mailInbox, tok), page(40_000, next(3)))
	c.ok(err, "the page-2 token under its own task")
	c.budget(l, k, 2, 2, 80_000, "page 2")
}

// TASK-04.beyond-max-pages: the I02 table: pages are counted per task, a
// page past max_pages is budget-exhausted, and a new contract resets
// nothing.
func task04BeyondMaxPages(c *checker, w *world, l task.TaskLedger) {
	k := w.active(refMailbox, "mailbox-summary", lim(12, 5, 1_048_576, 1800*time.Second))
	rows := []struct {
		row               string
		fromStart         bool
		refused           bool
		ops, pages, bytes int64
	}{
		{"row 1: first page, C1", true, false, 1, 1, 40_000},
		{"row 2: page 2, C2", false, false, 2, 2, 80_000},
		{"row 4: listing started again, C3", true, false, 3, 3, 120_000},
		{"row 5: page 2 of the new listing", false, false, 4, 4, 160_000},
		{"row 6: page 3", false, false, 5, 5, 200_000},
		{"row 7: page 4", false, true, 5, 5, 200_000},
		{"row 8: a new contract for a first page", true, true, 5, 5, 200_000},
	}
	tok := ""
	for i, r := range rows {
		cont := tok
		if r.fromStart {
			cont = ""
		}
		_, st, err := w.attempt(l, mail(w, "mailbox-summary", mailInbox, cont), page(40_000, next(i+2)))
		if r.refused {
			c.refused(err, task.LabelBudgetExhausted, r.row)
		} else if c.ok(err, r.row) {
			tok = st.PageToken
		}
		c.budget(l, k, r.ops, r.pages, r.bytes, r.row)
	}
	c.sent(w, mailPages, 5, "after row 8")
}

// TASK-04.listing-restart: a new listing does not reset max_pages.
func task04ListingRestart(c *checker, w *world, l task.TaskLedger) {
	k := w.active(refMailbox, "mailbox-summary", lim(12, 2, -1, 1800*time.Second))
	_, st, err := w.attempt(l, mail(w, "mailbox-summary", mailInbox, ""), page(1000, next(2)))
	if !c.ok(err, "inbox page 1") {
		return
	}
	_, _, err = w.attempt(l, mail(w, "mailbox-summary", mailInbox, st.PageToken), page(1000, ""))
	c.ok(err, "inbox page 2")
	_, _, err = w.attempt(l, mail(w, "mailbox-summary", mailSent, ""), page(1000, ""))
	c.refused(err, task.LabelBudgetExhausted, "page 1 of another listing with max_pages 2 spent")
	c.budget(l, k, 2, 2, 2000, "after the new listing")
}

// TASK-04.unknown-token: a token the ledger never issued is CONTEXT_MISMATCH;
// a next link the pager refuses is not recorded.
func task04UnknownToken(c *checker, w *world, l task.TaskLedger) {
	k := w.active(refMailbox, "mailbox-summary", lim(12, 5, -1, 1800*time.Second))
	_, st, err := w.attempt(l, mail(w, "mailbox-summary", mailInbox, ""), page(1000, "https://graph.contoso-mirror.example/v1.0/me/messages?$skiptoken=page-2"))
	if !c.ok(err, "page 1 with a foreign next link") {
		return
	}
	equal(c, st.PageToken, "", "page 1: a link the pager refuses yields no token")
	_, _, err = w.attempt(l, mail(w, "mailbox-summary", mailInbox, "gw-page-never-issued"), page(1000, ""))
	c.mismatch(err, "a token the ledger never issued")
	c.budget(l, k, 1, 1, 1000, "after the unknown token")
	c.sent(w, mailPages, 1, "after the unknown token")
}

// TASK-04.expired-task: a continuation ends with its task; its token is
// refused with task-cancelled after the task is cancelled, task-completed
// after it is completed, and deadline-elapsed at the deadline, code
// TASK_LIMIT, and nothing is counted (MO-58).
func task04ExpiredTask(c *checker, w *world, l task.TaskLedger) {
	k := w.active(refMailbox, "mailbox-summary", lim(12, 5, -1, 1800*time.Second))
	_, st, err := w.attempt(l, mail(w, "mailbox-summary", mailInbox, ""), page(1000, next(2)))
	if !c.ok(err, "page 1") {
		return
	}
	for _, end := range []struct {
		ref   task.Ref
		alias string
		state task.State
		label task.Label
	}{
		{refMailbox2, "mailbox-summary-0801", task.StateCancelled, task.LabelTaskCancelled},
		{refQueue, "queue-summary-run-0412", task.StateCompleted, task.LabelTaskCompleted},
	} {
		ke := w.active(end.ref, end.alias, lim(12, 5, -1, 1800*time.Second))
		_, ste, err := w.attempt(l, mail(w, end.alias, mailInbox, ""), page(1000, next(2)))
		if !c.ok(err, "page 1 of "+string(end.ref)) {
			return
		}
		w.reg.update(realm, end.ref, func(r *task.Record) { r.State = end.state })
		_, _, err = w.attempt(l, mail(w, end.alias, mailInbox, ste.PageToken), page(1000, ""))
		c.refused(err, end.label, "page 2 of a task "+string(end.state))
		c.budget(l, ke, 1, 1, 1000, "after page 2 of a task "+string(end.state))
	}
	c.sent(w, mailPages, 3, "before the deadline")
	w.clk.Set(t0.Add(1800 * time.Second))
	_, _, err = w.attempt(l, mail(w, "mailbox-summary", mailInbox, st.PageToken), page(1000, ""))
	c.refused(err, task.LabelDeadlineElapsed, "page 2 at the deadline")
	c.budget(l, k, 1, 1, 1000, "after the deadline")
	c.sent(w, mailPages, 3, "after the deadline")
}

// order is a keyed-write request of U06.
func order(w *world, body string) task.Request {
	return w.req(maya, agent, "purchase-0098", orderWrite, w.op("POST", orderTarget, body, nil), "")
}

// TASK-05.timeout-reconcile: a timed-out order is Unknown, a repeat is
// outcome-unknown, the native status source is read, and the native service
// sees no second write. A reconciliation of no effect lets a new attempt
// reuse the key.
func task05TimeoutReconcile(c *checker, w *world, l task.TaskLedger) {
	k := w.active(refOrder, "purchase-0098", lim(5, 5, -1, 3600*time.Second))
	r := order(w, `{"sku":"LAP-14","quantity":3}`)
	res, st, err := w.attempt(l, r, timedOut)
	if !c.ok(err, "an order that times out") {
		return
	}
	equal(c, st.Operation.State, task.OpUnknown, "timeout: record")
	c.report(st.Report, refOrder, core.EventExecution, core.OutcomeUnknown, core.DimensionNone, "timeout: ambiguous timeout report")
	r.Operation = w.again(r.Operation)
	_, _, err = w.attempt(l, r, ok(0))
	c.refused(err, task.LabelOutcomeUnknown, "the order asked again under contract C2")
	w.src.answer(nil, task.Status{Effect: task.EffectApplied, Authoritative: true})
	if _, err := w.tracker(l, 3).Track(bg, k, res.Operation.ID); c.ok(err, "reconcile") {
		c.opState(l, k, res.Operation.ID, task.OpSucceeded, "reconciled: the order took effect")
	}
	equal(c, w.src.count(), 1, "reconcile: status reads")
	r.Operation = w.again(r.Operation)
	res3, _, err := w.attempt(l, r, ok(0))
	if c.ok(err, "the order asked again after reconciliation") {
		equal(c, res3.Send, false, "after reconciliation: answered from the record")
	}
	c.sent(w, orderWrite, 1, "no second write")

	r2 := order(w, `{"sku":"MON-27","quantity":2}`)
	res4, _, err := w.attempt(l, r2, timedOut)
	if !c.ok(err, "a second order that times out") {
		return
	}
	w.src.answer(nil, task.Status{Effect: task.EffectNone, Authoritative: true})
	if _, err := w.tracker(l, 3).Track(bg, k, res4.Operation.ID); c.ok(err, "reconcile the second order") {
		c.opState(l, k, res4.Operation.ID, task.OpFailed, "reconciled: no effect, authoritatively")
	}
	r2.Operation = w.again(r2.Operation)
	res5, _, err := w.attempt(l, r2, ok(0))
	if c.ok(err, "a new attempt after an authoritative no-effect") {
		equal(c, res5.Send, true, "new attempt: send")
		equal(c, res5.Operation.IdempotencyKey, res4.Operation.IdempotencyKey, "new attempt: the key of the failed operation (MO-32)")
	}
	c.sent(w, orderWrite, 3, "after the new attempt")
	c.budget(l, k, 3, 0, -1, "after the new attempt")
}

// TASK-05.status-indeterminate: an indeterminate or non-authoritative status
// leaves the record Unknown; a status not listed as definitive is ambiguous
// and a listed one is a definitive failure.
func task05StatusIndeterminate(c *checker, w *world, l task.TaskLedger) {
	k := w.active(refOrder, "purchase-0098", lim(5, 5, -1, 3600*time.Second))
	r := order(w, `{"sku":"LAP-14","quantity":3}`)
	res, _, err := w.attempt(l, r, timedOut)
	if !c.ok(err, "an order that times out") {
		return
	}
	w.src.answer(nil, task.Status{Effect: task.EffectIndeterminate})
	_, _ = w.tracker(l, 1).Track(bg, k, res.Operation.ID)
	c.opState(l, k, res.Operation.ID, task.OpUnknown, "indeterminate status")
	w.src.answer(nil, task.Status{Effect: task.EffectNone, Authoritative: false})
	_, _ = w.tracker(l, 1).Track(bg, k, res.Operation.ID)
	c.opState(l, k, res.Operation.ID, task.OpUnknown, "no effect from a source that is not authoritative")
	r.Operation = w.again(r.Operation)
	_, _, err = w.attempt(l, r, ok(0))
	c.refused(err, task.LabelOutcomeUnknown, "the order asked again")
	c.sent(w, orderWrite, 1, "no second write")

	_, st, err := w.attempt(l, order(w, `{"sku":"KBD-02","quantity":1}`), task.Result{Sent: true, Status: 500})
	if c.ok(err, "an order answered 500") {
		equal(c, st.Operation.State, task.OpUnknown, "500, not listed as definitive")
	}
	_, st, err = w.attempt(l, order(w, `{"sku":"KBD-03","quantity":1}`), task.Result{Sent: true, Status: 422})
	if c.ok(err, "an order answered 422") {
		equal(c, st.Operation.State, task.OpFailed, "422, listed as definitive")
	}
}

// TASK-05.restart-timeout: a restart that times out is Unknown; no second
// POST is sent; after an authoritative no-effect a new attempt counts
// against the budget and is budget-exhausted.
func task05RestartTimeout(c *checker, w *world, l task.TaskLedger) {
	k := w.active(refRestart, "incident-1177", lim(1, 5, -1, 3600*time.Second))
	r := restart(w, "incident-1177")
	res, st, err := w.attempt(l, r, timedOut)
	if !c.ok(err, "a restart that times out") {
		return
	}
	equal(c, st.Operation.State, task.OpUnknown, "timeout: record")
	r.Operation = w.again(r.Operation)
	_, _, err = w.attempt(l, r, accepted(asyncHandle, 0))
	c.refused(err, task.LabelOutcomeUnknown, "the restart asked again")
	w.src.answer(nil, task.Status{Effect: task.EffectIndeterminate})
	_, _ = w.tracker(l, 2).Track(bg, k, res.Operation.ID)
	c.opState(l, k, res.Operation.ID, task.OpUnknown, "indeterminate status")
	equal(c, w.src.count(), 2, "reconciliation bounded by the tracker's reads")
	w.src.answer(nil, task.Status{Effect: task.EffectNone, Authoritative: true})
	_, _ = w.tracker(l, 2).Track(bg, k, res.Operation.ID)
	c.opState(l, k, res.Operation.ID, task.OpFailed, "authoritative no-effect")
	r.Operation = w.again(r.Operation)
	_, _, err = w.attempt(l, r, accepted(asyncHandle, 0))
	c.refused(err, task.LabelBudgetExhausted, "a new attempt with max_operations 1 spent")
	c.sent(w, vmRestart, 1, "no second POST")
}

// TASK-06.cancel-mid-task: after the registry cancels the task a new
// reservation is task-cancelled; an ambiguous write sent before the
// cancellation is still reconciled, and no request is sent for it (MO-38).
func task06CancelMidTask(c *checker, w *world, l task.TaskLedger) {
	k := w.active(refRenewal, "renewal-C-481", lim(8, 5, -1, 900*time.Second))
	for i := 1; i <= 2; i++ {
		if _, _, err := w.attempt(l, crm(w, maya, agent, "renewal-C-481"), ok(100)); !c.ok(err, "read before the cancellation") {
			return
		}
	}
	w.reg.update(realm, refRenewal, func(r *task.Record) { r.State = task.StateCancelled })
	_, _, err := w.attempt(l, crm(w, maya, agent, "renewal-C-481"), ok(100))
	c.refused(err, task.LabelTaskCancelled, "read after the cancellation")
	c.state(l, k, task.StateCancelled, "after the cancellation")
	c.budget(l, k, 2, 0, 200, "after the cancellation")
	c.sent(w, crmRead, 2, "after the cancellation")

	ko := w.active(refOrder, "purchase-0098", lim(5, 5, -1, 3600*time.Second))
	res, _, err := w.attempt(l, order(w, `{"sku":"LAP-14","quantity":3}`), timedOut)
	if !c.ok(err, "an order that times out before the cancellation") {
		return
	}
	w.reg.update(realm, refOrder, func(r *task.Record) { r.State = task.StateCancelled })
	_, _, err = w.attempt(l, order(w, `{"sku":"MON-27","quantity":2}`), ok(0))
	c.refused(err, task.LabelTaskCancelled, "a new order after the cancellation")
	w.src.answer(nil, task.Status{Effect: task.EffectApplied, Authoritative: true})
	if _, err := w.tracker(l, 3).Track(bg, ko, res.Operation.ID); c.ok(err, "reconcile after the cancellation") {
		c.opState(l, ko, res.Operation.ID, task.OpSucceeded, "reconciled after the cancellation")
	}
	equal(c, w.src.count(), 1, "reconcile after the cancellation: status reads")
	c.state(l, ko, task.StateCancelled, "the order's task after reconciliation")
	c.budget(l, ko, 1, 0, -1, "the order's task after reconciliation")
	c.sent(w, orderWrite, 1, "reconciliation sends no request")
}

// TASK-06.completed-task: the I08 table rows 4 to 6.
func task06CompletedTask(c *checker, w *world, l task.TaskLedger) {
	k := w.active(refQueue, "queue-summary-run-0412", lim(8, 6, -1, 600*time.Second))
	tok := ""
	for i := 1; i <= 2; i++ {
		_, st, err := w.attempt(l, w.req(maya, agent, "queue-summary-run-0412", queuePages, w.op("GET", queueList, "", nil), tok), page(50_000, next(i+1)))
		if !c.ok(err, "page before completion") {
			return
		}
		tok = st.PageToken
	}
	w.reg.update(realm, refQueue, func(r *task.Record) { r.State = task.StateCompleted })
	_, _, err := w.attempt(l, w.req(maya, agent, "queue-summary-run-0412", queuePages, w.op("GET", queueList, "", nil), tok), page(50_000, ""))
	c.refused(err, task.LabelTaskCompleted, "row 5: page 3 of run 0412")
	c.state(l, k, task.StateCompleted, "row 4")
	c.budget(l, k, 2, 2, 100_000, "row 5")
	k2 := w.active(refQueueNext, "queue-summary-run-0413", lim(8, 6, -1, 600*time.Second))
	c.noEntry(l, k2, "row 6: before the first reservation of run 0413")
	_, _, err = w.attempt(l, w.req(maya, agent, "queue-summary-run-0413", queuePages, w.op("GET", queueList, "", nil), ""), page(50_000, ""))
	c.ok(err, "row 6: run 0413 under the reference the registry issued")
	c.budget(l, k2, 1, 1, 50_000, "row 6: new counters")
	c.budget(l, k, 2, 2, 100_000, "row 6: run 0412 unchanged")
}

// TASK-06.context-after-send: a call whose context ends after the request
// may have been sent is Unknown, and the reservation stands.
func task06ContextAfterSend(c *checker, w *world, l task.TaskLedger) {
	k := w.active(refRestart, "incident-1177", lim(1, 5, -1, 3600*time.Second))
	_, st, err := w.attempt(l, restart(w, "incident-1177"), timedOut)
	if !c.ok(err, "a restart whose call ends after the send") {
		return
	}
	equal(c, st.Operation.State, task.OpUnknown, "after the send: record")
	c.budget(l, k, 1, 0, -1, "after the send")
}

// TASK-06.context-before-send: a call that ends before the send is Released
// and the counters are restored, so the operation can be reserved again.
func task06ContextBeforeSend(c *checker, w *world, l task.TaskLedger) {
	k := w.active(refRestart, "incident-1177", lim(1, 5, -1, 3600*time.Second))
	r := restart(w, "incident-1177")
	_, st, err := w.attempt(l, r, notSent)
	if !c.ok(err, "a restart whose call ends before the send") {
		return
	}
	equal(c, st.Operation.State, task.OpReleased, "before the send: record")
	c.budget(l, k, 0, 0, -1, "before the send: counters restored")
	c.sent(w, vmRestart, 0, "before the send")
	r.Operation = w.again(r.Operation)
	res, _, err := w.attempt(l, r, accepted(asyncHandle, 0))
	if c.ok(err, "the restart reserved again with max_operations 1") {
		equal(c, res.Send, true, "reserved again: send")
	}
	c.budget(l, k, 1, 0, -1, "reserved again")
}

// TASK-06.fresh-contract-after-cancel: a registry record that reappears as
// Active does not return a cancelled task to Active.
func task06FreshContractAfterCancel(c *checker, w *world, l task.TaskLedger) {
	k := w.active(refRenewal, "renewal-C-481", lim(8, 5, -1, 900*time.Second))
	if _, _, err := w.attempt(l, crm(w, maya, agent, "renewal-C-481"), ok(100)); !c.ok(err, "read") {
		return
	}
	w.reg.update(realm, refRenewal, func(r *task.Record) { r.State = task.StateCancelled })
	_, _, err := w.attempt(l, crm(w, maya, agent, "renewal-C-481"), ok(100))
	c.refused(err, task.LabelTaskCancelled, "read after the cancellation")
	w.reg.update(realm, refRenewal, func(r *task.Record) { r.State = task.StateActive })
	_, _, err = w.attempt(l, crm(w, maya, agent, "renewal-C-481"), ok(100))
	c.refused(err, task.LabelTaskCancelled, "a fresh contract after the record reappears as Active")
	c.state(l, k, task.StateCancelled, "the first terminal state wins")
	c.budget(l, k, 1, 0, 100, "after the fresh contract")
}

// TASK-07.alias-same-reference: two client values that resolve to one
// reference share one entry and one budget; reports carry the reference;
// the same reference in another realm is another key.
func task07AliasSameReference(c *checker, w *world, l task.TaskLedger) {
	k := w.active(refRenewal, "renewal-C-481", lim(2, 5, -1, 900*time.Second))
	w.reg.alias(maya, agent, "crm:renewal/C-481", refRenewal)
	for _, alias := range []string{"renewal-C-481", "crm:renewal/C-481"} {
		res, st, err := w.attempt(l, crm(w, maya, agent, alias), ok(100))
		if !c.ok(err, "read under "+alias) {
			return
		}
		equal(c, res.Key, k, "read under "+alias+": ledger key")
		c.report(st.Report, refRenewal, core.EventExecution, core.OutcomeSuccess, core.DimensionReliability, "read under "+alias+": report")
	}
	_, _, err := w.attempt(l, crm(w, maya, agent, "renewal-C-481"), ok(100))
	c.refused(err, task.LabelBudgetExhausted, "third read, max_operations 2 shared by both values")
	c.budget(l, k, 2, 0, 200, "one entry for both values")

	w.reg.put(otherRealm, task.Record{Ref: refRenewal, State: task.StateActive, Limits: lim(2, 5, -1, 900*time.Second)})
	w.reg.alias(mayaSouth, agent, "renewal-C-481", refRenewal)
	ko := task.Key{Realm: otherRealm, Task: refRenewal}
	res, _, err := w.attempt(l, crm(w, mayaSouth, agent, "renewal-C-481"), ok(100))
	if c.ok(err, "the same reference in another realm") {
		equal(c, res.Key, ko, "another realm: ledger key")
	}
	c.budget(l, ko, 1, 0, 100, "another realm")
	c.budget(l, k, 2, 0, 200, "the first realm unchanged")
}

// TASK-07.unknown-reference: a reference with no registry record is
// task-unknown and makes no entry.
func task07UnknownReference(c *checker, w *world, l task.TaskLedger) {
	k := w.active(refQueue, "queue-summary-run-0412", lim(8, 6, -1, 600*time.Second))
	w.reg.alias(maya, agent, "queue-summary-run-0413", refQueueNext)
	if _, _, err := w.attempt(l, w.req(maya, agent, "queue-summary-run-0412", queuePages, w.op("GET", queueList, "", nil), ""), page(50_000, "")); !c.ok(err, "page 1 of run 0412") {
		return
	}
	_, _, err := w.attempt(l, w.req(maya, agent, "queue-summary-run-0413", queuePages, w.op("GET", queueList, "", nil), ""), page(50_000, ""))
	c.refused(err, task.LabelTaskUnknown, "run 0413, not yet started")
	c.noEntry(l, task.Key{Realm: realm, Task: refQueueNext}, "run 0413")
	c.budget(l, k, 1, 1, 50_000, "run 0412 unchanged")
	c.sent(w, queuePages, 1, "after the refusal")
}

// TASK-07.unreconciled-id: a client value that resolves to no reference or
// to more than one is task-mismatch; an unavailable registry is
// DEPENDENCY_UNAVAILABLE; no counter changes.
func task07UnreconciledID(c *checker, w *world, l task.TaskLedger) {
	k := w.active(refRenewal, "renewal-C-481", lim(8, 5, -1, 900*time.Second))
	w.active(refOrder, "purchase-0098", lim(8, 5, -1, 900*time.Second))
	w.reg.alias(maya, agent, "my-current-task", refRenewal, refOrder)
	if _, _, err := w.attempt(l, crm(w, maya, agent, "renewal-C-481"), ok(100)); !c.ok(err, "read") {
		return
	}
	_, _, err := w.attempt(l, crm(w, maya, agent, "renewal-for-acme"), ok(100))
	c.refused(err, task.LabelTaskMismatch, "a value that resolves to no reference")
	_, _, err = w.attempt(l, crm(w, maya, agent, "my-current-task"), ok(100))
	c.refused(err, task.LabelTaskMismatch, "a value that resolves to two references")
	w.reg.setDown(true)
	_, _, err = w.attempt(l, crm(w, maya, agent, "renewal-C-481"), ok(100))
	equal(c, errors.Is(err, adapter.ErrDependencyUnavailable), true, "registry unavailable: DEPENDENCY_UNAVAILABLE")
	w.reg.setDown(false)
	c.budget(l, k, 1, 0, 100, "after the refusals")
	c.noEntry(l, task.Key{Realm: realm, Task: refOrder}, "the other task")
	c.sent(w, crmRead, 1, "after the refusals")
}

// TASK-07.terminal-no-entry: a task the ledger has no entry for and whose
// state is terminal is refused with the label of its state, code TASK_LIMIT,
// and makes no entry; task-unknown is only for a reference the registry has
// no record of (MO-6, MO-62).
func task07TerminalNoEntry(c *checker, w *world, l task.TaskLedger) {
	for _, end := range []struct {
		ref   task.Ref
		alias string
		state task.State
		label task.Label
	}{
		{refQueue, "queue-summary-run-0412", task.StateCompleted, task.LabelTaskCompleted},
		{refRenewal, "renewal-C-481", task.StateCancelled, task.LabelTaskCancelled},
	} {
		k := w.active(end.ref, end.alias, lim(8, 6, -1, 600*time.Second))
		w.reg.update(realm, end.ref, func(r *task.Record) { r.State = end.state })
		_, _, err := w.attempt(l, crm(w, maya, agent, end.alias), ok(100))
		c.refused(err, end.label, "a "+string(end.state)+" task with no entry")
		c.noEntry(l, k, "a "+string(end.state)+" task with no entry")
	}
	k := w.active(refOrder, "purchase-0098", lim(8, 6, -1, 600*time.Second))
	w.clk.Set(t0.Add(600 * time.Second))
	_, _, err := w.attempt(l, crm(w, maya, agent, "purchase-0098"), ok(100))
	c.refused(err, task.LabelDeadlineElapsed, "a task past its deadline with no entry")
	c.noEntry(l, k, "a task past its deadline with no entry")
	c.sent(w, crmRead, 0, "after the refusals")
}

// TASK-07.other-principal: the binding of the entry is that of its first
// reservation; another principal, workload or agent is task-mismatch; a
// refreshed credential with the same identifiers is the same binding.
func task07OtherPrincipal(c *checker, w *world, l task.TaskLedger) {
	k := w.active(refRenewal, "renewal-C-481", lim(8, 5, -1, 900*time.Second))
	w.reg.alias(omar, agent, "renewal-C-481", refRenewal)
	w.reg.alias(maya, otherAgent, "renewal-C-481", refRenewal)
	if _, _, err := w.attempt(l, crm(w, maya, agent, "renewal-C-481"), ok(100)); !c.ok(err, "row 1: read with token t1") {
		return
	}
	refreshed := maya
	refreshed.AuthenticatedAt = t0.Add(10 * time.Minute)
	refreshed.Mechanism = "bearer-refreshed"
	_, _, err := w.attempt(l, crm(w, refreshed, agent, "renewal-C-481"), ok(100))
	c.ok(err, "row 2: token refreshed, same principal and client")
	_, _, err = w.attempt(l, crm(w, omar, agent, "renewal-C-481"), ok(100))
	c.refused(err, task.LabelTaskMismatch, "row 3: token of another user")
	otherWorkload := maya
	otherWorkload.Workload = "client:batch-exporter"
	_, _, err = w.attempt(l, crm(w, otherWorkload, agent, "renewal-C-481"), ok(100))
	c.refused(err, task.LabelTaskMismatch, "another workload")
	_, _, err = w.attempt(l, crm(w, maya, otherAgent, "renewal-C-481"), ok(100))
	c.refused(err, task.LabelTaskMismatch, "another agent")
	c.budget(l, k, 2, 0, 200, "after the refusals")
	c.sent(w, crmRead, 2, "after the refusals")
}

// TASK-07.swap-between-calls: changing Intent.task_id between pages changes
// nothing when the value resolves to the same reference.
func task07SwapBetweenCalls(c *checker, w *world, l task.TaskLedger) {
	k := w.active(refMailbox, "mailbox-summary", lim(12, 5, -1, 1800*time.Second))
	w.reg.alias(maya, agent, "mail:summary/0731", refMailbox)
	tok := ""
	for i, alias := range []string{"mailbox-summary", "mail:summary/0731", "mailbox-summary"} {
		res, st, err := w.attempt(l, mail(w, alias, mailInbox, tok), page(1000, next(i+2)))
		if !c.ok(err, "page under "+alias) {
			return
		}
		equal(c, res.Key, k, "page under "+alias+": ledger key")
		tok = st.PageToken
	}
	c.budget(l, k, 3, 3, 3000, "one budget across the values")
}

// TASK-08.deadline-elapsed: at the deadline a reservation is refused and the
// task is Expired; the deadline is the earlier of the registry's and the
// authority's.
func task08DeadlineElapsed(c *checker, w *world, l task.TaskLedger) {
	k := w.active(refRenewal, "renewal-C-481", lim(8, 5, -1, 600*time.Second))
	k2 := w.active(refOrder, "purchase-0098", lim(8, 5, -1, 3600*time.Second))
	w.reg.update(realm, refOrder, func(r *task.Record) { r.AuthorityExpires = t0.Add(300 * time.Second) })
	if _, _, err := w.attempt(l, crm(w, maya, agent, "renewal-C-481"), ok(100)); !c.ok(err, "read at the start") {
		return
	}
	if _, _, err := w.attempt(l, crm(w, maya, agent, "purchase-0098"), ok(100)); !c.ok(err, "read of the second task at the start") {
		return
	}
	w.clk.Set(t0.Add(300 * time.Second))
	_, _, err := w.attempt(l, crm(w, maya, agent, "purchase-0098"), ok(100))
	c.refused(err, task.LabelDeadlineElapsed, "at the expiry of the authority, before the registry deadline")
	_, _, err = w.attempt(l, crm(w, maya, agent, "renewal-C-481"), ok(100))
	c.ok(err, "the first task before its deadline")
	w.clk.Set(t0.Add(600 * time.Second))
	_, _, err = w.attempt(l, crm(w, maya, agent, "renewal-C-481"), ok(100))
	c.refused(err, task.LabelDeadlineElapsed, "at the deadline")
	c.state(l, k, task.StateExpired, "at the deadline")
	c.state(l, k2, task.StateExpired, "at the expiry of the authority")
	c.budget(l, k, 2, 0, 200, "at the deadline")
	c.budget(l, k2, 1, 0, 100, "at the expiry of the authority")
}

// TASK-08.just-before-deadline: one second before the deadline a
// reservation is admitted.
func task08JustBeforeDeadline(c *checker, w *world, l task.TaskLedger) {
	k := w.active(refRenewal, "renewal-C-481", lim(8, 5, -1, 600*time.Second))
	w.clk.Set(t0.Add(599 * time.Second))
	_, _, err := w.attempt(l, crm(w, maya, agent, "renewal-C-481"), ok(100))
	c.ok(err, "one second before the deadline")
	c.state(l, k, task.StateActive, "one second before the deadline")
	c.budget(l, k, 1, 0, 100, "one second before the deadline")
}

// TASK-08.status-after-deadline: an operation already sent keeps its status
// tracking after the deadline, while a new reservation is refused.
func task08StatusAfterDeadline(c *checker, w *world, l task.TaskLedger) {
	k, res, _, good := acceptRestart(c, w, l, lim(2, 5, -1, 600*time.Second), 10*time.Second)
	if !good {
		return
	}
	r2 := restart(w, "incident-1177")
	r2.Operation.TargetURI += "?second"
	res2, st2, err := w.attempt(l, r2, timedOut)
	if !c.ok(err, "a second restart that times out before the deadline") {
		return
	}
	equal(c, st2.Operation.State, task.OpUnknown, "second restart: record")
	w.clk.Set(t0.Add(700 * time.Second))
	w.src.answer(nil, task.Status{Effect: task.EffectApplied})
	st, err := w.tracker(l, 3).Track(bg, k, res.Operation.ID)
	if c.ok(err, "status read after the deadline") {
		c.report(st.Report, refRestart, core.EventExecution, core.OutcomeSuccess, core.DimensionReliability, "completion after the deadline")
	}
	equal(c, w.src.count(), 1, "status reads after the deadline")
	c.opState(l, k, res.Operation.ID, task.OpSucceeded, "after the deadline")

	// Reconciliation learns the outcome after the deadline and sends nothing
	// (MO-38).
	w.src.answer(nil, task.Status{Effect: task.EffectApplied, Authoritative: true})
	if _, err := w.tracker(l, 3).Track(bg, k, res2.Operation.ID); c.ok(err, "reconcile after the deadline") {
		c.opState(l, k, res2.Operation.ID, task.OpSucceeded, "reconciled after the deadline")
	}
	equal(c, w.src.count(), 2, "status reads after the reconciliation")

	r := restart(w, "incident-1177")
	r.Operation.TargetURI += "?third"
	_, _, err = w.attempt(l, r, accepted(asyncHandle, 0))
	c.refused(err, task.LabelDeadlineElapsed, "a new restart after the deadline")
	c.sent(w, vmRestart, 2, "after the deadline: no request sent")
	c.budget(l, k, 2, 0, -1, "after the deadline")
}

// TASK-09.approval-other-task: an approval bound to another native task is
// APPROVAL_SCOPE_MISMATCH, even while pending; the check makes no entry.
func task09ApprovalOtherTask(c *checker, w *world, l task.TaskLedger) {
	k := w.active(refRestart, "incident-1177", lim(1, 5, -1, 3600*time.Second))
	k2 := w.active(refOrder, "purchase-0098", lim(1, 5, -1, 3600*time.Second))
	r := restart(w, "incident-1177")
	check := func(a task.Approval, want adapter.Verdict, code, what string) {
		o := task.CheckApprovalTask(bg, l, a, r)
		equal(c, o.Result, want, what+": result")
		equal(c, o.ReasonCode, code, what+": reason_code")
	}
	check(task.Approval{Task: refOrder}, adapter.VerdictFail, "APPROVAL_SCOPE_MISMATCH", "approval of another task")
	check(task.Approval{Task: refOrder, Pending: true}, adapter.VerdictFail, "APPROVAL_SCOPE_MISMATCH", "pending approval of another task")
	check(task.Approval{Task: refRestart}, adapter.VerdictPass, "REQUIREMENT_SATISFIED", "approval of this task")
	w.reg.setDown(true)
	check(task.Approval{Task: refRestart}, adapter.VerdictUnknown, "DEPENDENCY_UNAVAILABLE", "registry unavailable")
	w.reg.setDown(false)
	c.noEntry(l, k, "after the checks")
	c.noEntry(l, k2, "after the checks")
}

// TASK-09.late-approval-no-reset: an approval that arrives after the task is
// Expired supports a fresh evaluation and does not revive the task.
func task09LateApprovalNoReset(c *checker, w *world, l task.TaskLedger) {
	k := w.active(refRenewal, "renewal-C-481", lim(2, 5, -1, 600*time.Second))
	r := crm(w, maya, agent, "renewal-C-481")
	if _, _, err := w.attempt(l, r, ok(100)); !c.ok(err, "read") {
		return
	}
	w.clk.Set(t0.Add(600 * time.Second))
	_, _, err := w.attempt(l, crm(w, maya, agent, "renewal-C-481"), ok(100))
	c.refused(err, task.LabelDeadlineElapsed, "at the deadline")
	w.reg.update(realm, refRenewal, func(rec *task.Record) {
		rec.Limits.Deadline = t0.Add(7200 * time.Second)
		rec.Limits.MaxOperations = task.Bounded(10)
	})
	o := task.CheckApprovalTask(bg, l, task.Approval{Task: refRenewal}, r)
	equal(c, o.Result, adapter.VerdictPass, "the late approval supports a fresh evaluation")
	_, _, err = w.attempt(l, crm(w, maya, agent, "renewal-C-481"), ok(100))
	c.refused(err, task.LabelDeadlineElapsed, "a fresh contract after the late approval")
	c.state(l, k, task.StateExpired, "after the late approval")
	c.budget(l, k, 1, 0, 100, "after the late approval")
}

// TASK-09.pending-reserves-nothing: a pending approval reserves nothing and
// the deadline keeps running while it is pending.
func task09PendingReservesNothing(c *checker, w *world, l task.TaskLedger) {
	k := w.active(refRestart, "incident-1177", lim(1, 5, -1, 3600*time.Second))
	k2 := w.active(refOrder, "purchase-0098", lim(1, 5, -1, 600*time.Second))
	r := restart(w, "incident-1177")
	r2 := order(w, `{"sku":"LAP-14","quantity":3}`)
	o := task.CheckApprovalTask(bg, l, task.Approval{Task: refRestart, Pending: true}, r)
	equal(c, o.Result, adapter.VerdictUnknown, "row 1: activation pending: result")
	equal(c, o.ReasonCode, "APPROVAL_PENDING", "row 1: activation pending: reason_code")
	o = task.CheckApprovalTask(bg, l, task.Approval{Task: refOrder, Pending: true}, r2)
	equal(c, o.ReasonCode, "APPROVAL_PENDING", "the order's approval pending")
	c.noEntry(l, k, "row 1: nothing reserved")
	c.noEntry(l, k2, "the order: nothing reserved")

	w.clk.Advance(30 * time.Minute)
	o = task.CheckApprovalTask(bg, l, task.Approval{Task: refRestart}, r)
	equal(c, o.Result, adapter.VerdictPass, "row 2: activation complete")
	_, _, err := w.attempt(l, r, accepted(asyncHandle, 0))
	c.ok(err, "row 2: reserved after the activation")
	c.budget(l, k, 1, 0, -1, "row 2")
	_, _, err = w.attempt(l, r2, ok(0))
	c.refused(err, task.LabelDeadlineElapsed, "the order approved after its deadline passed while pending")
}
