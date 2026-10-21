package task_test

import (
	"fmt"
	"slices"
	"testing"

	"hop.top/pact-go/adapter/task"
)

// The ledger under test.
var underTest factory = memoryLedger

// runCase runs one case against a fresh world and ledger and returns its
// failures. A panic is a failure.
func runCase(tc taskCase, f factory) (failures []string) {
	defer func() {
		if p := recover(); p != nil {
			failures = append(failures, fmt.Sprintf("panic: %v", p))
		}
	}()
	w := newWorld()
	c := &checker{}
	tc.run(c, w, f(w))
	return c.failures
}

// evaluate runs every case against f and returns the failures by case id.
func evaluate(f factory) map[string][]string {
	out := map[string][]string{}
	for _, tc := range cases {
		out[tc.id] = runCase(tc, f)
	}
	return out
}

// TestTaskCases runs the TASK cases against the ledger under test.
func TestTaskCases(t *testing.T) {
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			for _, f := range runCase(tc, underTest) {
				t.Errorf("%s (%s): %s", tc.id, tc.rules, f)
			}
		})
	}
}

// The ids of profile section 15.1, family by family, as the profile lists
// the variants.
var plannedIDs = map[string][]string{
	"TASK-01": {"max-operations", "max-bytes", "registry-lowered-limit"},
	"TASK-02": {"keyed-write", "restart-dedupe", "key-other-payload", "key-other-task"},
	"TASK-03": {"accepted-not-completed", "succeeded", "failed", "cancelled", "poll-exhausted", "handle-other-origin", "tracking-forbidden"},
	"TASK-04": {"other-task", "beyond-max-pages", "listing-restart", "unknown-token", "expired-task"},
	"TASK-05": {"timeout-reconcile", "status-indeterminate", "restart-timeout"},
	"TASK-06": {"cancel-mid-task", "completed-task", "context-after-send", "context-before-send", "fresh-contract-after-cancel"},
	"TASK-07": {"alias-same-reference", "unknown-reference", "unreconciled-id", "other-principal", "swap-between-calls", "terminal-no-entry"},
	"TASK-08": {"deadline-elapsed", "just-before-deadline", "status-after-deadline"},
	"TASK-09": {"approval-other-task", "late-approval-no-reset", "pending-reserves-nothing"},
}

// TestCaseIDs: the cases are exactly the planned cases of the profile, one
// per variant.
func TestCaseIDs(t *testing.T) {
	var want, got []string
	for fam, variants := range plannedIDs {
		for _, v := range variants {
			want = append(want, fam+"."+v)
		}
	}
	for _, tc := range cases {
		got = append(got, tc.id)
		if tc.rules == "" {
			t.Errorf("%s: no rules cited", tc.id)
		}
	}
	slices.Sort(want)
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Errorf("case ids:\n got %v\nwant %v", got, want)
	}
}

// The client-keyed mutant must fail these cases, each because it counts by
// the client value (profile section 15.1: a stub keyed on the client task_id
// fails TASK-01 and TASK-07).
var mutantFails = []string{"TASK-01.max-operations", "TASK-01.max-bytes", "TASK-07.alias-same-reference", "TASK-07.swap-between-calls"}

// The mutant passes these: it is a working ledger but for its key.
var mutantPasses = []string{"TASK-01.registry-lowered-limit", "TASK-07.unknown-reference", "TASK-07.unreconciled-id", "TASK-07.other-principal", "TASK-07.terminal-no-entry"}

// TestClientKeyedLedgerFailsTask01And07 runs TASK-01 and TASK-07 against a
// ledger keyed on the client task_id.
func TestClientKeyedLedgerFailsTask01And07(t *testing.T) {
	res := evaluate(clientKeyedLedger)
	for _, id := range mutantFails {
		if len(res[id]) == 0 {
			t.Errorf("%s: the client-keyed ledger passes it", id)
		}
	}
	for _, id := range mutantPasses {
		if f := res[id]; len(f) != 0 {
			t.Errorf("%s: the client-keyed ledger was expected to pass it: %v", id, f)
		}
	}
	for _, fam := range []string{"TASK-01", "TASK-07"} {
		failed := false
		for _, v := range plannedIDs[fam] {
			failed = failed || len(res[fam+"."+v]) > 0
		}
		if !failed {
			t.Errorf("%s: the client-keyed ledger passes every variant", fam)
		}
	}
}

// TestRefusalCode: the limit labels wrap ErrTaskLimit (MO-11, draft 13.4).
func TestRefusalCode(t *testing.T) {
	for _, l := range []task.Label{
		task.LabelTaskUnknown, task.LabelTaskMismatch, task.LabelTaskCompleted, task.LabelTaskCancelled,
		task.LabelDeadlineElapsed, task.LabelBudgetExhausted, task.LabelOperationInFlight,
		task.LabelOutcomeUnknown, task.LabelIdempotencyConflict,
	} {
		c := &checker{}
		c.refused(&task.Refusal{Label: l}, l, string(l))
		for _, f := range c.failures {
			t.Error(f)
		}
	}
}
