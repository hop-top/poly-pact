package task

import (
	"context"
	"errors"

	"hop.top/pact-go/adapter"
)

// Approval is what a native approval record establishes about the task of
// an approval-class check.
type Approval struct {
	// Task is the native task the approval names, read from the native
	// approval record (MO-9).
	Task Ref
	// Pending is true when a legitimate request for this exact scope is open
	// and undecided (draft Section 17.3.1).
	Pending bool
}

// CheckApprovalTask is the task part of an approval-class check (MO-9, draft
// Section 17.3.1): it reconciles the task of req through l and compares it
// with the task of the approval. An approval of another native task is FAIL
// with APPROVAL_SCOPE_MISMATCH; a pending approval of this task is UNKNOWN
// with APPROVAL_PENDING; an approval of this task is PASS with
// REQUIREMENT_SATISFIED; a registry that cannot answer is UNKNOWN with
// DEPENDENCY_UNAVAILABLE. It reserves nothing and makes no entry (MO-6,
// MO-10).
//
// An approval record that names no task is FAIL with MISSING_FIELD (the
// required reference is absent). A request whose task_id reconciles to no
// single native task cannot be the task of any approval: FAIL with
// APPROVAL_SCOPE_MISMATCH.
func CheckApprovalTask(ctx context.Context, l TaskLedger, a Approval, req Request) adapter.CheckOutcome {
	out := func(v adapter.Verdict, code string) adapter.CheckOutcome {
		return adapter.CheckOutcome{Result: v, ReasonCode: code}
	}
	if l == nil {
		return out(adapter.VerdictUnknown, string(adapter.CodeDependencyUnavailable))
	}
	k, err := l.Resolve(ctx, req)
	var r *Refusal
	switch {
	case errors.As(err, &r) && r.Label == LabelTaskMismatch:
		return out(adapter.VerdictFail, "APPROVAL_SCOPE_MISMATCH")
	case err != nil:
		return out(adapter.VerdictUnknown, string(adapter.CodeDependencyUnavailable))
	case a.Task == "":
		return out(adapter.VerdictFail, string(adapter.CodeMissingField))
	case a.Task != k.Task:
		return out(adapter.VerdictFail, "APPROVAL_SCOPE_MISMATCH")
	case a.Pending:
		return out(adapter.VerdictUnknown, "APPROVAL_PENDING")
	}
	return out(adapter.VerdictPass, "REQUIREMENT_SATISFIED")
}
