package task

import (
	"errors"

	"hop.top/pact-go/adapter"
)

// CodeTaskLimit is the draft Section 13.4 code of a protected request refused
// because its native task has no budget left, is cancelled or completed, or
// is past its deadline (HTTP 403).
const CodeTaskLimit adapter.Code = "TASK_LIMIT"

type codeError struct {
	code adapter.Code
	text string
}

func (e *codeError) Error() string { return "task: " + e.text }

// Code returns the draft Section 13.4 code of the error.
func (e *codeError) Code() adapter.Code { return e.code }

var (
	// ErrTaskLimit is the TASK_LIMIT error (draft Section 13.4). A
	// [Refusal] labelled budget-exhausted, deadline-elapsed, task-cancelled
	// or task-completed wraps it (MO-11), so [adapter.CodeOf] reads
	// [CodeTaskLimit] from it.
	ErrTaskLimit error = &codeError{CodeTaskLimit, "the native task has no budget left, is cancelled or completed, or is past its deadline"}

	// ErrNoRecord: the registry has no record of the reference. The ledger
	// refuses it with task-unknown (MO-6).
	ErrNoRecord = errors.New("task: the registry has no record of the reference")

	// ErrNoEntry: the ledger has no entry for the key. It never means a
	// fresh budget (MO-24).
	ErrNoEntry = errors.New("task: the ledger has no entry for the task")
)

// Label is a refusal label of the ledger (MO-11). The labels are those of
// the profile for fixtures and logs, not reason codes of the draft.
type Label string

const (
	LabelTaskUnknown         Label = "task-unknown"
	LabelTaskMismatch        Label = "task-mismatch"
	LabelTaskCompleted       Label = "task-completed"
	LabelTaskCancelled       Label = "task-cancelled"
	LabelDeadlineElapsed     Label = "deadline-elapsed"
	LabelBudgetExhausted     Label = "budget-exhausted"
	LabelOperationInFlight   Label = "operation-in-flight"
	LabelOutcomeUnknown      Label = "outcome-unknown"
	LabelIdempotencyConflict Label = "idempotency-conflict"
)

// TaskLimit reports whether the label is answered with TASK_LIMIT (MO-11).
func (l Label) TaskLimit() bool {
	switch l {
	case LabelBudgetExhausted, LabelDeadlineElapsed, LabelTaskCancelled, LabelTaskCompleted:
		return true
	}
	return false
}

// Refusal is the error of a reservation the ledger declines. It is a native
// control, not a PACT decision.
type Refusal struct {
	Label Label
	// Operation is the record a repeat was answered from, for
	// operation-in-flight and outcome-unknown (MO-31); zero otherwise.
	Operation Operation
}

func (r *Refusal) Error() string { return "task: refused: " + string(r.Label) }

// Unwrap returns [ErrTaskLimit] for a limit label and nil otherwise.
func (r *Refusal) Unwrap() error {
	if r.Label.TaskLimit() {
		return ErrTaskLimit
	}
	return nil
}
