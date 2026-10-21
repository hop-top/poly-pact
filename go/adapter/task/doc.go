// Package task is the task ledger of the multi-operation profile
// (spec/v1.0/profiles/multi-operation.md): the gateway's memory of a native task
// across the admissions, contracts and downstream requests made for it.
//
// Every admission uses a new contract, a new presentation and a new receipt
// (PACT draft Sections 11.3 and 11.5), and native systems keep budget and
// idempotency enforcement (Section 10.3). The ledger is that enforcement on
// the gateway side. It acts at execution, after the attestation is consumed
// and authorize_native allowed the operation, and before the downstream
// request is sent (profile section 3.3). It adds no wire field and no check
// identifier.
//
// # Pieces
//
//   - [TaskLedger] is the ledger: one entry per native task, keyed by the
//     realm and the native task reference ([Key], rule MO-1), never by the
//     client's Intent.task_id, which is advisory and reconciled through the
//     task [Registry] (MO-3, draft Section 10.1). [Memory] is its in-memory
//     implementation.
//   - [Budget] is the limits and counters of a task (section 5): operations,
//     pages, bytes and the deadline. A fresh contract, presentation, nonce,
//     operation_id, token or receipt does not reset it (MO-20).
//   - [IdempotencyStore] holds the idempotency keys of the logical operations
//     of a task (section 6, MO-26 to MO-30).
//   - [AsyncTracker] reads the status of an accepted or ambiguous operation
//     with bounded attempts until it is terminal (sections 7 and 8).
//   - [Pager] is the hook that checks a next link before the ledger records
//     it as a continuation bound to the task (section 10, RB-57, RB-58).
//   - [CheckApprovalTask] is the task part of an approval-class check: the
//     approval is bound to the native task (MO-9, draft Section 17.3.1).
//
// # Refusals
//
// A reservation the ledger declines returns a *[Refusal] carrying one of the
// labels of rule MO-11. The labels budget-exhausted, deadline-elapsed,
// task-cancelled and task-completed are answered with TASK_LIMIT (403, draft
// Section 13.4): the refusal wraps [ErrTaskLimit]. The other labels have no
// code of draft Section 13.4. A continuation of another task, principal,
// agent, row or mapping version is refused with
// [adapter.ErrContextMismatch] before any reservation (MO-56). A registry or
// ledger that cannot answer is [adapter.ErrDependencyUnavailable]; a missing
// entry never means a fresh budget (MO-24).
package task
