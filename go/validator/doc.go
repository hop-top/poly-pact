// Package validator is the PACT admission validator: the algorithm of draft
// Section 11.3, the decisions of Section 11.4 and the receipts and state
// machine of Section 12, for a gateway that evaluates in its own request path
// or as a trusted sidecar (draft 4.4).
//
// # Evaluating
//
// Validator.Evaluate takes the signed presentation, the actual operation
// the gateway mapped from the request and the principal native
// authentication established (draft 13.2, evaluate; 17.1). Before an
// authenticated evaluation it applies, as transport checks that give no
// receipt (draft 12.2): native authentication; the presentation's size,
// strict parsing, typ and signature; the enrolled agent/key binding (an
// agent the workload has no record of, a revoked binding or a key that is not
// the enrolled one is INVALID_PROOF, an agent enrolled for another workload
// CONTEXT_MISMATCH); the publisher's signature and validity window of the
// embedded contract; the presentation's time bounds (EXPIRED); and the atomic
// consumption of the contract's nonce (REPLAY, or REQUIREMENTS_CHANGED when
// the contract was already sealed stale). The error then carries the draft
// 13.4 code, which adapter.CodeOf reads and ProblemOf turns into the RFC 9457
// transport error.
//
// An authenticated evaluation records every check in a CheckResult, in the
// order of the table of draft 12.1: native-authentication,
// agent-holder-binding, contract-validity, nonce, operation-binding,
// intent-binding, profile-validity, evidence-validity, reputation-context
// (when a snapshot is presented), security-hold, active-policy and
// receipt-store (when the receipt could not be recorded); then each field
// rule by its rule_id and each of the contract's context_checks, in contract
// order, each exactly once. A check that was not performed is never PASS: a field rule
// or context check the evaluation did not reach is UNKNOWN with
// NOT_EVALUATED (draft 12.1). Field rules apply the restricted schema keyword
// set of Appendix A.1, where any other keyword is UNKNOWN with
// UNSUPPORTED_REQUIREMENT, and compare the presented value with its
// authority: an evidence claim within its issuer's claim paths, the
// reputation snapshot value, or the native value read_native_claim returns
// (draft 8.4, 8.5). A rule on a snapshot value is observed at the snapshot's
// iat and status-checked by the evaluation's own security-hold check
// (Appendix A.2). When the pinned Selector is installed, contract-validity
// compares the contract's field_rules and context_checks with its table for
// the selected set (draft 11.3 step 3). The validator applies the published rules and nothing
// else; it never replaces them with a judgment of its own.
//
// Context checks run through the adapter's check_context with the principal
// and the binding this evaluation established, except the two the validator
// evaluates from what it holds: native-principal-binding-v1 (draft 17.5) and
// selection-consistency-v1 (draft 11.3 step 9), which re-derives the
// contract's set with its pinned Selector from the presented snapshot and
// from the gateway's own current input and fails with
// SELECTION_INPUT_CHANGED when either yields a stricter set. A check the
// gateway did not install is UNKNOWN.
//
// # Decisions and stores
//
// Decide is draft 11.4: a FAIL is INADMISSIBLE, except the stale-contract
// reasons SELECTION_INPUT_CHANGED and REQUIREMENTS_CHANGED, which defer;
// otherwise an UNKNOWN is DEFERRED; only results that are all PASS or
// NOT_APPLICABLE are ADMISSIBLE. A cancelled or expired evaluation is
// DEFERRED (draft 12.2).
//
// Every store is an interface the gateway implements: contract.ReplayStore,
// ReceiptStore, HoldStore, PolicyRegistry and StatusChecker. A store that
// cannot answer makes the check that needs it UNKNOWN, which defers; it never
// admits (draft 18). Before a positive result the validator checks again that
// the contract is active, no hold is in force and the binding stands
// (draft 11.3 step 10), and it records the receipt before it returns it: a
// receipt store that cannot record an ADMISSIBLE receipt turns it into a
// DEFERRED one with the check receipt-store UNKNOWN.
//
// # Time
//
// The Clock is the only source of time. The evaluation deadline is the
// earliest of the contract's and the presentation's exp and the start plus
// Config.EvaluationTime, at most 30 seconds (draft 12.2). Cancelling the
// context passed to Evaluate cancels the evaluation; a native read still
// outstanding at cancellation or at the deadline was not performed, and the
// receipt is DEFERRED with terminal reason CANCELLED or EXPIRED, sealed at
// that instant. A receipt expires at most 60 seconds after issuance and, when
// ADMISSIBLE, no later than its presentation, contract, profile, evidence and
// snapshot (draft 12.1). Next is the transition table of draft 12.2; each
// evaluation moves through it once, and a terminal state never changes.
//
// # Handoff
//
// Handoff is the gateway's check of a sidecar validator's attestation
// (draft 11.5): signature, audience, realm, principal, operation digest,
// positive enforced decision and expiry, then an atomic single consumption.
//
// The package is standard library and hop.top/pact-go packages only.
package validator
