// Package conformance drives the reference validator of package
// hop.top/pact-go/validator over the evaluation cases of spec/v1.0/fixtures: it is
// the implementation side of the evaluate and receipt verbs of the
// conformance runner's adapter contract (package hop.top/pact-go/runner).
//
// Evaluate reads a case directory with package
// hop.top/pact-go/runner/evalcase, builds the gateway the case describes and
// prints one line per response: the compact receipt of each submission, or
// the RFC 9457 Problem of a request rejected before an authenticated
// evaluation, then one line per handoff attempt. It never reads the case's
// expected results. Receipt prints a receipt an earlier Evaluate recorded in
// its state file.
//
// The gateway of a case is built from its files as follows:
//
//   - config.json is the validator's trusted configuration: the trust
//     records, the validator's key (whose private value is the published
//     test scalar of keys/test-private-scalars.json), the native mappings
//     with their declared source capabilities, the installed checks, the
//     active policy and the selection;
//   - native_context.json is the native state of an in-memory adapter of
//     package hop.top/pact-go/adapters/memory: the enrollment of the
//     authenticated workload, the native claims, and the native state of
//     each installed check, mapped to its verdict by the rules of draft
//     17.3.1 (native-approval-v1) and 17.5 (native-delegation-v1,
//     execution-identity-v1), with the source ages of the fixture README;
//   - the replay store is a contract.MemoryReplay in which the gateway's
//     publisher registered the nonce of every contract the case presents,
//     shared by the replicas and by the exchanges of a sequence, and the
//     receipts are kept in a validator.MemoryReceipts;
//   - exchange.json says what does not answer and when native reads
//     complete; the clock is a clock.Fake held at each submission's start.
//
// The purpose mapping of purpose-operation-v1, the reputation context
// mapping of the actual operation and the accepted scoring-policy revisions
// are config.json's purposes, reputation_context and
// active_policy.scoring_policy_revisions, whose defaults are the Appendix B
// values (B.2, B.3, B.6); the authorized context checks of a selector's set
// are selection.selector.checks, by default the contract's own.
package conformance
