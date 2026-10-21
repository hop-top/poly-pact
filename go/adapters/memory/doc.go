// Package memory is the in-memory reference adapter: the seven functions of
// draft 17.1 over native stores that live in process memory and are built from
// a document, with no network and no files.
//
// It is the baseline of the conformance suite in package adaptertest. It passes
// every common case, and it is written from the draft and the invariants the
// draft cites, not from the cases: a case that disagrees with it is as likely to
// be wrong as the adapter. Package hop.top/pact-go/adapters/internal/broken wraps
// it with deliberate defects to show the suite can fail.
//
// # Native state
//
// An adapter is built from a [State], the neutral "common/1" model that the
// common cases state their native state in: the gateway's trusted
// configuration, the installed operation mappings, an identity store of bearer
// tokens, an enrollment source, approved claim paths and their values, installed
// checks with their verdicts, an authorization policy, and the signer of outcome
// reports. [ParseState] reads it strictly from JSON and [New] builds the
// adapter over it. The clock passed to New is the adapter's only source of the
// current time.
//
// # What it does
//
//   - AuthenticateNative: the bearer token of the Authorization header decides.
//     Identity headers such as X-User are ignored, and a request that did not
//     pass through the enforcement point, marked with [Arrive], is refused.
//   - ResolveAgentBinding: looked up by realm, workload and agent ID together,
//     so the agent ID selects among the records of the workload only. A
//     binding that is revoked or compromised is returned as that status, with
//     the agent, operator and holder key of the record and no error (identity
//     mapping IM-11); an agent with no record on the workload in the realm
//     has status UNKNOWN, whatever other agents share the workload, and
//     EnrolledElsewhere says whether it has a record on another workload of
//     the realm (draft 17.1). By default a workload serves one agent, and a
//     workload with more than one enrollment in force is a configuration
//     error, UNSUPPORTED_REQUIREMENT with no binding, whichever agent the
//     request names (identity mapping IM-19); [WithSharedWorkloads] builds
//     the adapter of a profile whose workloads several agents may share.
//   - MapOperation: the baseline HTTP mapping of draft 10.2, by package binding.
//     A request it refuses, such as one with a fragment, userinfo, a content
//     encoding or an ambiguous encoding, is an ErrInvalidMessage error.
//   - ReadNativeClaim: only approved paths, per realm and principal, with the
//     times the source gives and never the time of the read. A fact of a
//     resource is read only for a resource of the operation in the claim
//     context, and a fact of a task only for the task of its intent.
//   - CheckContext: an exact match on the check id; anything else is UNKNOWN
//     with UNSUPPORTED_REQUIREMENT. A record that names a principal or an agent
//     applies only in a call from that principal and that agent's binding
//     (draft 17.1); an installed check that no record applies to, such as one
//     called with no binding for an agent, is FAIL with
//     APPROVAL_SCOPE_MISMATCH. A check with freshness limits evaluates
//     the record it consults with package freshness, with the baseline skew
//     and a guard against re-stamping that starts with the sightings of the
//     state: CLOCK_AHEAD, RESTAMPED and STALE_EVIDENCE are FAIL. A check pinned
//     to a revision of its source fails with REQUIREMENTS_CHANGED when the
//     source reports another.
//   - AuthorizeNative: the policy decides for the original principal, a deny
//     wins, and no rule is a deny. The decision carries the provenance of the
//     rule that decided, and always names a policy source.
//   - RecordOutcome: signs outcome reports with ES256, declares no visibility
//     for executions it does not observe, and removes credentials from free
//     text and references.
//
// A source that the state lists as unavailable is not read: a binding or a
// claim from it is an ErrDependencyUnavailable error and a check of it is
// UNKNOWN with DEPENDENCY_UNAVAILABLE. The adapter keeps no copy to fall back
// on.
//
// The adapter has no execution path, so it never runs the execution hook.
//
// The package imports package testing through [Factory]; it is a test baseline,
// not a component to link into a gateway.
package memory
