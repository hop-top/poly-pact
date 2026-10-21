// Package adapter defines the native adapter contract of PACT draft section
// 17.1: the seven logical functions an enforced gateway adapter exposes, the
// value types they exchange, and the errors they report.
//
// The package holds interfaces, types and errors only. An implementation
// lives in its own package; the validator and the conformance harness compile
// against the interfaces here. The contracts are behavioral, not new REST
// APIs (draft 17.1): an existing gateway plugin, policy hook, middleware,
// directory lookup or native claim can satisfy them. Each of the seven takes a
// context.Context first.
//
// # The seven functions
//
// One interface per row of the draft 17.1 table, and the composite [Adapter]
// that embeds all seven. Each row below gives the draft function name, the Go
// interface and method, and the draft's own Input and Output / requirement
// cells.
//
//	authenticate_native    NativeAuthenticator.AuthenticateNative
//	    Input:  Actual request
//	    Output: Authenticated principal and workload context, or native denial.
//
//	resolve_agent_binding  BindingResolver.ResolveAgentBinding
//	    Input:  Realm, authenticated workload, and the agent ID the request names
//	    Output: The enrolled binding of that agent ID to that workload in that realm:
//	            operator binding, holder key, and current binding status; `UNKNOWN` when
//	            no such enrollment exists, together with whether that agent ID is
//	            enrolled for another workload of the realm.
//
//	map_operation          OperationMapper.MapOperation
//	    Input:  Actual request and mapping version
//	    Output: Authoritative `OperationContext`; all consequential request data is covered.
//
//	read_native_claim      ClaimReader.ReadNativeClaim
//	    Input:  Approved native path and context
//	    Output: Authoritative value, original observation time, status time, and source ID.
//
//	check_context          ContextChecker.CheckContext
//	    Input:  Installed check ID; the authenticated principal and workload context that
//	            `authenticate_native` returned, with its authenticated attributes; the agent
//	            binding that `resolve_agent_binding` returned; intent; operation; evidence references
//	    Output: `PASS`, `FAIL`, or `UNKNOWN`, with a reason.
//
//	authorize_native       NativeAuthorizer.AuthorizeNative
//	    Input:  Original principal and actual operation
//	    Output: Existing policy decision; PACT cannot rewrite a denial.
//
//	record_outcome         OutcomeRecorder.RecordOutcome
//	    Input:  Attributable decision/execution observation
//	    Output: Signed outcome or declared absence of execution visibility.
//
// # Invariants
//
// Every implementation holds two invariants, whatever the native system:
//
//  1. Values come only from authenticated context or configured authoritative
//     lookups. A client-supplied header, profile text, URL parameter or model
//     output is never native context, and identities keep their issuer and
//     tenant namespace so that similarly named users or roles are not
//     conflated (draft 8.5, 17.2).
//  2. ObservedAt is the original source observation. An adapter never
//     refreshes a stale upstream fact by stamping it with the time of the
//     read, and it never reports a check or a freshness it did not perform
//     (draft 8.3, 17.2). A zero time means the source gives no such time; the
//     validator cannot establish freshness from it.
//
// # Errors
//
// The sentinel errors map to the codes of the draft 13.4 table, and [CodeOf]
// recovers the code from an error chain:
//
//	ErrInvalidMessage          INVALID_MESSAGE
//	ErrInvalidProof            INVALID_PROOF
//	ErrContextMismatch         CONTEXT_MISMATCH
//	ErrDependencyUnavailable   DEPENDENCY_UNAVAILABLE
//	ErrUnsupportedRequirement  UNSUPPORTED_REQUIREMENT
//	ErrUnsupportedPurpose      UNSUPPORTED_PURPOSE
//	ErrMissingField            MISSING_FIELD
//
// A function that cannot reach its source returns an error that wraps
// [ErrDependencyUnavailable]; the validator records the affected check as
// UNKNOWN and the admission decision as DEFERRED (draft 11.4, 17.3.1).
// CheckContext has no error result: it reports the same conditions as a
// [CheckOutcome] with the verdict UNKNOWN and the code as ReasonCode.
//
// # Times
//
// Times are [time.Time]. On the wire they are integer Unix seconds; a
// conversion truncates to the second and maps the zero time to an absent
// (null) member.
//
// The interfaces are the contract that implementations and the conformance
// harness share. Treat them as frozen once released: a change to a signature
// or to a type's fields breaks every implementation.
package adapter
