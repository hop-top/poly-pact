// Package adaptertest is the conformance suite for the native adapter contract
// of draft section 17.1: the seven functions of package adapter, and the two
// invariants it states (values come only from authenticated context or
// configured authoritative lookups; ObservedAt is the original observation).
//
// An adapter author writes a [Factory] and one test:
//
//	func TestConformance(t *testing.T) {
//		adaptertest.Run(t, newFactory, adaptertest.Options{Adapter: "mymechanism"})
//	}
//
// Run executes every case file under adapters/_common of the fixture tree,
// then the case files in adapters/<Options.Adapter>, each as a subtest. A case
// file may name the workload mode it applies to; Options.SharedWorkloads, set
// for an adapter whose profile supports workloads shared by several agents,
// selects the mode, and the default is dedicated workloads. The cases are
// language-neutral JSON, registered in spec/v1.0/fixtures/manifest.json
// with the kind adapter-case; spec/v1.0/fixtures/adapters/README.md defines the
// format, so an adapter in another language reads the same files.
//
// # What a case does
//
// A case names one of the seven functions, the native state the adapter starts
// from, the request and arguments to call it with, and what the draft requires
// of the result. The suite builds the adapter for the case with the Factory,
// holds the clock at the case's now, calls the function, and checks the result.
// Expected values are written in the case from the draft; none is read back
// from an implementation.
//
// The common cases cover, by id:
//
//	COMMON-01  client identity headers are ignored by AuthenticateNative
//	COMMON-02  a request that did not come through the enforcement point is refused
//	COMMON-03  MapOperation covers method, target URI, body digest and headers,
//	           and rejects a fragment, userinfo, an ambiguous encoding or a
//	           content encoding as INVALID_MESSAGE
//	COMMON-04  ReadNativeClaim keeps the source's times and never one later
//	           than now plus the skew
//	COMMON-05  an unknown check is UNKNOWN, never PASS
//	COMMON-06  a native decision is returned unchanged, with its provenance, and
//	           runs nothing
//	COMMON-07  RecordOutcome never emits EXECUTION SUCCESS without visibility
//	COMMON-08  a revoked or compromised binding comes back as its status, with
//	           its agent, operator and holder key, never as active
//	COMMON-09  same-spelled identifiers of different realms are not equal
//	COMMON-10  no credential appears in a returned report, outcome or error
//	COMMON-11  ReadNativeClaim reads a fact of a resource or a task only for the
//	           resources of the operation and the task of the intent it is given
//	COMMON-12  a check compares the agent and the principal against the inputs it
//	           receives, never against the operation's text: another agent, another
//	           principal or no agent binding is APPROVAL_SCOPE_MISMATCH, never PASS
//	FRESH-01   a binding revoked after the contract was issued is not usable
//	FRESH-02   a check's record older than its max_age_seconds is STALE_EVIDENCE
//	FRESH-03   a source time beyond now plus the skew is CLOCK_AHEAD, not a deferral
//	FRESH-04   a check pinned to a policy revision that changed is REQUIREMENTS_CHANGED
//	FRESH-05   a required source that cannot answer is DEPENDENCY_UNAVAILABLE, never PASS
//	FRESH-06   a record re-stamped with a later observation time is RESTAMPED
//
// The FRESH groups exercise spec/v1.0/profiles/freshness.md. CLOCK_AHEAD and
// RESTAMPED are check codes of that profile with no draft 13.4 row, so the
// cases expect them from CheckContext, whose reason code is a string.
//
// The identity cases show that an adapter tells native identities apart and
// binds an agent only through its enrollment (spec/v1.0/profiles/identity-mapping.md):
//
//	IDENT-01  another user of the same tenant is neither the enrolled account
//	          nor bound to its agent
//	IDENT-02  the same subject under another tenant of the issuer is another
//	          principal with no binding
//	IDENT-03  a user acting through another client has that client as the
//	          workload, with no binding
//	IDENT-04  a certificate for another workload, or of another authority, has
//	          no binding
//	IDENT-05  an account with the same display name is another principal
//	IDENT-06  a session of the enrolled role under another session policy has
//	          no binding
//	IDENT-07  the holder key is the enrolled key, never one a credential is
//	          bound to
//	IDENT-08  a compromised binding is not recovered by proof with the old key
//	IDENT-09  on a workload that several agents share, the agent ID the request
//	          names selects that agent and its own key, its own revoked or
//	          compromised binding, or UNKNOWN when it has no record there;
//	          shared workloads only
//	IDENT-10  a workload with more than one enrollment in force is a
//	          configuration error, UNSUPPORTED_REQUIREMENT with no binding; a
//	          revoked record does not count; dedicated workloads only
//
// # What the adapter provides
//
// The suite cannot know how an adapter keeps its identities or reads its
// credentials, so the [Factory] returns a [Subject] with the few mechanism
// hooks the suite needs: Arrive marks a request as coming through the
// enforcement point, and Credential attaches the credential of a named native
// identity. The native state of a case is passed to the Factory verbatim and
// the suite never reads it. The common cases state it in the neutral model
// "common/1", which every adapter's Factory must be able to realize; the
// fixture README defines it, and package memory shows one Factory that does.
//
// # Proof that the suite can fail
//
// A suite that every adapter passes proves nothing. Package
// hop.top/pact-go/adapters/internal/broken is an adapter with deliberate defects,
// and its test runs this suite against it with [Evaluate]: each defect must
// fail the cases it targets, all defects together must fail every case, and a
// case that no defect targets is itself a test failure.
package adaptertest
