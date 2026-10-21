// Package abac is the ABAC adapter of the integration profile
// spec/v1.0/profiles/abac: the decision client of attribute-based access control
// through an installed policy decision point, Open Policy Agent, reached
// through its REST Data API (integration sample I11). It uses only the
// standard library and this module.
//
// The adapter is built with [New] from a [Config] that names the gateway's
// native systems: the inherited authentication and binding resolution of the
// mechanism that authenticated the request (profile section 7), the
// authoritative fact sources ([SubjectSource], [ResourceSource],
// [DeviceSource], [EnvironmentSource]; [Gateway] is the gateway's own zone
// map and clock), their age limits ([ProfileLimits]), the [PDP], the
// installed ABAC check [Entry], other claim sources and installed checks, and
// the key that signs outcome reports. PACT never interprets the native
// policy: the adapter builds the input, asks the PDP, and returns its answer
// (draft 17.1).
//
// # What it does
//
//   - AuthenticateNative and ResolveAgentBinding: those of the authenticating
//     mechanism, which sets the Principal attributes [AttrDeviceID] and
//     [AttrPeerAddress].
//   - MapOperation: the baseline HTTP mapping of draft 10.2 with the route
//     table of the installed revision; [DocumentRoutes] is that of
//     pact-abac-1.
//   - ReadNativeClaim: the fact paths of profile section 8 from their sources,
//     with the source's own times; other approved paths from [Config.Claims].
//   - AuthorizeNative ([Adapter.Decide]): the input of profile section 11
//     from the facts only, no query unless every fact is fresh and of its
//     form (ABAC-8), the request of ABAC-13, and the answer classified by
//     ABAC-14 and returned as the PDP gave it: every obligation unchanged,
//     decision_id as SourceRef, policy_version as PolicyRevision, no
//     decision time.
//   - CheckContext: the ABAC check of [Config.Entry] on the principal and the
//     operation it receives (draft 17.1), and the installed checks of
//     [Config.Checks].
//   - RecordOutcome: signs admission and authorization reports and declares
//     no visibility of execution.
//
// The gateway uses a decision through [Gate], which compares the policy
// revision with the pinned version and the obligation types with the
// installed set. The executor side rechecks device, zone and time with
// [Adapter.Recheck] and enforces the obligations with [Enforcer] before it
// releases any content.
//
// The adapter never reads the wall clock: [Config.Clock] is its only source
// of the current time. It caches no fact and no decision.
//
// # Probes
//
// The task that wrote this package ran OPA 1.21.2 (the container image
// openpolicyagent/opa:1.21.2) with the policy of the fixture asset
// adapters/abac/assets/policy.rego and observed: a decision query answers
// 200 with decision_id and result, the members of each object in sorted
// order; an undefined path answers 200 with decision_id and no result;
// without decision logging the answer has no decision_id; a built-in error
// with strict-builtin-errors=true answers 500 with code internal_error and an
// errors entry of code eval_builtin_error, and without the parameter the
// document is undefined; a body that is not JSON answers 400 with code
// invalid_parameter; a path with a trailing slash answers 301; with
// provenance=true the answer carries provenance.version and no bundles when
// no bundle is loaded.
package abac
