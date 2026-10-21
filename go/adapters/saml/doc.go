// Package saml is the SAML service provider session to agent broker adapter
// of the integration profile spec/v1.0/profiles/saml: the seven functions of draft
// 17.1 for an SP whose application task broker performs delegated reads for an
// enrolled agent inside a user's SP session (integration example I05).
//
// The adapter consumes no SAML message (profile SB-1). The SP's own SAML
// implementation, for example a SAML library such as crewjam/saml, validates
// assertions and logout messages and writes the resulting [SPSession] records
// to a [SessionStore]; that integration point produces the SPSession and is
// outside the claim of this repository. The adapter reads the session records
// and the broker's [TaskGrant] records live and never writes them.
//
// The adapter is built with [New] from a [Config] that names the native
// systems: the agents' own broker authentication ([AgentAuthenticator]), the
// SP session store ([SessionStore]), the broker's grant store ([TaskBroker]),
// the enrollment registry (an [enroll.Registry]), the native access policy, a
// directory adapter for membership facts, further installed checks, and the
// key that signs outcome reports. It uses only the standard library and the
// packages of this module. [Sessions] and [Grants] are in-memory stores.
//
// # What it does
//
//   - AuthenticateNative: a request must carry the enforcement marker that the
//     broker's request stage sets with [Enforce] or [Mark]. The agent's own
//     broker credential is verified by the [AgentAuthenticator] and gives the
//     workload (SB-15). The task reference is the task_id segment of the route
//     the request names (profile section 2); the grant of that task is read,
//     then the session the grant records, live. The grant's agent must hold
//     an enrollment in force on the agent's workload: the broker serves a
//     grant only to the agent it names (SB-16). The principal is that
//     session's principal, and only when the session is live and the grant's
//     user is that principal (SB-6, SB-16). No header, query parameter, body,
//     cookie or profile value names the principal. Every failure is the same
//     public CREDENTIAL_REJECTED, or NO_CREDENTIAL without an agent
//     credential (SB-17).
//   - ResolveAgentBinding: the enrollment registry, through [enroll.Resolver],
//     for the agent's broker workload and the agent the request names. A
//     workload with more than one enrollment in force is the registry's
//     configuration error (identity mapping IM-19).
//   - MapOperation: the baseline HTTP mapping of draft 10.2, by package
//     binding, with the route table of the installed mapping revision;
//     [BrokerRoutes] is the table of revision pact-saml-1.
//   - ReadNativeClaim: [PathPrincipalID] and [PathIDPRealm] from the session
//     that the grant of the intent's task records, read live, with the read
//     time as observation and status time and no source reference (SB-23);
//     membership facts from the directory adapter of [Config.Directory], with
//     its own times (SB-22); any other path is unsupported.
//   - CheckContext: [CheckNativeDelegation] against the grant store and the
//     session store (SB-11), PASS with REQUIREMENT_SATISFIED for a usable
//     grant of the binding's agent within its scope, or a deployment's own
//     [Config.DelegationCheck],
//     and the installed checks of [Config.Checks].
//   - AuthorizeNative: the SP's access policy, for the session principal,
//     returned unchanged; the adapter never runs the operation.
//   - RecordOutcome: signs admission and authorization reports with ES256 and
//     declares no visibility of execution, which the broker reports, unless
//     [Config.ExecutionVisible] is set.
//
// # What it does not establish
//
// The syntax and resolution of /attributes/delegation/authority_ref wait for
// the delegation binding model (profile SB-12, OI-1). AuthenticateNative
// refuses a request on another agent's grant before any check runs (SB-16);
// native-delegation-v1 compares the grant's agent with the agent of the
// binding that check_context receives all the same (SB-11, condition 5), so
// it is never the only comparison.
//
// The adapter never reads the wall clock: [Config.Clock] is its only source
// of the current time.
package saml
