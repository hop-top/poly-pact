// Package enroll defines the enrollment registry behind the draft 17.1 function
// resolve_agent_binding: the record that binds a stable agent_id to an
// authenticated workload in a realm, with its operator and its holder key
// (draft 6.1, 6.2), and the lifecycle operations on that record (draft 6.4).
//
// The package holds the [Registry] contract, the [Actor] that may change a
// binding, the errors, the [AuditEntry] every change leaves, and [Resolver],
// which exposes a Registry as the [adapter.BindingResolver] an adapter needs.
// The backends live in subpackages; [hop.top/pact-go/adapter/enroll/memory] is the
// in-memory one.
//
// # Who may change a binding
//
// Enrollment, rotation and the compromise mark are native administrative
// operations (draft 6.1). The only trusted actors are [Admin], a native
// authenticated administrative workflow, and [AuthorizedIssuer], an identity-
// binding or rotation issuer the gateway's administrators configured. The agent
// holding the old key is an [Agent] actor and has no authority: proof by the
// old key alone never rotates a key and never recovers a compromised identity.
// An actor's authority is scoped to the one realm named in [Actor].Realm.
//
// # Binding status
//
// Lookup selects the record by the agent_id the request names, among the
// records of the authenticated workload in the realm, and reports the status of
// its [adapter.AgentBinding]:
//
//   - ACTIVE: enrolled and in force.
//   - REVOKED: withdrawn. It is not rotated or enrolled back to life.
//   - COMPROMISED: marked by an authority. It is terminal: no Registry method
//     returns it to ACTIVE or REVOKED. Clearing the security hold and enrolling
//     the agent again is a remediation process outside this package, and the
//     remediated agent is enrolled under a new agent_id.
//   - UNKNOWN: no current binding can be established. It covers an agent_id
//     with no record on the workload, including one enrolled only for another
//     workload, so that a workload alone, or a credential that several agents
//     share, never selects an agent. EnrolledElsewhere then says whether the
//     agent_id is enrolled for another workload of the realm (draft 17.1).
//
// # Dedicated workloads
//
// By default a workload serves one agent (identity mapping IM-19): a registry
// refuses to enroll an agent for a workload that an enrollment in force
// already names, with [ErrWorkloadInUse], and Lookup reports a workload with
// more than one enrollment in force as a configuration error, an error that
// wraps [adapter.ErrUnsupportedRequirement] with no binding (draft 17.1). An
// enrollment is in force unless it is revoked; a compromised one is in force,
// so that a compromise is never hidden behind a newer record. A backend may
// support workloads shared by several agents as an option, for a profile that
// supports them.
//
// The mapping rules these types implement are in spec/v1.0/profiles/identity-mapping.md.
package enroll
