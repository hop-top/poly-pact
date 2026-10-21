// Package basic is the HTTP Basic adapter of the integration profile
// spec/v1.0/profiles/basic: the seven functions of draft 17.1 for a gateway that
// authenticates callers with the Basic scheme of RFC 7617 against an existing
// account database, in front of a legacy invoice API (integration sample I01).
//
// The adapter is built with [New] from a [Config] that names the gateway's
// native systems: the account database ([AccountStore]), the enrollment
// registry (an [enroll.Registry]), the native permission lookup
// ([PermissionLookup]), further claim sources and installed checks, and the
// key that signs outcome reports. It uses only the standard library and the
// packages of this module.
//
// # What it does
//
//   - AuthenticateNative: a request must carry the enforcement marker that the
//     gateway's own filter chain sets with [Enforce] or [Mark]; without it the
//     request is refused before any credential is read. The credential is the
//     Basic value of the Authorization header (RFC 7617, section 2): the first
//     colon separates the user-id from the password, and a user-id or password
//     with a control character is refused. The password is checked in
//     constant time against the PBKDF2 hash the account database keeps
//     ([PasswordHash]); an unknown user-id is checked against a decoy hash, so
//     that it is denied like a wrong password, with the same public reason.
//     A disabled account is denied. The principal and workload are those the
//     account database gives, under the profile basic:{store-id}:{account-id}
//     ([PrincipalID]); the user-id never names anyone.
//   - ResolveAgentBinding: the enrollment registry, through [enroll.Resolver],
//     for the authenticated account and the agent the request names. An
//     account with more than one enrollment in force is the registry's
//     configuration error (identity mapping IM-19).
//   - MapOperation: the baseline HTTP mapping of draft 10.2, by package
//     binding, with the route table of the installed mapping revision;
//     [InvoiceRoutes] is the table of revision pact-basic-1.
//   - ReadNativeClaim: the approved paths /principal/id and /principal/roles
//     from the account database, the roles through the administrator-approved
//     translation of [Config.RoleMap] only, with the database's own answer
//     time; other approved paths from [Config.Claims]; any other path is
//     unsupported.
//   - CheckContext: the installed check of the exact id, with its freshness
//     limits and pinned revision; [PurposeOperation] is purpose-operation-v1.
//     Any other id is UNKNOWN.
//   - AuthorizeNative: the native permission lookup, for the original
//     principal, returned unchanged; the adapter never runs the operation.
//   - RecordOutcome: signs admission and authorization reports with ES256 and
//     declares no visibility of execution, which the backend reports, unless
//     [Config.ExecutionVisible] is set; credential material is removed from
//     free text and references first.
//
// The adapter never reads the wall clock: [Config.Clock] is its only source
// of the current time.
package basic
