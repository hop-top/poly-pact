// Package ldap is the LDAP adapter of the integration profile
// spec/v1.0/profiles/ldap: the seven functions of draft 17.1 for a gateway that
// authenticates dedicated directory accounts with the simple bind of
// RFC 4511 and reads their identity, group and account-state facts from
// OpenLDAP 2.6 or Active Directory Domain Services (integration sample I06).
//
// The adapter is built with [New] from a [Config] that names the gateway's
// native systems: the directory realms ([RealmConfig], each with a
// [Directory]), the enrollment registry, the application's native
// authorization ([PermissionLookup]), further claim sources and installed
// checks, and the key that signs outcome reports. [Server] is the
// [Directory] on github.com/go-ldap/ldap/v3, the only module outside the
// standard library and this module that the package uses.
//
// # What it does
//
//   - AuthenticateNative: a request must carry the enforcement marker of
//     [Enforce] or [Mark]. The name and the password come from the Basic
//     Authorization header (RFC 7617, section 2); the profile does not fix
//     the request form. An empty name, and a password that is empty after
//     the SASLprep mapping (RFC 4013, section 2.1), are NO_CREDENTIAL before
//     any directory request (LR-6). The lookup account finds exactly one
//     entry by the login attribute, with the name escaped (LR-11, RFC 4515
//     section 3); the password is bound as that entry's DN on a connection of
//     its own (LR-7), and an empty "Who am I?" identity rejects it (LR-8).
//     The principal and the workload are ldap:{realm_id}:{unique_id}
//     ([PrincipalID]), entryUUID or objectGUID (LR-2).
//   - ResolveAgentBinding: the enrollment registry through [enroll.Resolver];
//     an account with more than one enrollment in force is the registry's
//     configuration error (identity mapping IM-19).
//   - MapOperation: the baseline HTTP mapping of draft 10.2 with the route
//     table of the installed revision; [StockRoutes] is that of pact-ldap-1.
//   - ReadNativeClaim: /principal/id, /principal/group_ids (memberOf, each
//     value read back and kept only under a group base), the Active
//     Directory in-chain resolver for /principal/group_ids_nested, and
//     /principal/account_state by the realm's state map. Each directory read
//     is checked against the visibility sentinel on the same connection
//     (LR-14) and carries its as-of instant as observation and status time
//     (LR-25). Other approved paths come from [Config.Claims].
//   - CheckContext: the installed check of the exact id;
//     [ExecutionIdentity] is execution-identity-v1 for route R1.
//   - AuthorizeNative: the application's decision for the original
//     principal, unchanged; the lookup account is never passed.
//   - RecordOutcome: signs admission and authorization reports and declares
//     no visibility of execution.
//
// The adapter never reads the wall clock: [Config.Clock] is its only source
// of the current time. It caches nothing (LR-27).
//
// # Probes
//
// The task that wrote this package probed github.com/go-ldap/ldap/v3 v3.4.15
// before relying on it, by reading its source and by running it.
//
//   - Conn.Bind with an empty password returns the client-side error
//     ErrorEmptyPassword (206) and sends no request; Conn.UnauthenticatedBind
//     sends the simple bind with a zero-length password, the unauthenticated
//     mechanism of RFC 4513, section 5.1.2. The adapter rejects an empty
//     password before it opens a connection and never calls
//     UnauthenticatedBind; [Server] refuses an empty password as well.
//   - CompileFilter accepts the extensible match
//     (member:1.2.840.113556.1.4.1941:=<DN>) and encodes it as an
//     extensibleMatch with the matching rule, the type and the match value
//     of RFC 4511, section 4.5.1.7; an escape \hh in the value is decoded to
//     the octet, so a DN is escaped with [EscapeValue] before it is placed in
//     a filter, and an objectGUID value is written octet by octet.
//   - Conn.Search returns the entries received and the search result
//     references (Referrals) together with the error of a result other than
//     success, which is an *Error whose ResultCode is the code of RFC 4511;
//     codes from 200 up are go-ldap's own client-side conditions.
//   - Conn.Extended leaves the response value nil when the response field is
//     absent; a present empty field is a value with no octets, which is how
//     RFC 4532, section 3 reports an anonymous association.
//
// Against OpenLDAP 2.6.8 (the alpine 3.22 packages, memberof and ppolicy
// overlays) the same task observed: an add with the Relax Rules control by
// the root DN sets entryUUID to the value given, so a seed keeps its
// identifiers; pwdAccountLockedTime, pwdReset, pwdStartTime and pwdEndTime
// are accepted the same way and returned when requested by name; memberOf is
// maintained from member and returned when requested by name; the root DSE
// lists 1.3.6.1.4.1.4203.1.11.3 (profile P11 for that release); with
// "security simple_bind=128" a simple bind without TLS is refused with
// confidentialityRequired (profile P13 for that release); and a permanently
// locked account still binds when no password policy entry applies, which is
// why the adapter reads the state and does not rely on the bind (profile
// section 9, "Directory enforcement").
//
// The profile's other open items (Appendix H) remain open: an activedirectory
// realm needs the objectGUID octet order a deployment established (P3), given
// as [RealmConfig.GUIDText].
package ldap
