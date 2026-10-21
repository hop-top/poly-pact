// Package scim is a SCIM 2.0 service provider (RFC 7643, RFC 7644) that
// receives the users and groups an identity provider provisions and answers
// the draft 17.1 function read_native_claim from them. It is the receiving
// end of a push protocol in the sense of package [hop.top/pact-go/adapter/source]:
// the provisioning requests are the change feed, the [source.Store] holds
// the last pushed state of each principal, and a [source.Reader] answers from
// it. The source document spec/v1.0/profiles/sources/scim.md defines the rules
// this package implements; spec/v1.0/fixtures/sources/scim holds its cases.
//
// # Endpoint
//
// A [Server] is an [http.Handler] for the resource endpoints /Users and
// /Groups under a base path, and for the public, read-only
// /ServiceProviderConfig. On a user it serves create (POST), read and list
// (GET, with a filter of the form attribute eq "value" on userName and
// externalId), modify (PATCH of active, externalId, userName and
// displayName) and delete (DELETE). On a group it serves the same, and
// PATCH adds, removes and replaces members. It does not serve PUT, bulk,
// sorting, ETags, the /Schemas and /ResourceTypes endpoints, or the
// attributes and excludedAttributes parameters; a user or group keeps only
// the attributes above and the group members, and accepts and ignores any
// other attribute or PATCH path, which the facts do not depend on.
//
// The handler does not terminate TLS. RFC 7644 section 7.2 requires TLS, so
// the deployment serves the handler over TLS 1.2 or later (http.Server with
// a tls.Config, or a TLS-terminating proxy that the provisioning client
// reaches); a bearer token sent in the clear is a leaked token.
//
// # Authentication
//
// The provisioning client presents a bearer token (RFC 6750). A request with
// no credentials, another scheme or an unknown token is answered 401 with a
// WWW-Authenticate challenge; a known token whose [Credential] does not
// carry the provisioning right is answered 403 (RFC 7644 section 3.12,
// Table 8). Authentication comes before routing, so an unknown path or a
// malformed body is answered the same way to a client with no token. Tokens
// are compared in constant time.
//
// # Identity
//
// A SCIM record names no principal. The server joins it to one through
// [Config].Join: the record's externalId, which the identity provider's
// provisioning mapping fills from an immutable object identifier, appended
// to a prefix the deployment configures (source.Join). The user name, the
// e-mail addresses, the display name and the SCIM id never join. A record
// whose externalId is absent or empty joins no principal and answers no
// fact; the server logs it to [Config].ErrorLog. A user create or change
// whose externalId another user already holds is 409 uniqueness, as is a
// second group with the same externalId. A group is named in a user's facts
// by its externalId.
//
// # Facts
//
// For each joined user the server keeps two facts, at the paths
// [PathAccountState] and [PathGroupIDs]:
//
//   - account_state is "active" or "disabled", from the user's active
//     attribute. A user whose active attribute was never asserted has no
//     account_state fact.
//   - group_ids is the sorted list of the externalIds of the groups that list
//     the user as a member; a group without an externalId contributes none.
//
// Both facts carry the SCIM id of the user as their source reference and no
// times of their own: SCIM carries no as-of time, so the [source.Reader]
// reports the read time minus [Config].Lag, which the deployment declares as
// at least one provisioning cycle of the identity provider. A change reaches
// the facts before its request is answered. Deleting a user removes its
// facts, and a later read answers no fact for that principal.
//
// The server holds its resources in memory; a restart loses them, and reads
// then answer no fact until the identity provider provisions again.
package scim
