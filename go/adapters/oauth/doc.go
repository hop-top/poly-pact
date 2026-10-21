// Package oauth is the OAuth adapter of the integration profile
// spec/v1.0/profiles/oauth: the seven functions of draft 17.1 for a gateway that
// authenticates agent requests with OAuth 2.0 bearer access tokens and then
// requires a signed PACT presentation (integration samples I02, I03 and I14).
// It supports the profile's three token forms, and only those:
//
//   - Form I, an opaque token validated by RFC 7662 introspection at the
//     endpoint that the issuer entry names, with the gateway's own client
//     credentials (client_secret_basic, RFC 6749 section 2.3.1).
//   - Form E, a Microsoft Entra ID v2.0 access token, a JWS signed with RS256
//     and validated locally against the key set of one pinned tenant, reached
//     through that tenant's discovery document.
//   - Form G, a Google ID token, a JWS signed with RS256 and validated locally
//     against the key set of Google's discovery document, for one pinned
//     hosted domain (the hd claim). The key set is kept as long as the HTTP
//     cache headers of its response say, and never used stale. A Google
//     access token is opaque, is not a form, and is refused.
//
// It uses the standard library (net/http, encoding/json, crypto/rsa) and the
// packages of this module, and no third-party code: the RS256 verification of
// RFC 7518 section 3.3 is done here with crypto/rsa rather than through an
// OpenID Connect library, and package hop.top/pact-go/core/jws, which verifies
// PACT artifacts, is not widened. The adapter never reads the wall clock:
// [Config.Clock] is its only source of the current time.
//
// An adapter is built with [New] from a [Config]: the gateway's realm, the
// issuer entries ([Entry]), the route table that names one entry per route
// and the route's required scope ([Route]), and the deployment-supplied
// parts of package installed. The gateway marks requests with [Enforce] or
// [Mark]; a native sender-constraint verifier reports a verified DPoP or
// certificate-bound proof with [WithSenderProof].
//
// # What it does
//
//   - AuthenticateNative: the enforcement marker, then the single
//     Authorization field (OAUTH-1, OAUTH-2), then the route's issuer entry,
//     which fixes the form and is never fallen back from (OAUTH-6), then the
//     form's validation, then the sender constraint (OAUTH-34). The
//     principal is oauth:{issuer-id}:{tenant}:{subject} and the workload
//     oauth:{issuer-id}:{tenant}:{client} ([Identifier]); the subject is sub
//     in forms I and G and oid in form E, the client client_id, azp, or in
//     form G azp or else aud; the tenant of form G is the hosted domain. The token's
//     facts are in the attribute [AttrToken], a cnf in [AttrConfirmation].
//     No token text is kept, logged or returned (OAUTH-35).
//   - ResolveAgentBinding: the enrollment registry through [enroll.Resolver],
//     for the client workload and the agent the request names.
//   - ReadNativeClaim: the four paths of profile section F from the token
//     facts of the principal; other paths from the sources the deployment
//     installs.
//   - AuthorizeNative: the route's required delegated scope (OAUTH-31), then
//     the API's permission, unchanged.
//   - CheckContext, RecordOutcome, MapOperation: the deployment-supplied
//     parts of package installed, with the route table of mapping revision
//     pact-oauth-1 by default.
//
// # Form E claims, as probed
//
// The claim mapping rests on the Microsoft Learn page "Access token claims
// reference" (https://learn.microsoft.com/en-us/entra/identity-platform/access-token-claims-reference),
// read on 2026-10-18 (page updated 2026-07-24): azp is "only present in v2.0
// tokens" and is "a replacement for appid", which is "only present in v1.0
// tokens"; scp is a "String, a space separated list of scopes", "only
// included for user tokens"; roles is an "Array of strings"; ver is "String,
// either 1.0 or 2.0"; in v2.0 tokens aud "is always the client ID of the
// API"; the header typ is "always JWT"; oid is the immutable identifier of
// the requestor across applications of a tenant, and sub "a pairwise
// identifier that's unique to a particular application ID"; uti is
// "equivalent to jti". The adapter therefore reads azp and never appid,
// requires ver 2.0, parses scp as the space-delimited scope syntax of RFC 6749
// section 3.3, refuses a token with roles and no scp, and names the subject by
// oid.
//
// # Form G claims, as read
//
// The claim mapping rests on the Google Identity page "OpenID Connect"
// (https://developers.google.com/identity/openid-connect/openid-connect),
// read on 2026-10-19: iss is "Always https://accounts.google.com or
// accounts.google.com"; aud "must be one of the OAuth 2.0 client IDs of your
// application"; hd must be checked "when restricting access to a resource to
// only members of certain domains" and its absence "indicates that the
// account does not belong to a Google hosted domain"; sub is "unique among
// all Google Accounts and never reused", never changed, of at most 255
// ASCII characters, and is what an application keys a user by, where email
// "may not be unique to this account and could change over time"; the keys
// are those of the jwks_uri of the discovery document, which may be cached
// "using the cache directives of the HTTP response". The adapter therefore
// names the principal by sub in the pinned hosted domain, never reads email,
// and keeps a key set only while the response's Cache-Control, Expires and Age
// (RFC 9111) say it is fresh.
package oauth
