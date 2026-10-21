// Package mtls is the mutual-TLS adapter of the integration profile
// spec/v1.0/profiles/mtls: the seven functions of draft 17.1 for a listener that
// authenticates machine clients with X.509 client certificates over TLS 1.3
// and then requires a signed PACT presentation (integration sample I07). It
// uses crypto/tls and crypto/x509 of the standard library and the packages of
// this module, and no third-party code.
//
// An adapter serves one listener, direct or terminated (MTLS-22), and is
// built with [New] from a [Config]: the listener's role and realm, the pinned
// CA set ([CAEntry]), the terminator allowlist, the status bound, and the
// deployment-supplied parts of package installed. The gateway installs
// [Adapter.ServerTLSConfig] and [Adapter.ConnContext] on its http.Server,
// feeds each revocation list it fetches to [Adapter.Adopt], and closes a
// connection after a response with [CloseAfter].
//
// # What it does
//
//   - AuthenticateNative: re-reads the peer certificate from the TLS state of
//     every request (MTLS-18) and applies the certificate policy MTLS-3 to
//     MTLS-7: a pinned direct issuer, the client-auth purpose, an end-entity
//     key usage, validity with the baseline skew on notBefore only, and exactly
//     one subject alternative name of the CA's kind, read as issued. The
//     identifier is mtls:{ca-id}:{san-kind}:{workload-id} ([Identifier]), the
//     principal and the workload alike, in the listener's realm. A connection
//     that is not TLS 1.3 or that the stack reports as resumed is refused. The
//     status of the connection's peer is tested once per connection against
//     the snapshot of its CA, and the record is never refreshed; a record
//     older than the status bound is [ErrConnectionExpired] (MTLS-19). On a
//     terminated listener the peer must be an allowlisted terminator, and the
//     identity is the one certificate of the x-forwarded-client-cert header,
//     verified against the pinned set alone and tested for every request
//     (MTLS-23 to MTLS-25). The x-forwarded-client-cert header, the
//     ssl-client-* headers and the other headers of MTLS-26 are removed from
//     the request. The principal reports the RFC 7638 thumbprint of the leaf
//     key as its cnf attribute, for the validator's comparison with the
//     holder key (MTLS-9).
//   - Adopt: accepts a revocation list as a CA's snapshot only when it meets
//     every condition of MTLS-12; the adapter fetches nothing and makes no
//     OCSP request (MTLS-10).
//   - ResolveAgentBinding: the enrollment registry, through [enroll.Resolver],
//     for the authenticated workload and the agent the request names.
//   - ReadNativeClaim: /attributes/environment/workload_id from the
//     authenticated principal with the times its authentication established
//     (MTLS-30); other approved paths from the sources the deployment
//     installs.
//   - CheckContext, AuthorizeNative, RecordOutcome, MapOperation: the
//     deployment-supplied parts of package installed. The adapter installs no
//     check of its own (MTLS-31).
//
// The adapter never reads the wall clock: [Config.Clock] is its only source of
// the current time, also for the checks a handshake runs.
package mtls
