// Package ssf is a Shared Signals receiver: the membership and status source
// of an identity provider that transmits Security Event Tokens about its
// accounts and sessions (OpenID Shared Signals Framework 1.0, CAEP 1.0, RISC
// 1.0). It is the third source of package [source]: a receiver that verifies
// what the provider pushes and keeps the last state per principal in a
// [source.Store], answered by a [source.Reader] as the draft 17.1 function
// read_native_claim. The source document is spec/v1.0/profiles/sources/ssf.md; its
// cases are spec/v1.0/fixtures/sources/ssf.
//
// # Delivery
//
// [Receiver.PushHandler] is the push endpoint of RFC 8935 and [Poller] the
// client of the poll endpoint of RFC 8936. Both hand each compact SET to
// [Receiver.Accept]. [Transmitter] is the client of the stream management
// API of SSF 1.0 section 8.1: create and read a stream, read and set its
// status, and request a verification event, which [Receiver.Verified] confirms.
//
// # Verification
//
// Accept refuses a SET unless, in this order: it is a compact JWS within the
// size bound with explicit typing (typ secevent+jwt, RFC 8417 section 2.3), no
// key-by-reference header member and an alg in the algorithm list of its
// issuer, ES256 by default and RS256 where the issuer's [Issuer].Algorithms
// names it; its iss is a configured issuer; its kid names a key of that
// issuer's [KeySource] of the type the alg needs (an EC P-256 key for ES256,
// an [RSAKey] of at least [MinRSABits] bits for RS256, RFC 7518 section 3.3)
// and the signature verifies; its aud names this receiver; it has jti, iat within
// MaxAge and not later than now plus the skew, no sub and no exp, and one or
// more events whose payloads conform to their definitions (RFC 8417 section
// 2.2, SSF 1.0 section 4.1). A SET whose jti was applied before is not
// applied again ([Result].Replay); the jti is recorded only after the events
// were applied, so a SET that failed on a dependency is applied on its retry.
// The signature comes before the replay store is consulted, so a forged SET
// cannot poison a jti.
//
// # Events and state
//
// The receiver writes one fact per principal, /principal/account_state, with
// the event time (event_timestamp, else iat) as both the observation and the
// status time:
//
//	account-disabled                     disabled
//	account-enabled                      active
//	account-purged                       absent
//	account-credential-change-required   password_change_required
//	credential-compromise                credential_compromised
//	session-revoked, sessions-revoked    session_revoked
//	credential-change (not create)       credential_changed
//	assurance-level-change (not increase) assurance_changed
//
// An event older than the state it would replace is not applied. The receiver
// learns only what the transmitter sends: a principal no event named has no
// fact, and no event ever asserts that a session is still in force. Event
// types in Config.HoldOn also raise a [HoldCandidate] for a security
// authority; the receiver creates no hold.
//
// # Subjects
//
// A subject resolves to a principal only through a configured [Mapping] for
// the SET's issuer: iss_sub by the subject's iss and sub, opaque by id, email
// by the exact address. A complex subject resolves by its user member. A
// subject that resolves to nothing is ignored and reported as a
// [KindUnknownSubject] record that carries the format and never the
// identifier.
package ssf
