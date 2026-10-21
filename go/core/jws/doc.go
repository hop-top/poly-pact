// Package jws signs and verifies the compact JWS of PACT signed artifacts:
// the profile of draft Sections 7.2 and 7.3 over RFC 7515. ES256 (ECDSA
// P-256 and SHA-256, RFC 7518 section 3.4) is the baseline and the only
// algorithm accepted by default. Ed25519 (RFC 9864 section 2.2, keys of RFC
// 8037 section 2) is accepted only where a deployment has negotiated it
// explicitly, by listing it in [Algorithms]. The ambiguous EdDSA identifier
// is never accepted.
//
// # Verification
//
// [Verify] checks a compact JWS in this order and stops at the first failure,
// whose [Reason] it returns inside an [*Error]:
//
//  1. the length bound ([DefaultMaxCompactBytes]), then three segments
//     separated by two periods with a non-empty header segment;
//  2. the header segment is canonical unpadded base64url and a strict JSON
//     object ([hop.top/pact-go/core/strictjson]: no duplicate members, valid
//     Unicode, bounded depth);
//  3. no crit, b64, jku, x5u or x5c member; alg is one of
//     [Verifier.Algorithms] (ES256 when none are given); typ is in the draft
//     7.3 table and, when [Verifier.Typ] is set, equals it; kid, if present,
//     is a string. Other members are ignored (RFC 7515 section 4);
//  4. by the signer role of typ: a holder-signed artifact embeds a jwk that
//     [Algorithms.ParseJWK] accepts and that is a key for alg; any other
//     artifact has a kid and no jwk;
//  5. the payload segment is not empty (no detached payload), is canonical
//     base64url and a strict JSON object;
//  6. the signature segment is canonical base64url of exactly 64 octets;
//  7. the key: for a holder, the embedded jwk's RFC 7638 thumbprint equals
//     the holder_jkt the [KeyResolver] expects; otherwise kid is found in the
//     key set the resolver trusts for the role, and nowhere else, and that
//     key is a key for alg;
//  8. the signature of alg (ECDSA or Ed25519) over the received signing
//     input, the compact text up to its second period. Nothing is decoded
//     and re-encoded to rebuild it.
//
// Size and structure are checked before any key lookup or signature
// operation (draft 20.1). A high S is accepted, since neither RFC 7518 nor
// the draft has a low-S rule; whether PACT should reject it is open in the
// draft. [Sign] writes only low-S signatures; [SignEd25519] writes the
// deterministic signatures of RFC 8032.
//
// Verify checks the JWS, not the artifact: decode [ParsedJWS.Payload] with
// strictjson into its core type and apply the schema, time and authority
// rules separately.
//
// # Keys
//
// Keys come only from configuration. [KeySet] holds trusted public keys by
// kid; a [KeyResolver] returns the set for a signer role, or the holder_jkt
// enrolled for the agent. [StaticResolver] serves fixed configuration. JWKs
// must be EC P-256 public keys with both coordinates at their full 32 octets
// or, where Ed25519 is negotiated, OKP Ed25519 public keys with a 32-octet x
// and no y, x a valid encoding of an edwards25519 point (RFC 8032 section
// 5.1.3) in the subgroup of prime order L, so neither of small nor of mixed
// order; private members are rejected, and a key serves the one algorithm
// of its kty and crv. [Thumbprint] computes the RFC 7638 SHA-256 thumbprint
// over crv, kty, x and y, or crv, kty and x for an OKP key.
//
// # Vectors
//
// spec/v1.0/fixtures/vectors/jws holds language-neutral vectors, listed in
// spec/v1.0/fixtures/manifest.json under ids beginning vectors/jws/; their README
// describes the format. Their reject_reason values are the [Reason] strings.
// They are verified under the baseline, so they have no Ed25519 case that
// accepts.
package jws
