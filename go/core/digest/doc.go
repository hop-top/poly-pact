// Package digest computes the three digests of Section 7.4 of the draft. Each
// is SHA-256 written as base64url without padding, a [core.Digest] of 43
// characters.
//
//   - [ObjectDigest] hashes the RFC 8785 canonical UTF-8 form of a JSON object,
//     made by [hop.top/pact-go/core/jcs];
//   - [ArtifactDigest] hashes the ASCII bytes of the exact compact JWS string;
//   - [BytesDigest] hashes raw bytes.
//
// # ObjectDigest
//
// The value is encoded with encoding/json (HTML escaping off), then read back
// and canonicalized by jcs, so the digest depends on the JSON value and not on
// member order, white space or the Go type it came from. Because jcs reads the
// text with strictjson, the checks of Section 7.1 and the limits of Section
// 20.1 apply: duplicate member names, nesting over 16, text over 256 KiB,
// invalid UTF-8, unpaired surrogate escapes and integers outside ±(2^53-1) are
// errors that wrap the strictjson reasons, and NaN and infinities fail in the
// encoder. A float64 of integer value above 2^53 is written by encoding/json as
// an integer literal and is rejected for that reason.
//
// The draft defines the digest of a JSON object, so a value that encodes to
// anything else (an array, a string, a number, null, a nil map or pointer)
// returns [ErrNotObject]. Hash other bytes with [BytesDigest].
//
// To digest an object that was received, pass its text as json.RawMessage, not
// a struct decoded from it: a Go string cannot hold invalid UTF-8, and
// encoding/json replaces such bytes with U+FFFD instead of failing, so a
// string built in Go from bad bytes would hash the replacement.
//
// # ArtifactDigest
//
// The string is hashed as is: it is not trimmed, decoded or parsed. A byte
// outside ASCII is an error, because the draft defines the digest over ASCII
// bytes and a UTF-8 string would otherwise hash different bytes silently.
// Whether the string is a well-formed compact JWS is for the JWS package; the
// empty string hashes as zero bytes do.
//
// # Vectors
//
// spec/v1.0/fixtures/vectors/digest/appendix-b.json holds the vectors, listed in
// spec/v1.0/fixtures/manifest.json under the id vectors/digest/appendix-b. The file
// is one JSON array. Every element has exactly these members, so any
// language reads it the same way:
//
//	id              unique name of the vector
//	input_kind      "object", "artifact" or "bytes"
//	input           object: the JSON object itself;
//	                artifact: the compact JWS string;
//	                bytes: the bytes as lowercase hex ("" for no bytes)
//	expected_digest the digest this implementation must produce
//	spec_defect     true when appendix_value is not the digest the draft's
//	                algorithm gives for the input
//	appendix_value  the digest as the draft's Appendix B prints it, or null
//	                when the draft prints none for this input
//
// When spec_defect is false and appendix_value is set, it equals
// expected_digest. When spec_defect is true, expected_digest is the computed
// value, appendix_value differs from it, and a test asserts the computed value
// and reports the draft value as a named skip, never as a pass. vectors_test.go
// rejects a mismatch that is not marked, a mark on a matching value and a mark
// with no draft value.
package digest
