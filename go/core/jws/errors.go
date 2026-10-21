package jws

import "errors"

// Reason is the stable name of why a JWS, a JWK or a key set was rejected.
// The same names appear as reject_reason in the language-neutral vectors under
// spec/v1.0/fixtures/vectors/jws, so every SDK reports the same reason for the same
// input. A Reason is itself an error: test with errors.Is(err, ErrAlgUnsupported).
type Reason string

func (r Reason) Error() string { return "jws: " + string(r) }

// Reasons, roughly in the order Verify checks them.
const (
	// ErrCompactSize: the compact serialization is longer than the limit.
	ErrCompactSize Reason = "compact-size"
	// ErrCompactForm: not three segments separated by two periods, or an
	// empty protected header segment.
	ErrCompactForm Reason = "compact-form"
	// ErrBase64URL: a segment is not canonical unpadded base64url: padding,
	// white space, line breaks, the standard alphabet, a length of 1 mod 4 or
	// non-zero spare bits.
	ErrBase64URL Reason = "base64url"
	// ErrHeaderJSON: the protected header is not a strict JSON object (draft
	// 7.1), or kid is not a string.
	ErrHeaderJSON Reason = "header-json"
	// ErrHeaderCrit: the header has crit. The profile recognizes no critical
	// header, so any crit is unrecognized (draft 7.2).
	ErrHeaderCrit Reason = "header-crit"
	// ErrHeaderB64: the header has b64 (RFC 7797); unencoded payloads are
	// prohibited (draft 7.2).
	ErrHeaderB64 Reason = "header-b64"
	// ErrHeaderJKU: the header has jku (draft 7.2).
	ErrHeaderJKU Reason = "header-jku"
	// ErrHeaderX5U: the header has x5u (draft 7.2).
	ErrHeaderX5U Reason = "header-x5u"
	// ErrHeaderX5C: the header has x5c; keys come only from the trusted key
	// set or, for a holder, from the jwk that matches holder_jkt.
	ErrHeaderX5C Reason = "header-x5c"
	// ErrAlgUnsupported: alg is missing or is not an algorithm the verifier
	// accepts: ES256 and, where it is negotiated, Ed25519. none, HMAC, RSA,
	// RSA-PSS and EdDSA are never accepted.
	ErrAlgUnsupported Reason = "alg-unsupported"
	// ErrTypUnsupported: typ is missing or not in the draft 7.3 table.
	ErrTypUnsupported Reason = "typ-unsupported"
	// ErrTypMismatch: typ is in the table but is not the typ the caller
	// expects (Verifier.Typ).
	ErrTypMismatch Reason = "typ-mismatch"
	// ErrKidMissing: a service-signed artifact, or a key of a key set, has no
	// kid.
	ErrKidMissing Reason = "kid-missing"
	// ErrKidUnknown: kid is not in the key set trusted for the signer role.
	ErrKidUnknown Reason = "kid-unknown"
	// ErrKidDuplicate: two keys of a key set share a kid.
	ErrKidDuplicate Reason = "kid-duplicate"
	// ErrJWKMissing: a holder-signed artifact embeds no jwk.
	ErrJWKMissing Reason = "jwk-missing"
	// ErrJWKUnexpected: a service-signed artifact embeds a jwk.
	ErrJWKUnexpected Reason = "jwk-unexpected"
	// ErrJWKPrivate: a JWK carries a private member (d, p, q, dp, dq, qi, oth
	// or k).
	ErrJWKPrivate Reason = "jwk-private"
	// ErrJWKInvalid: a JWK is not a JSON object, a member has the wrong JSON
	// type, x or y is not the canonical base64url of exactly 32 octets, an OKP
	// key has a y, or key_ops names an operation twice.
	ErrJWKInvalid Reason = "jwk-invalid"
	// ErrJWKCurve: kty is not EC or crv is not P-256 (compared exactly), and
	// the key is not an OKP Ed25519 key where Ed25519 is negotiated.
	ErrJWKCurve Reason = "jwk-curve"
	// ErrJWKOffCurve: x and y are not a point of P-256, or the x of an
	// Ed25519 key does not decode as a point of edwards25519 (RFC 8032
	// section 5.1.3) or decodes as a point outside the subgroup of prime
	// order L, of small or of mixed order.
	ErrJWKOffCurve Reason = "jwk-off-curve"
	// ErrJWKUsage: the JWK's alg is not the algorithm of its kty and crv, its
	// use is not sig, its key_ops do not name verify, or the key that
	// verifies a JWS is not a key for the header's alg (an Ed25519 header
	// with a P-256 key, or ES256 with an Ed25519 key).
	ErrJWKUsage Reason = "jwk-usage"
	// ErrHolderJKTMismatch: the RFC 7638 thumbprint of the embedded jwk is
	// not the expected holder_jkt.
	ErrHolderJKTMismatch Reason = "holder-jkt-mismatch"
	// ErrKeyUnavailable: there is no resolver, the resolver failed, or it has
	// no expected holder_jkt.
	ErrKeyUnavailable Reason = "key-unavailable"
	// ErrPayloadDetached: the payload segment is empty (draft 7.2).
	ErrPayloadDetached Reason = "payload-detached"
	// ErrPayloadJSON: the payload is not a strict JSON object (draft 7.1).
	ErrPayloadJSON Reason = "payload-json"
	// ErrSignatureLength: the signature is not 64 octets (RFC 7518 section
	// 3.4).
	ErrSignatureLength Reason = "signature-length"
	// ErrSignatureInvalid: the signature does not verify over the received
	// signing input under the resolved key.
	ErrSignatureInvalid Reason = "signature-invalid"
	// ErrSigningKey: Sign or SignEd25519 was given no key, a key of the wrong
	// type or size, or a jwk that is not the key's public part.
	ErrSigningKey Reason = "signing-key"
)

// Error is the error the package returns. It wraps its Reason and, when
// there is one, the underlying cause (a strictjson error, a resolver error),
// so errors.Is and errors.As see both.
type Error struct {
	Reason Reason
	// Detail says what was found, such as the member name or the octet count.
	Detail string
	// Err is the underlying cause, or nil.
	Err error
}

func (e *Error) Error() string {
	s := e.Reason.Error()
	if e.Detail != "" {
		s += ": " + e.Detail
	}
	if e.Err != nil {
		s += ": " + e.Err.Error()
	}
	return s
}

// Unwrap returns the Reason and the cause.
func (e *Error) Unwrap() []error {
	if e.Err == nil {
		return []error{e.Reason}
	}
	return []error{e.Reason, e.Err}
}

// ReasonOf returns the Reason of the first *Error in err's chain, or "" when
// err is nil or not from this package.
func ReasonOf(err error) Reason {
	var e *Error
	if errors.As(err, &e) {
		return e.Reason
	}
	return ""
}

func fail(r Reason, detail string, cause error) error {
	return &Error{Reason: r, Detail: detail, Err: cause}
}
