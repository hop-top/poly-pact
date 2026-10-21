package jws

import (
	"crypto/ed25519"
	"fmt"
	"slices"
)

// Algorithms lists the JOSE algorithms a deployment accepts for its signed
// artifacts (draft 7.2). nil or empty is the baseline, ES256 alone. Ed25519
// (RFC 9864 section 2.2) is accepted only when it is listed, that is, when it
// has been negotiated explicitly; its keys are OKP keys of curve Ed25519
// (RFC 8037 section 2). ES256 and Ed25519 are the only algorithms the
// package implements: any other entry, the ambiguous EdDSA included, never
// matches a header or a key.
type Algorithms []string

// Accepts reports whether alg is an algorithm of a: ES256 or Ed25519, and
// listed in a, or ES256 when a is empty.
func (a Algorithms) Accepts(alg string) bool {
	if alg != AlgES256 && alg != AlgEd25519 {
		return false
	}
	if len(a) == 0 {
		return alg == AlgES256
	}
	return slices.Contains(a, alg)
}

// ParseJWK is the package's ParseJWK for the algorithms a: it also accepts
// an OKP Ed25519 public key when a accepts Ed25519. The key's alg member,
// when present, must be the algorithm of its kty and crv.
func (a Algorithms) ParseJWK(data []byte) (JWK, error) {
	return parseJWK(data, a)
}

// NewKeySet is the package's NewKeySet for the algorithms a: each key is
// checked as a.ParseJWK checks it.
func (a Algorithms) NewKeySet(keys ...JWK) (*KeySet, error) {
	return newKeySet(a, keys)
}

// Algorithm returns the one algorithm the key's kty and crv serve: ES256 for
// EC P-256, Ed25519 for OKP Ed25519 (RFC 9864 section 2.2, RFC 8037 section
// 2). Other key types fail with ErrJWKCurve. It does not check the key
// material, nor whether the algorithm is negotiated.
func (k JWK) Algorithm() (string, error) {
	switch {
	case k.Kty == "EC" && k.Crv == "P-256":
		return AlgES256, nil
	case k.Kty == "OKP" && k.Crv == "Ed25519":
		return AlgEd25519, nil
	}
	return "", fail(ErrJWKCurve, fmt.Sprintf("kty %q crv %q, want EC P-256 or, when negotiated, OKP Ed25519", k.Kty, k.Crv), nil)
}

// Ed25519PublicKey checks kty, crv and x of an OKP Ed25519 key (RFC 8037
// section 2: x is the 32-octet public key, there is no y) and returns the
// key. x must decode as a point of edwards25519 (RFC 8032 section 5.1.3) in
// the subgroup of prime order L, [L]A the identity, so neither of small nor
// of mixed order; otherwise the error is ErrJWKOffCurve. It does not
// look at Kid, Alg or Use.
func (k JWK) Ed25519PublicKey() (ed25519.PublicKey, error) {
	if k.Kty != "OKP" || k.Crv != "Ed25519" {
		return nil, fail(ErrJWKCurve, fmt.Sprintf("kty %q crv %q, want OKP Ed25519", k.Kty, k.Crv), nil)
	}
	if k.Y != "" {
		return nil, fail(ErrJWKInvalid, "an OKP key has no y", nil)
	}
	b, err := decodeSegment(k.X)
	if err != nil {
		return nil, fail(ErrJWKInvalid, "x is not canonical base64url", err)
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fail(ErrJWKInvalid, fmt.Sprintf("x has %d octets, want %d", len(b), ed25519.PublicKeySize), nil)
	}
	if err := checkEd25519Point(b); err != nil {
		return nil, fail(ErrJWKOffCurve, "x is "+err.Error(), nil)
	}
	return ed25519.PublicKey(b), nil
}

// PublicEd25519JWK returns the OKP JWK of an Ed25519 public key (RFC 8037
// section 2), with no optional members.
func PublicEd25519JWK(pub ed25519.PublicKey) (JWK, error) {
	if len(pub) != ed25519.PublicKeySize {
		return JWK{}, fail(ErrJWKInvalid, fmt.Sprintf("%d-octet Ed25519 public key, want %d", len(pub), ed25519.PublicKeySize), nil)
	}
	return JWK{Kty: "OKP", Crv: "Ed25519", X: b64.EncodeToString(pub)}, nil
}

// verifyEd25519 verifies a 64-octet Ed25519 signature (RFC 8032 section
// 5.1.7) over the signing input.
func verifyEd25519(pub ed25519.PublicKey, signingInput string, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, []byte(signingInput), sig)
}
