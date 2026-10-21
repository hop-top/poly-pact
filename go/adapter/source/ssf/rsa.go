package ssf

import (
	"context"
	"crypto"
	"crypto/fips140"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"slices"

	"hop.top/pact-go/core/jws"
	"hop.top/pact-go/core/strictjson"
)

// The signature algorithms of a SET that the receiver implements. ES256 is the
// baseline (draft 7.2) and the default of every issuer; RS256 is accepted for
// an issuer whose [Issuer].Algorithms names it. No other algorithm is
// implemented: none, the HMAC algorithms and every other RSA or EC algorithm
// are refused in configuration and never match a header.
const (
	// AlgES256 is ECDSA over P-256 with SHA-256 (RFC 7518 section 3.4).
	AlgES256 = "ES256"
	// AlgRS256 is RSASSA-PKCS1-v1_5 with SHA-256 (RFC 7518 section 3.3).
	AlgRS256 = "RS256"
)

// MinRSABits is the smallest modulus the receiver verifies RS256 with: RFC
// 7518 section 3.3 says a key of 2048 bits or larger MUST be used.
const MinRSABits = 2048

// maxRSABits bounds the modulus of a key the receiver considers, so that a key
// set cannot make one verification expensive without limit. It is a deployment
// bound, not a standard value.
const maxRSABits = 16384

// RSAKey is a public RSA key in JSON Web Key form (RFC 7517; RFC 7518 section
// 6.3.1), the key type of RS256. N and E are the canonical unpadded base64url
// of the modulus and the public exponent (RFC 7518 section 6.3.1.1, 6.3.1.2).
// Kid, Alg and Use are optional. A key built in Go is checked by PublicKey:
// when it is used, and, in a [StaticKeySet], when [NewReceiver] is called.
type RSAKey struct {
	Kty string `json:"kty"`
	N   string `json:"n"`
	E   string `json:"e"`
	Kid string `json:"kid,omitempty"`
	Alg string `json:"alg,omitempty"`
	Use string `json:"use,omitempty"`
	// KeyOps is the key_ops member (RFC 7517 section 4.3); nil when absent.
	// When present it must name "verify", once.
	KeyOps []string `json:"key_ops,omitempty"`
}

// privateMembers of RFC 7518 section 6: RSA d, p, q, dp, dq, qi, oth, and the
// symmetric k.
var rsaPrivateMembers = []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"}

// ParseRSAKey decodes a JWK and checks that it is a well-formed RSA public
// key: a strict JSON object (no duplicate member) without private members,
// kty RSA, n and e the canonical unpadded base64url of an odd modulus and an
// odd exponent of at least 3 and at most 31 bits, neither with a leading zero
// octet, a modulus of at most 16384 bits, alg and use, when present, RS256
// and sig, and key_ops, when present, an array of distinct strings that names
// verify (RFC 7517 section 4.3). Other members are ignored, as RFC 7517
// section 4 requires of members not understood. The minimum size of the
// modulus is the one check left to use: a key under [MinRSABits] parses, and
// [RSAKey.PublicKey] refuses it.
func ParseRSAKey(data []byte) (RSAKey, error) {
	var m map[string]json.RawMessage
	if err := strictjson.Unmarshal(data, strictjson.Limits{}, &m); err != nil {
		return RSAKey{}, fmt.Errorf("ssf: RSA key is not a strict JSON object: %w", err)
	}
	for _, name := range rsaPrivateMembers {
		if _, ok := m[name]; ok {
			return RSAKey{}, fmt.Errorf("ssf: RSA key has the private member %s", name)
		}
	}
	var k RSAKey
	for _, f := range []struct {
		name string
		dst  *string
	}{{"kty", &k.Kty}, {"n", &k.N}, {"e", &k.E}, {"kid", &k.Kid}, {"alg", &k.Alg}, {"use", &k.Use}} {
		raw, ok := m[f.name]
		if !ok {
			continue
		}
		if err := strictjson.Unmarshal(raw, strictjson.Limits{}, f.dst); err != nil {
			return RSAKey{}, fmt.Errorf("ssf: RSA key member %s is not a string", f.name)
		}
	}
	if raw, ok := m["key_ops"]; ok {
		var ops []string
		if err := strictjson.Unmarshal(raw, strictjson.Limits{}, &ops); err != nil {
			return RSAKey{}, errors.New("ssf: RSA key member key_ops is not an array of strings")
		}
		k.KeyOps = ops
	}
	if _, err := k.decode(); err != nil {
		return RSAKey{}, err
	}
	return k, nil
}

// decode checks the form of the key and returns it, whatever its size.
func (k RSAKey) decode() (*rsa.PublicKey, error) {
	if k.Kty != "RSA" {
		return nil, fmt.Errorf("ssf: kty %q, want RSA", k.Kty)
	}
	if k.Alg != "" && k.Alg != AlgRS256 {
		return nil, fmt.Errorf("ssf: alg %q, want %s", k.Alg, AlgRS256)
	}
	if k.Use != "" && k.Use != "sig" {
		return nil, fmt.Errorf("ssf: use %q, want sig", k.Use)
	}
	if k.KeyOps != nil {
		for i, op := range k.KeyOps {
			if slices.Contains(k.KeyOps[:i], op) {
				return nil, fmt.Errorf("ssf: key_ops names %q twice", op)
			}
		}
		if !slices.Contains(k.KeyOps, "verify") {
			return nil, fmt.Errorf("ssf: key_ops %q does not name verify", k.KeyOps)
		}
	}
	n, err := segment(k.N)
	if err != nil || len(n) == 0 || n[0] == 0 {
		return nil, errors.New("ssf: n is not the canonical base64url of a modulus without a leading zero")
	}
	e, err := segment(k.E)
	if err != nil || len(e) == 0 || e[0] == 0 || len(e) > 4 {
		return nil, errors.New("ssf: e is not the canonical base64url of an exponent without a leading zero, in at most 4 octets")
	}
	mod := new(big.Int).SetBytes(n)
	if mod.Bit(0) == 0 || mod.BitLen() > maxRSABits {
		return nil, fmt.Errorf("ssf: n is even or over %d bits", maxRSABits)
	}
	exp := new(big.Int).SetBytes(e)
	if !exp.IsInt64() || exp.Int64() < 3 || exp.Int64() > 1<<31-1 || exp.Bit(0) == 0 {
		return nil, errors.New("ssf: e is not an odd number from 3 to 2^31-1")
	}
	return &rsa.PublicKey{N: mod, E: int(exp.Int64())}, nil
}

// PublicKey checks the key as [ParseRSAKey] does, and that its modulus is at
// least [MinRSABits] long (RFC 7518 section 3.3), and returns it.
func (k RSAKey) PublicKey() (*rsa.PublicKey, error) {
	pub, err := k.decode()
	if err != nil {
		return nil, err
	}
	if pub.N.BitLen() < MinRSABits {
		return nil, fmt.Errorf("ssf: the modulus has %d bits, the minimum is %d", pub.N.BitLen(), MinRSABits)
	}
	return pub, nil
}

// RSAKeySource supplies the RSA keys a transmitter signs SETs with, by kid. A
// [KeySource] that also implements it can serve an issuer that allows
// [AlgRS256]; [JWKS] and [StaticKeySet] do.
type RSAKeySource interface {
	// RSAKey returns the RSA key with the given kid. A kid with no usable RSA
	// key, an EC key under that kid included, is [ErrUnknownKey]; any other
	// error means the source cannot answer now.
	RSAKey(ctx context.Context, kid string) (RSAKey, error)
}

// StaticKeySet is a [KeySource] and an [RSAKeySource] over fixed
// configuration: the EC P-256 keys served to ES256 and the RSA keys served to
// RS256. [NewReceiver] checks each key as a verification would use it, its
// size included, and refuses a set that holds a key that is not usable or a
// kid that two keys of one type share. Used without a receiver, the set
// trusts such a kid for neither key of that type. An EC key and an RSA key
// may share a kid (RFC 7517 section 4.5), each lookup serving the key of its
// type.
type StaticKeySet struct {
	EC  []jws.JWK
	RSA []RSAKey
}

// Key implements [KeySource]. It serves EC keys only.
func (s StaticKeySet) Key(_ context.Context, kid string) (jws.JWK, error) {
	if k, ok := unique(s.EC, kid, func(k jws.JWK) string { return k.Kid }); ok {
		return k, nil
	}
	return jws.JWK{}, ErrUnknownKey
}

// RSAKey implements [RSAKeySource]. It serves RSA keys only.
func (s StaticKeySet) RSAKey(_ context.Context, kid string) (RSAKey, error) {
	if k, ok := unique(s.RSA, kid, func(k RSAKey) string { return k.Kid }); ok {
		return k, nil
	}
	return RSAKey{}, ErrUnknownKey
}

// validateStatic checks every key of a [StaticKeySet] or [StaticKeys] as a
// verification uses it: each EC key as an ES256 key of the profile, each RSA
// key by [RSAKey.PublicKey], and that no two keys of one type share a kid. A
// static key that could never verify, or a kid that names two keys of one
// type, is a configuration error, not a rejection of each SET it signs. Other
// sources are not checked.
func validateStatic(src KeySource) error {
	var s StaticKeySet
	switch ks := src.(type) {
	case StaticKeySet:
		s = ks
	case *StaticKeySet:
		if ks == nil {
			return nil
		}
		s = *ks
	case StaticKeys:
		s.EC = ks
	case *StaticKeys:
		if ks == nil {
			return nil
		}
		s.EC = *ks
	default:
		return nil
	}
	ecKids := map[string]bool{}
	for i, k := range s.EC {
		if _, err := publicKey(k); err != nil {
			return fmt.Errorf("static EC key %d (kid %q) is not usable: %w", i, k.Kid, err)
		}
		if ecKids[k.Kid] {
			return fmt.Errorf("static EC key %d: kid %q names another EC key", i, k.Kid)
		}
		ecKids[k.Kid] = true
	}
	rsaKids := map[string]bool{}
	for i, k := range s.RSA {
		if _, err := k.PublicKey(); err != nil {
			return fmt.Errorf("static RSA key %d (kid %q) is not usable: %w", i, k.Kid, err)
		}
		if rsaKids[k.Kid] {
			return fmt.Errorf("static RSA key %d: kid %q names another RSA key", i, k.Kid)
		}
		rsaKids[k.Kid] = true
	}
	return nil
}

// unique finds the one key of keys, all of one type, with kid. ok is false
// when no key or more than one has the kid.
func unique[K any](keys []K, kid string, kidOf func(K) string) (found K, ok bool) {
	n := 0
	for _, k := range keys {
		if kidOf(k) == kid {
			found, n = k, n+1
		}
	}
	if n != 1 {
		var zero K
		return zero, false
	}
	return found, true
}

// verifyRS256 verifies an RSASSA-PKCS1-v1_5 signature with SHA-256 (RFC 7518
// section 3.3; RFC 8017 section 8.2.2): the signature is as long as the
// modulus. It returns nil when the signature verifies, errBadSignature when
// it does not, and another error when crypto/rsa refuses the key itself, as
// it does under GODEBUG=fips140=only for keys that RFC 7518 allows but the
// FIPS 140 module does not (an odd modulus size, an exponent of at most
// 2^16).
func verifyRS256(pub *rsa.PublicKey, signingInput string, sig []byte) error {
	if len(sig) != (pub.N.BitLen()+7)/8 {
		return errBadSignature
	}
	digest := sha256.Sum256([]byte(signingInput))
	err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, rsa.ErrVerification):
		return errBadSignature
	case fips140.Enforced():
		return fmt.Errorf("the key is refused by the FIPS 140 module: %w", err)
	default:
		return fmt.Errorf("the key is refused by crypto/rsa: %w", err)
	}
}

// errBadSignature is a signature that does not verify under its key.
var errBadSignature = errors.New("the signature does not verify")
