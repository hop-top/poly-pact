package jws

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"slices"

	"hop.top/pact-go/core"
	"hop.top/pact-go/core/strictjson"
)

// JWK is a public key in JSON Web Key form (RFC 7517): an EC P-256 key (RFC
// 7518 section 6.2.1) or, where Ed25519 is negotiated, an OKP Ed25519 key
// (RFC 8037 section 2), which has no y. Kid, Alg and Use are optional; JSON
// encoding omits them, and y, when empty. A JWK built in Go is checked when
// it is used: by PublicKey, Ed25519PublicKey, Thumbprint, NewKeySet and the
// signers.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y,omitempty"`
	Kid string `json:"kid,omitempty"`
	Alg string `json:"alg,omitempty"`
	Use string `json:"use,omitempty"`
}

// privateMembers are the private key members of RFC 7518 section 6: EC d,
// RSA d, p, q, dp, dq, qi, oth, and the symmetric k.
var privateMembers = []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"}

// ParseJWK decodes a JWK and checks that it is a usable ES256 public key:
// a strict JSON object (draft 7.1) without private members, kty EC, crv
// P-256, x and y the canonical unpadded base64url of 32 octets each and
// together a point of the curve, alg and use, when present, ES256 and sig,
// and key_ops, when present, an array of distinct strings that names verify
// (RFC 7517 section 4.3). key_ops is checked, not kept: the JWK has no
// member for it. Members RFC 7517 does not define for this use are ignored
// (RFC 7517 section 4). It is the baseline: [Algorithms.ParseJWK] also
// accepts an Ed25519 key where that algorithm is negotiated.
func ParseJWK(data []byte) (JWK, error) {
	return parseJWK(data, nil)
}

func parseJWK(data []byte, algs Algorithms) (JWK, error) {
	var m map[string]json.RawMessage
	if err := strictjson.Unmarshal(data, strictjson.Limits{}, &m); err != nil {
		return JWK{}, fail(ErrJWKInvalid, "not a strict JSON object", err)
	}
	for _, name := range privateMembers {
		if _, ok := m[name]; ok {
			return JWK{}, fail(ErrJWKPrivate, "member "+name, nil)
		}
	}
	var k JWK
	for _, f := range []struct {
		name string
		dst  *string
	}{
		{"kty", &k.Kty}, {"crv", &k.Crv}, {"x", &k.X}, {"y", &k.Y},
		{"kid", &k.Kid}, {"alg", &k.Alg}, {"use", &k.Use},
	} {
		raw, ok := m[f.name]
		if !ok {
			continue
		}
		if err := strictjson.Unmarshal(raw, strictjson.Limits{}, f.dst); err != nil {
			return JWK{}, fail(ErrJWKInvalid, f.name+" is not a string", err)
		}
	}
	if _, err := k.check(algs); err != nil {
		return JWK{}, err
	}
	if raw, ok := m["key_ops"]; ok {
		if err := checkKeyOps(raw); err != nil {
			return JWK{}, err
		}
	}
	return k, nil
}

// checkKeyOps checks a key_ops member (RFC 7517 section 4.3): an array of
// strings, none twice ("Duplicate key operation values MUST NOT be
// present"), that names verify, the operation a trusted public key serves.
func checkKeyOps(raw json.RawMessage) error {
	var ops []string
	if err := strictjson.Unmarshal(raw, strictjson.Limits{}, &ops); err != nil {
		return fail(ErrJWKInvalid, "key_ops is not an array of strings", err)
	}
	for i, op := range ops {
		if slices.Contains(ops[:i], op) {
			return fail(ErrJWKInvalid, fmt.Sprintf("key_ops names %q twice", op), nil)
		}
	}
	if !slices.Contains(ops, "verify") {
		return fail(ErrJWKUsage, fmt.Sprintf("key_ops %q does not name verify", ops), nil)
	}
	return nil
}

// check returns the algorithm of the key after checking that algs accepts
// it, that the key material is valid for it, and that alg and use, when
// present, are that algorithm and sig.
func (k JWK) check(algs Algorithms) (string, error) {
	alg, err := k.Algorithm()
	if err != nil {
		return "", err
	}
	if !algs.Accepts(alg) {
		return "", fail(ErrJWKCurve, fmt.Sprintf("kty %q crv %q: %s is not negotiated", k.Kty, k.Crv, alg), nil)
	}
	switch alg {
	case AlgES256:
		_, err = k.PublicKey()
	default:
		_, err = k.Ed25519PublicKey()
	}
	if err != nil {
		return "", err
	}
	return alg, k.checkUsage(alg)
}

// PublicKey checks kty, crv, x and y and returns the key. It does not look
// at Kid, Alg or Use.
func (k JWK) PublicKey() (*ecdsa.PublicKey, error) {
	if k.Kty != "EC" || k.Crv != "P-256" {
		return nil, fail(ErrJWKCurve, fmt.Sprintf("kty %q crv %q, want EC P-256", k.Kty, k.Crv), nil)
	}
	x, err := coordinate("x", k.X)
	if err != nil {
		return nil, err
	}
	y, err := coordinate("y", k.Y)
	if err != nil {
		return nil, err
	}
	point := make([]byte, 0, 65)
	point = append(point, 4)
	point = append(point, x...)
	point = append(point, y...)
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
	if err != nil {
		return nil, fail(ErrJWKOffCurve, "", err)
	}
	return pub, nil
}

func coordinate(name, s string) ([]byte, error) {
	b, err := decodeSegment(s)
	if err != nil {
		return nil, fail(ErrJWKInvalid, name+" is not canonical base64url", err)
	}
	if len(b) != 32 {
		return nil, fail(ErrJWKInvalid, fmt.Sprintf("%s has %d octets, want 32", name, len(b)), nil)
	}
	return b, nil
}

func (k JWK) checkUsage(alg string) error {
	if k.Alg != "" && k.Alg != alg {
		return fail(ErrJWKUsage, fmt.Sprintf("alg %q, want %s", k.Alg, alg), nil)
	}
	if k.Use != "" && k.Use != "sig" {
		return fail(ErrJWKUsage, fmt.Sprintf("use %q, want sig", k.Use), nil)
	}
	return nil
}

// PublicJWK returns the JWK of a P-256 public key, with x and y at their full
// 32 octets (RFC 7518 section 6.2.1.2) and no optional members.
func PublicJWK(pub *ecdsa.PublicKey) (JWK, error) {
	if pub == nil {
		return JWK{}, fail(ErrJWKInvalid, "nil public key", nil)
	}
	if pub.Curve != elliptic.P256() {
		return JWK{}, fail(ErrJWKCurve, "not a P-256 key", nil)
	}
	b, err := pub.Bytes()
	if err != nil {
		return JWK{}, fail(ErrJWKInvalid, "", err)
	}
	return JWK{Kty: "EC", Crv: "P-256", X: b64.EncodeToString(b[1:33]), Y: b64.EncodeToString(b[33:65])}, nil
}

// Thumbprint returns the RFC 7638 SHA-256 thumbprint of k: base64url, without
// padding, of SHA-256 over the required members in lexicographic order
// without white space, {"crv":...,"kty":...,"x":...,"y":...} for an EC key
// and {"crv":...,"kty":...,"x":...} for an OKP key (RFC 8037 Appendix A.3).
// Optional members do not enter it. k must be a valid P-256 key (see
// PublicKey) or Ed25519 key (see Ed25519PublicKey); the coordinates are
// hashed as written, which for a valid key is their canonical 43-character
// form.
func Thumbprint(k JWK) (core.Digest, error) {
	alg, err := k.Algorithm()
	if err != nil {
		return "", err
	}
	// The values are base64url and fixed ASCII names, so nothing needs JSON
	// escaping (RFC 7638 section 3.3).
	var input string
	switch alg {
	case AlgES256:
		if _, err := k.PublicKey(); err != nil {
			return "", err
		}
		input = `{"crv":"` + k.Crv + `","kty":"` + k.Kty + `","x":"` + k.X + `","y":"` + k.Y + `"}`
	default:
		if _, err := k.Ed25519PublicKey(); err != nil {
			return "", err
		}
		input = `{"crv":"` + k.Crv + `","kty":"` + k.Kty + `","x":"` + k.X + `"}`
	}
	sum := sha256.Sum256([]byte(input))
	return core.Digest(b64.EncodeToString(sum[:])), nil
}
