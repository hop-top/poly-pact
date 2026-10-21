package jws

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"

	"hop.top/pact-go/core"
	"hop.top/pact-go/core/strictjson"
)

// DefaultMaxCompactBytes bounds a compact JWS before any decoding: 360448
// bytes, the draft 20.1 transport frame minimum, which holds the base64url of
// a 256 KiB payload (349526) plus 10922 bytes for the JOSE header and
// signature.
const DefaultMaxCompactBytes = 360448

// Header is the protected header of a PACT JWS. All header fields are
// protected (draft 7.2); there is no unprotected header.
type Header struct {
	// Alg is ES256 or, where it is negotiated, Ed25519 (draft 7.2). Sign and
	// SignEd25519 accept it empty.
	Alg string
	// Typ is a typ of the draft 7.3 table.
	Typ string
	// Kid names the signing key within the trusted key set of a
	// service-signed artifact. For a holder-signed artifact it is optional
	// and plays no part in key selection.
	Kid string
	// JWK is the embedded public key of a holder-signed artifact, nil
	// otherwise.
	JWK *JWK
}

// ParsedJWS is a verified compact JWS.
type ParsedJWS struct {
	// Compact is the input, unchanged.
	Compact string
	// Header holds the protected header members the profile defines.
	Header Header
	// Role is the signer role of Header.Typ.
	Role Role
	// RawHeader and Payload are the decoded segments exactly as received.
	// Decode the payload with strictjson into the artifact type; compute
	// digests over these bytes or over Compact, never over a re-encoding.
	RawHeader []byte
	Payload   []byte
	// SigningInput is the received text the signature covers: the compact
	// serialization up to its second period.
	SigningInput string
	// Signature is the 64 octets of the signature: R || S for ES256, the
	// RFC 8032 signature for Ed25519.
	Signature []byte
	// Key is the key that verified the signature and KeyThumbprint its RFC
	// 7638 thumbprint.
	Key           JWK
	KeyThumbprint core.Digest
}

// Verifier verifies compact JWS. The zero values of MaxCompactBytes and
// Limits select the defaults.
type Verifier struct {
	// Keys resolves the verification key. Required.
	Keys KeyResolver
	// Typ, when set, is the only typ accepted: the typ the caller's slot
	// expects (draft 7.2: validators check the artifact-specific typ).
	Typ string
	// MaxCompactBytes bounds the compact serialization; at most
	// DefaultMaxCompactBytes is the baseline.
	MaxCompactBytes int
	// Limits bounds the strict decoding of the protected header and payload.
	Limits strictjson.Limits
	// Algorithms are the algorithms the deployment has negotiated; nil is the
	// baseline, ES256 alone. The header alg must be one of them, and the key
	// that verifies the signature must be a key of that algorithm.
	Algorithms Algorithms
}

// Verify is Verifier{Keys: keys}.Verify(compact).
func Verify(compact string, keys KeyResolver) (ParsedJWS, error) {
	return Verifier{Keys: keys}.Verify(compact)
}

// Verify checks compact against the PACT JWS profile and the signature over
// its received signing input. See the package documentation for the order of
// the checks. On error the ParsedJWS is empty.
func (v Verifier) Verify(compact string) (ParsedJWS, error) {
	limit := v.MaxCompactBytes
	if limit <= 0 {
		limit = DefaultMaxCompactBytes
	}
	if len(compact) > limit {
		return ParsedJWS{}, fail(ErrCompactSize, fmt.Sprintf("%d bytes, limit %d", len(compact), limit), nil)
	}
	first := strings.IndexByte(compact, '.')
	last := strings.LastIndexByte(compact, '.')
	if first < 0 || first == last || strings.IndexByte(compact[first+1:last], '.') >= 0 {
		return ParsedJWS{}, fail(ErrCompactForm, "want three segments separated by two periods", nil)
	}
	h64, p64, s64 := compact[:first], compact[first+1:last], compact[last+1:]
	if h64 == "" {
		return ParsedJWS{}, fail(ErrCompactForm, "empty protected header", nil)
	}

	rawHeader, err := decodeSegment(h64)
	if err != nil {
		return ParsedJWS{}, fail(ErrBase64URL, "protected header", err)
	}
	h, members, err := parseHeader(rawHeader, v.Limits, v.Algorithms)
	if err != nil {
		return ParsedJWS{}, err
	}
	if v.Typ != "" && h.Typ != v.Typ {
		return ParsedJWS{}, fail(ErrTypMismatch, fmt.Sprintf("typ %q, want %q", h.Typ, v.Typ), nil)
	}
	role, _ := TypRole(h.Typ)
	rawJWK, hasJWK := members["jwk"]
	if role == RoleHolder {
		if !hasJWK {
			return ParsedJWS{}, fail(ErrJWKMissing, "a holder-signed artifact embeds its public jwk", nil)
		}
		k, err := v.Algorithms.ParseJWK(rawJWK)
		if err != nil {
			return ParsedJWS{}, err
		}
		if err := matchAlg(h.Alg, k); err != nil {
			return ParsedJWS{}, err
		}
		h.JWK = &k
	} else {
		if hasJWK {
			return ParsedJWS{}, fail(ErrJWKUnexpected, fmt.Sprintf("typ %s is verified by kid, not by an embedded jwk", h.Typ), nil)
		}
		if h.Kid == "" {
			return ParsedJWS{}, fail(ErrKidMissing, "", nil)
		}
	}

	if p64 == "" {
		return ParsedJWS{}, fail(ErrPayloadDetached, "", nil)
	}
	payload, err := decodeSegment(p64)
	if err != nil {
		return ParsedJWS{}, fail(ErrBase64URL, "payload", err)
	}
	var object map[string]json.RawMessage
	if err := strictjson.Unmarshal(payload, v.Limits, &object); err != nil {
		return ParsedJWS{}, fail(ErrPayloadJSON, "", err)
	}

	sig, err := decodeSegment(s64)
	if err != nil {
		return ParsedJWS{}, fail(ErrBase64URL, "signature", err)
	}
	if len(sig) != 64 {
		return ParsedJWS{}, fail(ErrSignatureLength, fmt.Sprintf("%d octets, want 64", len(sig)), nil)
	}

	key, err := v.resolve(KeyRequest{Typ: h.Typ, Role: role, Kid: h.Kid, Header: rawHeader, Payload: payload}, h.JWK)
	if err != nil {
		return ParsedJWS{}, err
	}
	if err := matchAlg(h.Alg, key.jwk); err != nil {
		return ParsedJWS{}, err
	}
	signingInput := compact[:last]
	var valid bool
	switch key.alg {
	case AlgES256:
		valid = verifyES256(key.pub, signingInput, sig)
	case AlgEd25519:
		valid = verifyEd25519(key.ed, signingInput, sig)
	}
	if !valid {
		return ParsedJWS{}, fail(ErrSignatureInvalid, "", nil)
	}
	return ParsedJWS{
		Compact:       compact,
		Header:        h,
		Role:          role,
		RawHeader:     rawHeader,
		Payload:       payload,
		SigningInput:  signingInput,
		Signature:     sig,
		Key:           key.jwk,
		KeyThumbprint: key.thumbprint,
	}, nil
}

// prohibited are the header members the profile rejects, in the order
// checked.
var prohibited = []struct {
	name   string
	reason Reason
}{
	{"crit", ErrHeaderCrit},
	{"b64", ErrHeaderB64},
	{"jku", ErrHeaderJKU},
	{"x5u", ErrHeaderX5U},
	{"x5c", ErrHeaderX5C},
}

// matchAlg checks that the header alg is the algorithm of the checked key k:
// a key serves exactly one algorithm (RFC 9864 section 2.2, RFC 8037 section
// 2), so an Ed25519 header never verifies under a P-256 key, nor ES256 under
// an Ed25519 key.
func matchAlg(alg string, k JWK) error {
	keyAlg, err := k.Algorithm()
	if err != nil {
		return err
	}
	if keyAlg == alg {
		return nil
	}
	kid := ""
	if k.Kid != "" {
		kid = fmt.Sprintf(" (kid %q)", k.Kid)
	}
	return fail(ErrJWKUsage, fmt.Sprintf("alg %s, but the key%s is kty %s crv %s, a key for %s", alg, kid, k.Kty, k.Crv, keyAlg), nil)
}

// parseHeader decodes the protected header strictly and checks the members
// that do not depend on the signer role: alg must be one of algs. Members
// the profile does not define are ignored (RFC 7515 section 4), except the
// prohibited ones.
func parseHeader(raw []byte, limits strictjson.Limits, algs Algorithms) (Header, map[string]json.RawMessage, error) {
	var m map[string]json.RawMessage
	if err := strictjson.Unmarshal(raw, limits, &m); err != nil {
		return Header{}, nil, fail(ErrHeaderJSON, "", err)
	}
	for _, p := range prohibited {
		if _, ok := m[p.name]; ok {
			return Header{}, nil, fail(p.reason, "member "+p.name, nil)
		}
	}
	var h Header
	alg, ok := stringMember(m, "alg")
	if !ok || !algs.Accepts(alg) {
		return Header{}, nil, fail(ErrAlgUnsupported, describe("alg", m), nil)
	}
	h.Alg = alg
	typ, ok := stringMember(m, "typ")
	if _, known := TypRole(typ); !ok || !known {
		return Header{}, nil, fail(ErrTypUnsupported, describe("typ", m), nil)
	}
	h.Typ = typ
	if _, present := m["kid"]; present {
		kid, ok := stringMember(m, "kid")
		if !ok {
			return Header{}, nil, fail(ErrHeaderJSON, "kid is not a string", nil)
		}
		h.Kid = kid
	}
	return h, m, nil
}

// stringMember returns member name of m when it is present and a JSON string.
func stringMember(m map[string]json.RawMessage, name string) (string, bool) {
	raw, ok := m[name]
	if !ok {
		return "", false
	}
	var s string
	if err := strictjson.Unmarshal(raw, strictjson.Limits{}, &s); err != nil {
		return "", false
	}
	return s, true
}

func describe(name string, m map[string]json.RawMessage) string {
	raw, ok := m[name]
	if !ok {
		return "no " + name
	}
	const max = 64
	if len(raw) > max {
		raw = raw[:max]
	}
	return fmt.Sprintf("%s %s", name, raw)
}

func (v Verifier) resolve(req KeyRequest, embedded *JWK) (trustedKey, error) {
	if v.Keys == nil {
		return trustedKey{}, fail(ErrKeyUnavailable, "no key resolver", nil)
	}
	if req.Role == RoleHolder {
		want, err := v.Keys.HolderJKT(req)
		if err != nil {
			return trustedKey{}, fail(ErrKeyUnavailable, "holder_jkt", err)
		}
		if want == "" {
			return trustedKey{}, fail(ErrKeyUnavailable, "no expected holder_jkt", nil)
		}
		k, err := newTrustedKey(*embedded, v.Algorithms)
		if err != nil {
			return trustedKey{}, err
		}
		if k.thumbprint != want {
			return trustedKey{}, fail(ErrHolderJKTMismatch, fmt.Sprintf("jwk thumbprint %s, expected %s", k.thumbprint, want), nil)
		}
		return k, nil
	}
	set, err := v.Keys.TrustedKeys(req)
	if err != nil {
		return trustedKey{}, fail(ErrKeyUnavailable, "key set for "+string(req.Role), err)
	}
	k, ok := set.lookup(req.Kid)
	if !ok {
		return trustedKey{}, fail(ErrKidUnknown, fmt.Sprintf("kid %q is not in the key set trusted for %s", req.Kid, req.Role), nil)
	}
	return k, nil
}

// verifyES256 verifies a 64-octet R || S signature (RFC 7518 section 3.4)
// over the signing input. R and S outside [1, n-1] fail. A high S is accepted:
// the verification equation holds for S and n-S alike, and neither RFC 7518
// nor the draft adds a low-S rule.
func verifyES256(pub *ecdsa.PublicKey, signingInput string, sig []byte) bool {
	if len(sig) != 64 {
		return false
	}
	digest := sha256.Sum256([]byte(signingInput))
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	return ecdsa.Verify(pub, digest[:], r, s)
}

// wireHeader fixes the member order Sign writes: alg, typ, kid, jwk, as in
// draft Appendix C.
type wireHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid,omitempty"`
	JWK *JWK   `json:"jwk,omitempty"`
}

// Sign returns the compact JWS of payload under key with the protected
// header h. Alg may be empty and is always written as ES256. For a
// holder-signed typ the header embeds h.JWK, or the key's public JWK when
// h.JWK is nil; h.JWK must be that public key. Every other typ needs h.Kid
// and no h.JWK. payload must be a strict JSON object and is signed exactly as
// given, never re-encoded. ECDSA signing is randomized, so two calls give
// different signatures; S is always the low value of the pair (S, n-S).
func Sign(h Header, payload []byte, key *ecdsa.PrivateKey) (string, error) {
	if key == nil {
		return "", fail(ErrSigningKey, "nil key", nil)
	}
	pubJWK, err := PublicJWK(&key.PublicKey)
	if err != nil {
		return "", fail(ErrSigningKey, "not a P-256 key", err)
	}
	return sign(h, payload, AlgES256, pubJWK, func(signingInput string) ([]byte, error) {
		digest := sha256.Sum256([]byte(signingInput))
		r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
		if err != nil {
			return nil, err
		}
		if n := elliptic.P256().Params().N; s.Cmp(new(big.Int).Rsh(n, 1)) > 0 {
			s.Sub(n, s)
		}
		sig := make([]byte, 64)
		r.FillBytes(sig[:32])
		s.FillBytes(sig[32:])
		return sig, nil
	})
}

// SignEd25519 is Sign for a deployment that has negotiated Ed25519 (draft
// 7.2): the header alg is written as Ed25519 (RFC 9864 section 2.2), Alg may
// be empty or Ed25519, and an embedded holder jwk is the OKP key of RFC 8037
// section 2. Ed25519 signatures are deterministic (RFC 8032 section 5.1.6),
// so the same input always gives the same compact JWS.
func SignEd25519(h Header, payload []byte, key ed25519.PrivateKey) (string, error) {
	if len(key) != ed25519.PrivateKeySize {
		return "", fail(ErrSigningKey, fmt.Sprintf("%d-octet Ed25519 private key, want %d", len(key), ed25519.PrivateKeySize), nil)
	}
	pubJWK, err := PublicEd25519JWK(key.Public().(ed25519.PublicKey))
	if err != nil {
		return "", fail(ErrSigningKey, "", err)
	}
	return sign(h, payload, AlgEd25519, pubJWK, func(signingInput string) ([]byte, error) {
		return ed25519.Sign(key, []byte(signingInput)), nil
	})
}

// sign writes the header for alg, checks h against the signer's public JWK
// pubJWK and signs the signing input with signFn.
func sign(h Header, payload []byte, alg string, pubJWK JWK, signFn func(string) ([]byte, error)) (string, error) {
	if h.Alg != "" && h.Alg != alg {
		return "", fail(ErrAlgUnsupported, "alg "+h.Alg, nil)
	}
	role, ok := TypRole(h.Typ)
	if !ok {
		return "", fail(ErrTypUnsupported, "typ "+h.Typ, nil)
	}
	wh := wireHeader{Alg: alg, Typ: h.Typ, Kid: h.Kid}
	if role == RoleHolder {
		embedded := pubJWK
		if h.JWK != nil {
			given, err := Thumbprint(*h.JWK)
			if err != nil {
				return "", err
			}
			if err := h.JWK.checkUsage(alg); err != nil {
				return "", err
			}
			own, err := Thumbprint(pubJWK)
			if err != nil {
				return "", fail(ErrSigningKey, "", err)
			}
			if given != own {
				return "", fail(ErrSigningKey, "jwk is not the public key of the signing key", nil)
			}
			embedded = *h.JWK
		}
		wh.JWK = &embedded
	} else {
		if h.JWK != nil {
			return "", fail(ErrJWKUnexpected, fmt.Sprintf("typ %s is verified by kid, not by an embedded jwk", h.Typ), nil)
		}
		if h.Kid == "" {
			return "", fail(ErrKidMissing, "", nil)
		}
	}
	var object map[string]json.RawMessage
	if err := strictjson.Unmarshal(payload, strictjson.Limits{}, &object); err != nil {
		return "", fail(ErrPayloadJSON, "", err)
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(wh); err != nil {
		return "", fail(ErrHeaderJSON, "", err)
	}
	header := bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
	signingInput := b64.EncodeToString(header) + "." + b64.EncodeToString(payload)
	sig, err := signFn(signingInput)
	if err != nil {
		return "", fail(ErrSigningKey, "", err)
	}
	return signingInput + "." + b64.EncodeToString(sig), nil
}
