package ssf

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"slices"
	"strings"
	"time"

	"hop.top/pact-go/core/strictjson"
)

type jsonRaw = json.RawMessage

func unmarshalString(raw jsonRaw, s *string) error { return json.Unmarshal(raw, s) }

// token is a verified SET.
type token struct {
	issuer, jti string
	issuedAt    time.Time
	subID       jsonRaw
	events      map[string]map[string]jsonRaw
	digest      string
}

// typ values of a SET (RFC 8417 section 2.3; RFC 7515 section 4.1.9).
var setTyps = []string{"secevent+jwt", "application/secevent+jwt"}

// header members the receiver never follows: it takes keys from configuration
// and nowhere else (the profile of package jws, draft 7.2).
var forbiddenHeader = []string{"crit", "b64", "jku", "x5u", "x5c", "jwk"}

// verify checks a compact SET in this order: size and form; the protected
// header (explicit typing, no key-by-reference member); the issuer the
// unauthenticated payload names, which only selects configuration; an alg
// that issuer allows; the key and the signature; then the claims of the
// authenticated payload (RFC 8417 section 2.2; SSF 1.0 section 4.1: jti, iat,
// aud, no sub, no exp, one or more events). The token is returned with the error once the issuer and
// jti are authenticated, so a rejection can be reported against them.
func (r *Receiver) verify(ctx context.Context, compact string) (*token, error) {
	if len(compact) > r.c.MaxBytes {
		return nil, reject(CodeInvalidRequest, "the SET is %d bytes, over the limit of %d", len(compact), r.c.MaxBytes)
	}
	parts := strings.Split(compact, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" {
		return nil, reject(CodeInvalidRequest, "not a compact JWS with a payload")
	}
	rawHeader, err := segment(parts[0])
	if err != nil {
		return nil, reject(CodeInvalidRequest, "protected header: %v", err)
	}
	var header map[string]jsonRaw
	if err := strictjson.Unmarshal(rawHeader, strictjson.Limits{}, &header); err != nil {
		return nil, reject(CodeInvalidRequest, "protected header is not a strict JSON object")
	}
	for _, name := range forbiddenHeader {
		if _, ok := header[name]; ok {
			return nil, reject(CodeInvalidRequest, "protected header member %s is not accepted", name)
		}
	}
	typ, _ := headerString(header, "typ")
	if !sliceContains(setTyps, typ) {
		// A JWT of another kind, such as an ID token or an access token, is not
		// a SET (RFC 8417 section 4; SSF 1.0 section 4.1.1).
		return nil, reject(CodeInvalidRequest, "typ is not secevent+jwt")
	}
	alg, ok := headerString(header, "alg")
	if !ok {
		return nil, reject(CodeInvalidRequest, "no alg")
	}
	rawPayload, err := segment(parts[1])
	if err != nil {
		return nil, reject(CodeInvalidRequest, "payload: %v", err)
	}
	var claims map[string]jsonRaw
	if err := strictjson.Unmarshal(rawPayload, strictjson.Limits{}, &claims); err != nil {
		return nil, reject(CodeInvalidRequest, "payload is not a strict JSON object")
	}
	var iss string
	if json.Unmarshal(claims["iss"], &iss) != nil || iss == "" {
		return nil, reject(CodeInvalidRequest, "no iss")
	}
	issuer, ok := r.issuers[iss]
	if !ok {
		return nil, reject(CodeInvalidIssuer, "the issuer is not configured")
	}
	if !slices.Contains(issuer.Algorithms, alg) {
		return nil, reject(CodeInvalidKey, "alg %q is not accepted for this issuer", alg)
	}
	sig, err := segment(parts[2])
	if err != nil {
		return nil, reject(CodeInvalidKey, "the signature is not canonical base64url")
	}
	kid, ok := headerString(header, "kid")
	if !ok || kid == "" {
		return nil, reject(CodeInvalidKey, "no kid")
	}
	if err := r.verifySignature(ctx, issuer, alg, kid, parts[0]+"."+parts[1], sig); err != nil {
		return nil, err
	}

	// From here the payload is the transmitter's.
	t := &token{issuer: iss}
	// The digest covers the payload as received, not the signature: ES256
	// signatures differ between two signings of one payload, and a SET
	// signed again is still the same SET.
	sum := sha256.Sum256(rawPayload)
	t.digest = hex.EncodeToString(sum[:])
	if json.Unmarshal(claims["jti"], &t.jti) != nil || t.jti == "" {
		return nil, reject(CodeInvalidRequest, "no jti")
	}
	fail := func(code, format string, args ...any) (*token, error) {
		return t, reject(code, format, args...)
	}
	if _, present := claims["sub"]; present {
		return fail(CodeInvalidRequest, "a SET with an SSF event has no sub claim")
	}
	if _, present := claims["exp"]; present {
		return fail(CodeInvalidRequest, "a SET has no exp claim")
	}
	var aud []string
	if json.Unmarshal(claims["aud"], &aud) != nil {
		var one string
		if json.Unmarshal(claims["aud"], &one) != nil {
			return fail(CodeInvalidAudience, "aud is not a string or an array of strings")
		}
		aud = []string{one}
	}
	if !sliceContains(aud, issuer.Audience) {
		return fail(CodeInvalidAudience, "aud does not name this receiver")
	}
	iat, err := numericDate(claims["iat"])
	if err != nil {
		return fail(CodeInvalidRequest, "iat: %v", err)
	}
	t.issuedAt = iat
	now := r.c.Clock.Now()
	if iat.After(now.Add(r.skew)) {
		return fail(CodeInvalidRequest, "iat is later than now plus the clock skew")
	}
	if iat.Before(now.Add(-r.c.MaxAge)) {
		return fail(CodeInvalidRequest, "iat is older than the accepted age")
	}
	var events map[string]jsonRaw
	if json.Unmarshal(claims["events"], &events) != nil || len(events) == 0 {
		return fail(CodeInvalidRequest, "events is not an object with at least one event")
	}
	t.events = make(map[string]map[string]jsonRaw, len(events))
	for typ, raw := range events {
		var payload map[string]jsonRaw
		if json.Unmarshal(raw, &payload) != nil || payload == nil {
			return fail(CodeInvalidRequest, "the payload of %s is not a JSON object", short(typ))
		}
		t.events[typ] = payload
	}
	t.subID = claims["sub_id"]
	return t, nil
}

// verifySignature looks up the key of the issuer that the alg names, by kid,
// and verifies the signature over the signing input. The alg is one the issuer
// allows; the key set is asked for a key of the alg's type, and a key of
// another type is refused, so the header cannot select the algorithm a key is
// used with. Every refusal is invalid_key; a key source that cannot answer is
// an error that is not an *[Error].
func (r *Receiver) verifySignature(ctx context.Context, issuer Issuer, alg, kid, signingInput string, sig []byte) error {
	unusable := func(err error) error {
		if errors.Is(err, ErrUnknownKey) {
			return reject(CodeInvalidKey, "no %s key %q for this issuer", alg, kid)
		}
		return fmt.Errorf("ssf: keys of %s: %w", issuer.Issuer, err)
	}
	switch alg {
	case AlgES256:
		if len(sig) != 64 {
			return reject(CodeInvalidKey, "the signature is not 64 octets")
		}
		jwk, err := issuer.Keys.Key(ctx, kid)
		if err != nil {
			return unusable(err)
		}
		pub, err := publicKey(jwk)
		if err != nil {
			return reject(CodeInvalidKey, "key %q is not usable: %v", kid, err)
		}
		if !verifyES256(pub, signingInput, sig) {
			return reject(CodeInvalidKey, "the signature does not verify")
		}
	case AlgRS256:
		src, ok := issuer.Keys.(RSAKeySource)
		if !ok {
			return reject(CodeInvalidKey, "the key source of this issuer has no RSA keys")
		}
		rk, err := src.RSAKey(ctx, kid)
		if err != nil {
			return unusable(err)
		}
		pub, err := rk.PublicKey()
		if err != nil {
			return reject(CodeInvalidKey, "key %q is not usable: %v", kid, err)
		}
		if err := verifyRS256(pub, signingInput, sig); errors.Is(err, errBadSignature) {
			return reject(CodeInvalidKey, "the signature does not verify")
		} else if err != nil {
			return reject(CodeInvalidKey, "key %q: %v", kid, err)
		}
	default:
		// Unreachable while an issuer can list only ES256 and RS256: the
		// last guard should another algorithm ever be allowed without a
		// branch of its own here, so that it fails closed.
		return reject(CodeInvalidKey, "alg %q is not accepted", alg)
	}
	return nil
}

// segment decodes one canonical base64url segment without padding, or fails.
func segment(s string) ([]byte, error) {
	if strings.ContainsAny(s, "\r\n=") {
		return nil, errors.New("not canonical base64url")
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil {
		return nil, errors.New("not canonical base64url")
	}
	return b, nil
}

func headerString(h map[string]jsonRaw, name string) (string, bool) {
	var s string
	if raw, ok := h[name]; !ok || json.Unmarshal(raw, &s) != nil {
		return "", false
	}
	return s, true
}

func sliceContains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// numericDate reads a JSON number of seconds (RFC 7519 section 2), dropping
// any fraction.
func numericDate(raw jsonRaw) (time.Time, error) {
	var f float64
	if len(raw) == 0 || json.Unmarshal(raw, &f) != nil || math.IsNaN(f) || f < 1 || f > 1e11 {
		return time.Time{}, errors.New("not a NumericDate in seconds")
	}
	return time.Unix(int64(f), 0), nil
}

// eventTime is the time the event occurred: event_timestamp (CAEP 1.0
// section 2) when the payload has it, else the issue time of the SET. An
// event cannot have occurred after its SET was issued, so a later
// event_timestamp, such as one written in milliseconds, is not conformant.
func eventTime(payload map[string]jsonRaw, iat time.Time, skew time.Duration) (time.Time, error) {
	raw, ok := payload["event_timestamp"]
	if !ok {
		return iat, nil
	}
	t, err := numericDate(raw)
	if err != nil {
		return time.Time{}, fmt.Errorf("event_timestamp: %w", err)
	}
	if t.After(iat.Add(skew)) {
		return time.Time{}, errors.New("event_timestamp is later than the SET's iat plus the clock skew")
	}
	return t, nil
}

// verifyES256 verifies a 64-octet R || S signature (RFC 7518 section 3.4).
func verifyES256(pub *ecdsa.PublicKey, signingInput string, sig []byte) bool {
	digest := sha256.Sum256([]byte(signingInput))
	return ecdsa.Verify(pub, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:]))
}
