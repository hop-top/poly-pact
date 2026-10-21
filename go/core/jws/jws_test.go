package jws_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"math/big"
	"strings"
	"testing"

	"hop.top/pact-go/core"
	"hop.top/pact-go/core/jws"
	"hop.top/pact-go/core/strictjson"
)

const evidenceHeader = `{"alg":"ES256","typ":"pact-evidence+jwt","kid":"test-issuer-key-1"}`

const smallPayload = `{"pact_version":"0.1","jti":"unit"}`

// TestVerifyRejectsHeaders covers each header the draft (7.2) or the task
// prohibits. Every input carries a valid ES256 signature by the issuer key
// over its own signing input, so the rejection comes from the header alone.
func TestVerifyRejectsHeaders(t *testing.T) {
	issuer := scalarKey(t, 2)
	holder := scalarKey(t, 1)
	hj := fixtureJWK(t, "holder")
	hjwk := `{"kty":"EC","crv":"P-256","x":"` + hj.X + `","y":"` + hj.Y + `"}`
	cases := []struct {
		name   string
		header string
		key    *ecdsa.PrivateKey
		want   jws.Reason
	}{
		{"alg none", `{"alg":"none","typ":"pact-evidence+jwt","kid":"test-issuer-key-1"}`, issuer, jws.ErrAlgUnsupported},
		{"alg HS256", `{"alg":"HS256","typ":"pact-evidence+jwt","kid":"test-issuer-key-1"}`, issuer, jws.ErrAlgUnsupported},
		{"alg HS512", `{"alg":"HS512","typ":"pact-evidence+jwt","kid":"test-issuer-key-1"}`, issuer, jws.ErrAlgUnsupported},
		{"alg RS256", `{"alg":"RS256","typ":"pact-evidence+jwt","kid":"test-issuer-key-1"}`, issuer, jws.ErrAlgUnsupported},
		{"alg PS256", `{"alg":"PS256","typ":"pact-evidence+jwt","kid":"test-issuer-key-1"}`, issuer, jws.ErrAlgUnsupported},
		{"alg EdDSA", `{"alg":"EdDSA","typ":"pact-evidence+jwt","kid":"test-issuer-key-1"}`, issuer, jws.ErrAlgUnsupported},
		{"alg Ed25519 not in phase 1", `{"alg":"Ed25519","typ":"pact-evidence+jwt","kid":"test-issuer-key-1"}`, issuer, jws.ErrAlgUnsupported},
		{"alg es256 lowercase", `{"alg":"es256","typ":"pact-evidence+jwt","kid":"test-issuer-key-1"}`, issuer, jws.ErrAlgUnsupported},
		{"alg missing", `{"typ":"pact-evidence+jwt","kid":"test-issuer-key-1"}`, issuer, jws.ErrAlgUnsupported},
		{"alg not a string", `{"alg":["ES256"],"typ":"pact-evidence+jwt","kid":"test-issuer-key-1"}`, issuer, jws.ErrAlgUnsupported},
		{"jku", `{"alg":"ES256","typ":"pact-evidence+jwt","kid":"test-issuer-key-1","jku":"https://trust.example/jwks"}`, issuer, jws.ErrHeaderJKU},
		{"x5u", `{"alg":"ES256","typ":"pact-evidence+jwt","kid":"test-issuer-key-1","x5u":"https://trust.example/c.pem"}`, issuer, jws.ErrHeaderX5U},
		{"x5c", `{"alg":"ES256","typ":"pact-evidence+jwt","kid":"test-issuer-key-1","x5c":["MIIB"]}`, issuer, jws.ErrHeaderX5C},
		{"crit", `{"alg":"ES256","typ":"pact-evidence+jwt","kid":"test-issuer-key-1","crit":["ext"],"ext":1}`, issuer, jws.ErrHeaderCrit},
		{"crit empty", `{"alg":"ES256","typ":"pact-evidence+jwt","kid":"test-issuer-key-1","crit":[]}`, issuer, jws.ErrHeaderCrit},
		{"b64 false", `{"alg":"ES256","typ":"pact-evidence+jwt","kid":"test-issuer-key-1","b64":false}`, issuer, jws.ErrHeaderB64},
		{"b64 false with crit", `{"alg":"ES256","typ":"pact-evidence+jwt","kid":"test-issuer-key-1","b64":false,"crit":["b64"]}`, issuer, jws.ErrHeaderCrit},
		{"typ missing", `{"alg":"ES256","kid":"test-issuer-key-1"}`, issuer, jws.ErrTypUnsupported},
		{"typ JWT", `{"alg":"ES256","typ":"JWT","kid":"test-issuer-key-1"}`, issuer, jws.ErrTypUnsupported},
		{"typ unlisted", `{"alg":"ES256","typ":"pact-profile+jwt","kid":"test-issuer-key-1"}`, issuer, jws.ErrTypUnsupported},
		{"typ not a string", `{"alg":"ES256","typ":7,"kid":"test-issuer-key-1"}`, issuer, jws.ErrTypUnsupported},
		{"kid missing", `{"alg":"ES256","typ":"pact-evidence+jwt"}`, issuer, jws.ErrKidMissing},
		{"kid empty", `{"alg":"ES256","typ":"pact-evidence+jwt","kid":""}`, issuer, jws.ErrKidMissing},
		{"kid not a string", `{"alg":"ES256","typ":"pact-evidence+jwt","kid":1}`, issuer, jws.ErrHeaderJSON},
		{"kid unknown", `{"alg":"ES256","typ":"pact-evidence+jwt","kid":"test-issuer-key-2"}`, issuer, jws.ErrKidUnknown},
		{"jwk on a service-signed typ", `{"alg":"ES256","typ":"pact-evidence+jwt","kid":"test-issuer-key-1","jwk":` + hjwk + `}`, issuer, jws.ErrJWKUnexpected},
		{"duplicate member", `{"alg":"ES256","typ":"pact-evidence+jwt","kid":"test-issuer-key-1","alg":"ES256"}`, issuer, jws.ErrHeaderJSON},
		{"not an object", `["ES256"]`, issuer, jws.ErrHeaderJSON},
		{"not JSON", `alg=ES256`, issuer, jws.ErrHeaderJSON},
		{"lone surrogate", `{"alg":"ES256","typ":"pact-evidence+jwt","kid":"test-issuer-key-1","x":"\ud800"}`, issuer, jws.ErrHeaderJSON},
		{"holder jwk missing", `{"alg":"ES256","typ":"pact-presentation+jwt","kid":"test-holder-key-1"}`, holder, jws.ErrJWKMissing},
		{"holder jwk not an object", `{"alg":"ES256","typ":"pact-presentation+jwt","jwk":"x"}`, holder, jws.ErrJWKInvalid},
		{"holder jwk with d", `{"alg":"ES256","typ":"pact-presentation+jwt","jwk":{"kty":"EC","crv":"P-256","x":"` + hj.X + `","y":"` + hj.Y + `","d":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE"}}`, holder, jws.ErrJWKPrivate},
		{"holder jwk P-384", `{"alg":"ES256","typ":"pact-presentation+jwt","jwk":{"kty":"EC","crv":"P-384","x":"` + hj.X + `","y":"` + hj.Y + `"}}`, holder, jws.ErrJWKCurve},
		{"holder jwk RSA", `{"alg":"ES256","typ":"pact-presentation+jwt","jwk":{"kty":"RSA","n":"AQAB","e":"AQAB"}}`, holder, jws.ErrJWKCurve},
		{"holder jwk off curve", `{"alg":"ES256","typ":"pact-presentation+jwt","jwk":{"kty":"EC","crv":"P-256","x":"` + hj.X + `","y":"` + fixtureJWK(t, "issuer").Y + `"}}`, holder, jws.ErrJWKOffCurve},
		{"holder jwk short x", `{"alg":"ES256","typ":"pact-presentation+jwt","jwk":{"kty":"EC","crv":"P-256","x":"` + hj.X[:42] + `","y":"` + hj.Y + `"}}`, holder, jws.ErrJWKInvalid},
		{"holder jwk of another key", `{"alg":"ES256","typ":"pact-presentation+jwt","jwk":` + jwkJSON(t, fixtureJWK(t, "adversarial")) + `}`, scalarKey(t, 3), jws.ErrHolderJKTMismatch},
	}
	res := issuerResolver(t)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := jws.Verify(rawCompact(t, c.header, smallPayload, c.key), res)
			wantReason(t, err, c.want)
		})
	}
}

func jwkJSON(t testing.TB, k jws.JWK) string {
	t.Helper()
	return `{"kty":"` + k.Kty + `","crv":"` + k.Crv + `","x":"` + k.X + `","y":"` + k.Y + `"}`
}

func TestVerifyRejectsCompactForm(t *testing.T) {
	issuer := scalarKey(t, 2)
	good := rawCompact(t, evidenceHeader, smallPayload, issuer)
	parts := strings.Split(good, ".")
	si := parts[0] + "." + parts[1]
	cases := []struct {
		name    string
		compact string
		want    jws.Reason
	}{
		{"two segments", si, jws.ErrCompactForm},
		{"four segments", good + ".AAAA", jws.ErrCompactForm},
		{"five segments (JWE shape)", parts[0] + ".." + parts[1] + ".." + parts[2], jws.ErrCompactForm},
		{"empty header", "." + parts[1] + "." + parts[2], jws.ErrCompactForm},
		{"empty string", "", jws.ErrCompactForm},
		{"detached payload", parts[0] + ".." + parts[2], jws.ErrPayloadDetached},
		{"empty signature", si + ".", jws.ErrSignatureLength},
		{"padded header", parts[0] + "=." + parts[1] + "." + parts[2], jws.ErrBase64URL},
		{"padded signature", good + "==", jws.ErrBase64URL},
		{"line feed in payload", parts[0] + "." + parts[1][:5] + "\n" + parts[1][5:] + "." + parts[2], jws.ErrBase64URL},
		{"carriage return in header", parts[0][:5] + "\r" + parts[0][5:] + "." + parts[1] + "." + parts[2], jws.ErrBase64URL},
		{"space in signature", si + "." + parts[2][:5] + " " + parts[2][5:], jws.ErrBase64URL},
		{"standard alphabet", si + "." + strings.NewReplacer("-", "+", "_", "/").Replace(parts[2]) + "+", jws.ErrBase64URL},
		{"unencoded payload", parts[0] + `.{"jti":"unit"}.` + parts[2], jws.ErrBase64URL},
		{"unencoded payload with a period", parts[0] + "." + smallPayload + "." + parts[2], jws.ErrCompactForm},
		{"length 1 mod 4", si + "." + parts[2] + "AAA", jws.ErrBase64URL},
		{"payload not JSON", parts[0] + "." + b64.EncodeToString([]byte("hello")) + "." + parts[2], jws.ErrPayloadJSON},
		{"payload array", parts[0] + "." + b64.EncodeToString([]byte(`[1]`)) + "." + parts[2], jws.ErrPayloadJSON},
		{"payload duplicate member", parts[0] + "." + b64.EncodeToString([]byte(`{"a":1,"a":1}`)) + "." + parts[2], jws.ErrPayloadJSON},
		{"payload invalid UTF-8", parts[0] + "." + b64.EncodeToString([]byte("{\"a\":\"\xff\"}")) + "." + parts[2], jws.ErrPayloadJSON},
		{"payload too deep", parts[0] + "." + b64.EncodeToString([]byte(strings.Repeat(`{"a":`, 17)+"1"+strings.Repeat("}", 17))) + "." + parts[2], jws.ErrPayloadJSON},
	}
	res := issuerResolver(t)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := jws.Verify(c.compact, res)
			wantReason(t, err, c.want)
		})
	}
}

// TestVerifyRejectsSignatures checks the ES256 signature rules of RFC 7518
// section 3.4: exactly 64 octets, R and S in [1, n-1], over the received
// signing input.
func TestVerifyRejectsSignatures(t *testing.T) {
	issuer := scalarKey(t, 2)
	n := elliptic.P256().Params().N
	si := b64.EncodeToString([]byte(evidenceHeader)) + "." + b64.EncodeToString([]byte(smallPayload))
	sig := rawSig(t, si, issuer)
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	enc := func(r, s *big.Int) string {
		out := make([]byte, 64)
		r.FillBytes(out[:32])
		s.FillBytes(out[32:])
		return si + "." + b64.EncodeToString(out)
	}
	flipped := append([]byte(nil), sig...)
	flipped[10] ^= 0x80
	max := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
	cases := []struct {
		name    string
		compact string
		want    jws.Reason
	}{
		{"63 octets", si + "." + b64.EncodeToString(sig[:63]), jws.ErrSignatureLength},
		{"65 octets", si + "." + b64.EncodeToString(append(append([]byte(nil), sig...), 0)), jws.ErrSignatureLength},
		{"96 octets", si + "." + b64.EncodeToString(make([]byte, 96)), jws.ErrSignatureLength},
		{"r zero", enc(big.NewInt(0), s), jws.ErrSignatureInvalid},
		{"s zero", enc(r, big.NewInt(0)), jws.ErrSignatureInvalid},
		{"all zero", enc(big.NewInt(0), big.NewInt(0)), jws.ErrSignatureInvalid},
		{"r = n", enc(n, s), jws.ErrSignatureInvalid},
		{"s = n", enc(r, n), jws.ErrSignatureInvalid},
		{"r = 2^256-1", enc(max, s), jws.ErrSignatureInvalid},
		{"bit flipped", si + "." + b64.EncodeToString(flipped), jws.ErrSignatureInvalid},
		{"other payload", b64.EncodeToString([]byte(evidenceHeader)) + "." + b64.EncodeToString([]byte(`{"pact_version":"0.1","jti":"other"}`)) + "." + b64.EncodeToString(sig), jws.ErrSignatureInvalid},
		{"other key", si + "." + b64.EncodeToString(rawSig(t, si, scalarKey(t, 3))), jws.ErrSignatureInvalid},
	}
	res := issuerResolver(t)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := jws.Verify(c.compact, res)
			wantReason(t, err, c.want)
		})
	}
	// Records current behaviour, an open question for the draft: the high-S
	// twin of a valid signature verifies; no low-S rule applies.
	t.Run("high S accepted", func(t *testing.T) {
		if _, err := jws.Verify(enc(r, new(big.Int).Sub(n, s)), res); err != nil {
			t.Fatalf("high-S twin: %v", err)
		}
	})
}

// TestVerifyUsesReceivedSigningInput: the signature covers the received
// bytes, so a header and payload with white space, member order and escapes
// a serializer would change still verify, and come back unchanged.
func TestVerifyUsesReceivedSigningInput(t *testing.T) {
	header := "{ \"kid\" : \"test\\u002dissuer-key-1\",\n\"typ\":\"pact-evidence+jwt\" , \"alg\":\"ES256\" }"
	payload := "{\n  \"z\": 1.50,\n  \"a\": \"caf\\u00e9 \\/ café\",\n  \"pact_version\": \"0.1\"\n}"
	compact := rawCompact(t, header, payload, scalarKey(t, 2))
	p, err := jws.Verify(compact, issuerResolver(t))
	if err != nil {
		t.Fatal(err)
	}
	if string(p.Payload) != payload {
		t.Errorf("payload %q, want the received bytes %q", p.Payload, payload)
	}
	if string(p.RawHeader) != header {
		t.Errorf("header %q, want the received bytes %q", p.RawHeader, header)
	}
	if want := compact[:strings.LastIndexByte(compact, '.')]; p.SigningInput != want {
		t.Errorf("signing input %q, want %q", p.SigningInput, want)
	}
	if p.Header.Kid != "test-issuer-key-1" || p.Header.Typ != jws.TypEvidence || p.Header.Alg != jws.AlgES256 {
		t.Errorf("header %+v", p.Header)
	}
}

// TestSignMatchesAppendixCHeader: the header Sign writes for an evidence
// artifact is the protected header of the draft's Appendix C JWS, byte for
// byte.
func TestVerifierExpectedTyp(t *testing.T) {
	compact := rawCompact(t, evidenceHeader, smallPayload, scalarKey(t, 2))
	v := jws.Verifier{Keys: issuerResolver(t), Typ: jws.TypAdmission}
	_, err := v.Verify(compact)
	wantReason(t, err, jws.ErrTypMismatch)
	v.Typ = jws.TypEvidence
	if _, err := v.Verify(compact); err != nil {
		t.Fatal(err)
	}
}

func TestVerifierCompactSize(t *testing.T) {
	res := issuerResolver(t)
	big := strings.Repeat("A", jws.DefaultMaxCompactBytes-1)
	_, err := jws.Verify(big+".A.A", res)
	wantReason(t, err, jws.ErrCompactSize)

	compact := rawCompact(t, evidenceHeader, smallPayload, scalarKey(t, 2))
	v := jws.Verifier{Keys: res, MaxCompactBytes: len(compact) - 1}
	_, err = v.Verify(compact)
	wantReason(t, err, jws.ErrCompactSize)
	v.MaxCompactBytes = len(compact)
	if _, err := v.Verify(compact); err != nil {
		t.Fatal(err)
	}
}

func TestVerifierJSONLimits(t *testing.T) {
	payload := `{"pact_version":"0.1","pad":"` + strings.Repeat("x", 100) + `"}`
	compact := rawCompact(t, evidenceHeader, payload, scalarKey(t, 2))
	v := jws.Verifier{Keys: issuerResolver(t), Limits: strictjson.Limits{MaxBytes: 100}}
	_, err := v.Verify(compact)
	wantReason(t, err, jws.ErrPayloadJSON)
	var se *strictjson.Error
	if !errors.As(err, &se) || !errors.Is(err, strictjson.ErrSize) {
		t.Errorf("want a wrapped strictjson size error, got %v", err)
	}
}

type recordingResolver struct {
	reqs      []jws.KeyRequest
	keys      *jws.KeySet
	jkt       core.Digest
	keysErr   error
	holderErr error
}

func (r *recordingResolver) TrustedKeys(req jws.KeyRequest) (*jws.KeySet, error) {
	r.reqs = append(r.reqs, req)
	return r.keys, r.keysErr
}

func (r *recordingResolver) HolderJKT(req jws.KeyRequest) (core.Digest, error) {
	r.reqs = append(r.reqs, req)
	return r.jkt, r.holderErr
}

func TestKeyRequest(t *testing.T) {
	compact := rawCompact(t, evidenceHeader, smallPayload, scalarKey(t, 2))
	rr := &recordingResolver{keys: keySet(t, fixtureJWK(t, "issuer"))}
	if _, err := jws.Verify(compact, rr); err != nil {
		t.Fatal(err)
	}
	if len(rr.reqs) != 1 {
		t.Fatalf("%d resolver calls, want 1", len(rr.reqs))
	}
	req := rr.reqs[0]
	if req.Typ != jws.TypEvidence || req.Role != jws.RoleIssuer || req.Kid != "test-issuer-key-1" ||
		string(req.Header) != evidenceHeader || string(req.Payload) != smallPayload {
		t.Errorf("request %+v", req)
	}

	holderCompact, err := jws.Sign(jws.Header{Typ: jws.TypPresentation}, []byte(smallPayload), scalarKey(t, 1))
	if err != nil {
		t.Fatal(err)
	}
	rr = &recordingResolver{jkt: holderJKT}
	if _, err := jws.Verify(holderCompact, rr); err != nil {
		t.Fatal(err)
	}
	if len(rr.reqs) != 1 || rr.reqs[0].Role != jws.RoleHolder || rr.reqs[0].Typ != jws.TypPresentation {
		t.Errorf("holder requests %+v", rr.reqs)
	}
}

func TestResolverFailures(t *testing.T) {
	compact := rawCompact(t, evidenceHeader, smallPayload, scalarKey(t, 2))
	holderCompact, err := jws.Sign(jws.Header{Typ: jws.TypPresentation}, []byte(smallPayload), scalarKey(t, 1))
	if err != nil {
		t.Fatal(err)
	}
	cause := context.DeadlineExceeded
	cases := []struct {
		name    string
		compact string
		res     jws.KeyResolver
		want    jws.Reason
		cause   error
	}{
		{"nil resolver", compact, nil, jws.ErrKeyUnavailable, nil},
		{"key set error", compact, &recordingResolver{keysErr: cause}, jws.ErrKeyUnavailable, cause},
		{"nil key set", compact, &recordingResolver{}, jws.ErrKidUnknown, nil},
		{"holder jkt error", holderCompact, &recordingResolver{holderErr: cause}, jws.ErrKeyUnavailable, cause},
		{"holder jkt empty", holderCompact, &recordingResolver{}, jws.ErrKeyUnavailable, nil},
		{"static resolver without the role", compact, jws.StaticResolver{}, jws.ErrKidUnknown, nil},
		{"static resolver without holder_jkt", holderCompact, jws.StaticResolver{}, jws.ErrKeyUnavailable, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := jws.Verify(c.compact, c.res)
			wantReason(t, err, c.want)
			if c.cause != nil && !errors.Is(err, c.cause) {
				t.Errorf("error %v does not wrap %v", err, c.cause)
			}
		})
	}
}

// TestHeaderDecisions pins behaviour the draft leaves to RFC 7515: header
// members it does not define are ignored (RFC 7515 section 4), a kid next to
// the jwk of a holder-signed artifact plays no part in key selection, and typ
// is compared exactly.
func TestHeaderDecisions(t *testing.T) {
	issuer := scalarKey(t, 2)
	res := issuerResolver(t)
	ignored := `{"alg":"ES256","typ":"pact-evidence+jwt","kid":"test-issuer-key-1","cty":"json","x5t#S256":"abc","pact-note":{"a":1}}`
	if _, err := jws.Verify(rawCompact(t, ignored, smallPayload, issuer), res); err != nil {
		t.Errorf("unknown non-critical members: %v", err)
	}
	hj := fixtureJWK(t, "holder")
	withKid := `{"alg":"ES256","typ":"pact-presentation+jwt","kid":"no-such-key","jwk":` + jwkJSON(t, hj) + `}`
	if _, err := jws.Verify(rawCompact(t, withKid, smallPayload, scalarKey(t, 1)), res); err != nil {
		t.Errorf("holder kid: %v", err)
	}
	for _, typ := range []string{"PACT-EVIDENCE+JWT", "application/pact-evidence+jwt", " pact-evidence+jwt"} {
		h := `{"alg":"ES256","typ":"` + typ + `","kid":"test-issuer-key-1"}`
		_, err := jws.Verify(rawCompact(t, h, smallPayload, issuer), res)
		wantReason(t, err, jws.ErrTypUnsupported)
	}
}

func TestReasonOf(t *testing.T) {
	if r := jws.ReasonOf(nil); r != "" {
		t.Errorf("ReasonOf(nil) = %q", r)
	}
	if r := jws.ReasonOf(errors.New("x")); r != "" {
		t.Errorf("ReasonOf(other) = %q", r)
	}
	_, err := jws.Verify(rawCompact(t, `{"alg":"ES256","typ":"pact-evidence+jwt","kid":"test-issuer-key-1","alg":"ES256"}`, smallPayload, scalarKey(t, 2)), issuerResolver(t))
	wantReason(t, err, jws.ErrHeaderJSON)
	if !errors.Is(err, strictjson.ErrDuplicateKey) {
		t.Errorf("header error %v does not wrap strictjson.ErrDuplicateKey", err)
	}
	if !strings.HasPrefix(err.Error(), "jws: header-json") {
		t.Errorf("error text %q", err.Error())
	}
}

// TestSignWritesLowS: Sign normalizes S to the low value of (S, n-S), so its
// signatures verify whether or not a verifier rejects high S. Signing is
// randomized; the test checks a property of many signatures, never bytes.
