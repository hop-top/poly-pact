package jws_test

import (
	"crypto/ed25519"
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"

	"hop.top/pact-go/core"
	"hop.top/pact-go/core/jws"
)

// The Ed25519 pair of spec/v1.0/fixtures/keys: the seed of RFC 8032 section 7.1,
// test 1, which is also the private key of RFC 8037 Appendix A.1.
const ed25519SeedHex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"

// rfc8037JKT is the RFC 7638 thumbprint of that public key, RFC 8037
// Appendix A.3.
const rfc8037JKT core.Digest = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"

// rfc8037A4 is the compact JWS of RFC 8037 Appendix A.4, alg EdDSA.
const rfc8037A4 = "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc.hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg"

// negotiated is a deployment that has negotiated Ed25519 beside ES256
// (draft 7.2).
var negotiated = jws.Algorithms{jws.AlgES256, jws.AlgEd25519}

func ed25519Key(t testing.TB) ed25519.PrivateKey {
	t.Helper()
	seed, err := hex.DecodeString(ed25519SeedHex)
	if err != nil {
		t.Fatal(err)
	}
	return ed25519.NewKeyFromSeed(seed)
}

func ed25519FileBytes(t testing.TB) []byte {
	return readFile(t, filepath.Join(fixturesRoot, "keys", "ed25519.jwk.json"))
}

func ed25519JWK(t testing.TB) jws.JWK {
	t.Helper()
	k, err := negotiated.ParseJWK(ed25519FileBytes(t))
	if err != nil {
		t.Fatalf("parse ed25519.jwk.json: %v", err)
	}
	return k
}

// rawEd25519 signs header.payload with crypto/ed25519 directly, so that
// tests can build inputs the package's signers refuse to make.
func rawEd25519(t testing.TB, header, payload string, key ed25519.PrivateKey) string {
	t.Helper()
	si := b64.EncodeToString([]byte(header)) + "." + b64.EncodeToString([]byte(payload))
	return si + "." + b64.EncodeToString(ed25519.Sign(key, []byte(si)))
}

// mixedResolver trusts the issuer P-256 key and the Ed25519 key for the
// issuer role, and the RFC 8037 thumbprint for holders.
func mixedResolver(t testing.TB) jws.StaticResolver {
	t.Helper()
	set, err := negotiated.NewKeySet(fixtureJWK(t, "issuer"), ed25519JWK(t))
	if err != nil {
		t.Fatal(err)
	}
	return jws.StaticResolver{KeySets: map[jws.Role]*jws.KeySet{jws.RoleIssuer: set}, ExpectedHolderJKT: rfc8037JKT}
}

const ed25519EvidenceHeader = `{"alg":"Ed25519","typ":"pact-evidence+jwt","kid":"test-ed25519-key-1"}`

// TestEd25519KeyFile: the fixture key is the RFC 8037 A.2 public key, and
// its RFC 7638 thumbprint is the A.3 value.
func TestEd25519KeyFile(t *testing.T) {
	k := ed25519JWK(t)
	if k.Kty != "OKP" || k.Crv != "Ed25519" || k.X != "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo" || k.Y != "" || k.Alg != jws.AlgEd25519 || k.Kid != "test-ed25519-key-1" {
		t.Fatalf("ed25519.jwk.json parsed as %+v", k)
	}
	pub, err := k.Ed25519PublicKey()
	if err != nil || !pub.Equal(ed25519Key(t).Public()) {
		t.Fatalf("public key %x (%v), want that of the RFC 8032 seed", pub, err)
	}
	tp, err := jws.Thumbprint(k)
	if err != nil || tp != rfc8037JKT {
		t.Errorf("thumbprint %q (%v), want %s (RFC 8037 A.3)", tp, err, rfc8037JKT)
	}
	for _, c := range []struct {
		k    jws.JWK
		want string
	}{{k, jws.AlgEd25519}, {fixtureJWK(t, "issuer"), jws.AlgES256}} {
		if got, err := c.k.Algorithm(); err != nil || got != c.want {
			t.Errorf("Algorithm of %s %s = %q (%v), want %s", c.k.Kty, c.k.Crv, got, err, c.want)
		}
	}
	_, err = jws.JWK{Kty: "RSA"}.Algorithm()
	wantReason(t, err, jws.ErrJWKCurve)
	own, err := jws.PublicEd25519JWK(ed25519Key(t).Public().(ed25519.PublicKey))
	if err != nil || own.X != k.X || own.Kty != "OKP" || own.Crv != "Ed25519" {
		t.Errorf("PublicEd25519JWK = %+v (%v)", own, err)
	}
}

// TestEd25519NotNegotiated: without negotiation the profile is ES256 alone
// (draft 7.2): the OKP key, the alg and the key set are all refused.
func TestEd25519NotNegotiated(t *testing.T) {
	_, err := jws.ParseJWK(ed25519FileBytes(t))
	wantReason(t, err, jws.ErrJWKCurve)
	_, err = jws.Algorithms(nil).ParseJWK(ed25519FileBytes(t))
	wantReason(t, err, jws.ErrJWKCurve)
	_, err = jws.Algorithms{jws.AlgES256}.ParseJWK(ed25519FileBytes(t))
	wantReason(t, err, jws.ErrJWKCurve)
	_, err = jws.NewKeySet(ed25519JWK(t))
	wantReason(t, err, jws.ErrJWKCurve)
	_, err = jws.Thumbprint(jws.JWK{Kty: "OKP", Crv: "Ed448", X: ed25519JWK(t).X})
	wantReason(t, err, jws.ErrJWKCurve)

	compact := rawEd25519(t, ed25519EvidenceHeader, smallPayload, ed25519Key(t))
	res := mixedResolver(t)
	for name, v := range map[string]jws.Verifier{
		"zero":       {Keys: res},
		"ES256 only": {Keys: res, Algorithms: jws.Algorithms{jws.AlgES256}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := v.Verify(compact)
			wantReason(t, err, jws.ErrAlgUnsupported)
		})
	}
	// A holder presentation with an embedded OKP key is refused too.
	holder := `{"alg":"Ed25519","typ":"pact-presentation+jwt","jwk":{"kty":"OKP","crv":"Ed25519","x":"` + ed25519JWK(t).X + `"}}`
	_, err = jws.Verify(rawEd25519(t, holder, smallPayload, ed25519Key(t)), res)
	wantReason(t, err, jws.ErrAlgUnsupported)
}

// TestEd25519Negotiated: once negotiated, an Ed25519 JWS verifies under an
// OKP key (RFC 8037 section 2, RFC 9864 section 2.2), for a service signer
// by kid and for a holder by the thumbprint of its embedded key.
func TestEd25519Negotiated(t *testing.T) {
	res := mixedResolver(t)
	key := ed25519Key(t)
	for _, algs := range []jws.Algorithms{negotiated, {jws.AlgEd25519}} {
		v := jws.Verifier{Keys: res, Algorithms: algs}
		p, err := v.Verify(rawEd25519(t, ed25519EvidenceHeader, smallPayload, key))
		if err != nil {
			t.Fatalf("%v: %v", algs, err)
		}
		if p.Header.Alg != jws.AlgEd25519 || p.Key.Kid != "test-ed25519-key-1" || p.KeyThumbprint != rfc8037JKT || len(p.Signature) != 64 {
			t.Errorf("%v: parsed %+v", algs, p)
		}
		holder := `{"alg":"Ed25519","typ":"pact-presentation+jwt","jwk":{"kty":"OKP","crv":"Ed25519","x":"` + ed25519JWK(t).X + `"}}`
		p, err = v.Verify(rawEd25519(t, holder, smallPayload, key))
		if err != nil {
			t.Fatalf("%v holder: %v", algs, err)
		}
		if p.Header.JWK == nil || p.Header.JWK.Kty != "OKP" || p.KeyThumbprint != rfc8037JKT {
			t.Errorf("%v holder: parsed %+v", algs, p)
		}
	}
	// ES256 still verifies when both are negotiated, and not when only
	// Ed25519 is.
	es := rawCompact(t, evidenceHeader, smallPayload, scalarKey(t, 2))
	if _, err := (jws.Verifier{Keys: res, Algorithms: negotiated}).Verify(es); err != nil {
		t.Errorf("ES256 under ES256 and Ed25519: %v", err)
	}
	_, err := jws.Verifier{Keys: res, Algorithms: jws.Algorithms{jws.AlgEd25519}}.Verify(es)
	wantReason(t, err, jws.ErrAlgUnsupported)

	// A changed payload or signature fails.
	good := rawEd25519(t, ed25519EvidenceHeader, smallPayload, key)
	parts := strings.Split(good, ".")
	other := rawEd25519(t, ed25519EvidenceHeader, `{"pact_version":"0.1","jti":"other"}`, key)
	v := jws.Verifier{Keys: res, Algorithms: negotiated}
	_, err = v.Verify(parts[0] + "." + strings.Split(other, ".")[1] + "." + parts[2])
	wantReason(t, err, jws.ErrSignatureInvalid)
	sig := mustDecode(t, parts[2])
	sig[63] ^= 0x01
	_, err = v.Verify(parts[0] + "." + parts[1] + "." + b64.EncodeToString(sig))
	wantReason(t, err, jws.ErrSignatureInvalid)
}

// TestEd25519RejectsOtherIdentifiers: negotiating Ed25519 admits that one
// identifier. EdDSA (RFC 9864 section 4.1.2 deprecates it; draft 7.2 does
// not accept it), none and HMAC stay refused even with a valid Ed25519
// signature and even when a deployment lists them.
func TestEd25519RejectsOtherIdentifiers(t *testing.T) {
	res := mixedResolver(t)
	key := ed25519Key(t)
	lenient := jws.Algorithms{jws.AlgES256, jws.AlgEd25519, "EdDSA", "none", "HS256"}
	for _, alg := range []string{"EdDSA", "eddsa", "ed25519", "none", "HS256", "Ed448"} {
		h := `{"alg":"` + alg + `","typ":"pact-evidence+jwt","kid":"test-ed25519-key-1"}`
		for name, algs := range map[string]jws.Algorithms{"negotiated": negotiated, "listing it": lenient} {
			t.Run(alg+" "+name, func(t *testing.T) {
				_, err := jws.Verifier{Keys: res, Algorithms: algs}.Verify(rawEd25519(t, h, smallPayload, key))
				wantReason(t, err, jws.ErrAlgUnsupported)
			})
		}
	}
	// The RFC 8037 A.4 example itself: its signature is a valid Ed25519
	// signature, but its alg is EdDSA.
	_, err := jws.Verifier{Keys: res, Algorithms: lenient}.Verify(rfc8037A4)
	wantReason(t, err, jws.ErrAlgUnsupported)
}

// TestEd25519AlgKeyMismatch: the header alg must be the algorithm of the
// key that verifies it, in both directions.
func TestEd25519AlgKeyMismatch(t *testing.T) {
	res := mixedResolver(t)
	v := jws.Verifier{Keys: res, Algorithms: negotiated}
	cases := []struct {
		name, compact string
	}{
		{"Ed25519 header, P-256 kid", rawEd25519(t, `{"alg":"Ed25519","typ":"pact-evidence+jwt","kid":"test-issuer-key-1"}`, smallPayload, ed25519Key(t))},
		{"ES256 header, Ed25519 kid", rawCompact(t, `{"alg":"ES256","typ":"pact-evidence+jwt","kid":"test-ed25519-key-1"}`, smallPayload, scalarKey(t, 2))},
		{"Ed25519 header, P-256 holder jwk", rawEd25519(t, `{"alg":"Ed25519","typ":"pact-presentation+jwt","jwk":`+jwkJSON(t, fixtureJWK(t, "holder"))+`}`, smallPayload, ed25519Key(t))},
		{"ES256 header, OKP holder jwk", rawCompact(t, `{"alg":"ES256","typ":"pact-presentation+jwt","jwk":{"kty":"OKP","crv":"Ed25519","x":"`+ed25519JWK(t).X+`"}}`, smallPayload, scalarKey(t, 1))},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := v.Verify(c.compact)
			wantReason(t, err, jws.ErrJWKUsage)
		})
	}
}

// TestEd25519ParseJWK: an OKP key is checked as RFC 8037 section 2 writes
// it, once Ed25519 is negotiated.
func TestEd25519ParseJWK(t *testing.T) {
	x := ed25519JWK(t).X
	cases := []struct {
		name, src string
		want      jws.Reason
	}{
		{"d", `{"kty":"OKP","crv":"Ed25519","x":"` + x + `","d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"}`, jws.ErrJWKPrivate},
		{"crv Ed448", `{"kty":"OKP","crv":"Ed448","x":"` + x + `"}`, jws.ErrJWKCurve},
		{"crv X25519", `{"kty":"OKP","crv":"X25519","x":"` + x + `"}`, jws.ErrJWKCurve},
		{"crv missing", `{"kty":"OKP","x":"` + x + `"}`, jws.ErrJWKCurve},
		{"x missing", `{"kty":"OKP","crv":"Ed25519"}`, jws.ErrJWKInvalid},
		{"x 31 octets", `{"kty":"OKP","crv":"Ed25519","x":"` + b64.EncodeToString(mustDecode(t, x)[:31]) + `"}`, jws.ErrJWKInvalid},
		{"x padded", `{"kty":"OKP","crv":"Ed25519","x":"` + x + `="}`, jws.ErrJWKInvalid},
		{"y present", `{"kty":"OKP","crv":"Ed25519","x":"` + x + `","y":"` + x + `"}`, jws.ErrJWKInvalid},
		{"alg EdDSA", `{"kty":"OKP","crv":"Ed25519","x":"` + x + `","alg":"EdDSA"}`, jws.ErrJWKUsage},
		{"alg ES256", `{"kty":"OKP","crv":"Ed25519","x":"` + x + `","alg":"ES256"}`, jws.ErrJWKUsage},
		{"use enc", `{"kty":"OKP","crv":"Ed25519","x":"` + x + `","use":"enc"}`, jws.ErrJWKUsage},
		{"EC key with alg Ed25519", `{"kty":"EC","crv":"P-256","x":"` + fixtureJWK(t, "holder").X + `","y":"` + fixtureJWK(t, "holder").Y + `","alg":"Ed25519"}`, jws.ErrJWKUsage},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := negotiated.ParseJWK([]byte(c.src))
			wantReason(t, err, c.want)
		})
	}
	if _, err := negotiated.ParseJWK([]byte(`{"kty":"OKP","crv":"Ed25519","x":"` + x + `"}`)); err != nil {
		t.Errorf("bare OKP key: %v", err)
	}
	if _, err := negotiated.ParseJWK(readFile(t, filepath.Join(fixturesRoot, "keys", "issuer.jwk.json"))); err != nil {
		t.Errorf("P-256 key under negotiation: %v", err)
	}
}

// TestSignEd25519: SignEd25519 writes alg Ed25519 and a deterministic RFC
// 8032 signature over the received signing input.
func TestSignEd25519(t *testing.T) {
	key := ed25519Key(t)
	res := mixedResolver(t)
	v := jws.Verifier{Keys: res, Algorithms: negotiated}
	compact, err := jws.SignEd25519(jws.Header{Typ: jws.TypEvidence, Kid: "test-ed25519-key-1"}, []byte(smallPayload), key)
	if err != nil {
		t.Fatal(err)
	}
	want := rawEd25519(t, ed25519EvidenceHeader, smallPayload, key)
	if compact != want {
		t.Errorf("SignEd25519 = %s, want %s", compact, want)
	}
	if _, err := v.Verify(compact); err != nil {
		t.Errorf("Verify: %v", err)
	}
	holder, err := jws.SignEd25519(jws.Header{Typ: jws.TypPresentation}, []byte(smallPayload), key)
	if err != nil {
		t.Fatal(err)
	}
	if p, err := v.Verify(holder); err != nil || p.KeyThumbprint != rfc8037JKT {
		t.Errorf("holder: %+v %v", p, err)
	}
	_, err = jws.SignEd25519(jws.Header{Alg: jws.AlgES256, Typ: jws.TypEvidence, Kid: "k"}, []byte(smallPayload), key)
	wantReason(t, err, jws.ErrAlgUnsupported)
	_, err = jws.SignEd25519(jws.Header{Alg: "EdDSA", Typ: jws.TypEvidence, Kid: "k"}, []byte(smallPayload), key)
	wantReason(t, err, jws.ErrAlgUnsupported)
	_, err = jws.SignEd25519(jws.Header{Typ: jws.TypEvidence, Kid: "k"}, []byte(smallPayload), key[:10])
	wantReason(t, err, jws.ErrSigningKey)
	_, err = jws.Sign(jws.Header{Alg: jws.AlgEd25519, Typ: jws.TypEvidence, Kid: "k"}, []byte(smallPayload), scalarKey(t, 2))
	wantReason(t, err, jws.ErrAlgUnsupported)
	other := ed25519.NewKeyFromSeed(make([]byte, 32))
	otherJWK, err := jws.PublicEd25519JWK(other.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	_, err = jws.SignEd25519(jws.Header{Typ: jws.TypPresentation, JWK: &otherJWK}, []byte(smallPayload), key)
	wantReason(t, err, jws.ErrSigningKey)
}
