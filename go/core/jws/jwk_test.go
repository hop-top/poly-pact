package jws_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"strings"
	"testing"

	"hop.top/pact-go/core"
	"hop.top/pact-go/core/jws"
)

// TestThumbprintAppendixC: RFC 7638 over crv, kty, x, y in that order gives
// the holder_jkt printed in draft Appendix C; optional members and member
// order in the JWK do not matter.
func TestThumbprintAppendixC(t *testing.T) {
	for _, src := range []string{
		`{"kty":"EC","crv":"P-256","x":"axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY","y":"T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU"}`,
		`{"y":"T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU","use":"sig","x":"axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY","key_ops":["verify"],"crv":"P-256","kid":"k","kty":"EC"}`,
	} {
		k, err := jws.ParseJWK([]byte(src))
		if err != nil {
			t.Fatalf("ParseJWK(%s): %v", src, err)
		}
		got, err := jws.Thumbprint(k)
		if err != nil {
			t.Fatal(err)
		}
		if got != holderJKT {
			t.Errorf("thumbprint %s, want %s", got, holderJKT)
		}
	}
}

func TestThumbprintRejectsInvalidKeys(t *testing.T) {
	hj := fixtureJWK(t, "holder")
	cases := []struct {
		name string
		k    jws.JWK
		want jws.Reason
	}{
		{"kty RSA", jws.JWK{Kty: "RSA", Crv: "P-256", X: hj.X, Y: hj.Y}, jws.ErrJWKCurve},
		{"crv P-384", jws.JWK{Kty: "EC", Crv: "P-384", X: hj.X, Y: hj.Y}, jws.ErrJWKCurve},
		{"short x", jws.JWK{Kty: "EC", Crv: "P-256", X: hj.X[:42], Y: hj.Y}, jws.ErrJWKInvalid},
		{"empty y", jws.JWK{Kty: "EC", Crv: "P-256", X: hj.X}, jws.ErrJWKInvalid},
		{"off curve", jws.JWK{Kty: "EC", Crv: "P-256", X: hj.X, Y: fixtureJWK(t, "issuer").Y}, jws.ErrJWKOffCurve},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := jws.Thumbprint(c.k)
			if got != "" {
				t.Errorf("thumbprint %q with an error", got)
			}
			wantReason(t, err, c.want)
		})
	}
}

func TestParseJWK(t *testing.T) {
	hj := fixtureJWK(t, "holder")
	if hj.Kid != "test-holder-key-1" || hj.Alg != "ES256" || hj.Use != "sig" || hj.Kty != "EC" || hj.Crv != "P-256" {
		t.Errorf("holder.jwk.json parsed as %+v", hj)
	}
	xy := `"kty":"EC","crv":"P-256","x":"` + hj.X + `","y":"` + hj.Y + `"`
	cases := []struct {
		name string
		src  string
		want jws.Reason
	}{
		{"d", `{` + xy + `,"d":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE"}`, jws.ErrJWKPrivate},
		{"RSA private p", `{` + xy + `,"p":"AQAB"}`, jws.ErrJWKPrivate},
		{"RSA private q", `{` + xy + `,"q":"AQAB"}`, jws.ErrJWKPrivate},
		{"RSA private dp", `{` + xy + `,"dp":"AQAB"}`, jws.ErrJWKPrivate},
		{"RSA private dq", `{` + xy + `,"dq":"AQAB"}`, jws.ErrJWKPrivate},
		{"RSA private qi", `{` + xy + `,"qi":"AQAB"}`, jws.ErrJWKPrivate},
		{"RSA private oth", `{` + xy + `,"oth":[]}`, jws.ErrJWKPrivate},
		{"symmetric k", `{` + xy + `,"k":"AQAB"}`, jws.ErrJWKPrivate},
		{"d null", `{` + xy + `,"d":null}`, jws.ErrJWKPrivate},
		{"not JSON", `kty=EC`, jws.ErrJWKInvalid},
		{"array", `[]`, jws.ErrJWKInvalid},
		{"duplicate member", `{` + xy + `,"x":"` + hj.X + `"}`, jws.ErrJWKInvalid},
		{"x not a string", `{"kty":"EC","crv":"P-256","x":1,"y":"` + hj.Y + `"}`, jws.ErrJWKInvalid},
		{"kid not a string", `{` + xy + `,"kid":1}`, jws.ErrJWKInvalid},
		{"kty missing", `{"crv":"P-256","x":"` + hj.X + `","y":"` + hj.Y + `"}`, jws.ErrJWKCurve},
		{"kty OKP", `{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`, jws.ErrJWKCurve},
		{"crv lowercase", `{"kty":"EC","crv":"p-256","x":"` + hj.X + `","y":"` + hj.Y + `"}`, jws.ErrJWKCurve},
		{"y missing", `{"kty":"EC","crv":"P-256","x":"` + hj.X + `"}`, jws.ErrJWKInvalid},
		{"x padded", `{"kty":"EC","crv":"P-256","x":"` + hj.X + `=","y":"` + hj.Y + `"}`, jws.ErrJWKInvalid},
		{"y standard alphabet", `{"kty":"EC","crv":"P-256","x":"` + hj.X + `","y":"` + strings.NewReplacer("-", "+", "_", "/").Replace(hj.Y) + `"}`, jws.ErrJWKInvalid},
		{"x 33 octets", `{"kty":"EC","crv":"P-256","x":"` + b64.EncodeToString(append([]byte{0}, mustDecode(t, hj.X)...)) + `","y":"` + hj.Y + `"}`, jws.ErrJWKInvalid},
		{"x spare bits", `{"kty":"EC","crv":"P-256","x":"` + hj.X[:42] + "Z" + `","y":"` + hj.Y + `"}`, jws.ErrJWKInvalid},
		{"off curve", `{"kty":"EC","crv":"P-256","x":"` + hj.X + `","y":"` + fixtureJWK(t, "issuer").Y + `"}`, jws.ErrJWKOffCurve},
		{"x = p", `{"kty":"EC","crv":"P-256","x":"` + b64.EncodeToString(elliptic.P256().Params().P.Bytes()) + `","y":"` + hj.Y + `"}`, jws.ErrJWKOffCurve},
		{"alg RS256", `{` + xy + `,"alg":"RS256"}`, jws.ErrJWKUsage},
		{"use enc", `{` + xy + `,"use":"enc"}`, jws.ErrJWKUsage},
		// key_ops (RFC 7517 section 4.3): a verification key names verify,
		// and no operation twice.
		{"key_ops sign", `{` + xy + `,"key_ops":["sign"]}`, jws.ErrJWKUsage},
		{"key_ops encrypt", `{` + xy + `,"key_ops":["encrypt"]}`, jws.ErrJWKUsage},
		{"key_ops empty", `{` + xy + `,"key_ops":[]}`, jws.ErrJWKUsage},
		{"key_ops Verify", `{` + xy + `,"key_ops":["Verify"]}`, jws.ErrJWKUsage},
		{"key_ops duplicate", `{` + xy + `,"key_ops":["verify","verify"]}`, jws.ErrJWKInvalid},
		{"key_ops a string", `{` + xy + `,"key_ops":"verify"}`, jws.ErrJWKInvalid},
		{"key_ops not strings", `{` + xy + `,"key_ops":["verify",5]}`, jws.ErrJWKInvalid},
		{"key_ops null", `{` + xy + `,"key_ops":null}`, jws.ErrJWKInvalid},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := jws.ParseJWK([]byte(c.src))
			wantReason(t, err, c.want)
		})
	}
	// Members the JWK specification does not define are ignored (RFC 7517
	// section 4).
	if _, err := jws.ParseJWK([]byte(`{` + xy + `,"key_ops":["verify"],"x5t":"abc","ext":true}`)); err != nil {
		t.Errorf("extra members: %v", err)
	}
	// key_ops that name verify, alone or with other operations, are accepted.
	for _, ops := range []string{`["verify"]`, `["sign","verify"]`, `["verify","encrypt"]`} {
		if _, err := jws.ParseJWK([]byte(`{` + xy + `,"key_ops":` + ops + `}`)); err != nil {
			t.Errorf("key_ops %s: %v", ops, err)
		}
	}
	// The negotiated Ed25519 parser applies the same rule.
	okp := `"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"`
	ed := jws.Algorithms{jws.AlgES256, jws.AlgEd25519}
	if _, err := ed.ParseJWK([]byte(`{` + okp + `,"key_ops":["verify"]}`)); err != nil {
		t.Errorf("Ed25519 key_ops verify: %v", err)
	}
	_, err := ed.ParseJWK([]byte(`{` + okp + `,"key_ops":["sign"]}`))
	wantReason(t, err, jws.ErrJWKUsage)
}

func mustDecode(t testing.TB, s string) []byte {
	t.Helper()
	b, err := b64.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestPublicJWKKeepsLeadingZeros: coordinates are the full 32 octets (RFC
// 7518 section 6.2.1.2) even when they start with a zero octet. P-256 scalar
// 379 is the smallest above 6 whose x does.
func TestPublicJWKKeepsLeadingZeros(t *testing.T) {
	d := make([]byte, 32)
	d[30], d[31] = 379>>8, 379&0xff
	key, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), d)
	if err != nil {
		t.Fatal(err)
	}
	k, err := jws.PublicJWK(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	x := mustDecode(t, k.X)
	if len(k.X) != 43 || len(x) != 32 || x[0] != 0 {
		t.Fatalf("x %q: %d characters, %d octets, first %#x; want 43, 32 and 0", k.X, len(k.X), len(x), x[0])
	}
	pub, err := k.PublicKey()
	if err != nil || !pub.Equal(&key.PublicKey) {
		t.Errorf("round trip: %v", err)
	}
}

func TestPublicJWKRejects(t *testing.T) {
	if _, err := jws.PublicJWK(nil); err == nil {
		t.Error("nil key accepted")
	}
	var p384 ecdsa.PublicKey
	p384.Curve = elliptic.P384()
	_, err := jws.PublicJWK(&p384)
	wantReason(t, err, jws.ErrJWKCurve)
}

func TestKeySet(t *testing.T) {
	iss, val := fixtureJWK(t, "issuer"), fixtureJWK(t, "validator")
	s := keySet(t, iss, val)
	got, ok := s.Lookup("test-validator-key-1")
	if !ok || got.X != val.X {
		t.Errorf("Lookup(validator) = %+v, %v", got, ok)
	}
	if _, ok := s.Lookup("test-holder-key-1"); ok {
		t.Error("Lookup found a key that is not in the set")
	}
	if _, ok := (*jws.KeySet)(nil).Lookup("test-issuer-key-1"); ok {
		t.Error("nil set found a key")
	}
	if _, ok := s.Lookup(""); ok {
		t.Error("empty kid found a key")
	}

	_, err := jws.NewKeySet(iss, iss)
	wantReason(t, err, jws.ErrKidDuplicate)
	noKid := iss
	noKid.Kid = ""
	_, err = jws.NewKeySet(noKid)
	wantReason(t, err, jws.ErrKidMissing)
	bad := iss
	bad.Y = val.Y
	_, err = jws.NewKeySet(bad)
	wantReason(t, err, jws.ErrJWKOffCurve)
	wrongUse := iss
	wrongUse.Use = "enc"
	_, err = jws.NewKeySet(wrongUse)
	wantReason(t, err, jws.ErrJWKUsage)
}

// TestFixtureThumbprints: the thumbprints of the P-256 test keys, as
// computed independently in TypeScript, Python, Rust and PHP.
func TestFixtureThumbprints(t *testing.T) {
	want := map[string]core.Digest{
		"holder":              holderJKT,
		"issuer":              "AhqHzaYXA5MzmDCrsseUsVBGKyfhDhvekx0THjH_xIE",
		"adversarial":         "B3zQUJfL8WPQJT3fRc_9F85aNjqoqRkk-HMzwyAp7WU",
		"reputation-service":  "BcYkeRReg8Py6HmUFJw6240ruOKnvInXb5rRtK6Z9xQ",
		"learning-controller": "yiaHWTOH-NAS43bw6yPHO8YTK_T9cLz9jZaCu3qOg_k",
		"validator":           "uhdbksqePVMcTx2Fvr5RY78RjuSE2bd16nNAkdfZ36I",
	}
	for name, w := range want {
		got, err := jws.Thumbprint(fixtureJWK(t, name))
		if err != nil || got != w {
			t.Errorf("%s: thumbprint %q (%v), want %q", name, got, err, w)
		}
	}
}
