package jws_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
	"strings"
	"testing"

	"hop.top/pact-go/core/jws"
)

func TestSignVerifyRoundTrip(t *testing.T) {
	holder := scalarKey(t, 1)
	issuer := scalarKey(t, 2)
	issuerJWK := fixtureJWK(t, "issuer")
	sets := map[jws.Role]*jws.KeySet{}
	for _, typ := range jws.Typs() {
		role, _ := jws.TypRole(typ)
		if role != jws.RoleHolder {
			sets[role] = keySet(t, issuerJWK)
		}
	}
	res := jws.StaticResolver{KeySets: sets, ExpectedHolderJKT: holderJKT}
	payload := []byte("{\n  \"pact_version\": \"0.1\",\n  \"jti\": \"round-trip\"\n}")
	for _, typ := range jws.Typs() {
		t.Run(typ, func(t *testing.T) {
			role, ok := jws.TypRole(typ)
			if !ok {
				t.Fatalf("TypRole(%q) not ok", typ)
			}
			h, key, wantKey := jws.Header{Typ: typ, Kid: "test-issuer-key-1"}, issuer, issuerJWK
			if role == jws.RoleHolder {
				h, key, wantKey = jws.Header{Typ: typ}, holder, fixtureJWK(t, "holder")
			}
			compact, err := jws.Sign(h, payload, key)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			p, err := jws.Verify(compact, res)
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if p.Compact != compact || p.Role != role || p.Header.Typ != typ || p.Header.Alg != jws.AlgES256 {
				t.Errorf("parsed %+v", p)
			}
			if !bytes.Equal(p.Payload, payload) {
				t.Errorf("payload %q, want %q", p.Payload, payload)
			}
			if len(p.Signature) != 64 {
				t.Errorf("signature has %d octets, want 64", len(p.Signature))
			}
			if p.Key.X != wantKey.X || p.Key.Y != wantKey.Y {
				t.Errorf("verifying key %+v, want %+v", p.Key, wantKey)
			}
			wantTP, err := jws.Thumbprint(wantKey)
			if err != nil || p.KeyThumbprint != wantTP {
				t.Errorf("key thumbprint %q, want %q (%v)", p.KeyThumbprint, wantTP, err)
			}
			if role == jws.RoleHolder && (p.Header.JWK == nil || p.Header.Kid != "") {
				t.Errorf("holder header %+v: want an embedded jwk and no kid", p.Header)
			}
			if role != jws.RoleHolder && (p.Header.JWK != nil || p.Header.Kid != "test-issuer-key-1") {
				t.Errorf("service header %+v: want kid and no jwk", p.Header)
			}
		})
	}
}

func TestSignMatchesAppendixCHeader(t *testing.T) {
	appc := appendixCCompact(t)
	compact, err := jws.Sign(jws.Header{Typ: jws.TypEvidence, Kid: "test-issuer-key-1"}, []byte(appendixB5(t)), scalarKey(t, 2))
	if err != nil {
		t.Fatal(err)
	}
	got, want := strings.Split(compact, "."), strings.Split(appc, ".")
	if got[0] != want[0] {
		t.Errorf("header segment %s, want Appendix C %s", got[0], want[0])
	}
	if got[1] != want[1] {
		t.Errorf("payload segment differs from Appendix C: the payload bytes were changed")
	}
}

func TestSignHolderHeader(t *testing.T) {
	compact, err := jws.Sign(jws.Header{Typ: jws.TypPresentation}, []byte(smallPayload), scalarKey(t, 1))
	if err != nil {
		t.Fatal(err)
	}
	hdr, err := b64.DecodeString(strings.Split(compact, ".")[0])
	if err != nil {
		t.Fatal(err)
	}
	hj := fixtureJWK(t, "holder")
	want := `{"alg":"ES256","typ":"pact-presentation+jwt","jwk":{"kty":"EC","crv":"P-256","x":"` + hj.X + `","y":"` + hj.Y + `"}}`
	if string(hdr) != want {
		t.Errorf("header %s, want %s", hdr, want)
	}
}

func TestSignRejects(t *testing.T) {
	issuer := scalarKey(t, 2)
	holder := scalarKey(t, 1)
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	adv := fixtureJWK(t, "adversarial")
	cases := []struct {
		name    string
		h       jws.Header
		payload string
		key     *ecdsa.PrivateKey
		want    jws.Reason
	}{
		{"nil key", jws.Header{Typ: jws.TypEvidence, Kid: "k"}, smallPayload, nil, jws.ErrSigningKey},
		{"P-384 key", jws.Header{Typ: jws.TypEvidence, Kid: "k"}, smallPayload, p384, jws.ErrSigningKey},
		{"alg HS256", jws.Header{Alg: "HS256", Typ: jws.TypEvidence, Kid: "k"}, smallPayload, issuer, jws.ErrAlgUnsupported},
		{"typ unknown", jws.Header{Typ: "JWT", Kid: "k"}, smallPayload, issuer, jws.ErrTypUnsupported},
		{"service without kid", jws.Header{Typ: jws.TypEvidence}, smallPayload, issuer, jws.ErrKidMissing},
		{"service with jwk", jws.Header{Typ: jws.TypEvidence, Kid: "k", JWK: &adv}, smallPayload, issuer, jws.ErrJWKUnexpected},
		{"holder jwk of another key", jws.Header{Typ: jws.TypPresentation, JWK: &adv}, smallPayload, holder, jws.ErrSigningKey},
		{"payload not JSON", jws.Header{Typ: jws.TypEvidence, Kid: "k"}, "hello", issuer, jws.ErrPayloadJSON},
		{"payload array", jws.Header{Typ: jws.TypEvidence, Kid: "k"}, "[]", issuer, jws.ErrPayloadJSON},
		{"payload duplicate member", jws.Header{Typ: jws.TypEvidence, Kid: "k"}, `{"a":1,"a":2}`, issuer, jws.ErrPayloadJSON},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, err := jws.Sign(c.h, []byte(c.payload), c.key)
			if out != "" {
				t.Errorf("Sign returned %q with an error", out)
			}
			wantReason(t, err, c.want)
		})
	}
}

func TestSignWritesLowS(t *testing.T) {
	key := scalarKey(t, 2)
	half := new(big.Int).Rsh(elliptic.P256().Params().N, 1)
	res := issuerResolver(t)
	for i := range 64 {
		compact, err := jws.Sign(jws.Header{Typ: jws.TypEvidence, Kid: "test-issuer-key-1"}, []byte(smallPayload), key)
		if err != nil {
			t.Fatal(err)
		}
		p, err := jws.Verify(compact, res)
		if err != nil {
			t.Fatalf("signature %d: %v", i, err)
		}
		if s := new(big.Int).SetBytes(p.Signature[32:]); s.Cmp(half) > 0 {
			t.Fatalf("signature %d has a high S", i)
		}
	}
}
