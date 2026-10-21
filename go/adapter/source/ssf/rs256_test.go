package ssf_test

import (
	"crypto"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"

	"hop.top/pact-go/adapter/source"
	"hop.top/pact-go/adapter/source/ssf"
	"hop.top/pact-go/core/clock"
	"hop.top/pact-go/core/jws"
)

// RS256 is RSASSA-PKCS1-v1_5 with SHA-256 (RFC 7518 section 3.3), which
// requires a key of 2048 bits or larger. The receiver accepts it only for an
// issuer whose algorithm list names it; the list defaults to ES256.

const (
	kidRSA   = "test-rsa-key-1"
	kidSmall = "test-rsa-key-1024"
	kidEdge  = "test-rsa-key-2047"
)

// rsaKey returns the test key of the given size.
func rsaKey(t testing.TB, bits int) *rsa.PrivateKey {
	t.Helper()
	return rsaKeyOf(t, map[int]string{2048: kidRSA, 1024: kidSmall, 2047: kidEdge}[bits])
}

// rsaOther is a second 2048-bit key, the adversary's.
func rsaOther(t testing.TB) *rsa.PrivateKey { return rsaKeyOf(t, "adversarial") }

func rsaMembers(k *rsa.PrivateKey, kid string) map[string]any {
	return map[string]any{
		"kty": "RSA", "kid": kid, "alg": "RS256", "use": "sig",
		"n": b64(k.N.Bytes()), "e": b64(big.NewInt(int64(k.E)).Bytes()),
	}
}

func rsaJWK(t testing.TB, k *rsa.PrivateKey, kid string) ssf.RSAKey {
	t.Helper()
	b, err := json.Marshal(rsaMembers(k, kid))
	if err != nil {
		t.Fatal(err)
	}
	j, err := ssf.ParseRSAKey(b)
	if err != nil {
		t.Fatal(err)
	}
	return j
}

func rsHeader(kid string) map[string]any {
	return map[string]any{"alg": "RS256", "typ": "secevent+jwt", "kid": kid}
}

// compactRS signs header and claims with k as RS256.
func compactRS(t testing.TB, k *rsa.PrivateKey, header, claims map[string]any) string {
	t.Helper()
	in := signingInput(t, header, claims)
	sum := sha256.Sum256([]byte(in))
	sig, err := rsa.SignPKCS1v15(nil, k, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return in + "." + b64(sig)
}

func signingInput(t testing.TB, header, claims map[string]any) string {
	t.Helper()
	h, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	c, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return b64(h) + "." + b64(c)
}

// withKeys configures the issuer with its allowed algorithms and key set: the
// ES256 issuer key and the given RSA keys.
func withKeys(t testing.TB, algs []string, rsaKeys ...ssf.RSAKey) func(*ssf.Config) {
	return func(c *ssf.Config) {
		c.Issuers[0].Algorithms = algs
		c.Issuers[0].Keys = ssf.StaticKeySet{EC: []jws.JWK{jwkOf(t, key(t, 2), kid)}, RSA: rsaKeys}
	}
}

var both = []string{ssf.AlgES256, ssf.AlgRS256}

func disabledClaims(jti string) map[string]any {
	return claims(jti, nowSec-10, issSub("u-1"), ssf.EventAccountDisabled, nil)
}

func (r *rig) wantRejected(t testing.TB, tok, code string) {
	t.Helper()
	r.tel.reset()
	_, err := r.rx.Accept(bg, tok)
	wantCode(t, err, code)
	r.wantNoFact(t, principal("7a1f"))
	if got := r.tel.kinds(); !slices.Equal(got, []string{ssf.KindRejected}) {
		t.Fatalf("telemetry %v", got)
	}
}

func TestRS256Accepted(t *testing.T) {
	k := rsaKey(t, 2048)
	r := newRig(t, withKeys(t, both, rsaJWK(t, k, kidRSA)))
	r.accept(t, compactRS(t, k, rsHeader(kidRSA), disabledClaims("rs-1")))
	r.wantState(t, principal("7a1f"), ssf.StateDisabled, nowSec-10)
	// ES256 still verifies under the same issuer.
	r.accept(t, signed(t, claims("es-1", nowSec-5, issSub("u-1"), ssf.EventAccountEnabled, nil)))
	r.wantState(t, principal("7a1f"), ssf.StateActive, nowSec-5)
	// And RS256 again, with a later event.
	r.accept(t, compactRS(t, k, rsHeader(kidRSA), claims("rs-2", nowSec-1, issSub("u-1"), ssf.EventSessionRevoked, map[string]any{"event_timestamp": nowSec - 1})))
	r.wantState(t, principal("7a1f"), ssf.StateSessionRevoked, nowSec-1)
}

func TestRS256ReplayIsContentNotSignature(t *testing.T) {
	k := rsaKey(t, 2048)
	r := newRig(t, withKeys(t, both, rsaJWK(t, k, kidRSA)))
	c := disabledClaims("rs-1")
	r.accept(t, compactRS(t, k, rsHeader(kidRSA), c))
	// The same payload under ES256 is the same SET: a replay.
	if res := r.accept(t, signed(t, c)); !res.Replay {
		t.Fatal("same payload, another algorithm, was applied again")
	}
}

func TestRS256AllowList(t *testing.T) {
	k := rsaKey(t, 2048)
	c := disabledClaims("rs-1")
	rs := compactRS(t, k, rsHeader(kidRSA), c)
	es := signed(t, c)
	for name, tc := range map[string]struct {
		algs []string
		tok  string
		ok   bool
	}{
		"default list refuses RS256":      {nil, rs, false},
		"empty list is the default":       {[]string{}, rs, false},
		"ES256 only refuses RS256":        {[]string{ssf.AlgES256}, rs, false},
		"default list accepts ES256":      {nil, es, true},
		"both accept RS256":               {both, rs, true},
		"both accept ES256":               {both, es, true},
		"RS256 only accepts RS256":        {[]string{ssf.AlgRS256}, rs, true},
		"RS256 only refuses ES256":        {[]string{ssf.AlgRS256}, es, false},
		"order of the list is irrelevant": {[]string{ssf.AlgRS256, ssf.AlgES256}, es, true},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t, withKeys(t, tc.algs, rsaJWK(t, k, kidRSA)))
			if tc.ok {
				r.accept(t, tc.tok)
				r.wantState(t, principal("7a1f"), ssf.StateDisabled, nowSec-10)
				return
			}
			r.wantRejected(t, tc.tok, ssf.CodeInvalidKey)
		})
	}
}

// The allow-list is per issuer.
func TestAllowListIsPerIssuer(t *testing.T) {
	k := rsaKey(t, 2048)
	const other = "https://tx2.example.com"
	r := newRig(t, func(c *ssf.Config) {
		c.Issuers[0].Keys = ssf.StaticKeySet{EC: []jws.JWK{jwkOf(t, key(t, 2), kid)}, RSA: []ssf.RSAKey{rsaJWK(t, k, kidRSA)}}
		c.Issuers = append(c.Issuers, ssf.Issuer{
			Issuer: other, Audience: rxAud, Algorithms: []string{ssf.AlgRS256},
			Keys: ssf.StaticKeySet{RSA: []ssf.RSAKey{rsaJWK(t, k, kidRSA)}},
		})
		c.Mappings = append(c.Mappings, ssf.Mapping{Issuer: other, Format: "opaque", Value: "o-9", Local: "8e8e"})
	})
	cl := func(iss, jti string) map[string]any {
		m := claims(jti, nowSec-10, nil, ssf.EventAccountDisabled, nil)
		m["iss"] = iss
		m["sub_id"] = map[string]any{"format": "opaque", "id": "o-9"}
		return m
	}
	// tx (default list) refuses RS256; tx2 (RS256) accepts it.
	_, err := r.rx.Accept(bg, compactRS(t, k, rsHeader(kidRSA), cl(txIssuer, "a-1")))
	wantCode(t, err, ssf.CodeInvalidKey)
	r.accept(t, compactRS(t, k, rsHeader(kidRSA), cl(other, "a-2")))
	r.wantState(t, principal("8e8e"), ssf.StateDisabled, nowSec-10)
}

// RFC 7518 section 3.3: a key of 2048 bits or larger MUST be used with RS256.
func TestRS256MinimumKeySize(t *testing.T) {
	for _, tc := range []struct {
		bits int
		kid  string
		ok   bool
	}{
		{1024, kidSmall, false},
		{2047, kidEdge, false},
		{2048, kidRSA, true},
	} {
		t.Run(fmt.Sprint(tc.bits), func(t *testing.T) {
			k := rsaKey(t, tc.bits)
			// A published key is checked when it is used; a configured
			// static key, when the receiver is built (TestStaticKeySetIsValidated).
			srv := newJWKS(t, jwksOf(t, rsaMembers(k, tc.kid)))
			j, err := ssf.NewJWKS(srv.URL, srv.Client(), clock.NewFake(time.Unix(nowSec, 0)), time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			r := newRig(t, func(c *ssf.Config) {
				c.Issuers[0].Algorithms = both
				c.Issuers[0].Keys = j
			})
			tok := compactRS(t, k, rsHeader(tc.kid), disabledClaims("rs-1"))
			if tc.ok {
				r.accept(t, tok)
				return
			}
			// The signature is valid; the key is refused on its size alone.
			r.wantRejected(t, tok, ssf.CodeInvalidKey)
		})
	}
}

func TestRSAKeyPublicKeyChecksSize(t *testing.T) {
	if ssf.MinRSABits != 2048 {
		t.Fatalf("MinRSABits is %d", ssf.MinRSABits)
	}
	if _, err := rsaJWK(t, rsaKey(t, 2047), kidEdge).PublicKey(); err == nil {
		t.Fatal("2047-bit key accepted")
	}
	pub, err := rsaJWK(t, rsaKey(t, 2048), kidRSA).PublicKey()
	if err != nil || pub.N.BitLen() != 2048 || pub.E != 65537 {
		t.Fatalf("%v %v", pub, err)
	}
}

// The key type must match the header alg, in both directions.
func TestAlgKeyTypeMismatch(t *testing.T) {
	k := rsaKey(t, 2048)
	c := disabledClaims("m-1")
	r := newRig(t, withKeys(t, both, rsaJWK(t, k, kidRSA)))
	// RS256 header naming the EC key, signed by the RSA key (which is in the set).
	r.wantRejected(t, compactRS(t, k, rsHeader(kid), c), ssf.CodeInvalidKey)
	// ES256 header naming the RSA key, signed by the EC key (which is in the set).
	r.wantRejected(t, compact(t, key(t, 2), map[string]any{"alg": "ES256", "typ": "secevent+jwt", "kid": kidRSA}, c), ssf.CodeInvalidKey)
	// ES256 header naming the RSA key, with the RSA signature.
	in := signingInput(t, map[string]any{"alg": "ES256", "typ": "secevent+jwt", "kid": kidRSA}, c)
	sum := sha256.Sum256([]byte(in))
	sig, _ := rsa.SignPKCS1v15(nil, k, crypto.SHA256, sum[:])
	r.wantRejected(t, in+"."+b64(sig), ssf.CodeInvalidKey)
	// Nothing was recorded, so the right pairing is accepted.
	r.accept(t, compactRS(t, k, rsHeader(kidRSA), c))
}

// A custom source that serves a key of the wrong type is not trusted either:
// the key of the EC lookup claims to be RSA, and the key of the RSA lookup
// claims to be EC, each with the real members of a usable key.
type wrongTypeKeys struct {
	ec  jws.JWK
	rsa ssf.RSAKey
}

func (w wrongTypeKeys) Key(_ ctxT, _ string) (jws.JWK, error) {
	j := w.ec
	j.Kty = "RSA"
	return j, nil
}

func (w wrongTypeKeys) RSAKey(_ ctxT, _ string) (ssf.RSAKey, error) {
	r := w.rsa
	r.Kty = "EC"
	return r, nil
}

func TestSourceKeyOfWrongTypeIsRefused(t *testing.T) {
	k := rsaKey(t, 2048)
	r := newRig(t, func(c *ssf.Config) {
		c.Issuers[0].Algorithms = both
		c.Issuers[0].Keys = wrongTypeKeys{jwkOf(t, key(t, 2), kid), rsaJWK(t, k, kid)}
	})
	c := disabledClaims("w-1")
	r.wantRejected(t, signed(t, c), ssf.CodeInvalidKey)
	r.wantRejected(t, compactRS(t, k, rsHeader(kid), c), ssf.CodeInvalidKey)
	// The same key sets with the right types verify.
	r2 := newRig(t, func(cf *ssf.Config) {
		cf.Issuers[0].Algorithms = both
		cf.Issuers[0].Keys = ssf.StaticKeySet{EC: []jws.JWK{jwkOf(t, key(t, 2), kid)}, RSA: []ssf.RSAKey{rsaJWK(t, k, "rsa-kid")}}
	})
	r2.accept(t, signed(t, c))
	r2.accept(t, compactRS(t, k, rsHeader("rsa-kid"), claims("w-2", nowSec-9, issSub("u-2"), ssf.EventAccountDisabled, nil)))
}

// The classic key confusion: HS256 with the RSA public key as the HMAC secret.
func TestHS256WithRSAPublicKeyAsSecret(t *testing.T) {
	k := rsaKey(t, 2048)
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pkcs1 := x509.MarshalPKCS1PublicKey(&k.PublicKey)
	secrets := map[string][]byte{
		"PKIX PEM":  pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}),
		"PKCS1 PEM": pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: pkcs1}),
		"PKIX DER":  der,
		"modulus":   k.N.Bytes(),
	}
	for name, secret := range secrets {
		for _, algs := range [][]string{nil, both, {ssf.AlgRS256}} {
			t.Run(fmt.Sprint(name, algs), func(t *testing.T) {
				r := newRig(t, withKeys(t, algs, rsaJWK(t, k, kidRSA)))
				in := signingInput(t, map[string]any{"alg": "HS256", "typ": "secevent+jwt", "kid": kidRSA}, disabledClaims("h-1"))
				mac := hmac.New(sha256.New, secret)
				mac.Write([]byte(in))
				r.wantRejected(t, in+"."+b64(mac.Sum(nil)), ssf.CodeInvalidKey)
			})
		}
	}
}

// Only the algorithms the receiver implements may be listed, and RS256 needs
// a key source that holds RSA keys.
func TestAlgorithmsConfigIsValidated(t *testing.T) {
	k := rsaKey(t, 2048)
	base := func() ssf.Config {
		return ssf.Config{
			SourceID: "ssf-test", Store: source.NewMemory(), Clock: clock.NewFake(time.Unix(nowSec, 0)),
			PrincipalPrefix: prefix,
			Issuers: []ssf.Issuer{{Issuer: txIssuer, Audience: rxAud, Algorithms: both,
				Keys: ssf.StaticKeySet{EC: []jws.JWK{jwkOf(t, key(t, 2), kid)}, RSA: []ssf.RSAKey{rsaJWK(t, k, kidRSA)}}}},
			Mappings: defaultMappings(),
		}
	}
	if _, err := ssf.NewReceiver(base()); err != nil {
		t.Fatal(err)
	}
	for _, alg := range []string{"none", "HS256", "HS384", "HS512", "RS384", "RS512", "ES384", "ES512", "PS256", "EdDSA", "Ed25519", "rs256", "es256", "", " RS256"} {
		t.Run(fmt.Sprintf("%q", alg), func(t *testing.T) {
			c := base()
			c.Issuers[0].Algorithms = []string{ssf.AlgES256, alg}
			if _, err := ssf.NewReceiver(c); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	t.Run("duplicate", func(t *testing.T) {
		c := base()
		c.Issuers[0].Algorithms = []string{ssf.AlgRS256, ssf.AlgRS256}
		if _, err := ssf.NewReceiver(c); err == nil {
			t.Fatal("accepted")
		}
	})
	t.Run("RS256 over a source without RSA keys", func(t *testing.T) {
		c := base()
		c.Issuers[0].Keys = ssf.StaticKeys{jwkOf(t, key(t, 2), kid)}
		if _, err := ssf.NewReceiver(c); err == nil {
			t.Fatal("accepted")
		}
		c.Issuers[0].Algorithms = nil // ES256 over the same source is the old behaviour
		if _, err := ssf.NewReceiver(c); err != nil {
			t.Fatal(err)
		}
	})
}

func TestRS256SignatureForms(t *testing.T) {
	k := rsaKey(t, 2048)
	c := disabledClaims("s-1")
	r := newRig(t, withKeys(t, both, rsaJWK(t, k, kidRSA)))
	good := compactRS(t, k, rsHeader(kidRSA), c)
	parts := strings.Split(good, ".")
	sig, _ := b64d(parts[2])
	cases := map[string]string{
		"another RSA key under the real kid": compactRS(t, rsaOther(t), rsHeader(kidRSA), c),
		"truncated signature":                strings.Join([]string{parts[0], parts[1], b64(sig[1:])}, "."),
		"signature with a leading zero":      strings.Join([]string{parts[0], parts[1], b64(append([]byte{0}, sig...))}, "."),
		"signature plus the modulus":         strings.Join([]string{parts[0], parts[1], b64(new(big.Int).Add(new(big.Int).SetBytes(sig), k.N).Bytes())}, "."),
		"empty signature":                    parts[0] + "." + parts[1] + ".",
		"padded base64url":                   good + "=",
		"flipped bit":                        strings.Join([]string{parts[0], parts[1], b64(flip(sig))}, "."),
		"es256 sized signature":              strings.Join([]string{parts[0], parts[1], b64(sig[:64])}, "."),
		"payload replaced": strings.Join([]string{parts[0], b64([]byte(strings.Replace(
			`{"iss":"https://tx.example.com","aud":"https://rx.example.com/ssf","jti":"s-1","iat":1792079990,"sub_id":{"format":"iss_sub","iss":"https://tx.example.com","sub":"u-2"},"events":{"https://schemas.openid.net/secevent/risc/event-type/account-disabled":{}}}`, "u-2", "u-2", 1))), parts[2]}, "."),
	}
	for name, tok := range cases {
		t.Run(name, func(t *testing.T) { r.wantRejected(t, tok, ssf.CodeInvalidKey) })
	}
	r.accept(t, good)
}

func flip(b []byte) []byte {
	out := slices.Clone(b)
	out[len(out)-1] ^= 1
	return out
}

func b64d(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

// RSA JWK parsing is strict.
func TestParseRSAKey(t *testing.T) {
	k := rsaKey(t, 2048)
	good := func() map[string]any { return rsaMembers(k, kidRSA) }
	parse := func(m map[string]any) error {
		b, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		_, err = ssf.ParseRSAKey(b)
		return err
	}
	if err := parse(good()); err != nil {
		t.Fatal(err)
	}
	// Optional members may be absent; members not understood are ignored
	// (RFC 7517 section 4).
	m := good()
	delete(m, "alg")
	delete(m, "use")
	delete(m, "kid")
	m["x5t"] = "ignored"
	m["x-vendor"] = map[string]any{"verify": false}
	if err := parse(m); err != nil {
		t.Fatal(err)
	}
	// key_ops (RFC 7517 section 4.3), when present, must name "verify"; sign
	// with verify is a permitted combination.
	for _, ops := range [][]string{{"verify"}, {"sign", "verify"}, {"verify", "x-custom"}} {
		m := good()
		m["key_ops"] = ops
		if err := parse(m); err != nil {
			t.Fatalf("key_ops %v: %v", ops, err)
		}
		delete(m, "use")
		if err := parse(m); err != nil {
			t.Fatalf("key_ops %v without use: %v", ops, err)
		}
	}
	// A key under 2048 bits parses: its size is checked when it is used.
	if _, err := ssf.ParseRSAKey(mustJSON(t, rsaMembers(rsaKey(t, 1024), kidSmall))); err != nil {
		t.Fatalf("small key: %v", err)
	}
	// The accepting edge of each bound: e = 3 and e = 2^31-1 (RFC 7518
	// section 6.3.1.2, base64url of the octets 03 and 7f ff ff ff), and a
	// modulus of exactly 16384 bits (the odd n = 2^16383 + 1 and 2^16384 - 1).
	for name, mod := range map[string]map[string]string{
		"e three":         {"e": "Aw"},
		"e 2^31-1":        {"e": "f____w"},
		"n of 16384 bits": {"n": b64(new(big.Int).SetBit(big.NewInt(1), 16383, 1).Bytes())},
		"n 2^16384-1":     {"n": b64(new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 16384), big.NewInt(1)).Bytes())},
	} {
		t.Run(name, func(t *testing.T) {
			m := good()
			for k, v := range mod {
				m[k] = v
			}
			if err := parse(m); err != nil {
				t.Fatal(err)
			}
		})
	}
	set := func(name string, v any) func(map[string]any) {
		return func(m map[string]any) {
			if v == nil {
				delete(m, name)
			} else {
				m[name] = v
			}
		}
	}
	nb := b64(k.N.Bytes())
	for name, mod := range map[string]func(map[string]any){
		"kty EC":                set("kty", "EC"),
		"kty lowercase":         set("kty", "rsa"),
		"no kty":                set("kty", nil),
		"no n":                  set("n", nil),
		"no e":                  set("e", nil),
		"n not a string":        set("n", 5),
		"e not a string":        set("e", 65537),
		"n padded":              set("n", nb+"=="),
		"n not base64url":       set("n", "+/+/"),
		"n with a leading zero": set("n", b64(append([]byte{0}, k.N.Bytes()...))),
		"n empty":               set("n", ""),
		"n even":                set("n", b64(new(big.Int).Add(k.N, big.NewInt(1)).Bytes())),
		"n over the bound":      set("n", b64(new(big.Int).Lsh(big.NewInt(1), 16500).Add(new(big.Int).Lsh(big.NewInt(1), 16500), big.NewInt(1)).Bytes())),
		"n of 16385 bits":       set("n", b64(new(big.Int).SetBit(big.NewInt(1), 16384, 1).Bytes())),
		"e with a leading zero": set("e", b64([]byte{0, 1, 0, 1})),
		"e empty":               set("e", ""),
		"e one":                 set("e", b64([]byte{1})),
		"e even":                set("e", b64([]byte{1, 0, 0})),
		"e over 31 bits":        set("e", b64([]byte{0x80, 0, 0, 1})),
		"e over 4 octets":       set("e", b64([]byte{1, 0, 0, 0, 1})),
		"alg RS384":             set("alg", "RS384"),
		"alg ES256":             set("alg", "ES256"),
		"alg not a string":      set("alg", 256),
		"use enc":               set("use", "enc"),
		"key_ops encrypt":       set("key_ops", []string{"encrypt"}),
		"key_ops sign":          set("key_ops", []string{"sign"}),
		"key_ops empty":         set("key_ops", []string{}),
		"key_ops Verify":        set("key_ops", []string{"Verify"}),
		"key_ops duplicate":     set("key_ops", []string{"verify", "verify"}),
		"key_ops a string":      set("key_ops", "verify"),
		"key_ops not strings":   set("key_ops", []any{"verify", 5}),
		"key_ops null":          set("key_ops", json.RawMessage("null")),
		"kid not a string":      set("kid", 7),
		"private d":             set("d", nb),
		"private p":             set("p", nb),
		"private q":             set("q", nb),
		"private dp":            set("dp", nb),
		"private dq":            set("dq", nb),
		"private qi":            set("qi", nb),
		"private oth":           set("oth", []any{}),
		"private k":             set("k", nb),
	} {
		t.Run(name, func(t *testing.T) {
			m := good()
			mod(m)
			if err := parse(m); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	for name, raw := range map[string]string{
		"not an object":    `[]`,
		"duplicate member": `{"kty":"RSA","kty":"RSA","n":"` + nb + `","e":"AQAB"}`,
		"truncated":        `{"kty":"RSA"`,
		"empty":            ``,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ssf.ParseRSAKey([]byte(raw)); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func mustJSON(t testing.TB, v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestStaticKeySet(t *testing.T) {
	k, k2 := rsaKey(t, 2048), rsaOther(t)
	ks := ssf.StaticKeySet{
		EC: []jws.JWK{
			jwkOf(t, key(t, 2), "e-1"), jwkOf(t, key(t, 3), "shared"),
			jwkOf(t, key(t, 2), "two-ec"), jwkOf(t, key(t, 3), "two-ec"),
		},
		RSA: []ssf.RSAKey{
			rsaJWK(t, k, "r-1"), rsaJWK(t, k, "shared"), rsaJWK(t, k, "two-ec"),
			rsaJWK(t, k, "two-rsa"), rsaJWK(t, k2, "two-rsa"),
		},
	}
	if got, err := ks.Key(bg, "e-1"); err != nil || got.Kid != "e-1" {
		t.Fatalf("%v %v", got, err)
	}
	if got, err := ks.RSAKey(bg, "r-1"); err != nil || got.Kid != "r-1" {
		t.Fatalf("%v %v", got, err)
	}
	// Each lookup serves its own type only.
	if _, err := ks.Key(bg, "r-1"); !isUnknownKey(err) {
		t.Fatalf("EC lookup of an RSA kid: %v", err)
	}
	if _, err := ks.RSAKey(bg, "e-1"); !isUnknownKey(err) {
		t.Fatalf("RSA lookup of an EC kid: %v", err)
	}
	// A kid an EC key and an RSA key share names one key of each type (RFC
	// 7517 section 4.5): each lookup serves the key of its type.
	if got, err := ks.Key(bg, "shared"); err != nil || got.Kty != "EC" || got.X != jwkOf(t, key(t, 3), "").X {
		t.Fatalf("shared kid, EC: %v %v", got, err)
	}
	if got, err := ks.RSAKey(bg, "shared"); err != nil || got.Kty != "RSA" || got.N != b64(k.N.Bytes()) {
		t.Fatalf("shared kid, RSA: %v %v", got, err)
	}
	// Two keys of one type under a kid: that type is trusted for neither,
	// the other type still is.
	if _, err := ks.Key(bg, "two-ec"); !isUnknownKey(err) {
		t.Fatalf("two EC keys under one kid: %v", err)
	}
	if got, err := ks.RSAKey(bg, "two-ec"); err != nil || got.Kid != "two-ec" {
		t.Fatalf("the RSA key beside two EC keys: %v %v", got, err)
	}
	if _, err := ks.RSAKey(bg, "two-rsa"); !isUnknownKey(err) {
		t.Fatalf("two RSA keys under one kid: %v", err)
	}
	if _, err := ks.RSAKey(bg, "nope"); !isUnknownKey(err) {
		t.Fatalf("unknown kid: %v", err)
	}
}

// A JWKS of an RS256 transmitter, such as the keys document Google publishes.
func TestJWKSServesRSAKeys(t *testing.T) {
	k, k2 := rsaKey(t, 2048), rsaOther(t)
	srv := newJWKS(t, jwksOf(t,
		rsaMembers(k, kidRSA),
		withAlg(rsaMembers(k2, "wrong-alg"), "RS384"),
		rsaMembers(k, "shared"), jwkOf(t, key(t, 2), "shared"),
		jwkOf(t, key(t, 2), "shared-2"), rsaMembers(k, "shared-2"),
		jwkOf(t, key(t, 2), "ec-1"),
		rsaMembers(k, "two-rsa"), rsaMembers(k2, "two-rsa"), jwkOf(t, key(t, 2), "two-rsa"),
		jwkOf(t, key(t, 2), "three-ec"), jwkOf(t, key(t, 3), "three-ec"), jwkOf(t, key(t, 2), "three-ec"), rsaMembers(k, "three-ec"),
	))
	clk := clock.NewFake(time.Unix(nowSec, 0))
	j, err := ssf.NewJWKS(srv.URL, srv.Client(), clk, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := j.RSAKey(bg, kidRSA); err != nil || got.Kid != kidRSA || got.Kty != "RSA" {
		t.Fatalf("%v %v", got, err)
	}
	if _, err := j.RSAKey(bg, "wrong-alg"); !isUnknownKey(err) {
		t.Fatalf("a key whose alg is not RS256 was served: %v", err)
	}
	if _, err := j.Key(bg, kidRSA); !isUnknownKey(err) {
		t.Fatalf("an RSA key served as EC: %v", err)
	}
	if _, err := j.RSAKey(bg, "ec-1"); !isUnknownKey(err) {
		t.Fatalf("an EC key served as RSA: %v", err)
	}
	// A kid an EC key and an RSA key share names one key of each type (RFC
	// 7517 section 4.5), in either order.
	for _, shared := range []string{"shared", "shared-2"} {
		if got, err := j.RSAKey(bg, shared); err != nil || got.Kty != "RSA" || got.Kid != shared {
			t.Fatalf("shared kid %s, RSA: %v %v", shared, got, err)
		}
		if got, err := j.Key(bg, shared); err != nil || got.Kty != "EC" || got.Kid != shared {
			t.Fatalf("shared kid %s, EC: %v %v", shared, got, err)
		}
	}
	// Two keys of one type under a kid, or three: that type is trusted for
	// neither, the other type still is.
	if _, err := j.RSAKey(bg, "two-rsa"); !isUnknownKey(err) {
		t.Fatalf("two RSA keys under one kid: %v", err)
	}
	if got, err := j.Key(bg, "two-rsa"); err != nil || got.Kid != "two-rsa" {
		t.Fatalf("the EC key beside two RSA keys: %v %v", got, err)
	}
	if _, err := j.Key(bg, "three-ec"); !isUnknownKey(err) {
		t.Fatalf("three EC keys under one kid: %v", err)
	}
	if got, err := j.RSAKey(bg, "three-ec"); err != nil || got.Kid != "three-ec" {
		t.Fatalf("the RSA key beside three EC keys: %v %v", got, err)
	}
	// Cached: one fetch served all of it.
	if srv.hits.Load() != 1 {
		t.Fatalf("hits %d", srv.hits.Load())
	}
	// A rotated-out RSA key stops verifying after the next refresh; an outage is not an unknown key.
	srv.body.Store(jwksOf(t, jwkOf(t, key(t, 2), "ec-1")))
	clk.Advance(2 * time.Minute)
	if _, err := j.RSAKey(bg, kidRSA); !isUnknownKey(err) {
		t.Fatalf("removed key still served: %v", err)
	}
	srv.code.Store(500)
	clk.Advance(2 * time.Minute)
	if _, err := j.RSAKey(bg, kidRSA); err == nil || isUnknownKey(err) {
		t.Fatalf("outage: %v", err)
	}
}

func TestReceiverWithRSAJWKS(t *testing.T) {
	k := rsaKey(t, 2048)
	small := rsaKey(t, 1024)
	srv := newJWKS(t, jwksOf(t, rsaMembers(k, kidRSA), rsaMembers(small, kidSmall)))
	clk := clock.NewFake(time.Unix(nowSec, 0))
	j, err := ssf.NewJWKS(srv.URL, srv.Client(), clk, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	r := newRig(t, func(c *ssf.Config) {
		c.Issuers[0].Keys = j
		c.Issuers[0].Algorithms = []string{ssf.AlgRS256}
	})
	r.accept(t, compactRS(t, k, rsHeader(kidRSA), disabledClaims("j-1")))
	r.wantState(t, principal("7a1f"), ssf.StateDisabled, nowSec-10)
	_, err = r.rx.Accept(bg, compactRS(t, small, rsHeader(kidSmall), disabledClaims("j-2")))
	wantCode(t, err, ssf.CodeInvalidKey)
	// An outage of the key endpoint is a retry, not a rejection.
	srv.code.Store(500)
	clk.Advance(2 * time.Minute)
	_, err = r.rx.Accept(bg, compactRS(t, k, rsHeader("unlisted"), disabledClaims("j-3")))
	var e *ssf.Error
	if err == nil || asErr(err, &e) {
		t.Fatalf("outage: %v", err)
	}
}

func withAlg(m map[string]any, alg string) map[string]any {
	m["alg"] = alg
	return m
}

// An ES256 signature is exactly the 64 octets R || S (RFC 7518 section 3.4): a
// longer one that carries the same integers, such as R || 0x00 || S, is not
// the signature, and a short one does not panic the receiver.
func TestES256SignatureLength(t *testing.T) {
	c := disabledClaims("e-1")
	good := signed(t, c)
	parts := strings.Split(good, ".")
	sig, _ := b64d(parts[2])
	withSig := func(b []byte) string { return strings.Join([]string{parts[0], parts[1], b64(b)}, ".") }
	padded := append(append(slices.Clone(sig[:32]), 0), sig[32:]...)
	r := newRig(t)
	for name, tok := range map[string]string{
		"R || 0 || S": withSig(padded),
		"S padded":    withSig(append(slices.Clone(sig), 0)),
		"63 octets":   withSig(sig[:63]),
		"31 octets":   withSig(sig[:31]),
		"1 octet":     withSig(sig[:1]),
		"empty":       withSig(nil),
	} {
		t.Run(name, func(t *testing.T) { r.wantRejected(t, tok, ssf.CodeInvalidKey) })
	}
	r.accept(t, good)
}

// RFC 7517 section 4.5: keys of different types may share a kid as
// equivalent alternatives. An ES256-only issuer whose key set holds an EC
// P-256 key and an RSA key under one kid verifies ES256 with the EC key, and
// an RS256 issuer verifies RS256 with the RSA key, through a JWKS and a
// static key set alike. Two keys of one type under one kid stay ambiguous in
// a JWKS; in a static key set they are a configuration error
// (TestStaticKeySetDuplicateKid).
func TestKidSharedAcrossKeyTypes(t *testing.T) {
	k, k2 := rsaKey(t, 2048), rsaOther(t)
	ec, ecOther := jwkOf(t, key(t, 2), kid), jwkOf(t, key(t, 3), kid)
	sources := map[string]func(t *testing.T, ec []jws.JWK, rs []ssf.RSAKey) ssf.KeySource{
		"JWKS": func(t *testing.T, ec []jws.JWK, rs []ssf.RSAKey) ssf.KeySource {
			var ks []any
			for _, e := range ec {
				ks = append(ks, e)
			}
			for _, r := range rs {
				ks = append(ks, r)
			}
			srv := newJWKS(t, jwksOf(t, ks...))
			j, err := ssf.NewJWKS(srv.URL, srv.Client(), clock.NewFake(time.Unix(nowSec, 0)), time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			return j
		},
		"StaticKeySet": func(_ *testing.T, ec []jws.JWK, rs []ssf.RSAKey) ssf.KeySource {
			return ssf.StaticKeySet{EC: ec, RSA: rs}
		},
	}
	es := signed(t, disabledClaims("x-1"))
	rs := compactRS(t, k, rsHeader(kid), disabledClaims("x-1"))
	rsOther := compactRS(t, k2, rsHeader(kid), disabledClaims("x-1"))
	for name, src := range sources {
		t.Run(name, func(t *testing.T) {
			rig := func(algs []string, ecs []jws.JWK, rsas ...ssf.RSAKey) *rig {
				return newRig(t, func(c *ssf.Config) {
					c.Issuers[0].Algorithms = algs
					c.Issuers[0].Keys = src(t, ecs, rsas)
				})
			}
			shared := []ssf.RSAKey{rsaJWK(t, k, kid)}
			r := rig(nil, []jws.JWK{ec}, shared...)
			r.accept(t, es)
			r.wantState(t, principal("7a1f"), ssf.StateDisabled, nowSec-10)
			r = rig([]string{ssf.AlgRS256}, []jws.JWK{ec}, shared...)
			r.accept(t, rs)
			r.wantState(t, principal("7a1f"), ssf.StateDisabled, nowSec-10)
			r = rig(both, []jws.JWK{ec}, shared...)
			r.accept(t, es)
			r.accept(t, rs)
			if name == "StaticKeySet" {
				return
			}
			// Two EC keys under the kid: ES256 has no key, RS256 still does.
			r = rig(both, []jws.JWK{ec, ecOther}, shared...)
			r.wantRejected(t, es, ssf.CodeInvalidKey)
			r.accept(t, rs)
			// Two RSA keys under the kid: RS256 has no key, ES256 still does.
			r = rig(both, []jws.JWK{ec}, rsaJWK(t, k, kid), rsaJWK(t, k2, kid))
			r.wantRejected(t, rs, ssf.CodeInvalidKey)
			r.wantRejected(t, rsOther, ssf.CodeInvalidKey)
			r.accept(t, es)
		})
	}
}

// A static key set is configuration: each of its keys is checked when the
// receiver is built, as it would be when used, so a key that could never
// verify is a configuration error rather than a rejection of every SET.
func TestStaticKeySetIsValidated(t *testing.T) {
	good := rsaJWK(t, rsaKey(t, 2048), kidRSA)
	ec := jwkOf(t, key(t, 2), kid)
	cfg := func(algs []string, ks ssf.KeySource) ssf.Config {
		return ssf.Config{
			SourceID: "ssf-test", Store: source.NewMemory(), Clock: clock.NewFake(time.Unix(nowSec, 0)),
			PrincipalPrefix: prefix,
			Issuers:         []ssf.Issuer{{Issuer: txIssuer, Audience: rxAud, Algorithms: algs, Keys: ks}},
			Mappings:        defaultMappings(),
		}
	}
	for _, algs := range [][]string{nil, both} {
		set := ssf.StaticKeySet{EC: []jws.JWK{ec}, RSA: []ssf.RSAKey{good}}
		if _, err := ssf.NewReceiver(cfg(algs, set)); err != nil {
			t.Fatal(err)
		}
		if _, err := ssf.NewReceiver(cfg(algs, &set)); err != nil {
			t.Fatal(err)
		}
	}
	bad := map[string]func(*ssf.StaticKeySet){
		"RSA 1024 bits": func(s *ssf.StaticKeySet) { s.RSA = append(s.RSA, rsaJWK(t, rsaKey(t, 1024), kidSmall)) },
		"RSA 2047 bits": func(s *ssf.StaticKeySet) { s.RSA = append(s.RSA, rsaJWK(t, rsaKey(t, 2047), kidEdge)) },
		"RSA alg RS384": func(s *ssf.StaticKeySet) { k := good; k.Alg = "RS384"; s.RSA = append(s.RSA, k) },
		"RSA kty rsa":   func(s *ssf.StaticKeySet) { k := good; k.Kty = "rsa"; s.RSA = append(s.RSA, k) },
		"RSA even n": func(s *ssf.StaticKeySet) {
			k := good
			n, _ := b64d(k.N)
			k.N = b64(new(big.Int).Add(new(big.Int).SetBytes(n), big.NewInt(1)).Bytes())
			s.RSA = append(s.RSA, k)
		},
		"RSA use enc": func(s *ssf.StaticKeySet) { k := good; k.Use = "enc"; s.RSA = append(s.RSA, k) },
		"EC not on the curve": func(s *ssf.StaticKeySet) {
			k := jwkOf(t, key(t, 3), "e-3")
			k.X = ec.X
			s.EC = append(s.EC, k)
		},
	}
	for name, mod := range bad {
		for _, algs := range [][]string{nil, both, {ssf.AlgRS256}} {
			t.Run(fmt.Sprint(name, algs), func(t *testing.T) {
				set := ssf.StaticKeySet{EC: []jws.JWK{ec}, RSA: []ssf.RSAKey{good}}
				mod(&set)
				if _, err := ssf.NewReceiver(cfg(algs, set)); err == nil {
					t.Fatal("accepted")
				}
				if _, err := ssf.NewReceiver(cfg(algs, &set)); err == nil {
					t.Fatal("accepted by pointer")
				}
			})
		}
	}
}

// RFC 7517 section 4.3: a key whose key_ops do not name "verify" is not
// intended for verification, whether it is published or configured.
func TestRSAKeyOps(t *testing.T) {
	k := rsaKey(t, 2048)
	enc := rsaMembers(k, "enc-only")
	delete(enc, "use")
	enc["key_ops"] = []string{"encrypt"}
	ver := rsaMembers(k, kidRSA)
	delete(ver, "use")
	ver["key_ops"] = []string{"verify"}
	srv := newJWKS(t, jwksOf(t, enc, ver))
	j, err := ssf.NewJWKS(srv.URL, srv.Client(), clock.NewFake(time.Unix(nowSec, 0)), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	r := newRig(t, func(c *ssf.Config) {
		c.Issuers[0].Algorithms = both
		c.Issuers[0].Keys = j
	})
	r.wantRejected(t, compactRS(t, k, rsHeader("enc-only"), disabledClaims("o-1")), ssf.CodeInvalidKey)
	r.accept(t, compactRS(t, k, rsHeader(kidRSA), disabledClaims("o-2")))
	// A key built in Go: PublicKey and the static set check key_ops too.
	built := rsaJWK(t, k, "built")
	built.KeyOps = []string{"encrypt"}
	if _, err := built.PublicKey(); err == nil {
		t.Fatal("PublicKey accepted key_ops encrypt")
	}
	built.KeyOps = []string{}
	if _, err := built.PublicKey(); err == nil {
		t.Fatal("PublicKey accepted empty key_ops")
	}
	_, err = ssf.NewReceiver(ssf.Config{
		SourceID: "ssf-test", Store: source.NewMemory(), Clock: clock.NewFake(time.Unix(nowSec, 0)),
		PrincipalPrefix: prefix, Mappings: defaultMappings(),
		Issuers: []ssf.Issuer{{Issuer: txIssuer, Audience: rxAud, Algorithms: both,
			Keys: ssf.StaticKeySet{RSA: []ssf.RSAKey{built}}}},
	})
	if err == nil {
		t.Fatal("static key with empty key_ops accepted")
	}
	built.KeyOps = nil // absent
	if _, err := built.PublicKey(); err != nil {
		t.Fatal(err)
	}
	built.KeyOps = []string{"sign", "verify"}
	if _, err := built.PublicKey(); err != nil {
		t.Fatal(err)
	}
}
