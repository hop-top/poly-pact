package ssf_test

import (
	"fmt"
	"testing"
	"time"

	"hop.top/pact-go/adapter/source"
	"hop.top/pact-go/adapter/source/ssf"
	"hop.top/pact-go/core/clock"
	"hop.top/pact-go/core/jws"
)

// issuerConfig is a receiver configuration whose one issuer has the given
// algorithms and key source.
func issuerConfig(algs []string, ks ssf.KeySource) ssf.Config {
	return ssf.Config{
		SourceID: "ssf-test", Store: source.NewMemory(), Clock: clock.NewFake(time.Unix(nowSec, 0)),
		PrincipalPrefix: prefix,
		Issuers:         []ssf.Issuer{{Issuer: txIssuer, Audience: rxAud, Algorithms: algs, Keys: ks}},
		Mappings:        defaultMappings(),
	}
}

// An EC key built in Go is held to the rules of a published one (see
// jws.ParseJWK): alg, when present, ES256, and use, when present, sig (RFC
// 7517 sections 4.2 and 4.4). In a static key set it is checked when the
// receiver is configured; from any source, when it is used.
func TestBuiltECKeyUsage(t *testing.T) {
	ec := jwkOf(t, key(t, 2), kid)
	for name, mod := range map[string]func(*jws.JWK){
		"alg RS256":     func(k *jws.JWK) { k.Alg = "RS256" },
		"alg ES384":     func(k *jws.JWK) { k.Alg = "ES384" },
		"alg es256":     func(k *jws.JWK) { k.Alg = "es256" },
		"alg none":      func(k *jws.JWK) { k.Alg = "none" },
		"use enc":       func(k *jws.JWK) { k.Use = "enc" },
		"use Sig":       func(k *jws.JWK) { k.Use = "Sig" },
		"alg and use":   func(k *jws.JWK) { k.Alg, k.Use = "ES256", "enc" },
		"alg Ed25519":   func(k *jws.JWK) { k.Alg = jws.AlgEd25519 },
		"use sig alg x": func(k *jws.JWK) { k.Alg, k.Use = "HS256", "sig" },
	} {
		t.Run(name, func(t *testing.T) {
			k := ec
			mod(&k)
			for _, algs := range [][]string{nil, both} {
				set := ssf.StaticKeySet{EC: []jws.JWK{k}}
				if _, err := ssf.NewReceiver(issuerConfig(algs, set)); err == nil {
					t.Fatalf("static key set accepted, algorithms %v", algs)
				}
				if _, err := ssf.NewReceiver(issuerConfig(algs, &set)); err == nil {
					t.Fatalf("static key set accepted by pointer, algorithms %v", algs)
				}
				keys := ssf.StaticKeys{k}
				if _, err := ssf.NewReceiver(issuerConfig(algs, keys)); err == nil {
					t.Fatalf("static keys accepted, algorithms %v", algs)
				}
				if _, err := ssf.NewReceiver(issuerConfig(algs, &keys)); err == nil {
					t.Fatalf("static keys accepted by pointer, algorithms %v", algs)
				}
			}
			// A source that is not checked at configuration: the key is
			// refused when it is used.
			r := newRig(t, func(c *ssf.Config) { c.Issuers[0].Keys = unchecked{k} })
			r.wantRejected(t, signed(t, disabledClaims("u-1")), ssf.CodeInvalidKey)
		})
	}
	for name, mod := range map[string]func(*jws.JWK){
		"no alg, no use": func(*jws.JWK) {},
		"alg ES256":      func(k *jws.JWK) { k.Alg = "ES256" },
		"use sig":        func(k *jws.JWK) { k.Use = "sig" },
		"both":           func(k *jws.JWK) { k.Alg, k.Use = "ES256", "sig" },
	} {
		t.Run(name, func(t *testing.T) {
			k := ec
			mod(&k)
			if _, err := ssf.NewReceiver(issuerConfig(nil, ssf.StaticKeySet{EC: []jws.JWK{k}})); err != nil {
				t.Fatal(err)
			}
			r := newRig(t, func(c *ssf.Config) { c.Issuers[0].Keys = ssf.StaticKeySet{EC: []jws.JWK{k}} })
			r.accept(t, signed(t, disabledClaims("u-1")))
			r = newRig(t, func(c *ssf.Config) { c.Issuers[0].Keys = ssf.StaticKeys{k} })
			r.accept(t, signed(t, disabledClaims("u-1")))
		})
	}
}

// Two keys of one type under one kid in a static key set would make that kid
// unusable for that type: configuration, unlike a fetched set, can be
// corrected, so NewReceiver refuses it. An EC key and an RSA key may share a
// kid (RFC 7517 section 4.5).
func TestStaticKeySetDuplicateKid(t *testing.T) {
	k, k2 := rsaKey(t, 2048), rsaOther(t)
	ec, ecOther := jwkOf(t, key(t, 2), kid), jwkOf(t, key(t, 3), kid)
	for name, set := range map[string]ssf.StaticKeySet{
		"two EC keys":           {EC: []jws.JWK{ec, ecOther}},
		"one EC key twice":      {EC: []jws.JWK{ec, ec}},
		"two EC keys and RSA":   {EC: []jws.JWK{ec, ecOther}, RSA: []ssf.RSAKey{rsaJWK(t, k, kid)}},
		"two RSA keys":          {EC: []jws.JWK{ec}, RSA: []ssf.RSAKey{rsaJWK(t, k, kidRSA), rsaJWK(t, k2, kidRSA)}},
		"one RSA key twice":     {EC: []jws.JWK{ec}, RSA: []ssf.RSAKey{rsaJWK(t, k, kidRSA), rsaJWK(t, k, kidRSA)}},
		"two RSA keys under EC": {EC: []jws.JWK{ec}, RSA: []ssf.RSAKey{rsaJWK(t, k, kid), rsaJWK(t, k2, kid)}},
	} {
		for _, algs := range [][]string{nil, both, {ssf.AlgRS256}} {
			t.Run(fmt.Sprint(name, algs), func(t *testing.T) {
				if _, err := ssf.NewReceiver(issuerConfig(algs, set)); err == nil {
					t.Fatal("accepted")
				}
				if _, err := ssf.NewReceiver(issuerConfig(algs, &set)); err == nil {
					t.Fatal("accepted by pointer")
				}
			})
		}
	}
	shared := ssf.StaticKeySet{EC: []jws.JWK{ec, jwkOf(t, key(t, 3), "other")}, RSA: []ssf.RSAKey{rsaJWK(t, k, kid), rsaJWK(t, k2, kidRSA)}}
	if _, err := ssf.NewReceiver(issuerConfig(both, shared)); err != nil {
		t.Fatalf("an EC and an RSA key under one kid: %v", err)
	}
}

// A key source that is a nil pointer would panic on its first use; it is
// refused when the receiver is configured, as a nil interface is.
func TestTypedNilKeySource(t *testing.T) {
	var j *ssf.JWKS
	var s *ssf.StaticKeySet
	for name, ks := range map[string]ssf.KeySource{"*JWKS": j, "*StaticKeySet": s} {
		for _, algs := range [][]string{nil, both} {
			t.Run(fmt.Sprint(name, algs), func(t *testing.T) {
				if _, err := ssf.NewReceiver(issuerConfig(algs, ks)); err == nil {
					t.Fatal("accepted")
				}
			})
		}
	}
}

// unchecked is a key source NewReceiver does not look into: it serves its
// one key under any kid.
type unchecked struct{ k jws.JWK }

func (u unchecked) Key(ctxT, string) (jws.JWK, error) { return u.k, nil }

// StaticKeys is configuration too: NewReceiver checks each key as it is
// used and refuses a kid that names two keys, and a direct lookup of such a
// kid serves neither, as in a StaticKeySet.
func TestStaticKeysAreValidated(t *testing.T) {
	ec, ecOther := jwkOf(t, key(t, 2), kid), jwkOf(t, key(t, 3), kid)
	for name, keys := range map[string]ssf.StaticKeys{
		"two keys under one kid": {ec, ecOther},
		"one key twice":          {ec, ec},
		"not on the curve":       {func() jws.JWK { k := jwkOf(t, key(t, 3), "e-3"); k.X = ec.X; return k }()},
		"kty RSA":                {func() jws.JWK { k := ec; k.Kty = "RSA"; return k }()},
	} {
		for _, algs := range [][]string{nil, both} {
			t.Run(fmt.Sprint(name, algs), func(t *testing.T) {
				if _, err := ssf.NewReceiver(issuerConfig(algs, keys)); err == nil {
					t.Fatal("accepted")
				}
				if _, err := ssf.NewReceiver(issuerConfig(algs, &keys)); err == nil {
					t.Fatal("accepted by pointer")
				}
			})
		}
	}
	ok := ssf.StaticKeys{ec, jwkOf(t, key(t, 3), "other")}
	if _, err := ssf.NewReceiver(issuerConfig(nil, ok)); err != nil {
		t.Fatal(err)
	}
	if got, err := ok.Key(bg, "other"); err != nil || got.Kid != "other" {
		t.Fatalf("%v %v", got, err)
	}
	if _, err := (ssf.StaticKeys{ec, ecOther}).Key(bg, kid); !isUnknownKey(err) {
		t.Fatalf("two keys under one kid served: %v", err)
	}
	if _, err := ok.Key(bg, "nope"); !isUnknownKey(err) {
		t.Fatalf("unknown kid: %v", err)
	}
	var nilKeys *ssf.StaticKeys
	if _, err := ssf.NewReceiver(issuerConfig(nil, nilKeys)); err == nil {
		t.Fatal("nil *StaticKeys accepted")
	}
}
