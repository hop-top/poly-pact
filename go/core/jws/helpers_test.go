package jws_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"hop.top/pact-go/core"
	"hop.top/pact-go/core/jws"
)

// fixturesRoot is spec/v1.0/fixtures relative to this package directory.
var fixturesRoot = filepath.Join("..", "..", "..", "spec", "v1.0", "fixtures")

// draftPath is the specification relative to this package directory.
const draftPath = "../../../spec/v1.0/draft.md"

// holderJKT is the holder_jkt printed in draft Appendix C.
const holderJKT core.Digest = "xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M"

var b64 = base64.RawURLEncoding

func readFile(t testing.TB, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return b
}

// scalarKey returns the P-256 private key whose scalar is n, as the test keys
// of spec/v1.0/fixtures/keys define them.
func scalarKey(t testing.TB, n byte) *ecdsa.PrivateKey {
	t.Helper()
	d := make([]byte, 32)
	d[31] = n
	k, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), d)
	if err != nil {
		t.Fatalf("scalar %d: %v", n, err)
	}
	return k
}

func fixtureJWK(t testing.TB, name string) jws.JWK {
	t.Helper()
	k, err := jws.ParseJWK(readFile(t, filepath.Join(fixturesRoot, "keys", name+".jwk.json")))
	if err != nil {
		t.Fatalf("parse %s.jwk.json: %v", name, err)
	}
	return k
}

func keySet(t testing.TB, keys ...jws.JWK) *jws.KeySet {
	t.Helper()
	s, err := jws.NewKeySet(keys...)
	if err != nil {
		t.Fatalf("NewKeySet: %v", err)
	}
	return s
}

// rawCompact signs header.payload with crypto/ecdsa directly, so that tests
// can build inputs the package's Sign refuses to make.
func rawCompact(t testing.TB, header, payload string, key *ecdsa.PrivateKey) string {
	t.Helper()
	si := b64.EncodeToString([]byte(header)) + "." + b64.EncodeToString([]byte(payload))
	return si + "." + b64.EncodeToString(rawSig(t, si, key))
}

func rawSig(t testing.TB, signingInput string, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	h := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, key, h[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return sig
}

func wantReason(t testing.TB, err error, want jws.Reason) {
	t.Helper()
	if err == nil {
		t.Fatalf("got no error, want %s", want)
	}
	if got := jws.ReasonOf(err); got != want {
		t.Fatalf("reason %q, want %q (error: %v)", got, want, err)
	}
	if !errors.Is(err, want) {
		t.Fatalf("errors.Is(err, %s) is false (error: %v)", want, err)
	}
}

// issuerResolver trusts the issuer test key for the issuer role and expects
// the Appendix C holder thumbprint for holder-signed artifacts.
func issuerResolver(t testing.TB) jws.StaticResolver {
	t.Helper()
	return jws.StaticResolver{
		KeySets:           map[jws.Role]*jws.KeySet{jws.RoleIssuer: keySet(t, fixtureJWK(t, "issuer"))},
		ExpectedHolderJKT: holderJKT,
	}
}

func ecdsaKey(d []byte) (*ecdsa.PrivateKey, error) {
	return ecdsa.ParseRawPrivateKey(elliptic.P256(), d)
}
