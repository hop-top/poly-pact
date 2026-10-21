package holder_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"math/big"
	"testing"
	"time"

	"hop.top/pact-go/contract"
	"hop.top/pact-go/core/jws"
	"hop.top/pact-go/holder"
)

// TestMemoryKeyES256: the public key is the fixture holder JWK with no
// optional members, and signatures are 64-octet low-S ECDSA over SHA-256 of
// the signing input (RFC 7518 section 3.4).
func TestMemoryKeyES256(t *testing.T) {
	k := memoryKey(t, 1)
	pub := mustJWK(t, k)
	want := holderJWK(t)
	if pub.Kty != want.Kty || pub.Crv != want.Crv || pub.X != want.X || pub.Y != want.Y || pub.Kid != "" || pub.Alg != "" || pub.Use != "" {
		t.Fatalf("PublicJWK %+v, want %+v without kid, alg, use", pub, want)
	}
	input := []byte("eyJhbGciOiJFUzI1NiJ9.e30")
	sum := sha256.Sum256(input)
	half := new(big.Int).Rsh(elliptic.P256().Params().N, 1)
	// Half of all raw ECDSA signatures have a high S: 64 low-S ones in a row
	// show that the key normalizes.
	for range 64 {
		sig, err := k.Sign(bg, input)
		if err != nil || len(sig) != 64 {
			t.Fatalf("Sign: %d octets, %v", len(sig), err)
		}
		r, s := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])
		if !ecdsa.Verify(&scalarKey(t, 1).PublicKey, sum[:], r, s) {
			t.Fatal("signature does not verify")
		}
		if s.Cmp(half) > 0 {
			t.Fatal("high S")
		}
	}
	if _, err := holder.NewMemoryKeyES256(nil); err == nil {
		t.Fatal("nil key accepted")
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), zeroReader{})
	if err == nil {
		if _, err := holder.NewMemoryKeyES256(p384); err == nil {
			t.Fatal("P-384 key accepted")
		}
	}
	if _, err := holder.NewMemoryKeyEd25519(nil); err == nil {
		t.Fatal("empty Ed25519 key accepted")
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 7
	}
	return len(p), nil
}

// TestEd25519Presentation: where Ed25519 is negotiated (draft 7.2), an
// Ed25519 holder key signs a presentation that verifies; without the
// negotiation the holder refuses the key.
func TestEd25519Presentation(t *testing.T) {
	ed, err := holder.NewMemoryKeyEd25519(edKey(t))
	if err != nil {
		t.Fatal(err)
	}
	pub := mustJWK(t, ed)
	jkt, err := jws.Thumbprint(pub)
	if err != nil {
		t.Fatal(err)
	}
	c := issue(t, contract.NewMemoryReplay(4), jkt, bRequirements(t), bOperation(t), at(bTime))
	in := bInput(t)
	in.Contract = c.Compact
	in.Profile.HolderJKT = jkt
	in.Evidence = []string{signEvidence(t, 2, "test-issuer-key-1", withHolder(bEvidence(t), jkt))}
	in.Reputation = signSnapshotFor(t, bTime, jkt)

	h := bHolder(t, ed)
	_, err = h.Present(bg, in, at(bTime))
	wantErr(t, err, holder.ErrUnsupportedRequirement)

	h.Algorithms = jws.Algorithms{jws.AlgES256, jws.AlgEd25519}
	p, err := h.Present(bg, in, at(bTime))
	if err != nil {
		t.Fatalf("Present: %v", err)
	}
	g := gatewayChecks{enrolled: pub, algs: h.Algorithms, actual: bOperation(t), now: at(bTime).Add(time.Second)}
	if _, _, err := g.run(t, p.Compact); err != nil {
		t.Fatalf("gateway checks: %v", err)
	}
}
