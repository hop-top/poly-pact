package jws

import (
	"crypto/ed25519"
	"math/big"
	"strings"
	"testing"
)

// RFC 8037 Appendix A.4: an Ed25519 signature over a JWS signing input, with
// the public key of Appendix A.2. The values are copied from the RFC text.
// RFC 9864 section 2.2 defines alg Ed25519 as EdDSA with the Ed25519
// parameter set of RFC 8032 section 5.1, so these signature octets are what
// the fully specified identifier verifies; only the header names the older
// EdDSA identifier, which the profile does not accept (draft 7.2).
const (
	rfc8037A4Compact = "eyJhbGciOiJFZERTQSJ9" +
		".RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc" +
		".hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg"
	rfc8037X = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
)

func TestRFC8037A4Signature(t *testing.T) {
	k := JWK{Kty: "OKP", Crv: "Ed25519", X: rfc8037X}
	pub, err := k.Ed25519PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	last := strings.LastIndexByte(rfc8037A4Compact, '.')
	sig, err := decodeSegment(rfc8037A4Compact[last+1:])
	if err != nil {
		t.Fatal(err)
	}
	if !verifyEd25519(pub, rfc8037A4Compact[:last], sig) {
		t.Fatal("the RFC 8037 A.4 signature does not verify")
	}
	sig[0] ^= 1
	if verifyEd25519(pub, rfc8037A4Compact[:last], sig) {
		t.Fatal("a changed signature verifies")
	}
	if verifyEd25519(ed25519.PublicKey(pub[:31]), rfc8037A4Compact[:last], sig) {
		t.Fatal("a 31-octet public key verifies")
	}
}

// TestRecoverXOnCurve: for y = 0..299, recoverX finds an x exactly when
// (y^2 - 1) / (d y^2 + 1) is a square mod p, by Euler's criterion, and then
// (x, y) satisfies the curve equation -x^2 + y^2 = 1 + d x^2 y^2 (RFC 8032
// section 5.1). Both cases of step 3 of section 5.1.3 occur in the range.
func TestRecoverXOnCurve(t *testing.T) {
	one := big.NewInt(1)
	half := new(big.Int).Rsh(new(big.Int).Sub(edP, one), 1)
	square := 0
	for i := int64(0); i < 300; i++ {
		y := big.NewInt(i)
		yy := new(big.Int).Mul(y, y)
		u := new(big.Int).Sub(yy, one)
		v := new(big.Int).Add(new(big.Int).Mul(edD, yy), one)
		q := new(big.Int).Mul(u.Mod(u, edP), new(big.Int).ModInverse(v.Mod(v, edP), edP))
		q.Mod(q, edP)
		isSquare := q.Sign() == 0 || new(big.Int).Exp(q, half, edP).Cmp(one) == 0
		x, ok := recoverX(y)
		if ok != isSquare {
			t.Fatalf("y = %d: recoverX found a root %v, Euler's criterion says square %v", i, ok, isSquare)
		}
		if !ok {
			continue
		}
		square++
		xx := new(big.Int).Mul(x, x)
		lhs := new(big.Int).Sub(yy, xx)
		rhs := new(big.Int).Mul(edD, xx)
		rhs.Mul(rhs, yy).Add(rhs, one)
		if lhs.Mod(lhs, edP).Cmp(rhs.Mod(rhs, edP)) != 0 {
			t.Fatalf("y = %d: (x, y) is not on the curve", i)
		}
	}
	if square == 0 {
		t.Fatal("no y with a root")
	}
}

// TestEdMulMatchesAffine: [k]B by edMul, in extended coordinates, equals k
// affine additions of B by edAdd for k = 0..40, and [L]B is the identity
// (RFC 8032 section 5.1: B has order L). B is (x, 4/5) with x even.
func TestEdMulMatchesAffine(t *testing.T) {
	by := new(big.Int).Mul(big.NewInt(4), new(big.Int).ModInverse(big.NewInt(5), edP))
	by.Mod(by, edP)
	bx, ok := recoverX(by)
	if !ok {
		t.Fatal("no x for y = 4/5")
	}
	if bx.Bit(0) == 1 {
		bx.Sub(edP, bx)
	}
	ax, ay := big.NewInt(0), big.NewInt(1)
	for k := int64(0); k <= 40; k++ {
		q := edMul(big.NewInt(k), bx, by)
		zi := new(big.Int).ModInverse(q.Z, edP)
		qx := new(big.Int).Mod(new(big.Int).Mul(q.X, zi), edP)
		qy := new(big.Int).Mod(new(big.Int).Mul(q.Y, zi), edP)
		if qx.Cmp(ax) != 0 || qy.Cmp(ay) != 0 {
			t.Fatalf("[%d]B differs from %d affine additions", k, k)
		}
		if edIdentity(q) != (k == 0) {
			t.Fatalf("[%d]B: identity %v", k, edIdentity(q))
		}
		ax, ay = edAdd(ax, ay, bx, by)
	}
	if !edIdentity(edMul(edL, bx, by)) {
		t.Fatal("[L]B is not the identity")
	}
}
