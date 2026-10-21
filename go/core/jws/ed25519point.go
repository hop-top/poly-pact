package jws

import (
	"errors"
	"math/big"
)

// edwards25519 (RFC 8032 section 5.1, RFC 7748 section 4.1): p = 2^255 - 19
// and d = -121665/121666 mod p. The curve is -x^2 + y^2 = 1 + d x^2 y^2.
var (
	edP = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	edD = func() *big.Int {
		inv := new(big.Int).ModInverse(big.NewInt(121666), edP)
		d := new(big.Int).Mul(big.NewInt(-121665), inv)
		return d.Mod(d, edP)
	}()
	// edSqrtM1 is 2^((p-1)/4) mod p, a square root of -1.
	edSqrtM1 = new(big.Int).Exp(big.NewInt(2), new(big.Int).Rsh(new(big.Int).Sub(edP, big.NewInt(1)), 2), edP)
	// edExp is (p-5)/8, the exponent of the candidate root of step 2.
	edExp = new(big.Int).Rsh(new(big.Int).Sub(edP, big.NewInt(5)), 3)
	// edL is L = 2^252 + 27742317777372353535851937790883648493, the prime
	// order of the base point B (RFC 8032 section 5.1).
	edL = func() *big.Int {
		c, _ := new(big.Int).SetString("27742317777372353535851937790883648493", 10)
		return c.Add(c, new(big.Int).Lsh(big.NewInt(1), 252))
	}()
	// ed2D is 2d mod p, a constant of the addition formulas of RFC 8032
	// section 5.1.4.
	ed2D = new(big.Int).Mod(new(big.Int).Lsh(edD, 1), edP)
)

// checkEd25519Point decodes the 32-octet public key b as RFC 8032 section
// 5.1.3 does and fails when decoding fails: y is p or more (step 1), there
// is no x for that y (steps 2 and 3), or x is 0 with the sign bit set (step
// 4). It also fails for a point of small order, whose [8]P is the identity:
// key generation (RFC 8032 section 5.1.5, step 4) makes the public key
// [s]B, of the prime order L of the base point, so no such key is ever
// generated, and a signature under it is bound to no private key. For the
// same reason it fails for any other point A outside the subgroup of order
// L, one whose [L]A is not the identity: a point of mixed order, the sum of
// a point of order L and a nonzero point of small order, has [8]A not the
// identity and is caught only here.
func checkEd25519Point(b []byte) error {
	if len(b) != 32 {
		return errors.New("not 32 octets")
	}
	le := make([]byte, 32)
	for i := range b {
		le[31-i] = b[i]
	}
	x0 := uint(le[0] >> 7)
	le[0] &= 0x7f
	y := new(big.Int).SetBytes(le)
	if y.Cmp(edP) >= 0 {
		return errors.New("not an edwards25519 point: y is not below p (RFC 8032 section 5.1.3, step 1)")
	}
	x, ok := recoverX(y)
	if !ok {
		return errors.New("not an edwards25519 point: no x for its y (RFC 8032 section 5.1.3, step 3)")
	}
	if x.Sign() == 0 && x0 == 1 {
		return errors.New("not an edwards25519 point encoding: x = 0 with the sign bit set (RFC 8032 section 5.1.3, step 4)")
	}
	// Step 4 then picks x or p - x by x_0. Both points have the same order,
	// so the order check below does not depend on the choice.
	px, py := x, y
	for range 3 {
		px, py = edAdd(px, py, px, py)
	}
	if px.Sign() == 0 && py.Cmp(big.NewInt(1)) == 0 {
		return errors.New("an edwards25519 point of small order, which key generation never yields (RFC 8032 section 5.1.5)")
	}
	if !edIdentity(edMul(edL, x, y)) {
		return errors.New("an edwards25519 point outside the subgroup of prime order L: [L]A is not the identity, and key generation yields only [s]B (RFC 8032 section 5.1.5)")
	}
	return nil
}

// edPoint is a point of edwards25519 in extended homogeneous coordinates
// (RFC 8032 section 5.1.4): x = X/Z, y = Y/Z, x y = T/Z.
type edPoint struct{ X, Y, Z, T *big.Int }

// edMul returns [k](x, y) by double and add with the addition formulas of
// RFC 8032 section 5.1.4, which are complete, so they also double. The
// coordinates stay projective: no inversion per step.
func edMul(k, x, y *big.Int) edPoint {
	q := edPoint{new(big.Int), big.NewInt(1), big.NewInt(1), new(big.Int)}
	pt := edPoint{new(big.Int).Set(x), new(big.Int).Set(y), big.NewInt(1), new(big.Int).Mod(new(big.Int).Mul(x, y), edP)}
	for i := k.BitLen() - 1; i >= 0; i-- {
		q = edAddExt(q, q)
		if k.Bit(i) == 1 {
			q = edAddExt(q, pt)
		}
	}
	return q
}

// edAddExt adds two points in extended coordinates (RFC 8032 section 5.1.4):
// A = (Y1-X1)(Y2-X2), B = (Y1+X1)(Y2+X2), C = T1 2d T2, D = Z1 2 Z2,
// E = B-A, F = D-C, G = D+C, H = B+A, and X3 = E F, Y3 = G H, T3 = E H,
// Z3 = F G.
func edAddExt(p1, p2 edPoint) edPoint {
	mul := func(a, b *big.Int) *big.Int { return new(big.Int).Mod(new(big.Int).Mul(a, b), edP) }
	a := mul(new(big.Int).Sub(p1.Y, p1.X), new(big.Int).Sub(p2.Y, p2.X))
	b := mul(new(big.Int).Add(p1.Y, p1.X), new(big.Int).Add(p2.Y, p2.X))
	c := mul(mul(p1.T, ed2D), p2.T)
	d := mul(new(big.Int).Lsh(p1.Z, 1), p2.Z)
	e := new(big.Int).Sub(b, a)
	f := new(big.Int).Sub(d, c)
	g := new(big.Int).Add(d, c)
	h := new(big.Int).Add(b, a)
	return edPoint{X: mul(e, f), Y: mul(g, h), Z: mul(f, g), T: mul(e, h)}
}

// edIdentity reports whether q is the neutral element (0, 1): X = 0 and
// Y = Z mod p.
func edIdentity(q edPoint) bool {
	return q.X.Sign() == 0 && q.Y.Cmp(q.Z) == 0
}

// recoverX returns a square root of (y^2 - 1) / (d y^2 + 1) mod p (RFC 8032
// section 5.1.3, steps 2 and 3), or false when there is none.
func recoverX(y *big.Int) (*big.Int, bool) {
	yy := new(big.Int).Mul(y, y)
	u := new(big.Int).Sub(yy, big.NewInt(1))
	u.Mod(u, edP)
	v := new(big.Int).Mul(edD, yy)
	v.Add(v, big.NewInt(1)).Mod(v, edP)
	// x = u v^3 (u v^7)^((p-5)/8)
	v3 := new(big.Int).Exp(v, big.NewInt(3), edP)
	v7 := new(big.Int).Exp(v, big.NewInt(7), edP)
	uv7 := new(big.Int).Mul(u, v7)
	uv7.Mod(uv7, edP).Exp(uv7, edExp, edP)
	x := new(big.Int).Mul(u, v3)
	x.Mul(x, uv7).Mod(x, edP)
	vxx := new(big.Int).Mul(x, x)
	vxx.Mul(vxx, v).Mod(vxx, edP)
	negU := new(big.Int).Sub(edP, u)
	negU.Mod(negU, edP)
	switch {
	case vxx.Cmp(u) == 0:
		return x, true
	case vxx.Cmp(negU) == 0:
		return x.Mul(x, edSqrtM1).Mod(x, edP), true
	}
	return nil, false
}

// edAdd adds two points of edwards25519 in affine coordinates (RFC 8032
// section 3, a = -1): x3 = (x1 y2 + x2 y1) / (1 + d x1 x2 y1 y2) and y3 =
// (y1 y2 + x1 x2) / (1 - d x1 x2 y1 y2). The formulas are complete, so the
// denominators are never zero.
func edAdd(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
	t := new(big.Int).Mul(x1, x2)
	t.Mul(t, y1).Mul(t, y2).Mul(t, edD).Mod(t, edP)
	nx := new(big.Int).Mul(x1, y2)
	nx.Add(nx, new(big.Int).Mul(x2, y1))
	ny := new(big.Int).Mul(y1, y2)
	ny.Add(ny, new(big.Int).Mul(x1, x2))
	dx := new(big.Int).Add(big.NewInt(1), t)
	dy := new(big.Int).Sub(big.NewInt(1), t)
	dx.Mod(dx, edP).ModInverse(dx, edP)
	dy.Mod(dy, edP).ModInverse(dy, edP)
	nx.Mul(nx, dx).Mod(nx, edP)
	ny.Mul(ny, dy).Mod(ny, edP)
	return nx, ny
}
