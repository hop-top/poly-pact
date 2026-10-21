package jws_test

// Ed25519 public key validation. x of an OKP Ed25519 key (RFC 8037 section
// 2) must decode as a point of edwards25519 under RFC 8032 section 5.1.3:
// the y-coordinate, bit 255 cleared, is below p = 2^255 - 19 (step 1);
// (y^2 - 1) / (d y^2 + 1) has a square root mod p (steps 2 and 3); and x = 0
// does not come with the sign bit x_0 = 1 (step 4). A key that decodes to a
// point of small order, one whose [8]P is the identity, is rejected too: key
// generation (RFC 8032 section 5.1.5, step 4) makes the public key [s]B, a
// multiple of the base point B of prime order L, so no generated key is of
// small order, and such a key binds a signature to no private key. For the
// same reason a point of mixed order, a point of the prime-order subgroup
// plus a nonzero point of small order, is rejected: its [L]P is not the
// identity, L = 2^252 + 27742317777372353535851937790883648493 the order of
// B (RFC 8032 section 5.1). The encodings below were computed apart from
// this package, from the RFC 8032 formulas.

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"hop.top/pact-go/core/jws"
)

// rfc8032PublicKeys are the PUBLIC KEY values of RFC 8032 section 7.1:
// tests 1, 2, 3, 1024 and SHA(abc), then the base point B of section 5.1
// (y = 4/5, x even). All are of the prime order L.
var rfc8032PublicKeys = []string{
	"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
	"3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
	"fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
	"278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e",
	"ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
	"5866666666666666666666666666666666666666666666666666666666666666",
}

func okp(t *testing.T, hexKey string) jws.JWK {
	t.Helper()
	b, err := hex.DecodeString(hexKey)
	if err != nil || len(b) != 32 {
		t.Fatalf("test key %s: %v", hexKey, err)
	}
	return jws.JWK{Kty: "OKP", Crv: "Ed25519", X: base64.RawURLEncoding.EncodeToString(b), Kid: "k"}
}

func TestEd25519PublicKeyRFC8032Vectors(t *testing.T) {
	for _, h := range rfc8032PublicKeys {
		k := okp(t, h)
		pub, err := k.Ed25519PublicKey()
		if err != nil {
			t.Errorf("%s: %v", h, err)
			continue
		}
		if hex.EncodeToString(pub) != h {
			t.Errorf("%s: key %x", h, pub)
		}
		if _, err := (jws.Algorithms{jws.AlgEd25519}).NewKeySet(k); err != nil {
			t.Errorf("%s: NewKeySet: %v", h, err)
		}
	}
}

func TestEd25519PublicKeyInvalidEncodings(t *testing.T) {
	ff := strings.Repeat("ff", 30)
	tests := []struct {
		name, key, msg string
	}{
		// Step 1: y, bit 255 cleared, is p or more.
		{"y = p", "ed" + ff + "7f", "y is not below p"},
		{"y = p + 1, the identity not reduced", "ee" + ff + "7f", "y is not below p"},
		{"y = p, sign bit set", "ed" + ff + "ff", "y is not below p"},
		{"y = 2^255 - 1", "ff" + ff + "7f", "y is not below p"},
		// Steps 2 and 3: (y^2 - 1) / (d y^2 + 1) is not a square mod p for
		// y = 2 and y = 7.
		{"y = 2, no x", "02" + strings.Repeat("00", 31), "no x"},
		{"y = 2, no x, sign bit set", "02" + strings.Repeat("00", 30) + "80", "no x"},
		{"y = 7, no x", "07" + strings.Repeat("00", 31), "no x"},
		// Step 4: x = 0 with x_0 = 1, for y = 1 and y = p - 1.
		{"y = 1, x = 0, sign bit set", "01" + strings.Repeat("00", 30) + "80", "x = 0 with the sign bit set"},
		{"y = p - 1, x = 0, sign bit set", "ec" + ff + "ff", "x = 0 with the sign bit set"},
		// Small order: the eight points P with [8]P the identity.
		{"identity (0, 1)", "01" + strings.Repeat("00", 31), "small order"},
		{"order 2 (0, -1)", "ec" + ff + "7f", "small order"},
		{"order 4 (sqrt(-1), 0)", strings.Repeat("00", 32), "small order"},
		{"order 4 (-sqrt(-1), 0)", strings.Repeat("00", 31) + "80", "small order"},
		{"order 8, 1", "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85", "small order"},
		{"order 8, 2", "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05", "small order"},
		{"order 8, 3", "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa", "small order"},
		{"order 8, 4", "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a", "small order"},
		// Mixed order: B or the RFC 8032 test 1 key plus the small-order point
		// (0, -1) of order 2, (sqrt(-1), 0) of order 4, or "order 8, 2" above.
		// [8]P is not the identity, so the small-order check passes them;
		// their orders are 2L, 4L and 8L.
		{"B + order 2", "9599999999999999999999999999999999999999999999999999999999999999", "[L]A"},
		{"B + order 4", "5252cc0a7f208133b620acbd4537eba2a4123bf0a8c2e4f980c3b31bb69765ea", "[L]A"},
		{"B + order 8", "da99e28ba529cdde35a25fba9059e78ecaee239f99755b9b1aa4f65df00803e2", "[L]A"},
		{"test 1 + order 2", "16a567fe7d4ef5482ab4012c369bf8c5f11e8d0c2559dcda50fde59708f8aee5", "[L]A"},
		{"test 1 + order 4", "40c7570f4dd54835b9131184410ed4a0cc93e7d9ad053cbc6d07a62426999582", "[L]A"},
		{"test 1 + order 8", "3b5b475c4b82dd1572799fc546f4c6c03e478c6654aa4c7f945b347ea32af60d", "[L]A"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := okp(t, tt.key)
			_, err := k.Ed25519PublicKey()
			if jws.ReasonOf(err) != jws.ErrJWKOffCurve || !strings.Contains(err.Error(), tt.msg) {
				t.Errorf("Ed25519PublicKey = %v, want %s naming %q", err, jws.ErrJWKOffCurve, tt.msg)
			}
			if _, err := (jws.Algorithms{jws.AlgEd25519}).NewKeySet(k); jws.ReasonOf(err) != jws.ErrJWKOffCurve {
				t.Errorf("NewKeySet = %v, want %s", err, jws.ErrJWKOffCurve)
			}
			if _, err := (jws.Algorithms{jws.AlgEd25519}).ParseJWK([]byte(`{"kty":"OKP","crv":"Ed25519","x":"` + k.X + `"}`)); jws.ReasonOf(err) != jws.ErrJWKOffCurve {
				t.Errorf("ParseJWK = %v, want %s", err, jws.ErrJWKOffCurve)
			}
			if _, err := jws.Thumbprint(k); jws.ReasonOf(err) != jws.ErrJWKOffCurve {
				t.Errorf("Thumbprint = %v, want %s", err, jws.ErrJWKOffCurve)
			}
		})
	}
}
