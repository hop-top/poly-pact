package jws

import (
	"bytes"
	"strings"
	"testing"
)

// RFC 7515 Appendix A.3: ES256 over P-256. The compact serialization, the
// public key and the R and S octets are copied from the RFC text.
const (
	a3Compact = "eyJhbGciOiJFUzI1NiJ9" +
		".eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
		".DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"
	a3X = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU"
	a3Y = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
)

var (
	a3R = []byte{14, 209, 33, 83, 121, 99, 108, 72, 60, 47, 127, 21, 88, 7, 212, 2, 163, 178, 40, 3, 58, 249, 124, 126, 23, 129, 154, 195, 22, 158, 166, 101}
	a3S = []byte{197, 10, 7, 211, 140, 60, 112, 229, 216, 241, 45, 175, 8, 74, 84, 128, 166, 101, 144, 197, 242, 147, 80, 154, 143, 63, 127, 138, 131, 163, 84, 213}
	// UTF8 of the protected header {"alg":"ES256"}.
	a3Header = []byte{123, 34, 97, 108, 103, 34, 58, 34, 69, 83, 50, 53, 54, 34, 125}
)

func TestRFC7515A3(t *testing.T) {
	parts := strings.Split(a3Compact, ".")
	hdr, err := decodeSegment(parts[0])
	if err != nil || !bytes.Equal(hdr, a3Header) {
		t.Fatalf("header %q (%v)", hdr, err)
	}
	sig, err := decodeSegment(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sig, append(append([]byte(nil), a3R...), a3S...)) {
		t.Fatalf("signature is not R || S of the RFC")
	}
	pub, err := JWK{Kty: "EC", Crv: "P-256", X: a3X, Y: a3Y}.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	signingInput := parts[0] + "." + parts[1]
	if !verifyES256(pub, signingInput, sig) {
		t.Fatal("RFC 7515 A.3 signature does not verify")
	}
	if verifyES256(pub, signingInput+"A", sig) {
		t.Fatal("A.3 signature verifies over a changed signing input")
	}
	// A PACT verifier still rejects the JWS: its header has no typ.
	_, err = Verify(a3Compact, StaticResolver{})
	if ReasonOf(err) != ErrTypUnsupported {
		t.Fatalf("Verify(A.3) = %v, want %s", err, ErrTypUnsupported)
	}
}
