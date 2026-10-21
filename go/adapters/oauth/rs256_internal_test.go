package oauth

import (
	"encoding/base64"
	"math/big"
	"strings"
	"testing"
)

// The example of RFC 7515 appendix A.2: a JWS signed with RSASSA-PKCS1-v1_5
// SHA-256 (RS256, RFC 7518 section 3.3) and the RSA public key (n, e) of the
// example JWK. Line breaks of the RFC text are removed.
const (
	rfcN = "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddx" +
		"HmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMs" +
		"D1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSH" +
		"SXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdV" +
		"MTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8" +
		"NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ"
	rfcE   = "AQAB"
	rfcJWS = "eyJhbGciOiJSUzI1NiJ9" +
		"." +
		"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
		"cGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
		"." +
		"cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7" +
		"AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4" +
		"BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K" +
		"0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqv" +
		"hJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrB" +
		"p0igcN_IoypGlUPQGe77Rw"
)

// The first eight octets of the RFC's signature, written there as a JSON
// array, pin the decoding of the signature segment.
var rfcSigPrefix = []byte{112, 46, 33, 137, 67, 232, 143, 209}

func rfcKey(t *testing.T) []byte {
	t.Helper()
	n, err := base64.RawURLEncoding.DecodeString(rfcN)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestRS256VerifiesRFC7515A2(t *testing.T) {
	pub := rsaKey([]byte(`"`+rfcN+`"`), []byte(`"`+rfcE+`"`))
	if pub == nil {
		t.Fatal("rsaKey refused the RFC 7515 A.2 key")
	}
	if pub.E != 65537 || pub.N.Cmp(new(big.Int).SetBytes(rfcKey(t))) != 0 {
		t.Fatalf("decoded key n=%d bits e=%d", pub.N.BitLen(), pub.E)
	}
	segs := strings.Split(rfcJWS, ".")
	sig, err := base64.RawURLEncoding.Strict().DecodeString(segs[2])
	if err != nil {
		t.Fatal(err)
	}
	if string(sig[:8]) != string(rfcSigPrefix) || len(sig) != 256 {
		t.Fatalf("signature segment decodes to %v... (%d octets)", sig[:8], len(sig))
	}
	if err := verifyRS256(pub, segs[0]+"."+segs[1], sig); err != nil {
		t.Fatalf("RFC 7515 A.2 does not verify: %v", err)
	}
	h, ok := parseHeader(segs[0])
	if !ok || h.alg != "RS256" {
		t.Fatalf("header %+v", h)
	}
	// One flipped bit in the signature, in the signing input, or a
	// truncated signature fails.
	bad := append([]byte(nil), sig...)
	bad[100] ^= 1
	if verifyRS256(pub, segs[0]+"."+segs[1], bad) == nil {
		t.Error("an altered signature verifies")
	}
	if verifyRS256(pub, segs[0]+"."+segs[1]+"x", sig) == nil {
		t.Error("an altered signing input verifies")
	}
	if verifyRS256(pub, segs[0]+"."+segs[1], sig[:255]) == nil {
		t.Error("a short signature verifies")
	}
}

func TestRSAKeyRefusesMalformedMembers(t *testing.T) {
	for _, tc := range []struct{ n, e string }{
		{`"` + rfcN + `="`, `"AQAB"`},  // padded
		{`"AA` + rfcN + `"`, `"AQAB"`}, // leading zero octet
		{`"` + rfcN + `"`, `"AAEAAQ"`}, // e with a leading zero
		{`"` + rfcN + `"`, `"Ag"`},     // even exponent
		{`"` + rfcN + `"`, `"AQ"`},     // e = 1
		{`1`, `"AQAB"`},                // not a string
	} {
		if rsaKey([]byte(tc.n), []byte(tc.e)) != nil {
			t.Errorf("rsaKey(%.12s..., %s) accepted", tc.n, tc.e)
		}
	}
}

func TestScopeList(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want []string
	}{
		{"a b", []string{"a", "b"}},
		{"b a", []string{"b", "a"}},
		{"Mail.Read", []string{"Mail.Read"}},
		{"!#[]~", []string{"!#[]~"}},
		{"", nil}, {" a", nil}, {"a ", nil}, {"a  b", nil}, {"a a", nil},
		{"a\tb", nil}, {"a\"b", nil}, {`a\b`, nil}, {"é", nil},
	} {
		got, ok := scopeList(tc.in)
		if ok != (tc.want != nil) || strings.Join(got, "|") != strings.Join(tc.want, "|") {
			t.Errorf("scopeList(%q) = %q, %v", tc.in, got, ok)
		}
	}
}

func TestB64Token(t *testing.T) {
	for in, want := range map[string]bool{
		"mF_9.B5f-4.1JqM": true, "abc==": true, "a+/~": true,
		"": false, "==": false, "a=b": false, "a b": false, "a%": false, "a,b": false,
	} {
		if b64token(in) != want {
			t.Errorf("b64token(%q) = %v", in, !want)
		}
	}
}
