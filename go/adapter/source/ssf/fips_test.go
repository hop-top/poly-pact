package ssf_test

import (
	"crypto/fips140"
	"crypto/rsa"
	"os"
	"os/exec"
	"strings"
	"testing"

	"hop.top/pact-go/adapter/source/ssf"
)

const fipsChild = "SSF_TEST_FIPS140_ONLY_CHILD"

// Under GODEBUG=fips140=only, crypto/rsa refuses keys that RFC 7518 section
// 3.3 allows, such as a modulus of an odd number of bits. A SET signed with
// such a key is rejected as invalid_key, as before, and the error says that
// the FIPS 140 module refused the key, not that the signature does not
// verify. Outside that mode the same SET is accepted.
func TestRS256FIPSOnlyRefusal(t *testing.T) {
	const kid2049 = "test-rsa-key-2049"
	var (
		r               *rig
		tok, good, bad  string
		k2049, approved *rsa.PrivateKey
	)
	// Keys and signatures are made outside the module's enforcement, which
	// would refuse to sign with the 2049-bit key.
	fips140.WithoutEnforcement(func() {
		k2049, approved = deriveRSA(t, "ssf-rsa-2049", 2049), rsaKey(t, 2048)
		tok = compactRS(t, k2049, rsHeader(kid2049), disabledClaims("f-1"))
		good = compactRS(t, approved, rsHeader(kidRSA), disabledClaims("f-2"))
		bad = compactRS(t, rsaOther(t), rsHeader(kidRSA), disabledClaims("f-3"))
		r = newRig(t, withKeys(t, both, rsaJWK(t, k2049, kid2049), rsaJWK(t, approved, kidRSA)))
	})

	if os.Getenv(fipsChild) != "1" {
		if fips140.Enforced() {
			t.Skip("the test process itself runs with fips140=only")
		}
		r.accept(t, tok)
		cmd := exec.Command(os.Args[0], "-test.run=^TestRS256FIPSOnlyRefusal$", "-test.count=1", "-test.v")
		cmd.Env = append(os.Environ(), "GODEBUG=fips140=only", fipsChild+"=1")
		out, err := cmd.CombinedOutput()
		if err != nil || !strings.Contains(string(out), "--- PASS: TestRS256FIPSOnlyRefusal") {
			t.Fatalf("under fips140=only: %v\n%s", err, out)
		}
		return
	}

	if !fips140.Enforced() {
		t.Fatal("the child process does not run with fips140=only")
	}
	_, err := r.rx.Accept(bg, tok)
	wantCode(t, err, ssf.CodeInvalidKey)
	if msg := err.Error(); !strings.Contains(msg, "FIPS 140") || strings.Contains(msg, "does not verify") {
		t.Fatalf("refusal by the FIPS module reported as %q", msg)
	}
	// A key the module accepts verifies as before, and a forged signature
	// under it still does not verify.
	r.accept(t, good)
	_, err = r.rx.Accept(bg, bad)
	wantCode(t, err, ssf.CodeInvalidKey)
	if msg := err.Error(); !strings.Contains(msg, "does not verify") {
		t.Fatalf("forged signature reported as %q", msg)
	}
}
