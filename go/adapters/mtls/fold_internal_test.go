package mtls

import (
	"net/http"
	"testing"
)

// DNS names and field names are compared without regard to ASCII case only
// (RFC 4343 3; RFC 9110 5.1). strings.ToLower maps U+212A KELVIN SIGN to "k"
// and U+0130 LATIN CAPITAL LETTER I WITH DOT ABOVE to "i", so a name with
// either is another name.

// TestCanonicalDNSFoldASCII: MTLS-7 lowercases ASCII letters only, so a name
// with U+212A keeps a character outside letters, digits, hyphen and dot.
func TestCanonicalDNSFoldASCII(t *testing.T) {
	if got, err := canonicalDNS("ledger-writer.pac\u212A.example"); err == nil {
		t.Errorf("canonicalDNS() = %q, want a refusal", got)
	}
	if got, err := canonicalDNS("Ledger-Writer.PACK.example"); err != nil || got != "ledger-writer.pack.example" {
		t.Errorf("canonicalDNS(ASCII case variant) = %q, %v", got, err)
	}
}

// TestStripIdentityHeadersFoldASCII: "ssl-cl\u0130ent-verify" is not of the
// ssl-client-* family; "SSL-Client-Verify" is.
func TestStripIdentityHeadersFoldASCII(t *testing.T) {
	h := http.Header{"Ssl-Cl\u0130ent-Verify": {"x"}, "Ssl-Client-Verify": {"y"}}
	(&Adapter{}).stripIdentityHeaders(h)
	if _, ok := h["Ssl-Cl\u0130ent-Verify"]; !ok {
		t.Error("a header with U+0130 was removed as an ssl-client-* header")
	}
	if _, ok := h["Ssl-Client-Verify"]; ok {
		t.Error("Ssl-Client-Verify was kept")
	}
}
