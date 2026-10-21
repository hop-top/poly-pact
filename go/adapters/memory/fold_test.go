package memory_test

import (
	"testing"

	"hop.top/pact-go/adapters/memory"
)

// Hosts are compared without regard to ASCII case only (RFC 3986 3.2.2; a
// reg-name is ASCII). strings.ToLower maps two non-ASCII characters to ASCII
// letters, U+212A KELVIN SIGN to "k" and U+0130 LATIN CAPITAL LETTER I WITH
// DOT ABOVE to "i", so an origin naming either is another origin, never the
// ASCII one it lowercases to.
func TestNormalizeOriginFoldASCII(t *testing.T) {
	for in, ascii := range map[string]string{
		"https://pac\u212A.example": "https://pack.example",
		"https://\u0130dp.example":  "https://idp.example",
	} {
		if got, err := memory.NormalizeOrigin(in); err == nil && got == ascii {
			t.Errorf("NormalizeOrigin(%q) = %q, the ASCII origin", in, got)
		}
	}
	if got, err := memory.NormalizeOrigin("https://PACK.Example"); err != nil || got != "https://pack.example" {
		t.Errorf("NormalizeOrigin(ASCII case variant) = %q, %v", got, err)
	}
}
