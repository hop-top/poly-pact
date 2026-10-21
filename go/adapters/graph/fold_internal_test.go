package graph

import "testing"

// Hosts are compared without regard to ASCII case only (RFC 3986 3.2.2; a
// reg-name is ASCII). strings.ToLower maps U+212A KELVIN SIGN to "k" and
// U+0130 LATIN CAPITAL LETTER I WITH DOT ABOVE to "i", so a host with either
// is another host.

// TestLinkOKFoldASCII: a link to graph.m\u0130crosoft.com is not a link of
// the Graph origin.
func TestLinkOKFoldASCII(t *testing.T) {
	const path, query = "/v1.0/me/messages", "?$select=id,subject,body&$top=10"
	if linkOK("https://graph.m\u0130crosoft.com"+path+query, path) {
		t.Error("linkOK accepted a host with U+0130 as the Graph host")
	}
	if !linkOK("https://GRAPH.MICROSOFT.COM"+path+query, path) {
		t.Error("linkOK refused an ASCII case variant of the Graph host")
	}
}

// TestOriginNormalizedFoldASCII: the configured origin is lowercased over
// ASCII only.
func TestOriginNormalizedFoldASCII(t *testing.T) {
	a := &Adapter{cfg: Config{Origin: "https://pac\u212A.example"}}
	if got := a.originNormalized(); got == "https://pack.example" {
		t.Errorf("originNormalized() = %q, the ASCII origin", got)
	}
	a = &Adapter{cfg: Config{Origin: "https://PACK.Example:443"}}
	if got := a.originNormalized(); got != "https://pack.example" {
		t.Errorf("originNormalized(ASCII case variant) = %q", got)
	}
}
