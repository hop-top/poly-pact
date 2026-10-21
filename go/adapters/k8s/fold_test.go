package k8s_test

import (
	"net/http"
	"testing"

	"hop.top/pact-go/adapters/k8s"
)

// Field names are ASCII and compared without regard to ASCII case only (RFC
// 9110 5.1). strings.ToLower maps U+0130 LATIN CAPITAL LETTER I WITH DOT
// ABOVE to "i", so a name with it is another field.

// TestStripUserHeadersFoldASCII: "\u0130mpersonate-User" is not an
// impersonation header (KR-9); "Impersonate-User" is.
func TestStripUserHeadersFoldASCII(t *testing.T) {
	r, _ := http.NewRequest(http.MethodGet, "https://gw.example/x", nil)
	r.Header["\u0130mpersonate-User"] = []string{"x"}
	r.Header["Impersonate-User"] = []string{"y"}
	r = k8s.StripUserHeaders(r)
	if _, ok := r.Header["\u0130mpersonate-User"]; !ok {
		t.Error("a header with U+0130 was stripped as an impersonation header")
	}
	if _, ok := r.Header["Impersonate-User"]; ok {
		t.Error("Impersonate-User was kept")
	}
}
