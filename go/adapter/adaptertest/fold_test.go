package adaptertest

import (
	"context"
	"testing"
)

// TestBuildRequestHostFoldASCII: field names are ASCII and compared without
// regard to ASCII case only (RFC 9110 5.1), so "Ho\u017Ft" (U+017F LATIN
// SMALL LETTER LONG S, which strings.EqualFold folds to "s") is not Host.
func TestBuildRequestHostFoldASCII(t *testing.T) {
	req, _, err := buildRequest(context.Background(), &Request{Method: "GET", URL: "https://gw.example/x", Headers: map[string]string{"Ho\u017Ft": "other.example"}})
	if err != nil {
		t.Fatal(err)
	}
	if req.Host != "gw.example" || req.Header.Get("Ho\u017Ft") != "other.example" {
		t.Errorf("Host = %q, header = %q: a field with U+017F was taken as Host", req.Host, req.Header.Get("Ho\u017Ft"))
	}
	req, _, err = buildRequest(context.Background(), &Request{Method: "GET", URL: "https://gw.example/x", Headers: map[string]string{"HOST": "other.example"}})
	if err != nil || req.Host != "other.example" {
		t.Errorf("ASCII case variant: Host = %q, %v", req.Host, err)
	}
}
