package main

import (
	"encoding/json"
	"testing"
)

// TestBuiltBindingRequestHostFoldASCII: field names are ASCII and compared
// without regard to ASCII case only (RFC 9110 5.1), so "Ho\u017Ft" (U+017F
// LATIN SMALL LETTER LONG S, which strings.EqualFold folds to "s") is not
// Host.
func TestBuiltBindingRequestHostFoldASCII(t *testing.T) {
	build := func(name string) (host, field string) {
		var v bindingVector
		raw := `{"request": {"method": "GET", "raw_request_uri": "/x", "headers": [{"name": "Host", "value": "gw.example"}, {"name": ` + quote(name) + `, "value": "other.example"}]}}`
		if err := json.Unmarshal([]byte(raw), &v); err != nil {
			t.Fatal(err)
		}
		r := builtBindingRequest(v, nil)
		return r.Host, r.Header.Get(name)
	}
	if host, field := build("Ho\u017Ft"); host != "gw.example" || field != "other.example" {
		t.Errorf("Host = %q, field = %q: a field with U+017F was taken as Host", host, field)
	}
	if host, _ := build("HOST"); host != "other.example" {
		t.Errorf("ASCII case variant: Host = %q", host)
	}
}

func quote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
