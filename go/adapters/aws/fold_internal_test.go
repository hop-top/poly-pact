package aws

import (
	"strings"
	"testing"
)

// Query parameter names and hosts are compared without regard to ASCII case
// only (RFC 3986 3.2.2; AR-17). strings.EqualFold folds U+017F LATIN SMALL
// LETTER LONG S to "s" and U+212A KELVIN SIGN to "k"; strings.ToLower maps
// U+212A to "k" and U+0130 LATIN CAPITAL LETTER I WITH DOT ABOVE to "i". A
// name or host with one of them is another one.

// TestOriginHostFoldASCII: the origin host is lowercased over ASCII only.
func TestOriginHostFoldASCII(t *testing.T) {
	if got, err := originHost("https://ap\u0130.metrics.example"); err == nil && got == "api.metrics.example" {
		t.Errorf("originHost() = %q, the ASCII host", got)
	}
	if got, err := originHost("https://API.Metrics.example"); err != nil || got != "api.metrics.example" {
		t.Errorf("originHost(ASCII case variant) = %q, %v", got, err)
	}
}

// TestSigningParameterFoldASCII: x-amz-\u017Fignature is not the
// X-Amz-Signature parameter; X-AMZ-SIGNATURE is.
func TestSigningParameterFoldASCII(t *testing.T) {
	a := &Adapter{host: "api.metrics.example"}
	ev := func(q string) Event {
		return Event{Version: "2.0", RawQueryString: &q, RequestContext: RequestContext{Stage: "$default", DomainName: a.host}}
	}
	if err := a.checkShape(ev("x-amz-\u017Fignature=x")); err != nil {
		t.Errorf("checkShape refused a parameter with U+017F as a signing parameter: %v", err)
	}
	if err := a.checkShape(ev("X-AMZ-SIGNATURE=x")); err == nil || !strings.Contains(err.Error(), "Signature Version 4") {
		t.Errorf("checkShape(X-AMZ-SIGNATURE) = %v, want a refusal", err)
	}
}
