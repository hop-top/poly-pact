package binding_test

import (
	"errors"
	"maps"
	"net/http"
	"testing"

	"hop.top/pact-go/core/binding"
)

// Unicode simple case folding maps exactly two non-ASCII characters to ASCII
// letters: U+212A KELVIN SIGN to "k" and U+017F LATIN SMALL LETTER LONG S to
// "s". The protocol elements the binding compares without regard to case are
// ASCII: ABNF literal strings are case-insensitive over US-ASCII (RFC 5234
// 2.3), ALPHA is A-Z and a-z (RFC 5234 B.1), and schemes (RFC 3986 3.1), field
// names (RFC 9110 5.1, 5.6.2), connection options (RFC 9110 7.6.1) and
// transfer-coding names (RFC 9112 7; RFC 9110 10.1.4) are built from ALPHA,
// DIGIT and ASCII punctuation. A string with either character is therefore a
// different protocol element, never the ASCII one it folds to.
const (
	kelvin = "K" // KELVIN SIGN, folds to "k"
	longS  = "ſ" // LATIN SMALL LETTER LONG S, folds to "s"
)

// TestFoldOriginSchemeASCII: "httpſ" is not the https scheme (RFC 3986 3.1),
// so the origin is not an https origin.
func TestFoldOriginSchemeASCII(t *testing.T) {
	for _, o := range []string{"http" + longS + "://gateway.example", "HTTP" + longS + "://gateway.example"} {
		cfg := config()
		cfg.Origin = o
		if err := cfg.Validate(); !errors.Is(err, binding.ErrInvalidConfig) {
			t.Errorf("Validate(%q) = %v, want ErrInvalidConfig", o, err)
		}
	}
	cfg := config()
	cfg.Origin = "HttpS://gateway.example"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("ASCII case variant of https refused: %v", err)
	}
}

// TestFoldTargetSchemeASCII: an absolute-form target whose scheme is "httpſ"
// is neither http nor https (RFC 3986 3.1; RFC 9112 3.2.2).
func TestFoldTargetSchemeASCII(t *testing.T) {
	for _, s := range []string{"http" + longS, "HTTP" + longS} {
		_, err := from(config(), manual("GET", s+"://gateway.example/x"))
		wantRule(t, err, binding.RuleTargetForm)
	}
	for _, s := range []string{"HTTPS", "Http"} {
		op := mustBind(t, config(), manual("GET", s+"://gateway.example/x"))
		if want := origin + "/x"; op.TargetURI != want {
			t.Fatalf("target_uri %q, want %q", op.TargetURI, want)
		}
	}
}

// TestFoldHeaderNameASCII: a field name with a Kelvin sign or a long s is not
// the allowlisted name it folds to (RFC 9110 5.1, 5.6.2), so it is neither
// covered nor a second key for that name.
func TestFoldHeaderNameASCII(t *testing.T) {
	tests := []struct {
		name string
		h    http.Header
		want map[string]string
	}{
		{"long s", http.Header{"X-Ri" + longS + "k": {"1"}}, map[string]string{}},
		{"kelvin", http.Header{"X-Ris" + kelvin: {"1"}}, map[string]string{}},
		{"both", http.Header{"X-Ri" + longS + kelvin: {"1"}}, map[string]string{}},
		{"beside the ASCII name", http.Header{"X-Risk": {"a"}, "X-Ri" + longS + "k": {"b"}, "X-Ris" + kelvin: {"c"}},
			map[string]string{"x-risk": "a"}},
		{"ASCII case variant", http.Header{"x-RISK": {"a"}}, map[string]string{"x-risk": "a"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config()
			cfg.HeaderAllowlist = []string{"x-risk"}
			r := manual("GET", "/x")
			r.Header = tc.h
			op := mustBind(t, cfg, r)
			if !maps.Equal(op.Headers, tc.want) {
				t.Fatalf("headers %q, want %q", op.Headers, tc.want)
			}
		})
	}
	// Two keys that differ in ASCII case only are one name (RFC 9110 5.1).
	cfg := config()
	cfg.HeaderAllowlist = []string{"x-risk"}
	r := manual("GET", "/x")
	r.Header = http.Header{"X-Risk": {"a"}, "x-risk": {"b"}}
	_, err := from(cfg, r)
	wantRule(t, err, binding.RuleHeaderKeyCollision)
}

// TestFoldConnectionASCII: a connection option with a Kelvin sign or a long
// s does not name the allowlisted field it folds to (RFC 9110 7.6.1, 5.6.2),
// so that field stays covered. A Connection field spelled in another ASCII
// case still removes it.
func TestFoldConnectionASCII(t *testing.T) {
	tests := []struct {
		name string
		h    http.Header
		want map[string]string
	}{
		{"long s option", http.Header{"Connection": {"x-ri" + longS + "k"}, "X-Risk": {"1"}}, map[string]string{"x-risk": "1"}},
		{"kelvin option", http.Header{"Connection": {"X-RIS" + kelvin}, "X-Risk": {"1"}}, map[string]string{"x-risk": "1"}},
		{"ASCII option", http.Header{"Connection": {"X-RISK"}, "X-Risk": {"1"}}, map[string]string{}},
		{"ASCII case variant field name", http.Header{"cONNECTION": {"x-risk"}, "X-Risk": {"1"}}, map[string]string{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config()
			cfg.HeaderAllowlist = []string{"x-risk"}
			r := manual("GET", "/x")
			r.Header = tc.h
			op := mustBind(t, cfg, r)
			if !maps.Equal(op.Headers, tc.want) {
				t.Fatalf("headers %q, want %q", op.Headers, tc.want)
			}
		})
	}
}

// TestFoldChunkedASCII: "chunKed" with a Kelvin sign is not the chunked
// transfer coding (RFC 9112 7, 7.1), so the request is refused like any other
// coding net/http does not decode.
func TestFoldChunkedASCII(t *testing.T) {
	bad := "chun" + kelvin + "ed"
	r := withBody(manual("POST", "/x"), "abc")
	r.TransferEncoding = []string{bad}
	_, err := from(config(), r)
	wantRule(t, err, binding.RuleTransferCoding)

	r = withBody(manual("POST", "/x"), "abc")
	r.Header.Set("Transfer-Encoding", bad)
	_, err = from(config(), r)
	wantRule(t, err, binding.RuleTransferCoding)

	r = withBody(manual("POST", "/x"), "abc")
	r.TransferEncoding = []string{"CHUNKED"}
	mustBind(t, config(), r)
}

// TestFoldTransferEncodingNameASCII: "Tranſfer-Encoding" is not the
// Transfer-Encoding field (RFC 9110 5.1, 5.6.2; RFC 9112 6.1), so its value is
// not read as a transfer coding; "TRANSFER-ENCODING" is.
func TestFoldTransferEncodingNameASCII(t *testing.T) {
	r := withBody(manual("POST", "/x"), "abc")
	r.Header = http.Header{"Tran" + longS + "fer-Encoding": {"gzip"}}
	op := mustBind(t, config(), r)
	if op.BodyDigest != abcDigest {
		t.Fatalf("body_digest %q, want %q", op.BodyDigest, abcDigest)
	}

	r = withBody(manual("POST", "/x"), "abc")
	r.Header = http.Header{"TRANSFER-ENCODING": {"gzip"}}
	_, err := from(config(), r)
	wantRule(t, err, binding.RuleTransferCoding)
}

// TestFoldContentEncodingNameASCII: "content-encoding" has no letter that a
// non-ASCII character folds to, so only ASCII case variants name the field
// (RFC 9110 5.1, 8.4.1).
func TestFoldContentEncodingNameASCII(t *testing.T) {
	for _, k := range []string{"CONTENT-ENCODING", "content-Encoding"} {
		r := withBody(manual("POST", "/x"), "abc")
		r.Header = http.Header{k: {"gzip"}}
		_, err := from(config(), r)
		wantRule(t, err, binding.RuleContentEncoding)
	}
}
