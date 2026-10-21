package binding_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"hop.top/pact-go/core/binding"
)

// TestTargetURIPreserved: target_uri is the configured origin plus the exact
// path and query of the request target; octets, percent encoding and query
// order are kept (draft 10.2).
func TestTargetURIPreserved(t *testing.T) {
	tests := []struct {
		name, target, want string
	}{
		{"appendix B.3", "/invoices/INV-1042", origin + "/invoices/INV-1042"},
		{"root", "/", origin + "/"},
		{"query order", "/s?b=2&a=1&b=1", origin + "/s?b=2&a=1&b=1"},
		{"uppercase escapes kept", "/files/a%20b?q=%C3%A9", origin + "/files/a%20b?q=%C3%A9"},
		{"sub-delims colon at", "/a:b@c!$&'()*+,;=?x=/?:@", origin + "/a:b@c!$&'()*+,;=?x=/?:@"},
		{"empty query kept", "/a?", origin + "/a?"},
		{"dots inside a segment", "/a..b", origin + "/a..b"},
		{"three dots", "/.../", origin + "/.../"},
		{"dot in a segment", "/a.b/", origin + "/a.b/"},
		{"dot prefix and suffix", "/.a/b./..c/", origin + "/.a/b./..c/"},
		{"dot segments in the query", "/a?x=./..&y=/../.", origin + "/a?x=./..&y=/../."},
		{"double slash kept", "//a//b", origin + "//a//b"},
		{"encoded slash in query", "/a?u=%2F%3F%23", origin + "/a?u=%2F%3F%23"},
		{"encoded question mark in path", "/a%3Fb", origin + "/a%3Fb"},
		{"encoded percent in path", "/a%25b", origin + "/a%25b"},
		{"encoded backslash in path", "/a%5Cb", origin + "/a%5Cb"},
		{"encoded NUL in path", "/a%00b", origin + "/a%00b"},
		{"encoded space plus", "/a?q=a+b%20c", origin + "/a?q=a+b%20c"},
		{"absolute-form", "https://gateway.example/x?y=1", origin + "/x?y=1"},
		{"absolute-form other authority", "http://Other.Example:8080/x", origin + "/x"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			op := mustBind(t, config(), get(t, tc.target))
			if op.TargetURI != tc.want {
				t.Fatalf("target_uri %q, want %q", op.TargetURI, tc.want)
			}
		})
	}
}

// TestTargetURIIgnoresForwardingHeaders: the origin comes from trusted
// configuration; Host and forwarding headers cannot select it (draft 10.2).
func TestTargetURIIgnoresForwardingHeaders(t *testing.T) {
	r := parse(t, "GET /x HTTP/1.1\r\nHost: evil.example\r\n"+
		"X-Forwarded-Host: evil.example\r\nX-Forwarded-Proto: http\r\n"+
		"Forwarded: host=evil.example;proto=http\r\n\r\n")
	op := mustBind(t, config(), r)
	if op.TargetURI != origin+"/x" {
		t.Fatalf("target_uri %q, want %q", op.TargetURI, origin+"/x")
	}
}

// TestTargetURILength: target_uri has maxLength 1024 in the schema.
func TestTargetURILength(t *testing.T) {
	path := "/" + strings.Repeat("a", 1024-len(origin)-1)
	op := mustBind(t, config(), get(t, path))
	if len(op.TargetURI) != 1024 {
		t.Fatalf("length %d, want 1024", len(op.TargetURI))
	}
	_, err := from(config(), get(t, path+"a"))
	wantRule(t, err, binding.RuleTargetTooLong)
}

// TestMethodUppercased: method is the uppercase HTTP method (draft 10.2).
func TestMethodUppercased(t *testing.T) {
	for _, m := range []struct{ in, want string }{
		{"GET", "GET"}, {"get", "GET"}, {"Patch", "PATCH"}, {"DELETE", "DELETE"},
	} {
		t.Run(m.in, func(t *testing.T) {
			op := mustBind(t, config(), parse(t, m.in+" /x HTTP/1.1\r\nHost: gateway.example\r\n\r\n"))
			if op.Method != m.want {
				t.Fatalf("method %q, want %q", op.Method, m.want)
			}
		})
	}
}

// TestRejectMethod: the schema pattern for method is ^[A-Z]+$, and only ASCII
// letters are uppercased, so a Unicode case mapping cannot make one.
func TestRejectMethod(t *testing.T) {
	for _, m := range []string{"", "M-SEARCH", "GET1", "\u017fet", "G\u0130T"} {
		t.Run(m, func(t *testing.T) {
			_, err := from(config(), manual(m, "/x"))
			wantRule(t, err, binding.RuleMethod)
		})
	}
}

// TestRejectTarget has failing inputs for every target rule. The ambiguous
// encodings are those of draft 10.2: an encoded unreserved character, a
// lowercase hex digit in an escape, invalid or overlong UTF-8 in the decoded
// octets, an encoded slash in the path, and a dot segment, which the path
// segment normalization of RFC 3986 6.2.2.3 would remove. An encoded dot
// segment such as %2E%2E is refused as an encoded unreserved character.
func TestRejectTarget(t *testing.T) {
	tests := []struct {
		rule    binding.Rule
		name    string
		target  string
		program bool // build by hand: the server parser refuses it
	}{
		{binding.RuleFragment, "path", "/a#b", false},
		{binding.RuleFragment, "query", "/a?b#c", false},
		{binding.RuleFragment, "empty", "/a#", false},
		{binding.RuleFragment, "absolute-form", "https://gateway.example/a#b", false},

		{binding.RuleUserinfo, "user and password", "https://u:p@gateway.example/x", false},
		{binding.RuleUserinfo, "user", "https://u@gateway.example/x", false},
		{binding.RuleUserinfo, "empty", "https://@gateway.example/x", false},

		{binding.RuleNonASCIIHost, "raw UTF-8", "https://b\u00fccher.example/x", false},
		{binding.RuleNonASCIIHost, "percent-encoded", "https://b%C3%BCcher.example/x", false},
		{binding.RuleNonASCIIHost, "raw byte", "https://b\xfccher.example/x", false},

		{binding.RuleEncodedUnreserved, "ALPHA", "/%41", false},
		{binding.RuleEncodedUnreserved, "alpha", "/a%7A", false},
		{binding.RuleEncodedUnreserved, "DIGIT", "/%30", false},
		{binding.RuleEncodedUnreserved, "hyphen", "/a%2Db", false},
		{binding.RuleEncodedUnreserved, "dot segment", "/%2E%2E/secret", false},
		{binding.RuleEncodedUnreserved, "underscore", "/a%5F", false},
		{binding.RuleEncodedUnreserved, "tilde in query", "/a?x=%7E", false},

		{binding.RuleLowercaseHex, "encoded slash", "/a%2fb", false},
		{binding.RuleLowercaseHex, "UTF-8", "/caf%c3%a9", false},
		{binding.RuleLowercaseHex, "query", "/a?x=%3d", false},
		{binding.RuleLowercaseHex, "mixed case", "/a?x=%aB", false},
		{binding.RuleLowercaseHex, "second digit", "/%3a", false},

		{binding.RuleInvalidUTF8, "overlong slash", "/%C0%AF", false},
		{binding.RuleInvalidUTF8, "overlong three octets", "/%E0%80%AF", false},
		{binding.RuleInvalidUTF8, "overlong NUL in query", "/a?x=%C0%80", false},
		{binding.RuleInvalidUTF8, "surrogate", "/%ED%A0%80", false},
		{binding.RuleInvalidUTF8, "above U+10FFFF", "/%F4%90%80%80", false},
		{binding.RuleInvalidUTF8, "FF", "/%FF", false},
		{binding.RuleInvalidUTF8, "truncated", "/%C3", false},
		{binding.RuleInvalidUTF8, "split by a slash", "/%C3/%A9", false},

		{binding.RuleDotSegment, "single dot", "/a/./b", false},
		{binding.RuleDotSegment, "double dot", "/a/../b", false},
		{binding.RuleDotSegment, "root single dot", "/.", false},
		{binding.RuleDotSegment, "root double dot", "/..", false},
		{binding.RuleDotSegment, "trailing single dot", "/a/.", false},
		{binding.RuleDotSegment, "trailing double dot", "/a/..", false},
		{binding.RuleDotSegment, "before a query", "/a/..?x=1", false},
		{binding.RuleDotSegment, "after an empty segment", "//../a", false},
		{binding.RuleDotSegment, "absolute-form", "https://gateway.example/a/../b", false},

		{binding.RuleEncodedSlash, "inside a segment", "/a%2Fb", false},
		{binding.RuleEncodedSlash, "alone", "/%2F", false},

		{binding.RuleMalformedEscape, "non-hex in query", "/a?x=%zz", false},
		{binding.RuleMalformedEscape, "one digit at end of query", "/a?x=%4", false},
		{binding.RuleMalformedEscape, "bare percent in path", "/a%", true},
		{binding.RuleMalformedEscape, "non-hex in path", "/a%G1", true},

		{binding.RuleInvalidCharacter, "raw UTF-8 in path", "/caf\u00e9", false},
		{binding.RuleInvalidCharacter, "raw byte in query", "/a?x=\xff", false},
		{binding.RuleInvalidCharacter, "brackets in query", "/a?x[]=1", false},
		{binding.RuleInvalidCharacter, "brace", "/a{b}", false},
		{binding.RuleInvalidCharacter, "pipe", "/a|b", false},
		{binding.RuleInvalidCharacter, "backslash", "/a\\b", false},
		{binding.RuleInvalidCharacter, "quote", "/a\"b", false},
		{binding.RuleInvalidCharacter, "caret and backtick", "/a^`", false},
		{binding.RuleInvalidCharacter, "angle brackets", "/a<b>", false},
		{binding.RuleInvalidCharacter, "space", "/a b", true},
		{binding.RuleInvalidCharacter, "tab", "/a\tb", true},
		{binding.RuleInvalidCharacter, "DEL", "/a\x7fb", true},

		{binding.RuleTargetForm, "asterisk-form", "*", false},
		{binding.RuleTargetForm, "authority-form", "gateway.example:443", true},
		{binding.RuleTargetForm, "opaque URI", "foo:bar", false},
		{binding.RuleTargetForm, "other scheme", "ftp://gateway.example/x", false},
		{binding.RuleTargetForm, "empty host", "https:///x", true},
		{binding.RuleTargetForm, "absolute-form without path", "https://gateway.example", false},
		{binding.RuleTargetForm, "absolute-form query without path", "https://gateway.example?x", false},
		{binding.RuleTargetForm, "empty", "", true},
	}
	for _, tc := range tests {
		t.Run(string(tc.rule)+"/"+tc.name, func(t *testing.T) {
			var r *http.Request
			if tc.program {
				r = manual("GET", tc.target)
			} else {
				r = get(t, tc.target)
			}
			_, err := from(config(), r)
			wantRule(t, err, tc.rule)
		})
	}
}

// TestRejectTargetOverWire runs the target rules that matter most through a
// real server, so the inputs are what a gateway receives.
func TestRejectTargetOverWire(t *testing.T) {
	tests := []struct {
		rule   binding.Rule
		target string
	}{
		{binding.RuleFragment, "/a#b"},
		{binding.RuleUserinfo, "https://u:p@gateway.example/x"},
		{binding.RuleNonASCIIHost, "https://b\u00fccher.example/x"},
		{binding.RuleEncodedUnreserved, "/%41"},
		{binding.RuleLowercaseHex, "/a%2fb"},
		{binding.RuleInvalidUTF8, "/%C0%AF"},
		{binding.RuleEncodedSlash, "/a%2Fb"},
		{binding.RuleDotSegment, "/a/../b"},
	}
	for _, tc := range tests {
		t.Run(string(tc.rule), func(t *testing.T) {
			_, err := bind(t, config(), "GET "+tc.target+" HTTP/1.1\r\nHost: gateway.example\r\n\r\n")
			wantRule(t, err, tc.rule)
		})
	}
}

// TestRejectProgrammaticURL: a request built by a program can carry a fragment
// or userinfo in URL that RequestURI does not show.
func TestRejectProgrammaticURL(t *testing.T) {
	r := manual("GET", "/x")
	r.URL.Fragment = "f"
	_, err := from(config(), r)
	wantRule(t, err, binding.RuleFragment)

	r = manual("GET", "/x")
	r.URL.RawFragment = "f"
	_, err = from(config(), r)
	wantRule(t, err, binding.RuleFragment)

	r = manual("GET", "/x")
	r.URL.User = url.User("u")
	_, err = from(config(), r)
	wantRule(t, err, binding.RuleUserinfo)

	// RequestURI alone, with URL left without userinfo, is refused too.
	r = manual("GET", "https://u@gateway.example/x")
	r.URL.User = nil
	_, err = from(config(), r)
	wantRule(t, err, binding.RuleUserinfo)
}

// TestRejectNoRequest: a nil request or one without URL has nothing to bind.
func TestRejectNoRequest(t *testing.T) {
	_, err := from(config(), nil)
	wantRule(t, err, binding.RuleNoRequest)

	r := manual("GET", "/x")
	r.URL = nil
	_, err = from(config(), r)
	wantRule(t, err, binding.RuleNoRequest)
}

// TestOriginNormalized: scheme and host are lowercase and a default port is
// omitted (draft 10.2; RFC 3986 6.2.2.1 and 6.2.3; RFC 9110 4.2.2 and 4.2.3).
func TestOriginNormalized(t *testing.T) {
	tests := []struct{ origin, want string }{
		{"https://gateway.example", "https://gateway.example"},
		{"HTTPS://Gateway.EXAMPLE", "https://gateway.example"},
		{"https://gateway.example:443", "https://gateway.example"},
		{"https://gateway.example:", "https://gateway.example"},
		{"https://gateway.example:8443", "https://gateway.example:8443"},
		{"https://GATEWAY.example:8443", "https://gateway.example:8443"},
		{"https://192.0.2.1:443", "https://192.0.2.1"},
		{"https://[2001:DB8::1]:443", "https://[2001:db8::1]"},
		{"https://[2001:db8::1]:8443", "https://[2001:db8::1]:8443"},
	}
	for _, tc := range tests {
		t.Run(tc.origin, func(t *testing.T) {
			cfg := config()
			cfg.Origin = tc.origin
			op := mustBind(t, cfg, get(t, "/A%20B?Q"))
			if want := tc.want + "/A%20B?Q"; op.TargetURI != want {
				t.Fatalf("target_uri %q, want %q", op.TargetURI, want)
			}
		})
	}
}
