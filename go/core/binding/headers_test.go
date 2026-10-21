package binding_test

import (
	"bufio"
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"hop.top/pact-go/core/binding"
)

// TestHeaders: names are lowercase and come from the allowlist only; values
// are trimmed and field lines of one name are joined with ", " in order (RFC
// 9110 5.2, 5.3, 5.5); content-type is added when a body is present (draft
// 10.2).
func TestHeaders(t *testing.T) {
	tests := []struct {
		name  string
		allow []string
		raw   string // header lines and body after the request line
		want  map[string]string
	}{
		{"none", nil, "\r\n", map[string]string{}},
		{"allowlisted only", []string{"x-dry-run"},
			"X-Dry-Run: 1\r\nX-Other: 2\r\n\r\n", map[string]string{"x-dry-run": "1"}},
		{"allowlist name lowercased", []string{"If-Match"},
			"IF-MATCH: \"v1\"\r\n\r\n", map[string]string{"if-match": `"v1"`}},
		{"field lines joined in order", []string{"x-dry-run"},
			"X-Dry-Run: b\r\nX-Other: 1\r\nx-dry-run: a\r\n\r\n", map[string]string{"x-dry-run": "b, a"}},
		{"list value kept", []string{"x-dry-run"},
			"X-Dry-Run: a,b ,  c\r\n\r\n", map[string]string{"x-dry-run": "a,b ,  c"}},
		{"surrounding whitespace dropped", []string{"x-dry-run"},
			"X-Dry-Run: \t a \t\r\n\r\n", map[string]string{"x-dry-run": "a"}},
		{"empty value kept", []string{"x-dry-run"},
			"X-Dry-Run:\r\n\r\n", map[string]string{"x-dry-run": ""}},
		{"obs-text that is UTF-8 kept", []string{"x-dry-run"},
			"X-Dry-Run: caf\u00e9\r\n\r\n", map[string]string{"x-dry-run": "caf\u00e9"}},
		{"credentials and signatures not covered", []string{"x-dry-run"},
			"Authorization: Bearer t\r\nPACT-Presentation: a.b.c\r\nSignature: sig1=:AA==:\r\n" +
				"Signature-Input: sig1=()\r\nProxy-Authorization: Basic x\r\nCookie: s=1\r\n\r\n",
			map[string]string{}},
		{"content-type with body", []string{"x-dry-run"},
			"Content-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
			map[string]string{"content-type": "application/json"}},
		{"no content-type without body", []string{"x-dry-run"},
			"Content-Type: application/json\r\nContent-Length: 0\r\n\r\n", map[string]string{}},
		{"body without content-type", []string{"x-dry-run"},
			"Content-Length: 2\r\n\r\n{}", map[string]string{}},
		{"allowlisted content-type without body", []string{"content-type"},
			"Content-Type: text/plain\r\n\r\n", map[string]string{"content-type": "text/plain"}},
		{"connection-listed excluded", []string{"x-dry-run", "if-match"},
			"Connection: keep-alive, X-Dry-Run\r\nX-Dry-Run: 1\r\nIf-Match: *\r\n\r\n",
			map[string]string{"if-match": "*"}},
		{"connection-listed across field lines", []string{"x-dry-run", "if-match"},
			"Connection: close\r\nConnection:\tif-match ,\r\nX-Dry-Run: 1\r\nIf-Match: *\r\n\r\n",
			map[string]string{"x-dry-run": "1"}},
		{"connection-listed content-type excluded", []string{"x-dry-run"},
			"Connection: Content-Type\r\nContent-Type: text/plain\r\nContent-Length: 1\r\n\r\na",
			map[string]string{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config()
			cfg.HeaderAllowlist = tc.allow
			op := mustBind(t, cfg, parse(t, "POST /x HTTP/1.1\r\nHost: gateway.example\r\n"+tc.raw))
			if op.Headers == nil {
				t.Fatal("headers is nil, want an object")
			}
			if !maps.Equal(op.Headers, tc.want) {
				t.Fatalf("headers %q, want %q", op.Headers, tc.want)
			}
		})
	}
}

// TestHeadersTrimmedWhenBuilt: a request a program builds can carry
// whitespace net/http would have removed; the binding trims it itself.
func TestHeadersTrimmedWhenBuilt(t *testing.T) {
	r := manual("GET", "/x")
	r.Header["X-Dry-Run"] = []string{" a\t", "\t b ", ""}
	op := mustBind(t, config(), r)
	if got, want := op.Headers["x-dry-run"], "a, b, "; got != want {
		t.Fatalf("x-dry-run %q, want %q", got, want)
	}
}

// TestHeaderValueLength: header values have maxLength 8192 in the schema; the
// limit applies to the joined value.
func TestHeaderValueLength(t *testing.T) {
	r := manual("GET", "/x")
	r.Header.Set("X-Dry-Run", strings.Repeat("a", 8192))
	op := mustBind(t, config(), r)
	if len(op.Headers["x-dry-run"]) != 8192 {
		t.Fatalf("length %d, want 8192", len(op.Headers["x-dry-run"]))
	}

	r = manual("GET", "/x")
	r.Header.Set("X-Dry-Run", strings.Repeat("a", 8193))
	_, err := from(config(), r)
	wantRule(t, err, binding.RuleHeaderTooLong)

	r = manual("GET", "/x")
	r.Header["X-Dry-Run"] = []string{strings.Repeat("a", 4095), strings.Repeat("b", 4096)}
	_, err = from(config(), r)
	wantRule(t, err, binding.RuleHeaderTooLong)
}

// TestRejectHeaders has one failing input per header rule.
func TestRejectHeaders(t *testing.T) {
	tests := []struct {
		rule   binding.Rule
		name   string
		header http.Header
	}{
		{binding.RuleHeaderValue, "NUL", http.Header{"X-Dry-Run": {"a\x00b"}}},
		{binding.RuleHeaderValue, "CR", http.Header{"X-Dry-Run": {"a\rb"}}},
		{binding.RuleHeaderValue, "LF", http.Header{"X-Dry-Run": {"a\nb"}}},
		{binding.RuleHeaderValue, "other control", http.Header{"X-Dry-Run": {"a\x01b"}}},
		{binding.RuleHeaderValue, "DEL", http.Header{"X-Dry-Run": {"a\x7fb"}}},
		{binding.RuleHeaderValue, "invalid UTF-8", http.Header{"X-Dry-Run": {"\xff\xfe"}}},
		{binding.RuleHeaderValue, "second field line", http.Header{"X-Dry-Run": {"ok", "\xc0\xaf"}}},
		{binding.RuleHeaderValue, "content-type with body", http.Header{"Content-Type": {"text/\x01plain"}}},
		{binding.RuleHeaderKeyCollision, "two spellings", http.Header{"X-Dry-Run": {"1"}, "x-dry-run": {"2"}}},
	}
	for _, tc := range tests {
		t.Run(string(tc.rule)+"/"+tc.name, func(t *testing.T) {
			r := manual("POST", "/x")
			r.Header = tc.header
			r.Body = http.NoBody
			if _, ok := tc.header["Content-Type"]; ok {
				r = withBody(r, "a")
			}
			_, err := from(config(), r)
			wantRule(t, err, tc.rule)
		})
	}
}

// TestRejectDuplicateHost: a request whose Header holds more than one Host
// field line, under one key or under keys that differ only in case, is
// refused (RFC 9112 3.2; request-binding.md RB-65), even when the values are
// equal and even though Host is not allowlisted.
func TestRejectDuplicateHost(t *testing.T) {
	tests := []struct {
		name   string
		header http.Header
	}{
		{"same value", http.Header{"Host": {"gateway.example", "gateway.example"}}},
		{"other value", http.Header{"Host": {"gateway.example", "evil.example"}}},
		{"two keys", http.Header{"Host": {"gateway.example"}, "host": {"gateway.example"}}},
		{"with an allowlisted header", http.Header{"Host": {"a", "b"}, "If-Match": {`"v1"`}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := manual("GET", "/x")
			r.Header = tc.header
			_, err := from(config(), r)
			wantRule(t, err, binding.RuleDuplicateHost)
		})
	}
}

// TestOneHostLineAccepted: one Host field line in Header, as a program can
// set it beside Request.Host, is not refused and is not covered.
func TestOneHostLineAccepted(t *testing.T) {
	r := manual("GET", "/x")
	r.Header = http.Header{"Host": {"evil.example"}}
	op := mustBind(t, config(), r)
	if len(op.Headers) != 0 || op.TargetURI != origin+"/x" {
		t.Fatalf("headers %q target %q, want none and %s/x", op.Headers, op.TargetURI, origin)
	}
}

// validHosts and invalidHosts are Host values that are, and are not,
// uri-host [ ":" port ] with a non-empty host (RFC 9110 4.2.2, 7.2; RFC 3986
// 3.2.2, 3.2.3), around optional whitespace.
var (
	validHosts   = []string{"gateway.example", "GATEWAY.example:443", "gateway.example:", "192.0.2.1:8443", "[::1]", "[2001:db8::1]:443", "[v1.x]", "g%41teway.example", " gateway.example\t"}
	invalidHosts = []string{"", "gate way.example", "gateway.example/x", "a@b", "[::1", "[fe80::1%25en0]", "[192.0.2.1]", "gateway.example:abc", "caf\u00e9.example", "%zz.example", ":443", "a:1:2", "[::1]x"}
)

// TestHostValues: a Host value is checked whether it reaches the binding as
// Request.Host or as a Header line (request-binding.md RB-66).
func TestHostValues(t *testing.T) {
	for _, v := range validHosts {
		r := manual("GET", "/x")
		r.Host = v
		mustBind(t, config(), r)
		r = manual("GET", "/x")
		r.Header = http.Header{"Host": {v}}
		mustBind(t, config(), r)
	}
	for _, v := range invalidHosts {
		r := manual("GET", "/x")
		r.Host = ""
		r.Header = http.Header{"Host": {v}}
		_, err := from(config(), r)
		wantRule(t, err, binding.RuleInvalidHost)
		if v == "" {
			continue
		}
		r = manual("GET", "/x")
		r.Host = v
		_, err = from(config(), r)
		wantRule(t, err, binding.RuleInvalidHost)
	}
}

// TestMissingHost: an origin-form request with neither Request.Host nor a
// Host line is refused; an absolute-form target carries its own authority
// (RFC 9112 3.2.2) and needs no Host (request-binding.md RB-66).
func TestMissingHost(t *testing.T) {
	r := manual("GET", "/x")
	r.Host = ""
	_, err := from(config(), r)
	wantRule(t, err, binding.RuleMissingHost)

	r = manual("GET", "https://gateway.example/x")
	r.Host = ""
	if op := mustBind(t, config(), r); op.TargetURI != origin+"/x" {
		t.Fatalf("target %q", op.TargetURI)
	}
}

// TestInvalidHostOverWire: the net/http server passes a Host with a port
// that is not digits on to the handler, and the binding refuses it.
func TestInvalidHostOverWire(t *testing.T) {
	_, err := bind(t, config(), "GET /x HTTP/1.1\r\nHost: gateway.example:abc\r\n\r\n")
	wantRule(t, err, binding.RuleInvalidHost)
}

// TestDuplicateHostNeverReachesHandler: the net/http server answers 400 to
// a second Host field line itself (RFC 9112 3.2), and http.ReadRequest
// refuses it too, so only a program can hand the binding such a request.
func TestDuplicateHostNeverReachesHandler(t *testing.T) {
	raw := "GET /x HTTP/1.1\r\nHost: gateway.example\r\nHost: gateway.example\r\nConnection: close\r\n\r\n"
	if _, err := http.ReadRequest(bufio.NewReader(strings.NewReader(raw))); err == nil {
		t.Fatal("http.ReadRequest accepted two Host field lines")
	}
	called := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called <- struct{}{} }))
	defer srv.Close()
	conn, err := net.Dial("tcp", strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := io.WriteString(conn, raw); err != nil {
		t.Fatal(err)
	}
	status, _ := bufio.NewReader(conn).ReadString('\n')
	if !strings.HasPrefix(status, "HTTP/1.1 400 ") {
		t.Fatalf("status line %q, want 400", status)
	}
	select {
	case <-called:
		t.Fatal("the handler ran")
	default:
	}
}

// TestRejectHeaderValueOverWire: net/http passes obs-text through, so a
// header that is not UTF-8 reaches the binding from the wire.
func TestRejectHeaderValueOverWire(t *testing.T) {
	_, err := bind(t, config(), "GET /x HTTP/1.1\r\nHost: gateway.example\r\nX-Dry-Run: \xff\xfe\r\n\r\n")
	wantRule(t, err, binding.RuleHeaderValue)
}

// TestContentTypeIgnoredWithoutBody: without a body, content-type is not part
// of the operation context unless allowlisted, so its value is not examined.
func TestContentTypeIgnoredWithoutBody(t *testing.T) {
	r := manual("GET", "/x")
	r.Header.Set("Content-Type", "\xff")
	op := mustBind(t, config(), r)
	if len(op.Headers) != 0 {
		t.Fatalf("headers %q, want none", op.Headers)
	}
}
