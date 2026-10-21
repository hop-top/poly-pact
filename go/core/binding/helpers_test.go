package binding_test

import (
	"bufio"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"hop.top/pact-go/core"
	"hop.top/pact-go/core/binding"
)

const (
	// origin is the public origin of the draft Appendix B gateway.
	origin = "https://gateway.example"

	// emptyBodyDigest is the body_digest of draft Appendix B.3: SHA-256 of
	// zero bytes, base64url without padding.
	emptyBodyDigest core.Digest = "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"

	// abcDigest is SHA-256("abc"), the FIPS 180-4 example, base64url without
	// padding.
	abcDigest core.Digest = "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0"

	principal = "https://identity.example/principals/alice"
	action    = "invoice.read"
	resource  = "https://invoices.example/invoices/INV-1042"
)

// config is a valid configuration: the origin of Appendix B and the
// protected_header_names and identifiers of Appendix B.13.
func config() binding.Config {
	return binding.Config{
		Origin:                origin,
		HeaderAllowlist:       []string{"if-match", "x-dry-run"},
		HeaderNormalizationID: "finance-header-normalization-1",
		MappingVersion:        "finance-http-1",
		MaxBody:               1 << 20,
	}
}

// parse reads raw, the text of an HTTP/1.1 request, with the parser net/http
// servers use, so RequestURI, URL and Header are what a handler would see.
// It does not transfer-decode a chunked body; use bind for that.
func parse(t *testing.T, raw string) *http.Request {
	t.Helper()
	r, err := http.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return r
}

// get is a GET request for target as a server would parse it.
func get(t *testing.T, target string) *http.Request {
	t.Helper()
	return parse(t, "GET "+target+" HTTP/1.1\r\nHost: gateway.example\r\n\r\n")
}

// manual builds a request that net/http would not produce from the wire, for
// inputs the server parser rejects or that only a program can build.
func manual(method, target string) *http.Request {
	u, err := url.ParseRequestURI(target)
	if err != nil {
		u = &url.URL{}
	}
	return &http.Request{
		Method:     method,
		RequestURI: target,
		URL:        u,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     http.Header{},
		Body:       http.NoBody,
		Host:       "gateway.example",
	}
}

// bind sends raw over a TCP connection to a net/http server and runs
// FromRequest in its handler, so the request is exactly what a gateway gets,
// with the body transfer-decoded by the server.
func bind(t *testing.T, cfg binding.Config, raw string) (core.OperationContext, error) {
	t.Helper()
	type result struct {
		op  core.OperationContext
		err error
	}
	got := make(chan result, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		op, err := binding.FromRequest(cfg, r, principal, action, []string{resource})
		got <- result{op, err}
	}))
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
	select {
	case res := <-got:
		return res.op, res.err
	case <-time.After(5 * time.Second):
		t.Fatalf("handler not called for %q; server answered %q", raw, strings.TrimSpace(status))
		return core.OperationContext{}, nil
	}
}

// from runs FromRequest with the test principal, action and resource.
func from(cfg binding.Config, r *http.Request) (core.OperationContext, error) {
	return binding.FromRequest(cfg, r, principal, action, []string{resource})
}

// wantRule fails unless err is a *binding.RequestError for rule that wraps
// binding.ErrInvalidRequest.
func wantRule(t *testing.T, err error, rule binding.Rule) {
	t.Helper()
	if err == nil {
		t.Fatalf("got no error, want rule %q", rule)
	}
	var re *binding.RequestError
	if !errors.As(err, &re) {
		t.Fatalf("error %v is not a *binding.RequestError, want rule %q", err, rule)
	}
	if re.Rule != rule {
		t.Fatalf("rule %q (%v), want %q", re.Rule, err, rule)
	}
	if !errors.Is(err, binding.ErrInvalidRequest) {
		t.Fatalf("error %v does not wrap ErrInvalidRequest", err)
	}
	if errors.Is(err, binding.ErrInvalidConfig) {
		t.Fatalf("request error %v wraps ErrInvalidConfig", err)
	}
}

// mustBind fails on any error.
func mustBind(t *testing.T, cfg binding.Config, r *http.Request) core.OperationContext {
	t.Helper()
	op, err := from(cfg, r)
	if err != nil {
		t.Fatalf("FromRequest: %v", err)
	}
	return op
}
