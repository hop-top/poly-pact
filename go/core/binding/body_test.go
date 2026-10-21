package binding_test

import (
	"errors"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"hop.top/pact-go/core/binding"
)

// withBody gives r the body s with a known length.
func withBody(r *http.Request, s string) *http.Request {
	r.Body = io.NopCloser(strings.NewReader(s))
	r.ContentLength = int64(len(s))
	return r
}

// TestBodyDigest: body_digest hashes the exact body bytes after transfer
// decoding; an empty body hashes the empty byte string (draft 10.2).
func TestBodyDigest(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		op := mustBind(t, config(), get(t, "/x"))
		if op.BodyDigest != emptyBodyDigest {
			t.Fatalf("body_digest %q, want %q", op.BodyDigest, emptyBodyDigest)
		}
	})
	t.Run("nil body", func(t *testing.T) {
		r := manual("GET", "/x")
		r.Body = nil
		op := mustBind(t, config(), r)
		if op.BodyDigest != emptyBodyDigest {
			t.Fatalf("body_digest %q, want %q", op.BodyDigest, emptyBodyDigest)
		}
	})
	t.Run("content-length", func(t *testing.T) {
		op := mustBind(t, config(), parse(t, "POST /x HTTP/1.1\r\nHost: gateway.example\r\nContent-Length: 3\r\n\r\nabc"))
		if op.BodyDigest != abcDigest {
			t.Fatalf("body_digest %q, want %q", op.BodyDigest, abcDigest)
		}
	})
	t.Run("chunked over the wire", func(t *testing.T) {
		op, err := bind(t, config(), "POST /x HTTP/1.1\r\nHost: gateway.example\r\n"+
			"Transfer-Encoding: chunked\r\n\r\n1\r\na\r\n2\r\nbc\r\n0\r\n\r\n")
		if err != nil {
			t.Fatal(err)
		}
		if op.BodyDigest != abcDigest {
			t.Fatalf("body_digest %q, want %q (the transfer-decoded bytes)", op.BodyDigest, abcDigest)
		}
	})
	t.Run("largest MaxBody", func(t *testing.T) {
		cfg := config()
		cfg.MaxBody = math.MaxInt64
		op := mustBind(t, cfg, withBody(manual("POST", "/x"), "abc"))
		if op.BodyDigest != abcDigest {
			t.Fatalf("body_digest %q, want %q", op.BodyDigest, abcDigest)
		}
	})
	t.Run("exactly MaxBody", func(t *testing.T) {
		cfg := config()
		cfg.MaxBody = 3
		op := mustBind(t, cfg, withBody(manual("POST", "/x"), "abc"))
		if op.BodyDigest != abcDigest {
			t.Fatalf("body_digest %q, want %q", op.BodyDigest, abcDigest)
		}
	})
}

// TestBodyRestored: the body can be read again after the binding, and GetBody
// returns it too.
func TestBodyRestored(t *testing.T) {
	r := withBody(manual("POST", "/x"), "abc")
	mustBind(t, config(), r)
	b, err := io.ReadAll(r.Body)
	if err != nil || string(b) != "abc" {
		t.Fatalf("body after binding %q, %v; want \"abc\"", b, err)
	}
	if r.GetBody == nil {
		t.Fatal("GetBody is nil")
	}
	rc, err := r.GetBody()
	if err != nil {
		t.Fatal(err)
	}
	b, _ = io.ReadAll(rc)
	if string(b) != "abc" {
		t.Fatalf("GetBody %q, want \"abc\"", b)
	}
}

// TestRejectContentEncoding: the baseline forbids HTTP content encodings on
// protected requests (draft 10.2), so any Content-Encoding field is refused.
func TestRejectContentEncoding(t *testing.T) {
	for _, h := range []http.Header{
		{"Content-Encoding": {"gzip"}},
		{"Content-Encoding": {"identity"}},
		{"Content-Encoding": {""}},
		{"Content-Encoding": {"gzip", "br"}},
		{"content-encoding": {"gzip"}},
	} {
		r := withBody(manual("POST", "/x"), "abc")
		r.Header = h
		_, err := from(config(), r)
		wantRule(t, err, binding.RuleContentEncoding)
	}
	_, err := bind(t, config(), "POST /x HTTP/1.1\r\nHost: gateway.example\r\nContent-Encoding: gzip\r\nContent-Length: 3\r\n\r\nabc")
	wantRule(t, err, binding.RuleContentEncoding)
}

// TestRejectTransferCoding: only chunked is transfer-decoded by net/http; a
// request that claims another transfer coding has a body the binding cannot
// know to be decoded.
func TestRejectTransferCoding(t *testing.T) {
	r := withBody(manual("POST", "/x"), "abc")
	r.TransferEncoding = []string{"gzip", "chunked"}
	_, err := from(config(), r)
	wantRule(t, err, binding.RuleTransferCoding)

	r = withBody(manual("POST", "/x"), "abc")
	r.Header.Set("Transfer-Encoding", "gzip")
	_, err = from(config(), r)
	wantRule(t, err, binding.RuleTransferCoding)

	r = withBody(manual("POST", "/x"), "abc")
	r.TransferEncoding = []string{"chunked"}
	mustBind(t, config(), r)
}

// TestRejectBodyTooLarge: a body over MaxBody is refused, whether the length
// is declared or found while reading, and the request keeps its body.
func TestRejectBodyTooLarge(t *testing.T) {
	cfg := config()
	cfg.MaxBody = 3

	t.Run("declared length", func(t *testing.T) {
		r := withBody(manual("POST", "/x"), "abcd")
		_, err := from(cfg, r)
		wantRule(t, err, binding.RuleBodyTooLarge)
		if b, _ := io.ReadAll(r.Body); string(b) != "abcd" {
			t.Fatalf("body after rejection %q, want \"abcd\"", b)
		}
	})
	t.Run("declared length is not read", func(t *testing.T) {
		r := manual("POST", "/x")
		r.Body = io.NopCloser(failingReader{})
		r.ContentLength = 4
		_, err := from(cfg, r)
		wantRule(t, err, binding.RuleBodyTooLarge)
	})
	t.Run("unknown length", func(t *testing.T) {
		r := withBody(manual("POST", "/x"), "abcdef")
		r.ContentLength = -1
		_, err := from(cfg, r)
		wantRule(t, err, binding.RuleBodyTooLarge)
		if b, _ := io.ReadAll(r.Body); string(b) != "abcdef" {
			t.Fatalf("body after rejection %q, want \"abcdef\"", b)
		}
	})
	t.Run("understated length", func(t *testing.T) {
		r := withBody(manual("POST", "/x"), "abcd")
		r.ContentLength = 1
		_, err := from(cfg, r)
		wantRule(t, err, binding.RuleBodyTooLarge)
	})
	t.Run("chunked over the wire", func(t *testing.T) {
		_, err := bind(t, cfg, "POST /x HTTP/1.1\r\nHost: gateway.example\r\n"+
			"Transfer-Encoding: chunked\r\n\r\n4\r\nabcd\r\n0\r\n\r\n")
		wantRule(t, err, binding.RuleBodyTooLarge)
	})
	t.Run("zero MaxBody", func(t *testing.T) {
		zero := config()
		zero.MaxBody = 0
		_, err := from(zero, withBody(manual("POST", "/x"), "a"))
		wantRule(t, err, binding.RuleBodyTooLarge)
		mustBind(t, zero, manual("POST", "/x"))
	})
	t.Run("server byte limit", func(t *testing.T) {
		r := withBody(manual("POST", "/x"), "abcdef")
		r.ContentLength = -1
		r.Body = http.MaxBytesReader(httptest.NewRecorder(), r.Body, 2)
		_, err := from(config(), r)
		wantRule(t, err, binding.RuleBodyTooLarge)
	})
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("connection reset") }

// TestBodyReadError: a body that cannot be read is not a malformed request.
func TestBodyReadError(t *testing.T) {
	r := manual("POST", "/x")
	r.Body = io.NopCloser(failingReader{})
	r.ContentLength = -1
	_, err := from(config(), r)
	if !errors.Is(err, binding.ErrBodyRead) {
		t.Fatalf("error %v, want ErrBodyRead", err)
	}
	if errors.Is(err, binding.ErrInvalidRequest) || errors.Is(err, binding.ErrInvalidConfig) {
		t.Fatalf("error %v also wraps ErrInvalidRequest or ErrInvalidConfig", err)
	}
}
