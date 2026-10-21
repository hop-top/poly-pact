package binding_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"hop.top/pact-go/core/binding"
)

// TestConfigValid: the Appendix B configuration and its variants pass.
func TestConfigValid(t *testing.T) {
	many := make([]string, 63)
	for i := range many {
		many[i] = fmt.Sprintf("x-h%d", i)
	}
	tests := []struct {
		name string
		edit func(*binding.Config)
	}{
		{"appendix B", func(*binding.Config) {}},
		{"no allowlist", func(c *binding.Config) { c.HeaderAllowlist = nil }},
		{"token characters", func(c *binding.Config) { c.HeaderAllowlist = []string{"x-a!#$%&'*+.^_`|~1"} }},
		{"63 names plus content-type", func(c *binding.Config) { c.HeaderAllowlist = many }},
		{"64 names with content-type", func(c *binding.Config) { c.HeaderAllowlist = append(append([]string{}, many...), "content-type") }},
		{"zero MaxBody", func(c *binding.Config) { c.MaxBody = 0 }},
		{"1024 character identifiers", func(c *binding.Config) {
			c.MappingVersion = strings.Repeat("m", 1024)
			c.HeaderNormalizationID = strings.Repeat("n", 1024)
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config()
			tc.edit(&cfg)
			if err := cfg.Validate(); err != nil {
				t.Fatalf("Validate: %v", err)
			}
			mustBind(t, cfg, get(t, "/x"))
		})
	}
}

// TestRejectConfig: each configuration rule has a failing input. FromRequest
// refuses an invalid configuration with ErrInvalidConfig, not a request error.
func TestRejectConfig(t *testing.T) {
	many := make([]string, 64)
	for i := range many {
		many[i] = fmt.Sprintf("x-h%d", i)
	}
	origins := []struct{ name, origin string }{
		{"empty", ""},
		{"http scheme", "http://gateway.example"},
		{"no scheme", "gateway.example"},
		{"trailing slash", "https://gateway.example/"},
		{"path", "https://gateway.example/base"},
		{"query", "https://gateway.example?x"},
		{"fragment", "https://gateway.example#f"},
		{"userinfo", "https://u@gateway.example"},
		{"non-ASCII host", "https://b\u00fccher.example"},
		{"percent-encoded host", "https://b%C3%BCcher.example"},
		{"empty host", "https://"},
		{"empty host with port", "https://:443"},
		{"space in host", "https://gate way.example"},
		{"port not a number", "https://gateway.example:abc"},
		{"port with leading zero", "https://gateway.example:0443"},
		{"port zero", "https://gateway.example:0"},
		{"port too large", "https://gateway.example:65536"},
		{"IPv6 zone", "https://[fe80::1%25en0]"},
		{"IPvFuture", "https://[v1.x]"},
		{"IPv4 in brackets", "https://[192.0.2.1]"},
		{"unclosed bracket", "https://[::1"},
		{"text after bracket", "https://[::1]x"},
	}
	headers := []struct {
		name  string
		allow []string
	}{
		{"authorization", []string{"authorization"}},
		{"authorization any case", []string{"Authorization"}},
		{"cookie", []string{"cookie"}},
		{"set-cookie", []string{"set-cookie"}},
		{"pact-presentation", []string{"pact-presentation"}},
		{"pact-admission any case", []string{"PACT-Admission"}},
		{"any pact- name", []string{"pact-anything"}},
		{"connection", []string{"connection"}},
		{"keep-alive", []string{"keep-alive"}},
		{"te", []string{"te"}},
		{"transfer-encoding", []string{"transfer-encoding"}},
		{"upgrade", []string{"upgrade"}},
		{"proxy-authorization", []string{"proxy-authorization"}},
		{"proxy-connection", []string{"proxy-connection"}},
		{"any proxy- name", []string{"proxy-anything"}},
		{"signature", []string{"signature"}},
		{"signature-input", []string{"signature-input"}},
		{"host", []string{"host"}},
		{"host any case", []string{"Host"}},
		{"empty name", []string{""}},
		{"space in name", []string{"x dry"}},
		{"colon in name", []string{"x:y"}},
		{"non-ASCII name", []string{"x-caf\u00e9"}},
		{"duplicate", []string{"x-a", "X-A"}},
		{"65 names with content-type", many},
	}
	tests := []struct {
		name string
		edit func(*binding.Config)
	}{
		{"empty mapping version", func(c *binding.Config) { c.MappingVersion = "" }},
		{"long mapping version", func(c *binding.Config) { c.MappingVersion = strings.Repeat("m", 1025) }},
		{"empty header normalization id", func(c *binding.Config) { c.HeaderNormalizationID = "" }},
		{"long header normalization id", func(c *binding.Config) { c.HeaderNormalizationID = strings.Repeat("n", 1025) }},
		{"negative MaxBody", func(c *binding.Config) { c.MaxBody = -1 }},
	}
	for _, o := range origins {
		tests = append(tests, struct {
			name string
			edit func(*binding.Config)
		}{"origin/" + o.name, func(c *binding.Config) { c.Origin = o.origin }})
	}
	for _, h := range headers {
		tests = append(tests, struct {
			name string
			edit func(*binding.Config)
		}{"allowlist/" + h.name, func(c *binding.Config) { c.HeaderAllowlist = h.allow }})
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config()
			tc.edit(&cfg)
			err := cfg.Validate()
			if !errors.Is(err, binding.ErrInvalidConfig) {
				t.Fatalf("Validate: %v, want ErrInvalidConfig", err)
			}
			_, err = from(cfg, get(t, "/x"))
			if !errors.Is(err, binding.ErrInvalidConfig) {
				t.Fatalf("FromRequest: %v, want ErrInvalidConfig", err)
			}
			if errors.Is(err, binding.ErrInvalidRequest) {
				t.Fatalf("FromRequest: %v also wraps ErrInvalidRequest", err)
			}
		})
	}
}

// TestRejectConfigNonASCIIHost: a non-ASCII or percent-encoded host in the
// origin is reported as such (RFC 3986 3.2.2), not as a stray character.
func TestRejectConfigNonASCIIHost(t *testing.T) {
	for _, o := range []string{"https://b\u00fccher.example", "https://b%C3%BCcher.example"} {
		cfg := config()
		cfg.Origin = o
		err := cfg.Validate()
		if !errors.Is(err, binding.ErrInvalidConfig) || !strings.Contains(err.Error(), "non-ASCII host") {
			t.Errorf("Origin %q: %v, want a non-ASCII host error", o, err)
		}
	}
	cfg := config()
	cfg.Origin = "https://xn--bcher-kva.example"
	if err := cfg.Validate(); err != nil {
		t.Errorf("A-label origin: %v", err)
	}
}
