package binding

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"unicode/utf8"

	"hop.top/pact-go/internal/ascii"
)

// Schema bounds this package enforces so that its output validates against
// OperationContext and GatewayMetadata in spec/v1.0/schemas/pact.schema.json.
const (
	maxIdentifier  = 1024 // operation_mapping_version, header_normalization_id
	maxTargetURI   = 1024 // OperationContext.target_uri maxLength
	maxHeaders     = 64   // OperationContext.headers maxProperties
	maxHeaderValue = 8192 // OperationContext.headers value maxLength
)

// Config is the installed baseline HTTP mapping of a gateway. Its values come
// from trusted gateway configuration, never from the request.
type Config struct {
	// Origin is the public HTTPS origin, scheme "://" host [":" port], with no
	// path, query, fragment or userinfo. The scheme and host are lowercased and
	// port 443 is dropped. The host is ASCII: a registered name of unreserved
	// and sub-delims characters, a dotted IPv4 address, or a bracketed IPv6
	// address without a zone.
	Origin string

	// HeaderAllowlist names the application headers that can alter action
	// semantics. Names are RFC 9110 tokens, matched without regard to case and
	// written lowercase. Credential, presentation, hop-by-hop, signature and
	// Host headers are refused (see the package documentation). The gateway
	// publishes the list in GatewayMetadata.protected_header_names.
	HeaderAllowlist []string

	// HeaderNormalizationID names the header normalization this package
	// applies, as published in GatewayMetadata.header_normalization_id.
	HeaderNormalizationID string

	// MappingVersion is the installed mapping version, as published in
	// GatewayMetadata.operation_mapping_version. The caller records it when it
	// issues a requirement contract and checks that it is unchanged when it
	// validates the actual operation (draft 10.2); FromRequest only requires
	// it to be set.
	MappingVersion string

	// MaxBody is the largest request body, in bytes, that FromRequest reads.
	// Zero admits only an empty body.
	MaxBody int64
}

// Validate reports whether c is usable. The error wraps [ErrInvalidConfig].
// FromRequest calls it on every request; a gateway can call it at start-up.
func (c Config) Validate() error {
	_, _, err := c.prepare()
	return err
}

// prepare validates c and returns the normalized origin and the lowercase
// allowlist.
func (c Config) prepare() (origin string, allow []string, err error) {
	if origin, err = normalizeOrigin(c.Origin); err != nil {
		return "", nil, err
	}
	if allow, err = allowlist(c.HeaderAllowlist); err != nil {
		return "", nil, err
	}
	for _, id := range []struct{ name, v string }{
		{"HeaderNormalizationID", c.HeaderNormalizationID},
		{"MappingVersion", c.MappingVersion},
	} {
		if n := utf8.RuneCountInString(id.v); n < 1 || n > maxIdentifier || !utf8.ValidString(id.v) {
			return "", nil, configError("%s must be UTF-8 of 1 to %d characters", id.name, maxIdentifier)
		}
	}
	if c.MaxBody < 0 {
		return "", nil, configError("MaxBody is negative")
	}
	return origin, allow, nil
}

func configError(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidConfig, fmt.Sprintf(format, args...))
}

// normalizeOrigin checks an origin and returns it with the scheme and host in
// lowercase and the default port omitted (RFC 3986 6.2.2.1 and 6.2.3; RFC
// 9110 4.2.3).
func normalizeOrigin(s string) (string, error) {
	scheme, authority, ok := strings.Cut(s, "://")
	if !ok || !ascii.EqualFold(scheme, "https") {
		return "", configError("Origin %q is not an https origin", s)
	}
	if strings.ContainsAny(authority, "/?#") {
		return "", configError("Origin %q has a path, query or fragment", s)
	}
	if strings.Contains(authority, "@") {
		return "", configError("Origin %q has userinfo", s)
	}
	if !isASCII(authority) || strings.Contains(authority, "%") {
		// RFC 3986 3.2.2: percent-encoding in a host only represents UTF-8, so
		// it is a non-ASCII host too.
		return "", configError("Origin %q has a non-ASCII host", s)
	}
	host, port, err := splitHostPort(authority)
	if err != nil {
		return "", configError("Origin %q: %v", s, err)
	}
	out := "https://" + ascii.ToLower(host)
	if port != "" && port != "443" {
		out += ":" + port
	}
	return out, nil
}

// splitHostPort splits an ASCII authority without userinfo into a validated
// host and port. An empty port ("host:") is returned as "".
func splitHostPort(a string) (host, port string, err error) {
	if strings.HasPrefix(a, "[") {
		end := strings.IndexByte(a, ']')
		if end < 0 {
			return "", "", fmt.Errorf("unclosed IP literal")
		}
		host, rest := a[:end+1], a[end+1:]
		addr, perr := netip.ParseAddr(host[1 : len(host)-1])
		// RFC 3986 3.2.2: an IP literal is IPv6 (no zone identifier) or
		// IPvFuture, which no gateway resolves here.
		if perr != nil || !addr.Is6() || addr.Zone() != "" {
			return "", "", fmt.Errorf("IP literal %q is not an IPv6 address without zone", host)
		}
		if rest != "" && !strings.HasPrefix(rest, ":") {
			return "", "", fmt.Errorf("text after the IP literal")
		}
		port = strings.TrimPrefix(rest, ":")
		return host, port, checkPort(port)
	}
	host, port, _ = strings.Cut(a, ":")
	if host == "" {
		// RFC 9110 4.2.2: an https URI with an empty host is invalid.
		return "", "", fmt.Errorf("empty host")
	}
	for i := 0; i < len(host); i++ {
		if c := host[i]; !isUnreserved(c) && !isSubDelim(c) {
			return "", "", fmt.Errorf("host has the character %q", c)
		}
	}
	return host, port, checkPort(port)
}

// checkPort accepts an empty port or a decimal port 1..65535 without leading
// zero, so that the default port is recognized by its spelling.
func checkPort(p string) error {
	if p == "" {
		return nil
	}
	n, err := strconv.Atoi(p)
	if err != nil || n < 1 || n > 65535 || p[0] == '0' || p[0] == '+' {
		return fmt.Errorf("port %q is not a number 1..65535 without leading zero", p)
	}
	return nil
}

// excludedHeader reports whether a lowercase header name can never be
// covered: credentials and presentation headers (draft 10.2 and 19),
// hop-by-hop headers (RFC 9110 7.6.1), message signatures (RFC 9421 4.1,
// 4.2) and Host, which never selects the origin (request-binding.md RB-3,
// RB-20).
func excludedHeader(name string) bool {
	switch name {
	case "authorization", "cookie", "set-cookie",
		"connection", "keep-alive", "te", "transfer-encoding", "upgrade",
		"signature", "signature-input", "host":
		return true
	}
	return strings.HasPrefix(name, "pact-") || strings.HasPrefix(name, "proxy-")
}

// allowlist validates the configured header names and returns them in
// lowercase.
func allowlist(names []string) ([]string, error) {
	out := make([]string, 0, len(names))
	withContentType := 0
	for _, n := range names {
		if !isToken(n) {
			return nil, configError("header name %q is not an RFC 9110 token", n)
		}
		l := ascii.ToLower(n)
		if excludedHeader(l) {
			return nil, configError("header %q cannot be covered by an operation context", l)
		}
		for _, seen := range out {
			if seen == l {
				return nil, configError("header %q is listed twice", l)
			}
		}
		out = append(out, l)
		if l == "content-type" {
			withContentType = 1
		}
	}
	if n := len(out) + 1 - withContentType; n > maxHeaders {
		return nil, configError("%d header names with content-type, at most %d", n, maxHeaders)
	}
	return out, nil
}

// isToken reports whether s is an RFC 9110 5.6.2 token.
func isToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !isAlpha(c) && !isDigit(c) && !strings.ContainsRune("!#$%&'*+-.^_`|~", rune(c)) {
			return false
		}
	}
	return true
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

func isAlpha(c byte) bool { return 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' }
func isDigit(c byte) bool { return '0' <= c && c <= '9' }

// isUnreserved is RFC 3986 2.3 unreserved.
func isUnreserved(c byte) bool {
	return isAlpha(c) || isDigit(c) || c == '-' || c == '.' || c == '_' || c == '~'
}

// isSubDelim is RFC 3986 2.2 sub-delims.
func isSubDelim(c byte) bool { return strings.IndexByte("!$&'()*+,;=", c) >= 0 }
