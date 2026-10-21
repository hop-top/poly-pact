package binding

import (
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"unicode/utf8"

	"hop.top/pact-go/internal/ascii"
)

// selectHeaders returns the headers member: the allowlisted headers that are
// present, plus content-type when a body is present (draft 10.2). It is never
// nil. A name listed in a Connection field is hop-by-hop for this request
// (RFC 9110 7.6.1) and is left out.
func selectHeaders(h http.Header, allow []string, hasBody bool) (map[string]string, error) {
	names := allow
	if hasBody && !slices.Contains(allow, "content-type") {
		names = append(append([]string{}, allow...), "content-type")
	}
	hop := connectionOptions(h)
	out := make(map[string]string, len(names))
	for _, name := range names {
		if hop[name] {
			continue
		}
		v, ok, err := fieldValue(h, name)
		if err != nil {
			return nil, err
		}
		if ok {
			out[name] = v
		}
	}
	return out, nil
}

// fieldValue returns the combined value of the field name: each field line
// value without leading or trailing SP and HTAB (RFC 9110 5.5, 5.6.3), joined
// in order with ", " (RFC 9110 5.2, 5.3). ok is false when there is no field
// line.
func fieldValue(h http.Header, name string) (v string, ok bool, err error) {
	var lines []string
	key := ""
	for k, vs := range h {
		if !ascii.EqualFold(k, name) {
			continue
		}
		if key != "" {
			// Two map keys for one name: their relative order is lost.
			return "", false, refuse(RuleHeaderKeyCollision, "the header %q is stored under two keys", name)
		}
		key, lines = k, vs
	}
	if key == "" {
		return "", false, nil
	}
	trimmed := make([]string, len(lines))
	for i, l := range lines {
		trimmed[i] = strings.Trim(l, " \t")
	}
	v = strings.Join(trimmed, ", ")
	for i := 0; i < len(v); i++ {
		// RFC 9110 5.5: field-content is VCHAR, obs-text, SP and HTAB; CR, LF,
		// NUL and the other controls are invalid.
		if c := v[i]; c < 0x20 && c != '\t' || c == 0x7f {
			return "", false, refuse(RuleHeaderValue, "the header %q has the control octet 0x%02X", name, c)
		}
	}
	if !utf8.ValidString(v) {
		// Draft 7.1: PACT objects are UTF-8 JSON, so other obs-text octets
		// cannot be carried exactly.
		return "", false, refuse(RuleHeaderValue, "the header %q is not valid UTF-8", name)
	}
	if n := utf8.RuneCountInString(v); n > maxHeaderValue {
		return "", false, refuse(RuleHeaderTooLong, "the header %q has %d characters, at most %d", name, n, maxHeaderValue)
	}
	return v, true, nil
}

// checkHost applies the Host rules of RFC 9112 3.2 (request-binding.md RB-65,
// RB-66) to a request whose target has passed requestTarget.
//
// More than one Host field line is refused. A net/http server and
// http.ReadRequest refuse such a request themselves and keep no Host line in
// the header map, so only a program can build one: under one key, or under
// keys that differ only in ASCII case. Request.Host is a single value and is
// not counted.
//
// Request.Host stands for the Host line of an origin-form request: a server
// fills it from Host, or over HTTP/2 from :authority (RFC 9113 8.3.1). An
// origin-form request with neither it nor a Host line has no authority and is
// refused. An absolute-form target carries its own authority (RFC 9112
// 3.2.2), and net/http sets Request.Host from it, so Request.Host is not
// checked then. Every value checked must be uri-host [ ":" port ] with a
// non-empty host.
func checkHost(r *http.Request) error {
	var lines []string
	for k, vs := range r.Header {
		if ascii.EqualFold(k, "host") {
			lines = append(lines, vs...)
		}
	}
	if len(lines) > 1 {
		return refuse(RuleDuplicateHost, "the request has %d Host field lines", len(lines))
	}
	originForm := strings.HasPrefix(r.RequestURI, "/")
	if originForm && len(lines) == 0 && r.Host == "" {
		return refuse(RuleMissingHost, "an origin-form request without Host")
	}
	values := lines
	if originForm && r.Host != "" {
		values = append(values, r.Host)
	}
	for _, v := range values {
		if !validHost(strings.Trim(v, " \t")) {
			return refuse(RuleInvalidHost, "the Host value is not uri-host [ \":\" port ]")
		}
	}
	return nil
}

// validHost reports whether v is uri-host [ ":" port ] (RFC 9110 7.2) with a
// host that is not empty (RFC 9110 4.2.1, 4.2.2): an IP literal, IPv6
// without a zone identifier or IPvFuture, or a registered name of
// unreserved, sub-delims and percent-encoded characters, which includes a
// dotted IPv4 address (RFC 3986 3.2.2); then a port of digits (3.2.3).
func validHost(v string) bool {
	var port string
	if strings.HasPrefix(v, "[") {
		end := strings.IndexByte(v, ']')
		if end < 0 {
			return false
		}
		lit, rest := v[1:end], v[end+1:]
		if !ipvFuture(lit) {
			addr, err := netip.ParseAddr(lit)
			if strings.Contains(lit, "%") || err != nil || !addr.Is6() || addr.Zone() != "" {
				return false
			}
		}
		if rest != "" && rest[0] != ':' {
			return false
		}
		port = strings.TrimPrefix(rest, ":")
	} else {
		var host string
		host, port, _ = strings.Cut(v, ":")
		if host == "" {
			return false
		}
		for i := 0; i < len(host); i++ {
			switch c := host[i]; {
			case isUnreserved(c) || isSubDelim(c):
			case c == '%' && i+2 < len(host) && isHex(host[i+1]) && isHex(host[i+2]):
				i += 2
			default:
				return false
			}
		}
	}
	for i := 0; i < len(port); i++ {
		if !isDigit(port[i]) {
			return false
		}
	}
	return true
}

// ipvFuture reports whether s is IPvFuture (RFC 3986 3.2.2):
// "v" 1*HEXDIG "." 1*( unreserved / sub-delims / ":" ), "v" in any case.
func ipvFuture(s string) bool {
	if len(s) < 4 || s[0] != 'v' && s[0] != 'V' {
		return false
	}
	i := 1
	for i < len(s) && isHex(s[i]) {
		i++
	}
	if i == 1 || i >= len(s)-1 || s[i] != '.' {
		return false
	}
	for _, c := range []byte(s[i+1:]) {
		if !isUnreserved(c) && !isSubDelim(c) && c != ':' {
			return false
		}
	}
	return true
}

// connectionOptions returns the lowercase connection options of every
// Connection field line (RFC 9110 7.6.1).
func connectionOptions(h http.Header) map[string]bool {
	out := map[string]bool{}
	for k, vs := range h {
		if !ascii.EqualFold(k, "connection") {
			continue
		}
		for _, v := range vs {
			for _, opt := range strings.Split(v, ",") {
				if opt = strings.Trim(opt, " \t"); opt != "" {
					out[ascii.ToLower(opt)] = true
				}
			}
		}
	}
	return out
}
