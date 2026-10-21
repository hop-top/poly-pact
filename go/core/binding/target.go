package binding

import (
	"net/http"
	"strings"
	"unicode/utf8"

	"hop.top/pact-go/internal/ascii"
)

// requestTarget returns the exact path and query of r's request-target
// (RFC 9112 3.2): all of it in origin-form, the part after the authority in
// absolute-form. Other forms, a fragment, userinfo, a non-ASCII host, the
// ambiguous encodings and dot segments are refused.
func requestTarget(r *http.Request) (string, error) {
	// net/http does not split a fragment off a request-target: it stays in
	// RequestURI and URL.Path. A program can also set one in URL.
	rt := r.RequestURI
	if strings.Contains(rt, "#") || r.URL.Fragment != "" || r.URL.RawFragment != "" {
		return "", refuse(RuleFragment, "the target has a fragment")
	}
	if r.URL.User != nil {
		return "", refuse(RuleUserinfo, "the target has userinfo")
	}
	var pathQuery string
	switch {
	case rt == "":
		return "", refuse(RuleTargetForm, "no request-target (RequestURI is empty)")
	case rt[0] == '/':
		pathQuery = rt
	default:
		pq, err := absoluteForm(rt)
		if err != nil {
			return "", err
		}
		pathQuery = pq
	}
	path, query, hasQuery := strings.Cut(pathQuery, "?")
	if err := checkComponent(path, true); err != nil {
		return "", err
	}
	if err := checkDotSegments(path); err != nil {
		return "", err
	}
	if hasQuery {
		if err := checkComponent(query, false); err != nil {
			return "", err
		}
	}
	return pathQuery, nil
}

// absoluteForm returns the path and query of an http or https absolute-form
// target. The authority is checked and then dropped: the origin comes from
// configuration. An empty path is refused rather than normalized to "/".
func absoluteForm(rt string) (string, error) {
	scheme, rest, ok := strings.Cut(rt, "://")
	if !ok || !ascii.EqualFold(scheme, "https") && !ascii.EqualFold(scheme, "http") {
		return "", refuse(RuleTargetForm, "the target is not origin-form or an http(s) absolute-form")
	}
	end := strings.IndexAny(rest, "/?")
	if end < 0 {
		end = len(rest)
	}
	authority, pathQuery := rest[:end], rest[end:]
	if strings.Contains(authority, "@") {
		// RFC 9110 4.2.4: a recipient treats userinfo in an http(s) URI as an
		// error.
		return "", refuse(RuleUserinfo, "the target has userinfo")
	}
	if !isASCII(authority) || strings.Contains(authority, "%") {
		// RFC 3986 3.2.2: percent-encoding in a host only represents UTF-8.
		return "", refuse(RuleNonASCIIHost, "the target has a non-ASCII host")
	}
	if host, _, _ := strings.Cut(authority, ":"); host == "" {
		// RFC 9110 4.2.1, 4.2.2: an http(s) URI with an empty host is invalid.
		return "", refuse(RuleTargetForm, "the absolute-form target has an empty host")
	}
	if !strings.HasPrefix(pathQuery, "/") {
		return "", refuse(RuleTargetForm, "the absolute-form target has an empty path")
	}
	return pathQuery, nil
}

// checkComponent checks the path (isPath) or the query of a request target:
// every octet is allowed there by RFC 3986 3.3 or 3.4, every "%" starts a
// pct-encoded triplet (2.1), and the encoding is not ambiguous:
//   - no escape has a lowercase hex digit (2.1, 6.2.2.1);
//   - no escape encodes an unreserved character (2.3, 6.2.2.2);
//   - the path has no %2F, an encoded path separator;
//   - the decoded octets are valid UTF-8, so no overlong form, surrogate or
//     stray byte (RFC 3629 3).
func checkComponent(s string, isPath bool) error {
	name := "query"
	if isPath {
		name = "path"
	}
	decoded := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '%' {
			if !isPchar(c) && c != '/' && (isPath || c != '?') {
				return refuse(RuleInvalidCharacter, "the %s has the octet 0x%02X at offset %d, not allowed in a URI", name, c, i)
			}
			decoded = append(decoded, c)
			continue
		}
		if i+2 >= len(s) || !isHex(s[i+1]) || !isHex(s[i+2]) {
			return refuse(RuleMalformedEscape, "the %s has a %% at offset %d not followed by two hex digits", name, i)
		}
		if isLowerHex(s[i+1]) || isLowerHex(s[i+2]) {
			return refuse(RuleLowercaseHex, "the %s has a lowercase hex digit in the escape at offset %d", name, i)
		}
		b := unhex(s[i+1])<<4 | unhex(s[i+2])
		if isUnreserved(b) {
			return refuse(RuleEncodedUnreserved, "the %s encodes the unreserved character %q at offset %d", name, b, i)
		}
		if isPath && b == '/' {
			return refuse(RuleEncodedSlash, "the path has an encoded slash at offset %d", i)
		}
		decoded = append(decoded, b)
		i += 2
	}
	if !utf8.Valid(decoded) {
		return refuse(RuleInvalidUTF8, "the decoded %s is not valid UTF-8", name)
	}
	return nil
}

// checkDotSegments refuses a path with a complete "." or ".." segment (RFC
// 3986 3.3). Path segment normalization (6.2.2.3) removes such segments with
// remove_dot_segments (5.2.4), so the path is an ambiguous encoding (draft
// 10.2). Segments are delimited by "/" only: "a..b", "..." and dots in the
// query are not dot segments. An encoded dot, as in "%2E%2E", has already
// been refused by checkComponent as an encoded unreserved character (2.3,
// 6.2.2.2).
func checkDotSegments(path string) error {
	offset := 0
	for seg := range strings.SplitSeq(path, "/") {
		if seg == "." || seg == ".." {
			return refuse(RuleDotSegment, "the path has the dot segment %q at offset %d", seg, offset)
		}
		offset += len(seg) + 1
	}
	return nil
}

// isPchar is RFC 3986 3.3 pchar without pct-encoded.
func isPchar(c byte) bool { return isUnreserved(c) || isSubDelim(c) || c == ':' || c == '@' }

func isHex(c byte) bool      { return isDigit(c) || 'A' <= c && c <= 'F' || 'a' <= c && c <= 'f' }
func isLowerHex(c byte) bool { return 'a' <= c && c <= 'f' }

func unhex(c byte) byte {
	switch {
	case isDigit(c):
		return c - '0'
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10
	default:
		return c - 'a' + 10
	}
}
