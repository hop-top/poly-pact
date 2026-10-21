package adaptertest

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// credentialPatterns recognize credential material of draft 19 in text that
// must not carry any. Receipts, outcome reports and logs must not contain the
// headers authorization, proxy-authorization, cookie, set-cookie,
// pact-presentation and pact-admission, any private JWK parameter, or native
// tokens and passwords.
//
// The patterns are deliberately narrow, so that a legitimate message such as
// "basic authentication failed" does not match: an authorization value needs a
// long token after the scheme, a header name needs to be a JSON member name,
// and a key=value secret needs a name that only credentials have.
var credentialPatterns = []struct {
	name string
	re   *regexp.Regexp
	// placeholder, when set, receives a match's submatches and reports a
	// match that is not a credential after all.
	placeholder func(sub []string) bool
}{
	{"authorization value", regexp.MustCompile(`(?i)\b(?:bearer|basic)\s+[A-Za-z0-9._~+/-]{16,}=*`), nil},
	{"compact JWS or JWT", regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`), nil},
	{"credential header as a member name", regexp.MustCompile(`(?i)"(?:authorization|proxy-authorization|cookie|set-cookie|pact-presentation|pact-admission)"\s*:`), nil},
	{"private JWK parameter as a member name", regexp.MustCompile(`"(?:d|p|q|dp|dq|qi|k)"\s*:`), nil},
	{"credential assignment", regexp.MustCompile(`(?i)\b(?:access_token|refresh_token|id_token|api_?key|password|passwd|secret|session(?:_?id)?|sid)=([^\s&;"']{6,})`), isPlaceholder},
}

// isPlaceholder reports whether the value of an assignment is a mask such as
// [redacted], REDACTED, ***** or xxxxxx rather than a credential.
func isPlaceholder(sub []string) bool {
	v := strings.ToLower(strings.Trim(sub[1], "[]<>(){}*_-.x"))
	switch v {
	case "", "redacted", "removed", "hidden", "masked", "filtered", "omitted", "elided":
		return true
	}
	return false
}

// findCredentials returns a description of every credential in text: each
// secret that occurs literally and each pattern that matches.
func findCredentials(text string, secrets []string) []string {
	var found []string
	for _, s := range secrets {
		if s != "" && strings.Contains(text, s) {
			found = append(found, fmt.Sprintf("secret %q", s))
		}
	}
	for _, p := range credentialPatterns {
		for _, sub := range p.re.FindAllStringSubmatch(text, -1) {
			if p.placeholder != nil && p.placeholder(sub) {
				continue
			}
			found = append(found, fmt.Sprintf("%s %q", p.name, sub[0]))
			break
		}
	}
	return found
}

// jsonText marshals v without HTML escaping, so a secret that holds & < or >
// is found as written.
func jsonText(v any) string {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return fmt.Sprintf("<unencodable %T: %v>", v, err)
	}
	return b.String()
}

// scanText fails the case for each credential in text, when the case asks for
// the scan. what names the value for the message.
func (r *run) scanText(what, text string) {
	ls := r.c.Expect.LeakScan
	if ls == nil {
		return
	}
	for _, f := range findCredentials(text, ls.Secrets) {
		r.failf("%s carries a credential: %s", what, f)
	}
}

// scanValue scans the JSON form of a returned value.
func (r *run) scanValue(what string, v any) {
	if r.c.Expect.LeakScan == nil {
		return
	}
	r.scanText(what, jsonText(v))
}

// scanError scans an error's text, which includes the text of everything it
// wraps.
func (r *run) scanError(what string, err error) {
	if err == nil || r.c.Expect.LeakScan == nil {
		return
	}
	r.scanText(what+" error", err.Error())
}

// scanJWS scans a compact JWS: the string as returned, and its header and
// payload decoded, since a credential inside the payload is base64url text in
// the string itself.
func (r *run) scanJWS(what, jws string) {
	if r.c.Expect.LeakScan == nil {
		return
	}
	// Only literal secrets are looked for in the encoded form; the patterns
	// would match the JWS itself.
	for _, s := range r.c.Expect.LeakScan.Secrets {
		if s != "" && strings.Contains(jws, s) {
			r.failf("%s carries a credential: secret %q", what, s)
		}
	}
	for i, seg := range strings.Split(jws, ".") {
		if i > 1 {
			break
		}
		raw, err := base64.RawURLEncoding.DecodeString(seg)
		if err != nil {
			continue
		}
		r.scanText(fmt.Sprintf("%s segment %d", what, i), string(raw))
	}
}
