package oauth

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"hop.top/pact-go/core/clock"
	"hop.top/pact-go/core/strictjson"
	"hop.top/pact-go/internal/ascii"
)

// maxSubject is the longest sub Google documents: "Maximum length of 255
// case-sensitive ASCII characters" (Google Identity, OpenID Connect, ID token
// claims).
const maxSubject = 255

// verifyGoogleID validates a Google ID token of a form G entry (profile
// section H).
//
// The token is a compact JWS of three segments, read before any key is
// fetched (OAUTH-42). Its header has an alg of the entry's allowlist (RS256),
// a kid, no crit, and a typ that is absent or JWT; jku, x5u, jwk and x5c are
// ignored and never fetched (RFC 8725 sections 3.1, 3.10, 3.11). The key is
// the member of the entry's key set with that kid ([Adapter.googleKeyFor]),
// and the signature is verified before any claim is read (OAUTH-25). The
// claims then need iss of the two documented spellings, an accepted aud, the
// entry's hd, exp and iat inside draft 7.5 with a lifetime of at most L, a
// sub of at most 255 ASCII characters, and a client of the allowlist
// (OAUTH-44 to OAUTH-48). Every failure is a native denial; a key set that
// cannot be had is [adapter.ErrDependencyUnavailable] (OAUTH-43).
func (a *Adapter) verifyGoogleID(ctx context.Context, e *entry, token string) (facts, error) {
	if len(token) > maxToken {
		return facts{}, rejected
	}
	segs := strings.Split(token, ".")
	if len(segs) != 3 {
		return facts{}, rejected
	}
	h, ok := parseHeader(segs[0])
	if !ok || h.crit || h.kid == "" || !slices.Contains(e.Algorithms, h.alg) || h.hasTyp && h.typ != "JWT" {
		return facts{}, rejected
	}
	sig, err := base64.RawURLEncoding.Strict().DecodeString(segs[2])
	if err != nil || len(sig) == 0 {
		return facts{}, rejected
	}
	pub, err := a.googleKeyFor(ctx, e, h.kid)
	if err != nil {
		return facts{}, err
	}
	if err := verifyRS256(pub, segs[0]+"."+segs[1], sig); err != nil {
		return facts{}, rejected
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(segs[1])
	if err != nil {
		return facts{}, rejected
	}
	return e.googleClaims(payload, a.cfg.Clock.Now())
}

// googleKeyFor returns the RSA key of kid from the key set of a form G entry
// (OAUTH-42, OAUTH-43).
//
// A key set is used while it is fresh under the HTTP cache headers of the
// response that carried it ([freshFor]); once it is not, it is fetched again,
// and when that fails the result is DEFERRED: a stale key set is never used
// (RFC 9111 section 4.2.4). A kid the fresh set lacks triggers a fetch at most
// once every 300 seconds; a kid still unknown after a successful fetch is a
// native denial. Two members with the kid, and a member that is not an RSA
// signing key of at least 2048 bits, with an alg other than RS256 when it
// names one, or with another issuer when it names one, are native denials.
func (a *Adapter) googleKeyFor(ctx context.Context, e *entry, kid string) (*rsa.PublicKey, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := a.cfg.Clock.Now()
	fetched := false
	if e.keys == nil || !now.Before(e.keys.expires) {
		if err := a.refreshLocked(ctx, e); err != nil {
			return nil, err
		}
		fetched = true
	}
	m, n := e.keys.lookup(kid)
	if n == 0 && !fetched && now.Sub(e.lastFetch) >= UnknownKeyRefetch {
		if err := a.refreshLocked(ctx, e); err != nil {
			return nil, err
		}
		m, n = e.keys.lookup(kid)
	}
	if n != 1 {
		return nil, rejected
	}
	if m.kty != "RSA" || m.use != "" && m.use != "sig" || m.alg != "" && m.alg != algRS256 ||
		m.issuer != "" && m.issuer != e.Issuer || m.pub == nil || m.pub.N.BitLen() < minRSABits {
		return nil, rejected
	}
	return m.pub, nil
}

// googleClaims applies the claim rules of section H to a verified payload.
func (e *entry) googleClaims(payload []byte, now time.Time) (facts, error) {
	var m map[string]json.RawMessage
	if strictjson.Unmarshal(payload, strictjson.Limits{}, &m) != nil {
		return facts{}, rejected
	}
	str := func(name string) (string, bool) {
		v, ok := m[name]
		if !ok {
			return "", false
		}
		var s string
		if strictString(v, &s) != nil {
			return "", false
		}
		return s, true
	}
	num := func(name string) (int64, bool) {
		v, ok := m[name]
		if !ok {
			return 0, false
		}
		n, err := number(v)
		if err != nil {
			return 0, false
		}
		t, ok := unixOf(n)
		return t.Unix(), ok
	}
	if iss, ok := str("iss"); !ok || iss != GoogleIssuer && iss != "accounts.google.com" {
		return facts{}, rejected
	}
	if aud, ok := str("aud"); !ok || !slices.Contains(e.Audiences, aud) {
		return facts{}, rejected
	}
	if hd, ok := str("hd"); !ok || hd != e.Tenant {
		return facts{}, rejected
	}
	exp, okE := num("exp")
	iat, okI := num("iat")
	nbf := iat
	if _, has := m["nbf"]; has {
		var okN bool
		if nbf, okN = num("nbf"); !okN {
			return facts{}, rejected
		}
	}
	if !okE || !okI || exp <= iat || clock.CheckWindow(iat, nbf, exp, now, clock.BaselineSkew) != nil {
		return facts{}, rejected
	}
	if time.Duration(exp-iat)*time.Second > e.Lifetime {
		return facts{}, rejected
	}
	sub, ok := str("sub")
	if !ok || !subjectText(sub) {
		return facts{}, rejected
	}
	client, _ := str("aud")
	if _, has := m["azp"]; has {
		if client, ok = str("azp"); !ok {
			return facts{}, rejected
		}
	}
	if !slices.Contains(e.Clients, client) {
		return facts{}, rejected
	}
	f := facts{subject: sub, client: client, scopes: []string{}, issuedAt: time.Unix(iat, 0)}
	if raw, ok := m["cnf"]; ok {
		c, err := confirmation(raw)
		if err != nil || c == nil {
			return facts{}, rejected
		}
		f.cnf = c
	}
	return f, nil
}

// subjectText reports whether s is a sub Google can have issued: 1 to 255
// visible ASCII characters.
func subjectText(s string) bool {
	if s == "" || len(s) > maxSubject {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7E {
			return false
		}
	}
	return true
}

// domainName reports whether s is a domain name of letters, digits, hyphens
// and dots, with no empty, leading-hyphen or trailing-hyphen label.
func domainName(s string) bool {
	if s == "" {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			switch {
			case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-':
			default:
				return false
			}
		}
	}
	return true
}

// freshFor returns for how long, from the receipt of a response, the response
// is fresh under its HTTP cache headers, at least 0 and at most limit (OAUTH-43).
//
// It follows RFC 9111. no-store and no-cache give 0: the response is not
// reused without a new fetch (sections 5.2.2.4, 5.2.2.5). Otherwise the
// freshness lifetime is the max-age directive (5.2.2.1), else Expires minus
// Date, or minus the receipt time when there is no Date (5.3, 4.2.1); s-maxage
// is for shared caches and is not read. Information that is invalid or given
// twice is stale information and gives 0 (4.2.1): a max-age that is not a
// non-negative integer in the token form, two max-age directives, a date that
// does not parse, an Expires of "0". A response with no freshness information
// is fresh for def (heuristic freshness, 4.2.2). The lifetime is bounded by
// limit, and the Age of the response is subtracted from it (4.2.3, 5.1; an
// invalid Age is ignored).
func freshFor(h http.Header, received time.Time, def, limit time.Duration) time.Duration {
	var life time.Duration
	maxAges, hasMaxAge := 0, false
	for _, d := range directives(h.Values("Cache-Control")) {
		name, arg, _ := strings.Cut(d, "=")
		switch ascii.ToLower(strings.TrimSpace(name)) {
		case "no-store", "no-cache":
			return 0
		case "max-age":
			maxAges++
			hasMaxAge = true
			life = deltaSeconds(strings.TrimSpace(arg), limit)
		}
	}
	switch expires := h.Values("Expires"); {
	case maxAges > 1:
		return 0
	case hasMaxAge:
	case len(expires) > 1:
		return 0
	case len(expires) == 1:
		exp, err := http.ParseTime(strings.TrimSpace(expires[0]))
		if err != nil {
			return 0
		}
		date := received
		if v := h.Get("Date"); v != "" {
			if d, err := http.ParseTime(v); err == nil {
				date = d
			}
		}
		life = max(exp.Sub(date), 0)
	default:
		life = def
	}
	life = min(life, limit)
	if age, ok := headerAge(h, limit); ok {
		life -= age
	}
	return max(life, 0)
}

// deltaSeconds parses the delta-seconds of RFC 9111 section 1.2.2: one or more
// digits. A value too large for a duration is the limit; anything else is 0.
func deltaSeconds(s string, limit time.Duration) time.Duration {
	if s == "" {
		return 0
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0
		}
	}
	n, err := strconv.ParseUint(s, 10, 63)
	if err != nil || n > uint64(limit/time.Second) {
		return limit
	}
	return time.Duration(n) * time.Second
}

// headerAge reads the Age field (RFC 9111 section 5.1): the first member of
// a list, a non-negative integer, else ignored.
func headerAge(h http.Header, limit time.Duration) (time.Duration, bool) {
	v := h.Get("Age")
	if v == "" {
		return 0, false
	}
	first, _, _ := strings.Cut(v, ",")
	first = strings.TrimSpace(first)
	for i := 0; i < len(first); i++ {
		if first[i] < '0' || first[i] > '9' {
			return 0, false
		}
	}
	if first == "" {
		return 0, false
	}
	return deltaSeconds(first, limit), true
}

// directives splits the Cache-Control field lines into directives at the
// commas outside quoted strings.
func directives(lines []string) []string {
	var out []string
	for _, line := range lines {
		start, quoted := 0, false
		for i := 0; i < len(line); i++ {
			switch {
			case line[i] == '\\' && quoted:
				i++
			case line[i] == '"':
				quoted = !quoted
			case line[i] == ',' && !quoted:
				out = append(out, strings.TrimSpace(line[start:i]))
				start = i + 1
			}
		}
		out = append(out, strings.TrimSpace(line[start:]))
	}
	return slices.DeleteFunc(out, func(s string) bool { return s == "" })
}
