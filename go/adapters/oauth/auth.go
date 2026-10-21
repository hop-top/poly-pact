package oauth

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/internal/ascii"
)

// facts are what a validated token establishes, in either form.
type facts struct {
	subject, client string
	scopes          []string
	issuedAt        time.Time
	statusChecked   time.Time
	tokenID         string
	cnf             map[string]string
}

// denial returns a native denial with the public reason.
func denial(reason adapter.DenialReason) error { return &adapter.NativeDenial{Reason: reason} }

var rejected = denial(adapter.DenialCredentialRejected)

// AuthenticateNative authenticates r under the issuer entry of its route.
//
// The checks run in the order of OAUTH-40. A request without the enforcement
// marker is refused before any token is read: NO_CREDENTIAL without an
// Authorization field, CREDENTIAL_REJECTED otherwise. The token comes only
// from a single Authorization field with the scheme Bearer, matched without
// regard to case, or DPoP on an entry whose sender constraint is dpop
// (OAUTH-1); no field, even with a token in the query or the body, and a
// field of another scheme, such as Basic, which RFC 6750 section 3.1 treats as
// a request that lacks authentication information, are NO_CREDENTIAL; two
// fields, a credential that is not a b64token (RFC 6750 section 2.1), or a
// token also in an access_token query or form parameter are
// CREDENTIAL_REJECTED (OAUTH-2). The route's one entry decides
// the form, and a token is never tried under another (OAUTH-6): form I
// introspects it ([Adapter.introspect]), form E verifies it as an Entra ID
// v2.0 JWS ([Adapter.verifyJWT]), form G verifies it as a Google ID token
// ([Adapter.verifyGoogleID]). The sender constraint is then checked
// (OAUTH-34). A source that cannot answer is an error that wraps
// [adapter.ErrDependencyUnavailable], never a denial.
//
// The principal is oauth:{issuer-id}:{tenant}:{subject} and the workload
// oauth:{issuer-id}:{tenant}:{client}, written under IM-2 (OAUTH-37,
// OAUTH-38), in the gateway's realm. The token's facts are reported in the
// attribute [AttrToken] and a cnf in [AttrConfirmation]; the token text is
// never kept (OAUTH-35).
func (a *Adapter) AuthenticateNative(ctx context.Context, r *http.Request) (adapter.Principal, error) {
	if err := live(ctx, "authenticate"); err != nil {
		return adapter.Principal{}, err
	}
	if r == nil || r.URL == nil {
		return adapter.Principal{}, denial(adapter.DenialNoCredential)
	}
	lines := r.Header.Values("Authorization")
	switch {
	case len(lines) == 0:
		return adapter.Principal{}, denial(adapter.DenialNoCredential)
	case !Marked(r):
		return adapter.Principal{}, rejected
	case len(lines) > 1:
		return adapter.Principal{}, rejected
	}
	rt, ok := a.routeOf(r.Method, r.URL.EscapedPath())
	if !ok {
		return adapter.Principal{}, fmt.Errorf("oauth: authenticate: no issuer entry serves %s %s: %w", r.Method, r.URL.EscapedPath(), adapter.ErrUnsupportedRequirement)
	}
	e := a.entries[rt.Entry]
	scheme, token, ok := credentials(lines[0])
	if !ok {
		return adapter.Principal{}, rejected
	}
	switch {
	case ascii.EqualFold(scheme, "Bearer"):
		// RFC 9449 section 7.2: a DPoP-bound token received as a bearer
		// token is rejected; on a dpop entry every token is DPoP-bound.
		if e.SenderConstraint == SenderDPoP {
			return adapter.Principal{}, rejected
		}
	case ascii.EqualFold(scheme, "DPoP"):
		if e.SenderConstraint != SenderDPoP {
			return adapter.Principal{}, rejected
		}
	default:
		// RFC 6750 section 3.1: an unsupported authentication method is a
		// request that lacks authentication information (OAUTH-1).
		return adapter.Principal{}, denial(adapter.DenialNoCredential)
	}
	other, err := otherCarriage(r)
	if err != nil {
		return adapter.Principal{}, fmt.Errorf("oauth: authenticate: the body cannot be read: %w", adapter.ErrDependencyUnavailable)
	}
	if other {
		return adapter.Principal{}, rejected
	}
	var f facts
	switch e.Form {
	case FormIntrospection:
		f, err = a.introspect(ctx, e, token)
	case FormEntraV2:
		f, err = a.verifyJWT(ctx, e, token)
	case FormGoogleID:
		f, err = a.verifyGoogleID(ctx, e, token)
	}
	if err != nil {
		return adapter.Principal{}, err
	}
	if err := checkSender(e, r, f); err != nil {
		return adapter.Principal{}, err
	}
	return a.principal(e, f), nil
}

// credentials splits an Authorization value into its scheme and a b64token
// (RFC 6750 section 2.1: "Bearer" 1*SP b64token).
func credentials(v string) (scheme, token string, ok bool) {
	scheme, rest, found := strings.Cut(v, " ")
	if !found || scheme == "" {
		return "", "", false
	}
	token = strings.TrimLeft(rest, " ")
	return scheme, token, b64token(token)
}

// b64token reports whether s matches 1*( ALPHA / DIGIT / "-" / "." / "_" /
// "~" / "+" / "/" ) *"=".
func b64token(s string) bool {
	body := strings.TrimRight(s, "=")
	if body == "" {
		return false
	}
	for i := 0; i < len(body); i++ {
		c := body[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '-', c == '.', c == '_', c == '~', c == '+', c == '/':
		default:
			return false
		}
	}
	return true
}

// otherCarriage reports whether the request also carries an access_token in
// the query or in an application/x-www-form-urlencoded body (OAUTH-2). The
// body is read up to maxBody and put back for the next reader.
func otherCarriage(r *http.Request) (bool, error) {
	if hasAccessToken(r.URL.RawQuery) {
		return true, nil
	}
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mt != "application/x-www-form-urlencoded" || r.Body == nil || r.Body == http.NoBody {
		return false, nil
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	_ = r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(body))
	if err != nil {
		return false, err
	}
	return hasAccessToken(string(body)), nil
}

// hasAccessToken reports whether a form-encoded string has a parameter named
// access_token, however its name is escaped.
func hasAccessToken(s string) bool {
	for _, pair := range strings.Split(s, "&") {
		name, _, _ := strings.Cut(pair, "=")
		if n, err := url.QueryUnescape(name); err == nil && n == "access_token" || name == "access_token" {
			return true
		}
	}
	return false
}

// checkSender applies the entry's sender constraint (OAUTH-34).
func checkSender(e *entry, r *http.Request, f facts) error {
	switch e.SenderConstraint {
	case SenderNone:
		if f.cnf != nil {
			return rejected
		}
	case SenderDPoP:
		if f.cnf["jkt"] == "" || senderProof(r) != SenderDPoP {
			return rejected
		}
	case SenderMTLS:
		if f.cnf["x5t#S256"] == "" || senderProof(r) != SenderMTLS {
			return rejected
		}
	}
	return nil
}

// principal builds the authenticated principal of a token's facts.
func (a *Adapter) principal(e *entry, f facts) adapter.Principal {
	tok := map[string]any{
		"entry": e.ID, "form": string(e.Form), "tenant": e.Tenant, "scopes": slices.Clone(f.scopes),
	}
	if !f.issuedAt.IsZero() {
		tok["issued_at"] = f.issuedAt.Unix()
	}
	if !f.statusChecked.IsZero() {
		tok["status_checked_at"] = f.statusChecked.Unix()
	}
	if f.tokenID != "" {
		tok["token_id"] = f.tokenID
	}
	attrs := map[string]any{AttrToken: tok}
	if f.cnf != nil {
		c := map[string]any{}
		for k, v := range f.cnf {
			c[k] = v
		}
		attrs[AttrConfirmation] = c
	}
	return adapter.Principal{
		ID:              Identifier(e.Issuer, e.Tenant, f.subject),
		Realm:           a.cfg.Realm,
		Workload:        adapter.Workload(Identifier(e.Issuer, e.Tenant, f.client)),
		Mechanism:       Mechanism,
		AuthenticatedAt: a.cfg.Clock.Now(),
		Attributes:      attrs,
	}
}

// Identifier is oauth:{issuer-id}:{tenant}:{local} with each component
// written under IM-2: every octet that is not unreserved as %XX in upper case.
func Identifier(issuer, tenant, local string) string {
	return "oauth:" + component(issuer) + ":" + component(tenant) + ":" + component(local)
}

func component(s string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '.', c == '_', c == '~':
			b.WriteByte(c)
		default:
			b.WriteByte('%')
			b.WriteByte(hex[c>>4])
			b.WriteByte(hex[c&15])
		}
	}
	return b.String()
}

// scopeList parses a space-delimited scope value (RFC 6749 section 3.3,
// OAUTH-14): single spaces between scope-tokens of %x21 / %x23-5B / %x5D-7E,
// no empty token and no repeated token.
func scopeList(s string) ([]string, bool) {
	if s == "" {
		return nil, false
	}
	parts := strings.Split(s, " ")
	for i, p := range parts {
		if p == "" || slices.Contains(parts[:i], p) {
			return nil, false
		}
		for j := 0; j < len(p); j++ {
			c := p[j]
			if c < 0x21 || c == 0x22 || c == 0x5C || c > 0x7E {
				return nil, false
			}
		}
	}
	return parts, true
}

// errUnusable marks a source answer the adapter cannot use (OAUTH-9).
var errUnusable = errors.New("oauth: unusable answer")
