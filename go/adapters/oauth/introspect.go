package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/core/clock"
	"hop.top/pact-go/core/strictjson"
	"hop.top/pact-go/internal/ascii"
)

// maxAnswer bounds an introspection response, a discovery document and a key
// set.
const maxAnswer = 256 << 10

// cached is an introspected answer kept under OAUTH-15: the parsed facts, the
// instant the request that produced them was sent, and the token's exp.
type cached struct {
	f    facts
	sent time.Time
	exp  time.Time
}

// introspect validates an opaque token of a form I entry (profile section C).
//
// The token is sent to the entry's endpoint alone, with POST, the form
// parameters token and token_type_hint=access_token (RFC 7662 section 2.1),
// and the gateway's client credentials in HTTP Basic, each form-urlencoded
// (RFC 6749 section 2.3.1; OAUTH-7, OAUTH-8). An error status, HTTP 401 to the
// gateway, a transport failure, a timeout, and a body that is not one JSON
// object with no duplicate member and members of their RFC 7662 section 2.2
// types are [adapter.ErrDependencyUnavailable] (OAUTH-9). active false, and
// active true without a valid exp, sub, client_id, scope and audience, are
// native denials (OAUTH-10 to OAUTH-17).
func (a *Adapter) introspect(ctx context.Context, e *entry, token string) (facts, error) {
	now := a.cfg.Clock.Now()
	key := sha256.Sum256([]byte(token))
	if e.CacheBound > 0 {
		e.mu.Lock()
		c, ok := e.cache[key]
		e.mu.Unlock()
		if ok && now.Sub(c.sent) <= e.CacheBound && now.Before(c.exp) {
			return c.f, nil
		}
	}
	sent := now
	body, err := a.postIntrospection(ctx, e, token)
	if err != nil {
		return facts{}, fmt.Errorf("oauth: introspection at entry %s: %w", e.ID, adapter.ErrDependencyUnavailable)
	}
	f, exp, err := e.introspected(body, now)
	if err != nil {
		return facts{}, err
	}
	f.statusChecked = sent
	if e.CacheBound > 0 {
		e.mu.Lock()
		for k, c := range e.cache {
			if now.Sub(c.sent) > e.CacheBound || !now.Before(c.exp) {
				delete(e.cache, k)
			}
		}
		e.cache[key] = cached{f: f, sent: sent, exp: exp}
		e.mu.Unlock()
	}
	return f, nil
}

// postIntrospection sends the request and returns the body of an HTTP 200
// answer. Any other outcome is an error; its text never holds the token or
// the answer.
func (a *Adapter) postIntrospection(ctx context.Context, e *entry, token string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, a.cfg.Timeout)
	defer cancel()
	form := url.Values{"token": {token}, "token_type_hint": {"access_token"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.IntrospectionEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, errUnusable
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(url.QueryEscape(e.ClientID), url.QueryEscape(e.ClientSecret))
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, errUnusable
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, errUnusable
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxAnswer+1))
	if err != nil || len(body) > maxAnswer {
		return nil, errUnusable
	}
	return body, nil
}

// introspected applies OAUTH-9 to OAUTH-17 to an answer.
func (e *entry) introspected(body []byte, now time.Time) (facts, time.Time, error) {
	unusable := fmt.Errorf("oauth: introspection at entry %s: unusable answer: %w", e.ID, adapter.ErrDependencyUnavailable)
	var members map[string]json.RawMessage
	if err := strictjson.Unmarshal(body, strictjson.Limits{}, &members); err != nil {
		return facts{}, time.Time{}, unusable
	}
	var r struct {
		active                       *bool
		sub, client, scope, iss, jti *string
		tokenType                    *string
		exp, iat, nbf                *json.Number
		aud                          []string
		audPresent                   bool
		cnf                          map[string]string
		cnfPresent                   bool
	}
	for name, raw := range members {
		var err error
		switch name {
		case "active":
			r.active = new(bool)
			err = json.Unmarshal(raw, r.active)
		case "sub", "client_id", "scope", "iss", "jti", "token_type", "username":
			var s string
			if err = strictString(raw, &s); err == nil {
				switch name {
				case "sub":
					r.sub = &s
				case "client_id":
					r.client = &s
				case "scope":
					r.scope = &s
				case "iss":
					r.iss = &s
				case "jti":
					r.jti = &s
				case "token_type":
					r.tokenType = &s
				}
			}
		case "exp", "iat", "nbf":
			n, nerr := number(raw)
			err = nerr
			switch name {
			case "exp":
				r.exp = n
			case "iat":
				r.iat = n
			case "nbf":
				r.nbf = n
			}
		case "aud":
			r.audPresent = true
			r.aud, err = audience(raw)
		case "cnf":
			r.cnfPresent = true
			r.cnf, err = confirmation(raw)
		}
		if err != nil {
			return facts{}, time.Time{}, unusable
		}
	}
	if r.active == nil {
		return facts{}, time.Time{}, unusable
	}
	if !*r.active {
		return facts{}, time.Time{}, rejected
	}
	exp, okExp := unixOf(r.exp)
	if r.exp == nil || !okExp || r.sub == nil || *r.sub == "" || r.client == nil || *r.client == "" || r.scope == nil {
		return facts{}, time.Time{}, rejected
	}
	scopes, ok := scopeList(*r.scope)
	if !ok {
		return facts{}, time.Time{}, rejected
	}
	if !slices.Contains(e.Clients, *r.client) {
		return facts{}, time.Time{}, rejected
	}
	if r.iss != nil && *r.iss != e.Issuer {
		return facts{}, time.Time{}, rejected
	}
	if r.tokenType != nil && !ascii.EqualFold(*r.tokenType, "Bearer") &&
		(e.SenderConstraint != SenderDPoP || !ascii.EqualFold(*r.tokenType, "DPoP")) {
		return facts{}, time.Time{}, rejected
	}
	switch {
	case r.audPresent && !anyOf(r.aud, e.Audiences):
		// RFC 9700 section 2.3: refused even on an introspection-scoped entry.
		return facts{}, time.Time{}, rejected
	case !r.audPresent && e.Binding != BindingIntrospectionScoped:
		return facts{}, time.Time{}, rejected
	}
	var iat, nbf int64
	var issued time.Time
	if r.iat != nil {
		t, ok := unixOf(r.iat)
		if !ok {
			return facts{}, time.Time{}, rejected
		}
		iat, issued = t.Unix(), t
		if exp.Sub(t) > e.Lifetime {
			return facts{}, time.Time{}, rejected
		}
	}
	if r.nbf != nil {
		t, ok := unixOf(r.nbf)
		if !ok {
			return facts{}, time.Time{}, rejected
		}
		nbf = t.Unix()
	}
	if clock.CheckWindow(iat, nbf, exp.Unix(), now, clock.BaselineSkew) != nil {
		return facts{}, time.Time{}, rejected
	}
	if r.cnfPresent && r.cnf == nil {
		return facts{}, time.Time{}, rejected
	}
	f := facts{subject: *r.sub, client: *r.client, scopes: scopes, issuedAt: issued, cnf: r.cnf}
	if r.jti != nil {
		f.tokenID = *r.jti
	}
	return f, exp, nil
}

// strictString decodes a JSON string.
func strictString(raw json.RawMessage, s *string) error {
	if len(raw) == 0 || raw[0] != '"' {
		return errUnusable
	}
	return json.Unmarshal(raw, s)
}

// number decodes a JSON number, keeping its text.
func number(raw json.RawMessage) (*json.Number, error) {
	if len(raw) == 0 || raw[0] != '-' && (raw[0] < '0' || raw[0] > '9') {
		return nil, errUnusable
	}
	n := json.Number(raw)
	return &n, nil
}

// unixOf reads a NumericDate that is an integer within 0 to 2^53-1.
func unixOf(n *json.Number) (time.Time, bool) {
	if n == nil {
		return time.Time{}, false
	}
	v, err := n.Int64()
	if err != nil || v < 0 || v > strictjson.MaxSafeInteger {
		return time.Time{}, false
	}
	return time.Unix(v, 0), true
}

// audience decodes aud, a string or an array of strings.
func audience(raw json.RawMessage) ([]string, error) {
	var s string
	if strictString(raw, &s) == nil {
		return []string{s}, nil
	}
	var list []string
	if len(raw) == 0 || raw[0] != '[' {
		return nil, errUnusable
	}
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, errUnusable
	}
	return list, nil
}

// confirmation decodes cnf: an object whose jkt and x5t#S256 members, when
// present, are non-empty strings (RFC 7800 section 3.1, RFC 9449 section 6,
// RFC 8705 section 3). Nil means a cnf of no confirmation method this
// profile reads, which no sender constraint accepts.
func confirmation(raw json.RawMessage) (map[string]string, error) {
	if len(raw) == 0 || raw[0] != '{' {
		return nil, errUnusable
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, errUnusable
	}
	out := map[string]string{}
	for _, k := range []string{"jkt", "x5t#S256"} {
		v, ok := m[k]
		if !ok {
			continue
		}
		var s string
		if strictString(v, &s) != nil || s == "" {
			return nil, nil
		}
		out[k] = s
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// anyOf reports whether some value of got is in want.
func anyOf(got, want []string) bool {
	for _, g := range got {
		if slices.Contains(want, g) {
			return true
		}
	}
	return false
}
