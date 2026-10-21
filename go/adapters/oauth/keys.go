package oauth

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"slices"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/core/strictjson"
)

// keySet is a key set of a form E entry with the instant of the successful
// fetch that produced it.
type keySet struct {
	fetched time.Time
	members []member
	// header is the HTTP header of the key-set response, and expires the end
	// of its freshness, which only form G reads (OAUTH-43).
	header  http.Header
	expires time.Time
}

// member is one JWK of a key set, as received.
type member struct {
	kid, kty, use, alg, issuer string
	pub                        *rsa.PublicKey
}

// RefreshKeys fetches the key set of the form E entry id now, through its
// discovery document, and holds it on success (OAUTH-23, OAUTH-24). A gateway
// calls it every K, or at start; AuthenticateNative also refreshes on its own.
func (a *Adapter) RefreshKeys(ctx context.Context, id string) error {
	e, ok := a.entries[id]
	if !ok || e.Form != FormEntraV2 && e.Form != FormGoogleID {
		return fmt.Errorf("oauth: %q is not a form E or form G entry", id)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return a.refreshLocked(ctx, e)
}

// refreshLocked fetches the key set; e.mu is held.
func (a *Adapter) refreshLocked(ctx context.Context, e *entry) error {
	now := a.cfg.Clock.Now()
	e.lastFetch = now
	ks, err := a.fetchKeys(ctx, e)
	if err != nil {
		return fmt.Errorf("oauth: key set of entry %s: %w", e.ID, adapter.ErrDependencyUnavailable)
	}
	ks.fetched = now
	if e.Form == FormGoogleID {
		ks.expires = now.Add(freshFor(ks.header, now, e.KeyRefresh, e.KeyMaxAge))
	}
	e.keys = ks
	return nil
}

// keyFor returns the RSA key of kid from the entry's key set.
//
// A key set is refreshed when it is K old; while refreshes fail, a held set
// is used until it is T old, and then the result is DEFERRED. A kid the held
// set lacks triggers a fetch at most once every 300 seconds; a kid still
// unknown after a successful fetch is a native denial, and a failed fetch for
// it is DEFERRED (OAUTH-24). Two members with the kid, a member that is not an
// RSA signing key of at least 2048 bits, and a member whose issuer property
// differs from the entry's issuer are native denials (OAUTH-22).
func (a *Adapter) keyFor(ctx context.Context, e *entry, kid string) (*rsa.PublicKey, error) {
	if e.Form == FormGoogleID {
		return a.googleKeyFor(ctx, e, kid)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	now := a.cfg.Clock.Now()
	if e.keys == nil || now.Sub(e.keys.fetched) >= e.KeyRefresh {
		if err := a.refreshLocked(ctx, e); err != nil && (e.keys == nil || now.Sub(e.keys.fetched) > e.KeyMaxAge) {
			return nil, err
		}
	}
	if now.Sub(e.keys.fetched) > e.KeyMaxAge {
		return nil, fmt.Errorf("oauth: key set of entry %s is older than its bound: %w", e.ID, adapter.ErrDependencyUnavailable)
	}
	m, n := e.keys.lookup(kid)
	if n == 0 && now.Sub(e.lastFetch) >= UnknownKeyRefetch {
		if err := a.refreshLocked(ctx, e); err != nil {
			return nil, err
		}
		m, n = e.keys.lookup(kid)
	}
	if n != 1 {
		return nil, rejected
	}
	if m.kty != "RSA" || m.use != "" && m.use != "sig" || m.issuer != "" && m.issuer != e.Issuer ||
		m.pub == nil || m.pub.N.BitLen() < minRSABits {
		return nil, rejected
	}
	return m.pub, nil
}

// lookup returns the member with kid, compared as case-sensitive strings, and
// how many members have it.
func (ks *keySet) lookup(kid string) (member, int) {
	var found member
	n := 0
	for _, m := range ks.members {
		if m.kid == kid {
			found = m
			n++
		}
	}
	return found, n
}

// fetchKeys reads the entry's discovery document from the issuer identifier
// followed by /.well-known/openid-configuration, uses it only when its issuer
// is the entry's issuer exactly, and reads the key set at its jwks_uri, which
// must be https within the trusted origins (OAUTH-23).
func (a *Adapter) fetchKeys(ctx context.Context, e *entry) (*keySet, error) {
	doc, err := a.get(ctx, e.Issuer+"/.well-known/openid-configuration")
	if err != nil {
		return nil, err
	}
	var d map[string]json.RawMessage
	if err := strictjson.Unmarshal(doc, strictjson.Limits{}, &d); err != nil {
		return nil, errUnusable
	}
	var issuer, jwksURI string
	if strictString(d["issuer"], &issuer) != nil || issuer != e.Issuer {
		return nil, errUnusable
	}
	if strictString(d["jwks_uri"], &jwksURI) != nil {
		return nil, errUnusable
	}
	u, err := url.Parse(jwksURI)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil ||
		!slices.Contains(e.TrustedOrigins, u.Scheme+"://"+u.Host) {
		return nil, errUnusable
	}
	body, header, err := a.getHeader(ctx, jwksURI)
	if err != nil {
		return nil, err
	}
	var set map[string]json.RawMessage
	if err := strictjson.Unmarshal(body, strictjson.Limits{}, &set); err != nil {
		return nil, errUnusable
	}
	var keys []map[string]json.RawMessage
	if err := json.Unmarshal(set["keys"], &keys); err != nil || keys == nil {
		return nil, errUnusable
	}
	ks := &keySet{header: header}
	for _, k := range keys {
		var m member
		_ = strictString(k["kid"], &m.kid)
		_ = strictString(k["kty"], &m.kty)
		_ = strictString(k["use"], &m.use)
		_ = strictString(k["issuer"], &m.issuer)
		if raw, ok := k["alg"]; ok && strictString(raw, &m.alg) != nil {
			m.alg = "?"
		}
		if m.kty == "RSA" {
			m.pub = rsaKey(k["n"], k["e"])
		}
		ks.members = append(ks.members, m)
	}
	return ks, nil
}

// rsaKey decodes the n and e members of an RSA JWK (RFC 7518 section 6.3.1),
// or returns nil.
func rsaKey(nRaw, eRaw json.RawMessage) *rsa.PublicKey {
	var ns, es string
	if strictString(nRaw, &ns) != nil || strictString(eRaw, &es) != nil {
		return nil
	}
	n, err1 := base64.RawURLEncoding.Strict().DecodeString(ns)
	e, err2 := base64.RawURLEncoding.Strict().DecodeString(es)
	if err1 != nil || err2 != nil || len(n) == 0 || n[0] == 0 || len(e) == 0 || len(e) > 4 || e[0] == 0 {
		return nil
	}
	exp := int(new(big.Int).SetBytes(e).Int64())
	if exp < 3 || exp%2 == 0 {
		return nil
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: exp}
}

// get fetches url with GET and returns the body of an HTTP 200 answer.
func (a *Adapter) get(ctx context.Context, target string) ([]byte, error) {
	body, _, err := a.getHeader(ctx, target)
	return body, err
}

// getHeader is get with the header of the answer.
func (a *Adapter) getHeader(ctx context.Context, target string) ([]byte, http.Header, error) {
	ctx, cancel := context.WithTimeout(ctx, a.cfg.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, nil, errUnusable
	}
	req.Header.Set("Accept", "application/json")
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, nil, errUnusable
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, nil, errUnusable
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxAnswer+1))
	if err != nil || len(body) > maxAnswer {
		return nil, nil, errUnusable
	}
	return body, resp.Header, nil
}
