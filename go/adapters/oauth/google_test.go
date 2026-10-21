package oauth_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"slices"
	"sync"
	"testing"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapters/memory"
	"hop.top/pact-go/adapters/oauth"
	"hop.top/pact-go/core/clock"
)

const (
	gIssuer   = "https://accounts.google.com"
	gDisc     = gIssuer + "/.well-known/openid-configuration"
	gJWKS     = "https://www.googleapis.com/oauth2/v3/certs"
	gHD       = "corp.acme.example"
	gClient   = "412038750493-q7r2m9k4v1x8c3b6n0d5f2h7j9l1p3s4.apps.googleusercontent.com"
	gSubject  = "104837201958362914057"
	gPrincipl = "oauth:https%3A%2F%2Faccounts.google.com:corp.acme.example:104837201958362914057"
)

// googleServer is Google's discovery document and key set for one RSA key,
// with the Cache-Control of the key set the test sets.
type googleServer struct {
	key          *rsa.PrivateKey
	kid          string
	mu           sync.Mutex
	cacheControl string
	// alg is the JSON text of the key's alg member; empty is "RS256".
	alg string
}

func (g *googleServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.String() {
	case gDisc:
		_, _ = fmt.Fprintf(w, `{"issuer":%q,"jwks_uri":%q,"id_token_signing_alg_values_supported":["RS256"]}`, gIssuer, gJWKS)
	case gJWKS:
		g.mu.Lock()
		cc := g.cacheControl
		g.mu.Unlock()
		if cc != "" {
			w.Header().Set("Cache-Control", cc)
		}
		n := base64.RawURLEncoding.EncodeToString(g.key.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(g.key.E)).Bytes())
		alg := g.alg
		if alg == "" {
			alg = `"RS256"`
		}
		_, _ = fmt.Fprintf(w, `{"keys":[{"kty":"RSA","use":"sig","alg":%s,"kid":%q,"n":%q,"e":%q}]}`, alg, g.kid, n, e)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func googleEntry(id, hd string) oauth.Entry {
	return oauth.Entry{ID: id, Form: oauth.FormGoogleID, Issuer: oauth.GoogleIssuer, Tenant: hd,
		Audiences: []string{gClient}, Clients: []string{gClient}}
}

func googleToken(t *testing.T, key *rsa.PrivateKey, kid string, at time.Time, hd string) string {
	t.Helper()
	return signRS256(t, key, map[string]any{"alg": "RS256", "kid": kid, "typ": "JWT"}, map[string]any{
		"iss": gIssuer, "aud": gClient, "azp": gClient, "sub": gSubject, "hd": hd, "email": "alice@" + hd,
		"iat": at.Unix() - 60, "exp": at.Unix() + 3000,
	})
}

// newGoogleAdapter is an adapter over the given entries and routes.
func newGoogleAdapter(t *testing.T, clk clock.Clock, client *http.Client, routes []oauth.Route, entries ...oauth.Entry) *oauth.Adapter {
	t.Helper()
	ref, err := memory.New(memory.State{Model: memory.Model, Gateway: memory.Gateway{
		TenantID: "acme", EnvironmentID: "env", Origin: "https://gateway.acme.example", HeaderAllowlist: []string{},
	}}, clk)
	if err != nil {
		t.Fatal(err)
	}
	a, err := oauth.New(oauth.Config{
		Realm: adapter.Realm{TenantID: "acme", EnvironmentID: "env"}, Entries: entries, Routes: routes,
		DefaultEntry: entries[0].ID, HTTPClient: client, Origin: "https://gateway.acme.example",
		Registry: referenceRegistry{ref}, Permissions: commonPolicy{}, Clock: clk,
	})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// TestGoogleKeyCacheFollowsMaxAge: the key set is used while its age is below
// the max-age of the response and fetched again at the age equal to it (OAUTH-43;
// RFC 9111 section 4.2: fresh while the freshness lifetime exceeds the age).
func TestGoogleKeyCacheFollowsMaxAge(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	srv := &googleServer{key: key, kid: "k1", cacheControl: "public, max-age=600, must-revalidate"}
	tr := &handlerTransport{h: srv}
	start := time.Unix(tNow, 0)
	clk := clock.NewFake(start)
	a := newGoogleAdapter(t, clk, &http.Client{Transport: tr}, nil, googleEntry("G1", gHD))
	if err := a.RefreshKeys(context.Background(), "G1"); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		at   time.Duration
		want int
	}{{599 * time.Second, 1}, {600 * time.Second, 2}, {1199 * time.Second, 2}, {1200 * time.Second, 3}} {
		clk.Set(start.Add(tc.at))
		p, err := a.AuthenticateNative(context.Background(), bearer(t, googleToken(t, key, "k1", clk.Now(), gHD)))
		if err != nil {
			t.Fatalf("at +%v: %v", tc.at, err)
		}
		if p.ID != gPrincipl {
			t.Fatalf("principal %q, want %q", p.ID, gPrincipl)
		}
		if n := tr.count(gJWKS); n != tc.want {
			t.Errorf("at +%v: %d key-set fetches, want %d", tc.at, n, tc.want)
		}
	}
}

// TestGoogleNoStaleKeyOnFailure: a key set past its max-age is not used when
// the fetch fails, even though its key verifies the token (OAUTH-43; RFC 9111
// section 4.2.4).
func TestGoogleNoStaleKeyOnFailure(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	srv := &googleServer{key: key, kid: "k1", cacheControl: "max-age=600"}
	down := false
	var mu sync.Mutex
	tr := &handlerTransport{h: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		d := down
		mu.Unlock()
		if d {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		srv.ServeHTTP(w, r)
	})}
	start := time.Unix(tNow, 0)
	clk := clock.NewFake(start)
	a := newGoogleAdapter(t, clk, &http.Client{Transport: tr}, nil, googleEntry("G1", gHD))
	if err := a.RefreshKeys(context.Background(), "G1"); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	down = true
	mu.Unlock()
	clk.Set(start.Add(599 * time.Second))
	if _, err := a.AuthenticateNative(context.Background(), bearer(t, googleToken(t, key, "k1", clk.Now(), gHD))); err != nil {
		t.Fatalf("a fresh key set is refused while the source is down: %v", err)
	}
	clk.Set(start.Add(601 * time.Second))
	_, err = a.AuthenticateNative(context.Background(), bearer(t, googleToken(t, key, "k1", clk.Now(), gHD)))
	if !errors.Is(err, adapter.ErrDependencyUnavailable) {
		t.Fatalf("a stale key set with the source down: %v, want DEPENDENCY_UNAVAILABLE", err)
	}
}

// TestGoogleDefaultLifetime: the reference L of a form G entry is the
// 3900 seconds of the example token on Google's page: a token of that
// lifetime authenticates and one second more does not (OAUTH-47).
func TestGoogleDefaultLifetime(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tr := &handlerTransport{h: &googleServer{key: key, kid: "k1", cacheControl: "max-age=600"}}
	clk := clock.NewFake(time.Unix(tNow, 0))
	a := newGoogleAdapter(t, clk, &http.Client{Transport: tr}, nil, googleEntry("G1", gHD))
	if oauth.DefaultLifetimeGoogle != 3900*time.Second {
		t.Fatalf("DefaultLifetimeGoogle = %v", oauth.DefaultLifetimeGoogle)
	}
	for _, tc := range []struct {
		life int64
		ok   bool
	}{{3900, true}, {3901, false}} {
		iat := int64(tNow - 60)
		tok := signRS256(t, key, map[string]any{"alg": "RS256", "kid": "k1"}, map[string]any{
			"iss": gIssuer, "aud": gClient, "sub": gSubject, "hd": gHD, "iat": iat, "exp": iat + tc.life,
		})
		_, err := a.AuthenticateNative(context.Background(), bearer(t, tok))
		if (err == nil) != tc.ok {
			t.Errorf("lifetime %d: %v", tc.life, err)
		}
	}
}

// TestGoogleKeyAlgMember: a key whose alg member is not a string, or is not
// RS256, does not verify an RS256 token (OAUTH-42; RFC 7517 section 4.4).
func TestGoogleKeyAlgMember(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for _, alg := range []string{`5`, `["RS256"]`, `"PS256"`, `"rs256"`, `null`} {
		tr := &handlerTransport{h: &googleServer{key: key, kid: "k1", cacheControl: "max-age=600", alg: alg}}
		clk := clock.NewFake(time.Unix(tNow, 0))
		a := newGoogleAdapter(t, clk, &http.Client{Transport: tr}, nil, googleEntry("G1", gHD))
		_, err := a.AuthenticateNative(context.Background(), bearer(t, googleToken(t, key, "k1", clk.Now(), gHD)))
		var nd *adapter.NativeDenial
		if !errors.As(err, &nd) {
			t.Errorf("a key with alg %s verified the token: %v", alg, err)
		}
	}
}

// TestGoogleRouteNamesOneEntry: a token refused under the route's entry is not
// tried under another entry of the same issuer (OAUTH-6).
func TestGoogleRouteNamesOneEntry(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tr := &handlerTransport{h: &googleServer{key: key, kid: "k1", cacheControl: "max-age=600"}}
	clk := clock.NewFake(time.Unix(tNow, 0))
	routes := []oauth.Route{
		{Method: http.MethodGet, Path: "/customers/{customer_id}", Entry: "G1"},
		{Method: http.MethodGet, Path: "/other", Entry: "G2"},
	}
	a := newGoogleAdapter(t, clk, &http.Client{Transport: tr}, routes, googleEntry("G1", gHD), googleEntry("G2", "other.example"))
	_, err = a.AuthenticateNative(context.Background(), bearer(t, googleToken(t, key, "k1", clk.Now(), "other.example")))
	var nd *adapter.NativeDenial
	if !errors.As(err, &nd) || nd.Reason != adapter.DenialCredentialRejected {
		t.Fatalf("a token of the other domain under the first entry: %v", err)
	}
	if n := tr.count(gJWKS); n != 1 {
		t.Errorf("%d key-set fetches, want the one of the route's entry", n)
	}
}

// TestGoogleConfigRefused: the entry rules of OAUTH-41.
func TestGoogleConfigRefused(t *testing.T) {
	clk := clock.NewFake(time.Unix(tNow, 0))
	base := func() oauth.Config {
		ref, _ := memory.New(memory.State{Model: memory.Model, Gateway: memory.Gateway{
			TenantID: "acme", EnvironmentID: "env", Origin: "https://gateway.acme.example", HeaderAllowlist: []string{},
		}}, clk)
		return oauth.Config{Realm: adapter.Realm{TenantID: "acme", EnvironmentID: "env"}, Entries: []oauth.Entry{googleEntry("G1", gHD)},
			Origin: "https://gateway.acme.example", Registry: referenceRegistry{ref}, Permissions: commonPolicy{}, Clock: clk}
	}
	for name, mutate := range map[string]func(*oauth.Config){
		"other issuer":         func(c *oauth.Config) { c.Entries[0].Issuer = "https://accounts.google.com/" },
		"issuer without https": func(c *oauth.Config) { c.Entries[0].Issuer = "accounts.google.com" },
		"no hosted domain":     func(c *oauth.Config) { c.Entries[0].Tenant = "" },
		"domain with a colon":  func(c *oauth.Config) { c.Entries[0].Tenant = "corp:acme" },
		"no audience":          func(c *oauth.Config) { c.Entries[0].Audiences = nil },
		"no clients":           func(c *oauth.Config) { c.Entries[0].Clients = nil },
		"dpop":                 func(c *oauth.Config) { c.Entries[0].SenderConstraint = oauth.SenderDPoP },
		"HS256 allowed":        func(c *oauth.Config) { c.Entries[0].Algorithms = []string{"RS256", "HS256"} },
		"K above T":            func(c *oauth.Config) { c.Entries[0].KeyRefresh, c.Entries[0].KeyMaxAge = 2*time.Hour, time.Hour },
		"scope on the route": func(c *oauth.Config) {
			c.Routes = []oauth.Route{{Method: http.MethodGet, Path: "/x", Entry: "G1", Scope: "files.read"}}
		},
	} {
		cfg := base()
		mutate(&cfg)
		if _, err := oauth.New(cfg); err == nil {
			t.Errorf("%s: New accepted the configuration", name)
		}
	}
	cfg := base()
	cfg.Routes = []oauth.Route{{Method: http.MethodGet, Path: "/x", Entry: "G1"}}
	if _, err := oauth.New(cfg); err != nil {
		t.Fatalf("the base configuration is refused: %v", err)
	}
}

// TestGoogleDescriptors: the third form has its own descriptor.
func TestGoogleDescriptors(t *testing.T) {
	clk := clock.NewFake(time.Unix(tNow, 0))
	entra := oauth.Entry{ID: "E2", Form: oauth.FormEntraV2, Issuer: entraIssuer, Tenant: tenantID,
		Audiences: []string{apiID}, Clients: []string{clientID}}
	a := newGoogleAdapter(t, clk, nil, nil, formIEntry(0), entra, googleEntry("G1", gHD))
	want := adapter.Descriptor{Protocol: "google-id-token", Version: "oidc-core-1.0", MappingRevision: "pact-oauth-1"}
	got := a.Descriptors()
	if len(got) != 3 || got[2] != want {
		t.Errorf("Descriptors() = %v, want the third to be %v", got, want)
	}
	if !slices.Contains(adapter.DescriptorsOf(a), want) {
		t.Errorf("DescriptorsOf = %v lacks the Google descriptor", adapter.DescriptorsOf(a))
	}
}
