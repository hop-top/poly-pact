package oauth_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/installed"
	"hop.top/pact-go/adapters/memory"
	"hop.top/pact-go/adapters/oauth"
	"hop.top/pact-go/core/clock"
)

const (
	tNow       = 1792080000
	asIssuer   = "https://as.acme.example"
	asEndpoint = "https://as.acme.example/oauth2/introspect"
	tenantID   = "7c1d0b3a-5e7f-4a53-9a43-2f7d1f0e9b11"
	apiID      = "6e2b8c4d-1a3f-4e5b-9c7d-8f0a1b2c3d4e"
	clientID   = "5d7e9f1a-2b3c-4d5e-8f60-718293a4b5c6"
)

var entraIssuer = "https://login.microsoftonline.com/" + tenantID + "/v2.0"

// handlerTransport serves every request of the adapter with h and counts
// them by URL.
type handlerTransport struct {
	h     http.Handler
	mu    sync.Mutex
	calls map[string]int
}

func (t *handlerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	t.mu.Lock()
	if t.calls == nil {
		t.calls = map[string]int{}
	}
	t.calls[r.URL.String()]++
	t.mu.Unlock()
	rec := httptest.NewRecorder()
	t.h.ServeHTTP(rec, r)
	return rec.Result(), nil
}

func (t *handlerTransport) count(u string) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.calls[u]
}

// formIEntry is an introspection entry with the reference values.
func formIEntry(cache time.Duration) oauth.Entry {
	return oauth.Entry{
		ID: "E1", Form: oauth.FormIntrospection, Issuer: asIssuer, Tenant: "none",
		Audiences: []string{"https://gateway.acme.example"}, Clients: []string{"crm-assistant"},
		IntrospectionEndpoint: asEndpoint, ClientID: "pact-gateway", ClientSecret: "gw-secret",
		CacheBound: cache,
	}
}

func newAdapter(t *testing.T, clk clock.Clock, client *http.Client, entries ...oauth.Entry) *oauth.Adapter {
	t.Helper()
	ref, err := memory.New(memory.State{Model: memory.Model, Gateway: memory.Gateway{
		TenantID: "acme", EnvironmentID: "https://gateway.acme.example/environments/crm",
		Origin: "https://gateway.acme.example", HeaderAllowlist: []string{},
	}}, clk)
	if err != nil {
		t.Fatal(err)
	}
	a, err := oauth.New(oauth.Config{
		Realm:        adapter.Realm{TenantID: "acme", EnvironmentID: "https://gateway.acme.example/environments/crm"},
		Entries:      entries,
		DefaultEntry: entries[0].ID,
		HTTPClient:   client,
		Origin:       "https://gateway.acme.example",
		Registry:     referenceRegistry{ref},
		Permissions:  commonPolicy{},
		Clock:        clk,
	})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func bearer(t *testing.T, token string) *http.Request {
	t.Helper()
	r, err := http.NewRequest(http.MethodGet, "https://gateway.acme.example/customers/C-1042", nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Authorization", "Bearer "+token)
	return oauth.Mark(r)
}

// asServer is an authorization server whose answer for every token is the
// current value of active, with exp at expAt.
type asServer struct {
	mu     sync.Mutex
	active bool
	expAt  int64
}

func (s *asServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.active {
		_, _ = fmt.Fprint(w, `{"active":false}`)
		return
	}
	_, _ = fmt.Fprintf(w, `{"active":true,"sub":"248289761001","client_id":"crm-assistant","scope":"crm.customers.read",`+
		`"aud":"https://gateway.acme.example","iat":%d,"exp":%d}`, tNow-600, s.expAt)
}

// TestIntrospectionCache is profile case OAUTH-08: with C = 0 every
// evaluation introspects; with C > 0 a response is reused while its age is at
// most C and never at or after its exp, so a revoked token stays usable only
// until C passes (OAUTH-15).
func TestIntrospectionCache(t *testing.T) {
	start := time.Unix(tNow, 0)
	t.Run("C=0", func(t *testing.T) {
		as := &asServer{active: true, expAt: tNow + 3000}
		tr := &handlerTransport{h: as}
		clk := clock.NewFake(start)
		a := newAdapter(t, clk, &http.Client{Transport: tr}, formIEntry(0))
		for range 2 {
			if _, err := a.AuthenticateNative(context.Background(), bearer(t, "tok-a")); err != nil {
				t.Fatal(err)
			}
		}
		if n := tr.count(asEndpoint); n != 2 {
			t.Errorf("C = 0: %d introspections for two evaluations, want 2", n)
		}
	})
	t.Run("C=30", func(t *testing.T) {
		as := &asServer{active: true, expAt: tNow + 3000}
		tr := &handlerTransport{h: as}
		clk := clock.NewFake(start)
		a := newAdapter(t, clk, &http.Client{Transport: tr}, formIEntry(30*time.Second))
		auth := func() error {
			_, err := a.AuthenticateNative(context.Background(), bearer(t, "tok-a"))
			return err
		}
		if err := auth(); err != nil {
			t.Fatal(err)
		}
		// Revoked at the authorization server; the cached answer is
		// still inside C.
		as.mu.Lock()
		as.active = false
		as.mu.Unlock()
		clk.Set(start.Add(30 * time.Second))
		if err := auth(); err != nil {
			t.Errorf("a response 30 s old with C = 30 is not reused: %v", err)
		}
		if n := tr.count(asEndpoint); n != 1 {
			t.Errorf("%d introspections inside C, want 1", n)
		}
		clk.Set(start.Add(31 * time.Second))
		if err := auth(); !errors.Is(err, adapter.ErrInvalidProof) {
			t.Errorf("31 s with C = 30: %v, want a denial after a new introspection", err)
		}
		if n := tr.count(asEndpoint); n != 2 {
			t.Errorf("%d introspections after C passed, want 2", n)
		}
	})
	t.Run("at exp", func(t *testing.T) {
		as := &asServer{active: true, expAt: tNow + 20}
		tr := &handlerTransport{h: as}
		clk := clock.NewFake(start)
		a := newAdapter(t, clk, &http.Client{Transport: tr}, formIEntry(30*time.Second))
		if _, err := a.AuthenticateNative(context.Background(), bearer(t, "tok-a")); err != nil {
			t.Fatal(err)
		}
		clk.Set(start.Add(20 * time.Second))
		if _, err := a.AuthenticateNative(context.Background(), bearer(t, "tok-a")); !errors.Is(err, adapter.ErrInvalidProof) {
			t.Errorf("at exp: %v, want a denial", err)
		}
		if n := tr.count(asEndpoint); n != 2 {
			t.Errorf("a cached response was reused at its exp: %d introspections", n)
		}
	})
	t.Run("outage after C", func(t *testing.T) {
		as := &asServer{active: true, expAt: tNow + 3000}
		tr := &handlerTransport{h: as}
		clk := clock.NewFake(start)
		a := newAdapter(t, clk, &http.Client{Transport: tr}, formIEntry(30*time.Second))
		if _, err := a.AuthenticateNative(context.Background(), bearer(t, "tok-a")); err != nil {
			t.Fatal(err)
		}
		tr.h = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) })
		clk.Set(start.Add(31 * time.Second))
		if _, err := a.AuthenticateNative(context.Background(), bearer(t, "tok-a")); !errors.Is(err, adapter.ErrDependencyUnavailable) {
			t.Errorf("a cached response stood in for a failed introspection: %v", err)
		}
	})
}

// TestIntrospectionOverTLS runs the introspection request against a real TLS
// endpoint: with the endpoint's certificate trusted it authenticates, and
// with the default trust store the certificate check fails, which defers
// (RFC 7662 section 4; OAUTH-7, OAUTH-9). The request is a POST of the form
// parameters with the gateway's credentials in HTTP Basic.
func TestIntrospectionOverTLS(t *testing.T) {
	var got struct {
		method, ctype, user, pass, token, hint string
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.method, got.ctype = r.Method, r.Header.Get("Content-Type")
		got.user, got.pass, _ = r.BasicAuth()
		_ = r.ParseForm()
		got.token, got.hint = r.PostForm.Get("token"), r.PostForm.Get("token_type_hint")
		_, _ = fmt.Fprintf(w, `{"active":true,"sub":"s1","client_id":"crm-assistant","scope":"crm.customers.read","aud":"https://gateway.acme.example","exp":%d}`, tNow+600)
	}))
	defer srv.Close()
	e := formIEntry(0)
	e.IntrospectionEndpoint = srv.URL + "/introspect"
	e.ClientID, e.ClientSecret = "pact gateway", "s3cr:t&"
	clk := clock.NewFake(time.Unix(tNow, 0))
	a := newAdapter(t, clk, srv.Client(), e)
	p, err := a.AuthenticateNative(context.Background(), bearer(t, "tok-tls"))
	if err != nil {
		t.Fatal(err)
	}
	if p.ID != oauth.Identifier(asIssuer, "none", "s1") {
		t.Errorf("principal %s", p.ID)
	}
	if got.method != http.MethodPost || got.ctype != "application/x-www-form-urlencoded" || got.token != "tok-tls" || got.hint != "access_token" {
		t.Errorf("introspection request %+v", got)
	}
	// RFC 6749 section 2.3.1: each credential form-urlencoded, then Basic.
	if got.user != url.QueryEscape("pact gateway") || got.pass != url.QueryEscape("s3cr:t&") {
		t.Errorf("Basic credentials %q:%q", got.user, got.pass)
	}
	untrusting := newAdapter(t, clk, nil, e)
	if _, err := untrusting.AuthenticateNative(context.Background(), bearer(t, "tok-tls")); !errors.Is(err, adapter.ErrDependencyUnavailable) {
		t.Errorf("an untrusted server certificate: %v, want DEPENDENCY_UNAVAILABLE", err)
	}
}

// TestNoRedirect: a redirect from the introspection endpoint is not followed
// (OAUTH-7): the answer is not HTTP 200, so the source defers.
func TestNoRedirect(t *testing.T) {
	tr := &handlerTransport{h: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://elsewhere.example/introspect", http.StatusTemporaryRedirect)
	})}
	a := newAdapter(t, clock.NewFake(time.Unix(tNow, 0)), &http.Client{Transport: tr}, formIEntry(0))
	if _, err := a.AuthenticateNative(context.Background(), bearer(t, "tok-a")); !errors.Is(err, adapter.ErrDependencyUnavailable) {
		t.Errorf("redirect: %v", err)
	}
	if tr.count("https://elsewhere.example/introspect") != 0 {
		t.Error("the redirect was followed")
	}
}

// keyServer is Entra ID's tenant discovery document and key set for one RSA
// key.
type keyServer struct {
	key *rsa.PrivateKey
	kid string
}

func (k *keyServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.String() {
	case entraIssuer + "/.well-known/openid-configuration":
		_, _ = fmt.Fprintf(w, `{"issuer":%q,"jwks_uri":"https://login.microsoftonline.com/%s/discovery/v2.0/keys"}`, entraIssuer, tenantID)
	case "https://login.microsoftonline.com/" + tenantID + "/discovery/v2.0/keys":
		n := base64.RawURLEncoding.EncodeToString(k.key.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.key.E)).Bytes())
		_, _ = fmt.Fprintf(w, `{"keys":[{"kty":"RSA","use":"sig","kid":%q,"n":%q,"e":%q,"issuer":%q}]}`, k.kid, n, e, entraIssuer)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func signRS256(t *testing.T, key *rsa.PrivateKey, header, claims map[string]any) string {
	t.Helper()
	h, _ := json.Marshal(header)
	c, _ := json.Marshal(claims)
	input := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(c)
	d := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, d[:])
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// TestKeyRefreshInterval: the key set is fetched again only when it is K old
// (OAUTH-24), and the gateway can fetch it ahead with RefreshKeys.
func TestKeyRefreshInterval(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tr := &handlerTransport{h: &keyServer{key: key, kid: "k1"}}
	start := time.Unix(tNow, 0)
	clk := clock.NewFake(start)
	e := oauth.Entry{ID: "E2", Form: oauth.FormEntraV2, Issuer: entraIssuer, Tenant: tenantID,
		Audiences: []string{apiID}, Clients: []string{clientID}}
	a := newAdapter(t, clk, &http.Client{Transport: tr}, e)
	if err := a.RefreshKeys(context.Background(), "E2"); err != nil {
		t.Fatal(err)
	}
	jwksURL := "https://login.microsoftonline.com/" + tenantID + "/discovery/v2.0/keys"
	token := func(at time.Time) *http.Request {
		tok := signRS256(t, key, map[string]any{"typ": "JWT", "alg": "RS256", "kid": "k1"}, map[string]any{
			"aud": apiID, "iss": entraIssuer, "tid": tenantID, "ver": "2.0", "azp": clientID, "oid": "o1", "scp": "Mail.Read",
			"iat": at.Unix() - 60, "nbf": at.Unix() - 60, "exp": at.Unix() + 600,
		})
		return bearer(t, tok)
	}
	clk.Set(start.Add(oauth.DefaultKeyRefresh - time.Second))
	if _, err := a.AuthenticateNative(context.Background(), token(clk.Now())); err != nil {
		t.Fatal(err)
	}
	if n := tr.count(jwksURL); n != 1 {
		t.Errorf("%d key-set fetches before K, want 1", n)
	}
	clk.Set(start.Add(oauth.DefaultKeyRefresh))
	if _, err := a.AuthenticateNative(context.Background(), token(clk.Now())); err != nil {
		t.Fatal(err)
	}
	if n := tr.count(jwksURL); n != 2 {
		t.Errorf("%d key-set fetches at K, want 2", n)
	}
	if err := a.RefreshKeys(context.Background(), "E1"); err == nil {
		t.Error("RefreshKeys of an unknown entry succeeded")
	}
}

// TestConfigRefused: the configuration rules of OAUTH-5, OAUTH-7, OAUTH-8 and
// OAUTH-21.
func TestConfigRefused(t *testing.T) {
	clk := clock.NewFake(time.Unix(tNow, 0))
	base := func() oauth.Config {
		ref, _ := memory.New(memory.State{Model: memory.Model, Gateway: memory.Gateway{
			TenantID: "acme", EnvironmentID: "env", Origin: "https://gateway.acme.example", HeaderAllowlist: []string{},
		}}, clk)
		return oauth.Config{Realm: adapter.Realm{TenantID: "acme", EnvironmentID: "env"}, Entries: []oauth.Entry{formIEntry(0)},
			Origin: "https://gateway.acme.example", Registry: referenceRegistry{ref}, Permissions: commonPolicy{}, Clock: clk}
	}
	entra := oauth.Entry{ID: "E2", Form: oauth.FormEntraV2, Issuer: entraIssuer, Tenant: tenantID,
		Audiences: []string{apiID}, Clients: []string{clientID}}
	for name, mutate := range map[string]func(*oauth.Config){
		"cleartext endpoint": func(c *oauth.Config) { c.Entries[0].IntrospectionEndpoint = "http://as.acme.example/introspect" },
		"no credentials":     func(c *oauth.Config) { c.Entries[0].ClientSecret = "" },
		"no audience":        func(c *oauth.Config) { c.Entries[0].Audiences = nil },
		"no clients":         func(c *oauth.Config) { c.Entries[0].Clients = nil },
		"unknown form":       func(c *oauth.Config) { c.Entries[0].Form = "jwt" },
		"two entries E1":     func(c *oauth.Config) { c.Entries = append(c.Entries, formIEntry(0)) },
		"route without entry": func(c *oauth.Config) {
			c.Routes = []oauth.Route{{Method: http.MethodGet, Path: "/x", Entry: "E9"}}
		},
		"HS256 allowed": func(c *oauth.Config) {
			e := entra
			e.Algorithms = []string{"RS256", "HS256"}
			c.Entries = []oauth.Entry{e}
		},
		"issuer of another tenant": func(c *oauth.Config) {
			e := entra
			e.Tenant = "0b9e4f62-8d1a-4c3e-b7f5-6a2d9c1e8f30"
			c.Entries = []oauth.Entry{e}
		},
		"token path claimed by a source": func(c *oauth.Config) { c.Claims = map[string]installed.ClaimSource{oauth.PathScopes: nil} },
		"no clock":                       func(c *oauth.Config) { c.Clock = nil },
	} {
		cfg := base()
		mutate(&cfg)
		if _, err := oauth.New(cfg); err == nil {
			t.Errorf("%s: New accepted the configuration", name)
		}
	}
	if _, err := oauth.New(base()); err != nil {
		t.Fatalf("the base configuration is refused: %v", err)
	}
}

// TestDescriptors: one descriptor per form (profile section 1).
func TestDescriptors(t *testing.T) {
	clk := clock.NewFake(time.Unix(tNow, 0))
	entra := oauth.Entry{ID: "E2", Form: oauth.FormEntraV2, Issuer: entraIssuer, Tenant: tenantID,
		Audiences: []string{apiID}, Clients: []string{clientID}}
	a := newAdapter(t, clk, nil, formIEntry(0), entra)
	want := []adapter.Descriptor{
		{Protocol: "oauth-introspection", Version: "rfc7662", MappingRevision: "pact-oauth-1"},
		{Protocol: "entra-access-token", Version: "2.0", MappingRevision: "pact-oauth-1"},
	}
	got := a.Descriptors()
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] || a.Describe() != want[0] {
		t.Errorf("Descriptors() = %v, Describe() = %v", got, a.Describe())
	}
	var _ adapter.MultiDescriber = a
	if got := adapter.DescriptorsOf(a); !slices.Equal(got, want) {
		t.Errorf("DescriptorsOf = %v, want %v, once each", got, want)
	}
}

// TestIdentifierExample: the informative example of OAUTH-37.
func TestIdentifierExample(t *testing.T) {
	const want = "oauth:https%3A%2F%2Flogin.microsoftonline.com%2F7c1d0b3a-5e7f-4a53-9a43-2f7d1f0e9b11%2Fv2.0:" +
		"7c1d0b3a-5e7f-4a53-9a43-2f7d1f0e9b11:3f2a9d54-0c1e-4d7e-8f1a-5b6c7d8e9f01"
	if got := oauth.Identifier(entraIssuer, tenantID, "3f2a9d54-0c1e-4d7e-8f1a-5b6c7d8e9f01"); got != want {
		t.Errorf("Identifier = %s", got)
	}
	if got := oauth.Identifier("a b", "é", "x~y"); got != "oauth:a%20b:%C3%A9:x~y" {
		t.Errorf("Identifier encodes %s", got)
	}
}

// TestMapOperationReference: rows R1 and R2 of mapping revision pact-oauth-1.
func TestMapOperationReference(t *testing.T) {
	clk := clock.NewFake(time.Unix(tNow, 0))
	a := newAdapter(t, clk, nil, formIEntry(0))
	p := adapter.Principal{ID: oauth.Identifier(asIssuer, "none", "s1"),
		Realm: adapter.Realm{TenantID: "acme", EnvironmentID: "https://gateway.acme.example/environments/crm"}}
	for _, tc := range []struct {
		url, action, resource string
		ok                    bool
	}{
		{"https://gateway.acme.example/customers/C-1042", "crm.customer.read", "crm-customer:C-1042", true},
		{"https://gateway.acme.example/mail/messages", "mail.message.list", "mailbox:" + p.ID, true},
		{"https://gateway.acme.example/customers/C_1042", "", "", false},
		{"https://gateway.acme.example/customers/" + strings.Repeat("a", 65), "", "", false},
	} {
		r, _ := http.NewRequest(http.MethodGet, tc.url, nil)
		r.RequestURI = tc.url
		op, err := a.MapOperation(context.Background(), r, p, oauth.MappingRevision)
		if tc.ok != (err == nil) || err == nil && (op.Action != tc.action || len(op.Resources) != 1 || op.Resources[0] != tc.resource) {
			t.Errorf("%s: %+v, %v", tc.url, op, err)
		}
		if !tc.ok && !errors.Is(err, adapter.ErrUnsupportedRequirement) {
			t.Errorf("%s: %v, want UNSUPPORTED_REQUIREMENT", tc.url, err)
		}
	}
}

// TestBodyRestored: the form body read for OAUTH-2 is put back.
func TestBodyRestored(t *testing.T) {
	as := &asServer{active: true, expAt: tNow + 3000}
	a := newAdapter(t, clock.NewFake(time.Unix(tNow, 0)), &http.Client{Transport: &handlerTransport{h: as}}, formIEntry(0))
	r, _ := http.NewRequest(http.MethodPost, "https://gateway.acme.example/customers/C-1042", strings.NewReader("note=hello"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Authorization", "Bearer tok-a")
	r = oauth.Mark(r)
	if _, err := a.AuthenticateNative(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	if b, _ := io.ReadAll(r.Body); string(b) != "note=hello" {
		t.Errorf("body after authentication: %q", b)
	}
}
