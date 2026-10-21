package graph_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapters/graph"
	"hop.top/pact-go/core/clock"
)

// baseConfig is a valid configuration of a form, with its acquirers.
func baseConfig(t *testing.T, form string) graph.Config {
	t.Helper()
	clk := clock.NewFake(time.Unix(uNow, 0))
	acq, aud, err := acquirers(form, uTID, uGatewayApp, uExecApp, nil, clk)
	if err != nil {
		t.Fatal(err)
	}
	cfg := graph.Config{
		Form: graph.Form(form), Realm: uRealm, Origin: uOrigin, Tenant: uTID, Acquirer: acq,
		Registry: fixtureRegistry{}, Authenticator: noFrontDoor{}, Enrollments: noEnrollments{}, Permissions: noPolicy{}, Clock: clk,
	}
	if form == formApplication {
		cfg.Preflight = &graph.PreflightConfig{Auditor: aud, RBAC: attestSource{func() *attestation { return nil }}}
	}
	return cfg
}

// TestOneAcquirerPerForm is the type-level part of GRAPH-06 and GRAPH-17: an
// adapter holds exactly one acquirer, of its form's grant, so there is no
// credential to fall back to (GR-1, GR-11).
func TestOneAcquirerPerForm(t *testing.T) {
	clk := clock.NewFake(time.Unix(uNow, 0))
	obo, _, err := acquirers(formDelegated, uTID, uGatewayApp, "", nil, clk)
	if err != nil {
		t.Fatal(err)
	}
	cc, _, err := acquirers(formApplication, uTID, uGatewayApp, uExecApp, nil, clk)
	if err != nil {
		t.Fatal(err)
	}
	d := baseConfig(t, formDelegated)
	d.Acquirer = cc
	if _, err := graph.New(d); err == nil {
		t.Error("a form D adapter accepted a client credentials acquirer")
	}
	a := baseConfig(t, formApplication)
	a.Acquirer = obo
	if _, err := graph.New(a); err == nil {
		t.Error("a form A adapter accepted an OBO acquirer")
	}
	for _, form := range []string{formDelegated, formApplication} {
		if _, err := graph.New(baseConfig(t, form)); err != nil {
			t.Errorf("%s: %v", form, err)
		}
	}
}

// TestPreflightConfiguration refuses form A without a preflight, an auditor
// that is the executor application, an OBO auditor, and an allowlist entry
// of the Microsoft Graph service principal (GR-17, GR-18).
func TestPreflightConfiguration(t *testing.T) {
	clk := clock.NewFake(time.Unix(uNow, 0))
	mk := func(f func(c *graph.Config)) error {
		c := baseConfig(t, formApplication)
		f(&c)
		_, err := graph.New(c)
		return err
	}
	same, _ := graph.NewClientCredentials(graph.AcquirerConfig{Tenant: uTID, ClientID: uExecApp, Auth: graph.ClientAuth{Secret: "s"}, Clock: clk})
	obo, _ := graph.NewOnBehalfOf(graph.AcquirerConfig{Tenant: uTID, ClientID: uAuditorApp, Auth: graph.ClientAuth{Secret: "s"}, Clock: clk})
	graphSP := "c0ffee00-1111-4222-8333-444455556666"
	for name, f := range map[string]func(c *graph.Config){
		"no preflight":     func(c *graph.Config) { c.Preflight = nil },
		"auditor executor": func(c *graph.Config) { c.Preflight.Auditor = same },
		"auditor OBO":      func(c *graph.Config) { c.Preflight.Auditor = obo },
		"no RBAC source":   func(c *graph.Config) { c.Preflight.RBAC = nil },
		"graph allowlist": func(c *graph.Config) {
			c.Preflight.GraphServicePrincipalID = graphSP
			c.Preflight.Allowlist = []graph.AppRole{{ResourceID: graphSP, AppRoleID: "11111111-aaaa-4bbb-8ccc-000000000001"}}
		},
		"allowlist without graph sp": func(c *graph.Config) {
			c.Preflight.Allowlist = []graph.AppRole{{ResourceID: "2222aaaa-3333-4bbb-8ccc-dddd0000eeee", AppRoleID: "r"}}
		},
	} {
		if mk(f) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	d := baseConfig(t, formDelegated)
	d.Preflight = &graph.PreflightConfig{}
	if _, err := graph.New(d); err == nil {
		t.Error("form D accepted a preflight")
	}
}

// TestCertificateAssertion runs the OBO request with a certificate
// credential: the token endpoint verifies a PS256 assertion with x5t#S256,
// aud the token endpoint, iss and sub the client [M12].
func TestCertificateAssertion(t *testing.T) {
	cloud := newCloud(t, nil)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "mail-gateway"}, NotBefore: time.Unix(uNow-3600, 0), NotAfter: time.Unix(uNow+86400, 0)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	cloud.certKeys[uGatewayApp] = certKey{pub: &key.PublicKey, thumbprint: base64.RawURLEncoding.EncodeToString(sum[:])}
	delete(cloud.clientSecrets, uGatewayApp)
	cert, err := graph.NewCertificate(der, key)
	if err != nil {
		t.Fatal(err)
	}
	clk := clock.NewFake(time.Unix(uNow, 0))
	obo, err := graph.NewOnBehalfOf(graph.AcquirerConfig{Tenant: uTID, ClientID: uGatewayApp, Auth: graph.ClientAuth{Certificate: cert}, HTTPClient: cloud.client, Clock: clk})
	if err != nil {
		t.Fatal(err)
	}
	tok, err := obo.Acquire(t.Context(), cloud.tokenA(uGatewayApp, "uti-cert", clk.Now()))
	if err != nil {
		t.Fatalf("OBO with a certificate assertion: %v", err)
	}
	if got := fmt.Sprintf("%v %+v %#v %s", tok, tok, tok, tok); strings.Contains(got, "graph-token-b") {
		t.Errorf("token B formatted: %s", got)
	}
	raw, _ := json.Marshal(tok)
	if strings.Contains(string(raw), "graph-token-b") {
		t.Errorf("token B encoded: %s", raw)
	}
	calls := cloud.tokens()
	if len(calls) != 1 || calls[0].ClientSecret != "" || calls[0].ClientAssertion == "" {
		t.Errorf("token requests %+v; want one with a client assertion and no secret", calls)
	}
}

// TestAttestationFile parses the operator's attestation file strictly.
func TestAttestationFile(t *testing.T) {
	dir := t.TempDir()
	good := `{"identity":"` + uExecApp + `","resource":"` + uMailbox + `","ran_at":1792079900,"rows":[{"RoleName":"Application Mail.Read","GrantedPermissions":"Mail.Read","AllowedResourceScope":"Mail Digest Mailboxes","ScopeType":"CustomRecipientScope","InScope":"True"}]}`
	path := filepath.Join(dir, "rbac.json")
	if err := os.WriteFile(path, []byte(good), 0o600); err != nil {
		t.Fatal(err)
	}
	att, err := graph.AttestationFile{Path: path}.Attestation(t.Context(), uExecApp, uMailbox)
	if err != nil || len(att.Rows) != 1 || att.Rows[0].InScope != "True" || att.RanAt.Unix() != 1792079900 || att.Ref == "" {
		t.Fatalf("attestation %+v, %v", att, err)
	}
	for name, bad := range map[string]string{
		"unknown member": strings.Replace(good, `"rows"`, `"extra":1,"rows"`, 1),
		"no ran_at":      strings.Replace(good, `"ran_at":1792079900,`, ``, 1),
		"two objects":    good + good,
		"no rows":        strings.Replace(good, `"rows":[`, `"x":[`, 1),
	} {
		if _, err := graph.ParseAttestation([]byte(bad)); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
	if _, err := (graph.AttestationFile{Path: filepath.Join(dir, "absent.json")}).Attestation(t.Context(), uExecApp, uMailbox); !errors.Is(err, adapter.ErrDependencyUnavailable) {
		t.Errorf("absent file: %v", err)
	}
}

// TestStatusOf maps execution errors to the gateway's answers (GR-34).
func TestStatusOf(t *testing.T) {
	for _, c := range []struct {
		err  error
		want int
	}{
		{nil, http.StatusOK},
		{&graph.InteractionRequired{Challenge: `Bearer error="interaction_required"`}, http.StatusUnauthorized},
		{&graph.Throttled{RetryAfter: "10"}, http.StatusServiceUnavailable},
		{fmt.Errorf("x: %w", graph.ErrNativeDenial), http.StatusForbidden},
		{graph.ErrExecutorMismatch, http.StatusForbidden},
		{fmt.Errorf("x: %w", adapter.ErrContextMismatch), http.StatusForbidden},
		{fmt.Errorf("x: %w", adapter.ErrInvalidMessage), http.StatusBadRequest},
		{fmt.Errorf("x: %w", adapter.ErrUnsupportedRequirement), http.StatusUnprocessableEntity},
		{fmt.Errorf("x: %w", adapter.ErrDependencyUnavailable), http.StatusServiceUnavailable},
	} {
		if got, _ := graph.StatusOf(c.err); got != c.want {
			t.Errorf("StatusOf(%v) = %d, want %d", c.err, got, c.want)
		}
	}
	if _, h := graph.StatusOf(&graph.Throttled{RetryAfter: "10"}); h.Get("Retry-After") != "10" {
		t.Error("no Retry-After")
	}
	if _, h := graph.StatusOf(&graph.InteractionRequired{Challenge: "Bearer x"}); h.Get("WWW-Authenticate") != "Bearer x" {
		t.Error("no WWW-Authenticate")
	}
}
