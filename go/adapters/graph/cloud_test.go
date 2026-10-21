package graph_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"hop.top/pact-go/adapter/adaptertest"
)

// tokenCall is one request to the fake token endpoint.
type tokenCall struct {
	Tenant              string
	GrantType           string
	RequestedTokenUse   string
	ClientID            string
	ClientSecret        string
	ClientAssertionType string
	ClientAssertion     string
	Assertion           string
	Scope               string
	// Form holds every parameter of the request body.
	Form map[string][]string
}

// graphCall is one request to the fake Graph.
type graphCall struct {
	Path          string
	RawQuery      string
	Authorization string
	Header        http.Header
}

// tokenAnswer is a scripted answer of the token endpoint.
type tokenAnswer struct {
	Status int
	Body   map[string]any
}

// graphAnswer is a scripted answer of Graph to a mail request.
type graphAnswer struct {
	Status int
	Header map[string]string
	Body   any
}

// fakeCloud is an in-process Microsoft identity platform token endpoint and
// Microsoft Graph over TLS. Its client dials only the in-process listener,
// whatever host a request names, so no test reaches a real endpoint.
type fakeCloud struct {
	t      testing.TB
	srv    *httptest.Server
	client *http.Client
	hooks  *adaptertest.Hooks

	// clientSecrets are the registered client secrets by application ID;
	// certKeys the registered certificate keys with their x5t#S256.
	clientSecrets map[string]string
	certKeys      map[string]certKey
	// auditorApp is the application ID of the auditor identity.
	auditorApp string
	// executorApps are the application IDs whose service principal step 1
	// of the preflight reads.
	signingKey *rsa.PrivateKey

	mu         sync.Mutex
	tokenCalls []tokenCall
	graphCalls []graphCall
	auditCalls []graphCall
	issued     map[string]string // token value to "client|grant"
	n          int
	// onToken scripts the token endpoint; nil answers with a token.
	onToken func(c tokenCall) *tokenAnswer
	// onGraph scripts the mail requests; nil answers one page of two
	// messages.
	onGraph func(c graphCall) *graphAnswer
	// tokenLifetime is the expires_in of an issued token.
	tokenLifetime int
	// pages are the step 1 answers of the current preflight run;
	// auditUnreachable makes step 1 answer 503.
	pages            [][]map[string]any
	auditUnreachable bool
}

// certKey is a registered certificate credential.
type certKey struct {
	pub        *rsa.PublicKey
	thumbprint string
}

func newCloud(t testing.TB, hooks *adaptertest.Hooks) *fakeCloud {
	t.Helper()
	c := &fakeCloud{
		t: t, hooks: hooks,
		clientSecrets: map[string]string{uGatewayApp: secretOBO, uExecApp: secretExecutor, uAuditorApp: secretAuditor},
		certKeys:      map[string]certKey{},
		auditorApp:    uAuditorApp,
		issued:        map[string]string{},
		tokenLifetime: 3599,
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	c.signingKey = key
	cert, pool := selfSigned(t, loginHost, graphHost)
	c.srv = httptest.NewUnstartedServer(http.HandlerFunc(c.serve))
	c.srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	c.srv.StartTLS()
	t.Cleanup(c.srv.Close)
	addr := c.srv.Listener.Addr().String()
	c.client = &http.Client{Transport: &http.Transport{
		Proxy:           nil,
		TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
		DisableKeepAlives: true,
	}}
	return c
}

// selfSigned is a certificate for the given hosts and the pool that trusts it.
func selfSigned(t testing.TB, hosts ...string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: hosts[0]}, DNSNames: hosts,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

func (c *fakeCloud) fire(name string) {
	if c.hooks != nil {
		c.hooks.Fire(name)
	}
}

func writeJSON(w http.ResponseWriter, status int, header map[string]string, body any) {
	for k, v := range header {
		w.Header().Set(k, v)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func (c *fakeCloud) serve(w http.ResponseWriter, r *http.Request) {
	switch r.Host {
	case loginHost:
		c.serveLogin(w, r)
	case graphHost:
		c.serveGraph(w, r)
	default:
		c.t.Errorf("fake cloud: request to unexpected host %q", r.Host)
		http.Error(w, "unexpected host", http.StatusMisdirectedRequest)
	}
}

// serveLogin is the token endpoint of the tenant, and the discovery
// document and key set the OAuth front door reads.
func (c *fakeCloud) serveLogin(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/"+uTID+"/v2.0/.well-known/openid-configuration":
		writeJSON(w, 200, nil, map[string]any{
			"issuer":   "https://" + loginHost + "/" + uTID + "/v2.0",
			"jwks_uri": "https://" + loginHost + "/" + uTID + "/discovery/v2.0/keys",
		})
		return
	case r.Method == http.MethodGet && r.URL.Path == "/"+uTID+"/discovery/v2.0/keys":
		pub := c.signingKey.PublicKey
		writeJSON(w, 200, nil, map[string]any{"keys": []map[string]any{{
			"kty": "RSA", "use": "sig", "kid": "nw-key-1",
			"n": b64(pub.N.Bytes()), "e": b64(big.NewInt(int64(pub.E)).Bytes()),
		}}})
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
	if r.Method != http.MethodPost || len(parts) != 4 || parts[1] != "oauth2" || parts[2] != "v2.0" || parts[3] != "token" {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if err := r.ParseForm(); err != nil || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
		writeJSON(w, 400, nil, map[string]any{"error": "invalid_request"})
		return
	}
	call := tokenCall{
		Tenant: parts[0], GrantType: r.PostForm.Get("grant_type"), RequestedTokenUse: r.PostForm.Get("requested_token_use"),
		ClientID: r.PostForm.Get("client_id"), ClientSecret: r.PostForm.Get("client_secret"),
		ClientAssertionType: r.PostForm.Get("client_assertion_type"), ClientAssertion: r.PostForm.Get("client_assertion"),
		Assertion: r.PostForm.Get("assertion"), Scope: r.PostForm.Get("scope"), Form: r.PostForm,
	}
	c.mu.Lock()
	c.tokenCalls = append(c.tokenCalls, call)
	script := c.onToken
	c.mu.Unlock()
	if call.ClientID == c.auditorApp {
		c.fire("audit")
	} else {
		c.fire("token")
	}
	if !c.clientAuthenticated(call) {
		writeJSON(w, 401, nil, map[string]any{"error": "invalid_client", "error_codes": []int{7000215}})
		return
	}
	if script != nil {
		if a := script(call); a != nil {
			writeJSON(w, a.Status, nil, a.Body)
			return
		}
	}
	c.mu.Lock()
	c.n++
	value := fmt.Sprintf("graph-token-b-%s-%04d-%s", call.ClientID[:8], c.n, strings.Repeat("x", 12))
	c.issued[value] = call.ClientID + "|" + call.GrantType
	life := c.tokenLifetime
	c.mu.Unlock()
	body := map[string]any{"token_type": "Bearer", "expires_in": life, "ext_expires_in": 0, "access_token": value}
	if call.GrantType == grantOBO {
		body["scope"] = scopeMail
	}
	writeJSON(w, 200, nil, body)
}

// clientAuthenticated checks the client secret or the certificate assertion
// of a token request.
func (c *fakeCloud) clientAuthenticated(call tokenCall) bool {
	if call.ClientSecret != "" {
		return call.ClientAssertion == "" && c.clientSecrets[call.ClientID] == call.ClientSecret
	}
	k, ok := c.certKeys[call.ClientID]
	if !ok || call.ClientAssertionType != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		return false
	}
	segs := strings.Split(call.ClientAssertion, ".")
	if len(segs) != 3 {
		return false
	}
	var h map[string]any
	var p map[string]any
	hb, err1 := base64.RawURLEncoding.DecodeString(segs[0])
	pb, err2 := base64.RawURLEncoding.DecodeString(segs[1])
	sig, err3 := base64.RawURLEncoding.DecodeString(segs[2])
	if err1 != nil || err2 != nil || err3 != nil || json.Unmarshal(hb, &h) != nil || json.Unmarshal(pb, &p) != nil {
		return false
	}
	if h["alg"] != "PS256" || h["typ"] != "JWT" || h["x5t#S256"] != k.thumbprint {
		return false
	}
	sum := sha256.Sum256([]byte(segs[0] + "." + segs[1]))
	if rsa.VerifyPSS(k.pub, crypto.SHA256, sum[:], sig, nil) != nil {
		return false
	}
	aud := "https://" + loginHost + "/" + call.Tenant + "/oauth2/v2.0/token"
	return p["aud"] == aud && p["iss"] == call.ClientID && p["sub"] == call.ClientID && p["jti"] != nil && p["exp"] != nil && p["nbf"] != nil
}

// serveGraph is Microsoft Graph: the mail paths of the translation rows and
// the appRoleAssignments read of step 1 of the preflight.
func (c *fakeCloud) serveGraph(w http.ResponseWriter, r *http.Request) {
	call := graphCall{Path: r.URL.EscapedPath(), RawQuery: r.URL.RawQuery, Authorization: r.Header.Get("Authorization"), Header: r.Header.Clone()}
	if strings.HasPrefix(call.Path, "/v1.0/servicePrincipals") {
		c.serveAudit(w, call)
		return
	}
	c.mu.Lock()
	c.graphCalls = append(c.graphCalls, call)
	script := c.onGraph
	who, known := c.issued[strings.TrimPrefix(call.Authorization, "Bearer ")]
	c.mu.Unlock()
	c.fire("execute")
	if !known || !strings.HasPrefix(call.Authorization, "Bearer ") {
		writeJSON(w, 401, nil, map[string]any{"error": map[string]any{"code": "InvalidAuthenticationToken"}})
		return
	}
	if script != nil {
		if a := script(call); a != nil {
			writeJSON(w, a.Status, a.Header, a.Body)
			return
		}
	}
	_ = who
	writeJSON(w, 200, map[string]string{"request-id": "94fb3b52-452a-4535-a601-69e0a90e3aa2"}, messagesPage(call.Path, false))
}

// messagesPage is a page of two messages, with a next link when more is set.
func messagesPage(path string, more bool) map[string]any {
	page := map[string]any{
		"@odata.context": graphOrigin + "/v1.0/$metadata#users('" + uOID + "')/messages(id,subject,body)",
		"value": []map[string]any{
			{"id": "AAMkAGUAAAwTW09AAA=", "subject": "Quarterly digest", "body": map[string]any{"contentType": "html", "content": "<p>hello</p>"}},
			{"id": "AAMkAGUAAAwTW09AAB=", "subject": "Invoice 42", "body": map[string]any{"contentType": "html", "content": "<p>due</p>"}},
		},
	}
	if more {
		page["@odata.nextLink"] = graphOrigin + path + "?$select=id,subject,body&$top=10&$skip=10"
	}
	return page
}

func (c *fakeCloud) serveAudit(w http.ResponseWriter, call graphCall) {
	c.mu.Lock()
	c.auditCalls = append(c.auditCalls, call)
	who := c.issued[strings.TrimPrefix(call.Authorization, "Bearer ")]
	pages, down := c.pages, c.auditUnreachable
	c.mu.Unlock()
	c.fire("audit")
	if !strings.HasPrefix(who, c.auditorApp+"|") {
		writeJSON(w, 403, nil, map[string]any{"error": map[string]any{"code": "Authorization_RequestDenied"}})
		return
	}
	if down {
		writeJSON(w, 503, nil, map[string]any{"error": map[string]any{"code": "serviceNotAvailable"}})
		return
	}
	i := 0
	if strings.HasPrefix(call.RawQuery, "$skiptoken=page") {
		i, _ = strconv.Atoi(strings.TrimPrefix(call.RawQuery, "$skiptoken=page"))
	}
	if i >= len(pages) {
		if len(pages) == 0 && i == 0 {
			writeJSON(w, 200, nil, map[string]any{"value": []any{}})
			return
		}
		http.Error(w, "no such page", http.StatusBadRequest)
		return
	}
	body := map[string]any{"@odata.context": graphOrigin + "/v1.0/$metadata#appRoleAssignments", "value": pages[i]}
	if i+1 < len(pages) {
		body["@odata.nextLink"] = graphOrigin + call.Path + "?$skiptoken=page" + strconv.Itoa(i+1)
	}
	writeJSON(w, 200, nil, body)
}

// counts of the recorded calls.
func (c *fakeCloud) tokens() []tokenCall {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.tokenCalls)
}

func (c *fakeCloud) graph() []graphCall {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.graphCalls)
}

// executorTokens are the token calls of the gateway and executor
// applications, without the auditor's.
func (c *fakeCloud) executorTokens() []tokenCall {
	var out []tokenCall
	for _, t := range c.tokens() {
		if t.ClientID != c.auditorApp {
			out = append(out, t)
		}
	}
	return out
}

func (c *fakeCloud) issuedTo(value string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.issued[value]
	return v, ok
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// tokenA mints token A: an Entra ID v2.0 access token for aud, signed with
// the tenant key the front door trusts.
func (c *fakeCloud) tokenA(aud, uti string, now time.Time) string {
	header := map[string]any{"typ": "JWT", "alg": "RS256", "kid": "nw-key-1"}
	claims := map[string]any{
		"aud": aud, "iss": "https://" + loginHost + "/" + uTID + "/v2.0", "tid": uTID, "ver": "2.0",
		"iat": now.Unix() - 60, "nbf": now.Unix() - 60, "exp": now.Unix() + 3000,
		"azp": uClientApp, "scp": "Mail.Read", "oid": uOID, "sub": "pairwise-" + uOID[:8], "uti": uti,
	}
	hb, _ := json.Marshal(header)
	cb, _ := json.Marshal(claims)
	input := b64(hb) + "." + b64(cb)
	sum := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, c.signingKey, crypto.SHA256, sum[:])
	if err != nil {
		c.t.Fatal(err)
	}
	return input + "." + b64(sig)
}
