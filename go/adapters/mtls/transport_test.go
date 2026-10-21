package mtls_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapters/memory"
	"hop.top/pact-go/adapters/mtls"
	"hop.top/pact-go/core/clock"
)

// The names of the test world of the Go-only tests.
const (
	uriReconciler = "spiffe://acme.example/ns/finance/sa/reconciler"
	uriTerminator = "spiffe://acme.example/ns/edge/sa/envoy-terminator"
	statusBound   = 360
)

var (
	idReconciler = mtls.Identifier("workload-ca-2026", mtls.SANKindURI, uriReconciler)
	idTerminator = mtls.Identifier("workload-ca-2026", mtls.SANKindURI, uriTerminator)
)

// testWorld is a world of one pinned CA, the reconciler, a server-only
// certificate and the terminator, valid around now, with a snapshot of the
// CA published at thisUpdate.
func testWorld(t *testing.T, role string, now time.Time, thisUpdate time.Time) *world {
	t.Helper()
	eku, ku, server := []string{"client_auth"}, []string{"digital_signature"}, []string{"server_auth"}
	nb, na := now.Add(-24*time.Hour).Unix(), now.Add(30*24*time.Hour).Unix()
	st := mtlsState{
		Model:       mtlsModel,
		Listener:    listenerState{Role: role, TenantID: "acme", EnvironmentID: "https://gateway.acme.example/environments/reconciliation"},
		StatusBound: statusBound,
		Authorities: []authorityState{{Ref: "workload-ca", SubjectCN: "Acme Workload CA 2026", KeySeed: "pact-mtls-fixture/workload-ca",
			NotBefore: now.Add(-365 * 24 * time.Hour).Unix(), NotAfter: now.Add(365 * 24 * time.Hour).Unix()}},
		PinnedCAs: []pinnedState{{CAID: "workload-ca-2026", Authority: "workload-ca", SANKind: "uri"}},
		Peers: []peerState{
			{Ref: "reconciler", Issuer: "workload-ca", Serial: 4097, SubjectCN: "reconciler", URIs: []string{uriReconciler},
				NotBefore: nb, NotAfter: na, ExtKeyUsage: &eku, KeyUsage: &ku, KeySeed: "pact-mtls-fixture/reconciler"},
			{Ref: "terminator", Issuer: "workload-ca", Serial: 4100, SubjectCN: "envoy-terminator", URIs: []string{uriTerminator},
				NotBefore: nb, NotAfter: na, ExtKeyUsage: &eku, KeyUsage: &ku, KeySeed: "pact-mtls-fixture/terminator"},
			{Ref: "server-only", Issuer: "workload-ca", Serial: 4101, SubjectCN: "reconciler", URIs: []string{uriReconciler},
				NotBefore: nb, NotAfter: na, ExtKeyUsage: &server, KeyUsage: &ku, KeySeed: "pact-mtls-fixture/server-only"},
		},
		Snapshots: []snapshotState{{CAID: "workload-ca-2026", Number: 1, ThisUpdate: thisUpdate.Unix(), NextUpdate: now.Add(time.Hour).Unix()}},
	}
	if role == "terminated" {
		st.Terminators = []string{string(idTerminator)}
	}
	w, err := buildWorld(st)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

// testAdapter builds the adapter of w on clk.
func testAdapter(t *testing.T, w *world, clk clock.Clock) *mtls.Adapter {
	t.Helper()
	ref, err := memory.New(w.commonState(), clk)
	if err != nil {
		t.Fatal(err)
	}
	a, err := adapterOf(w, mtls.Config{Origin: "https://gateway.acme.example", Registry: referenceRegistry{ref}, Permissions: commonPolicy{}, Clock: clk})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// clientCert is the TLS client certificate of the peer ref of w.
func clientCert(w *world, ref string) tls.Certificate {
	m := w.peers[ref]
	return tls.Certificate{Certificate: [][]byte{m.cert.Raw}, PrivateKey: m.key, Leaf: m.cert}
}

// gateway is a TLS server of the adapter: it authenticates every request and
// answers 200, 401 or 503, and closes the connection where CloseAfter says.
type gateway struct {
	srv   *httptest.Server
	conns atomic.Int32
	proto atomic.Int32
}

func startGateway(t *testing.T, a *mtls.Adapter, h2 bool) *gateway {
	t.Helper()
	g := &gateway{}
	g.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g.proto.Store(int32(r.ProtoMajor))
		p, err := a.AuthenticateNative(r.Context(), r)
		switch {
		case err == nil:
			_, _ = io.WriteString(w, p.ID)
		case errors.Is(err, adapter.ErrDependencyUnavailable):
			mtls.CloseAfter(w, err)
			w.WriteHeader(http.StatusServiceUnavailable)
		default:
			mtls.CloseAfter(w, err)
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	g.srv.EnableHTTP2 = h2
	g.srv.TLS = a.ServerTLSConfig(nil)
	g.srv.Config.ConnContext = a.ConnContext
	g.srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			g.conns.Add(1)
		}
	}
	g.srv.StartTLS()
	t.Cleanup(g.srv.Close)
	return g
}

// client returns an HTTP client of the gateway that presents cert.
func (g *gateway) client(cert tls.Certificate, cache tls.ClientSessionCache, maxVersion uint16) *http.Client {
	c := g.srv.Client()
	tr := c.Transport.(*http.Transport)
	tr.TLSClientConfig.Certificates = []tls.Certificate{cert}
	tr.TLSClientConfig.ClientSessionCache = cache
	tr.TLSClientConfig.MaxVersion = maxVersion
	return c
}

func get(t *testing.T, c *http.Client, url string) (int, string, bool) {
	t.Helper()
	resp, err := c.Get(url)
	if err != nil {
		return 0, err.Error(), false
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body), resp.Close
}

// TestConnectionStatusRecord is MTLS-15 over HTTP/1.1 and HTTP/2: a request at
// u + S is served on the connection; one at u + S + 1 s is DEFERRED and the
// connection is closed after it; a new connection with a fresh snapshot is
// served. It is also MTLS-18: every request is evaluated on the connection's
// TLS state.
func TestConnectionStatusRecord(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		name := "http1.1"
		if h2 {
			name = "http2"
		}
		t.Run(name, func(t *testing.T) {
			now := time.Now().Truncate(time.Second)
			u := now.Add(-60 * time.Second)
			clk := clock.NewFake(now)
			w := testWorld(t, "direct", now, u)
			a := testAdapter(t, w, clk)
			g := startGateway(t, a, h2)
			c := g.client(clientCert(w, "reconciler"), nil, 0)

			if code, body, _ := get(t, c, g.srv.URL); code != 200 || body != string(idReconciler) {
				t.Fatalf("first request: %d %q", code, body)
			}
			if want := map[bool]int32{false: 1, true: 2}[h2]; g.proto.Load() != want {
				t.Fatalf("HTTP/%d, want HTTP/%d", g.proto.Load(), want)
			}
			clk.Set(u.Add(statusBound * time.Second))
			if code, _, _ := get(t, c, g.srv.URL); code != 200 {
				t.Fatalf("request at u+S: %d, want 200", code)
			}
			if g.conns.Load() != 1 {
				t.Fatalf("connections = %d, want one reused connection", g.conns.Load())
			}
			clk.Set(u.Add((statusBound + 1) * time.Second))
			code, _, closing := get(t, c, g.srv.URL)
			if code != 503 {
				t.Fatalf("request at u+S+1: %d, want 503", code)
			}
			if !h2 && !closing {
				t.Error("HTTP/1.1 response does not close the connection")
			}
			if err := a.Adopt("workload-ca-2026", w.mintCRLAt(t, 2, clk.Now(), nil)); err != nil {
				t.Fatal(err)
			}
			if code, _, _ := get(t, c, g.srv.URL); code != 200 {
				t.Fatalf("request on a new connection with a fresh snapshot: %d, want 200", code)
			}
			if g.conns.Load() != 2 {
				t.Errorf("connections = %d, want a new connection after the closing response", g.conns.Load())
			}
		})
	}
}

// TestRevokedAfterConnectionOpened is MTLS-16: a certificate revoked after
// the connection opened is served on it until the record ages past S, then
// DEFERRED and closed; a new connection is refused with 401.
func TestRevokedAfterConnectionOpened(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	clk := clock.NewFake(now)
	w := testWorld(t, "direct", now, now.Add(-10*time.Second))
	a := testAdapter(t, w, clk)
	g := startGateway(t, a, false)
	c := g.client(clientCert(w, "reconciler"), nil, 0)
	if code, _, _ := get(t, c, g.srv.URL); code != 200 {
		t.Fatalf("first request: %d", code)
	}
	clk.Set(now.Add(30 * time.Second))
	if err := a.Adopt("workload-ca-2026", w.mintCRLAt(t, 2, clk.Now(), []int64{4097})); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := get(t, c, g.srv.URL); code != 200 {
		t.Fatalf("request on the open connection after the revocation: %d, want 200 until the record ages past S", code)
	}
	clk.Set(now.Add((statusBound - 10 + 1) * time.Second))
	if code, _, _ := get(t, c, g.srv.URL); code != 503 {
		t.Fatalf("request after the record aged past S: %d, want 503", code)
	}
	if code, _, _ := get(t, c, g.srv.URL); code != 401 {
		t.Fatalf("request on a new connection: %d, want 401", code)
	}
}

// TestCAWithdrawnOnOpenConnection is MTLS-20 and MTLS-21: removing a pinned CA
// refuses the next request of a connection it issued.
func TestCAWithdrawnOnOpenConnection(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	clk := clock.NewFake(now)
	w := testWorld(t, "direct", now, now.Add(-10*time.Second))
	a := testAdapter(t, w, clk)
	g := startGateway(t, a, false)
	c := g.client(clientCert(w, "reconciler"), nil, 0)
	if code, _, _ := get(t, c, g.srv.URL); code != 200 {
		t.Fatalf("first request: %d", code)
	}
	if err := a.ReplacePinnedCAs([]mtls.CAEntry{{CAID: "partner-ca-2026", Certificate: otherCA(t, now), SANKind: mtls.SANKindURI}}); err != nil {
		t.Fatal(err)
	}
	code, _, closing := get(t, c, g.srv.URL)
	if code != 401 || !closing {
		t.Fatalf("request after the CA was withdrawn: %d, closing %t; want 401 and a closing connection", code, closing)
	}
	if g.conns.Load() != 1 {
		t.Errorf("connections = %d, want the refusal on the open connection", g.conns.Load())
	}
}

// otherCA is the certificate of an authority that is not the test world's.
func otherCA(t *testing.T, now time.Time) *x509.Certificate {
	t.Helper()
	w, err := buildWorld(mtlsState{Authorities: []authorityState{{Ref: "partner-ca", SubjectCN: "Partner Workload CA 2026",
		KeySeed: "pact-mtls-fixture/partner-ca", NotBefore: now.Add(-time.Hour).Unix(), NotAfter: now.Add(time.Hour).Unix()}}})
	if err != nil {
		t.Fatal(err)
	}
	return w.authorities["partner-ca"].cert
}

// TestHandshakePolicy covers MTLS-1, MTLS-6 and MTLS-17 at connection setup:
// a TLS 1.2 client and a client without a certificate are refused, a session
// ticket is never issued, so a second connection is a full handshake, and a
// connection the stack reports as resumed is refused.
func TestHandshakePolicy(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	clk := clock.NewFake(now)
	w := testWorld(t, "direct", now, now.Add(-10*time.Second))
	a := testAdapter(t, w, clk)
	g := startGateway(t, a, false)

	t.Run("TLS 1.2 refused", func(t *testing.T) {
		if code, msg, _ := get(t, g.client(clientCert(w, "reconciler"), nil, tls.VersionTLS12), g.srv.URL); code != 0 {
			t.Errorf("TLS 1.2 client: %d %s, want a refused handshake", code, msg)
		}
	})
	t.Run("no client certificate refused", func(t *testing.T) {
		c := g.srv.Client()
		if code, msg, _ := get(t, c, g.srv.URL); code != 0 {
			t.Errorf("client without a certificate: %d %s, want a refused handshake", code, msg)
		}
	})
	t.Run("certificate policy at setup", func(t *testing.T) {
		if code, msg, _ := get(t, g.client(clientCert(w, "server-only"), nil, 0), g.srv.URL); code != 0 {
			t.Errorf("certificate without the client-auth purpose: %d %s, want a refused handshake", code, msg)
		}
	})
	t.Run("no ticket, no resumption", func(t *testing.T) {
		cache := tls.NewLRUClientSessionCache(4)
		cfg := g.client(clientCert(w, "reconciler"), cache, 0).Transport.(*http.Transport).TLSClientConfig.Clone()
		for i := range 2 {
			conn, err := tls.Dial("tcp", g.srv.Listener.Addr().String(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			// A ticket arrives after the handshake; reading lets the client
			// process one, if the server sent it.
			_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			_, _ = conn.Read(make([]byte, 1))
			if conn.ConnectionState().DidResume {
				t.Errorf("connection %d resumed a session", i+1)
			}
			_ = conn.Close()
		}
	})
	t.Run("resumed state refused", func(t *testing.T) {
		cfg := a.ServerTLSConfig(nil)
		cs := tls.ConnectionState{DidResume: true, PeerCertificates: []*x509.Certificate{w.peers["reconciler"].cert}}
		if err := cfg.VerifyConnection(cs); err == nil {
			t.Error("a resumed connection passes the setup check")
		}
		if cfg.SessionTicketsDisabled != true || cfg.MinVersion != tls.VersionTLS13 {
			t.Errorf("tls.Config: tickets disabled %t, minimum version %x", cfg.SessionTicketsDisabled, cfg.MinVersion)
		}
	})
}

// TestTerminatedListenerBypass is MTLS-06: the terminated listener refuses at
// connection setup a client without a certificate and an agent with a valid
// certificate that is not an allowlisted terminator; the terminator itself is
// accepted.
func TestTerminatedListenerBypass(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	clk := clock.NewFake(now)
	w := testWorld(t, "terminated", now, now.Add(-10*time.Second))
	a := testAdapter(t, w, clk)
	g := startGateway(t, a, false)
	if code, msg, _ := get(t, g.client(clientCert(w, "reconciler"), nil, 0), g.srv.URL); code != 0 {
		t.Errorf("agent certificate on the terminated listener: %d %s, want a refused handshake", code, msg)
	}
	if code, msg, _ := get(t, g.srv.Client(), g.srv.URL); code != 0 {
		t.Errorf("no certificate on the terminated listener: %d %s, want a refused handshake", code, msg)
	}
	// The terminator passes setup; without a forwarded header the request
	// is a native denial.
	if code, _, _ := get(t, g.client(clientCert(w, "terminator"), nil, 0), g.srv.URL); code != 401 {
		t.Errorf("terminator without a forwarded header: %d, want 401", code)
	}
}

// TestIdentityHeadersRemoved is MTLS-26 for MTLS-01 and MTLS-07: the
// forwarded-certificate header, the ssl-client-* headers and the configured
// ones are absent from the request after AuthenticateNative, on a direct and
// on a terminated listener, also when authentication fails.
func TestIdentityHeadersRemoved(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	for _, role := range []string{"direct", "terminated"} {
		t.Run(role, func(t *testing.T) {
			w := testWorld(t, role, now, now.Add(-10*time.Second))
			w.st.Forwarded = [][][]string{{{"Cert", "@cert:reconciler"}}}
			a := testAdapter(t, w, clock.NewFake(now))
			r := a.Arrive(requestOf(t))
			ref := "reconciler"
			if role == "terminated" {
				ref = "terminator"
			}
			if err := w.Credential(r, ref); err != nil {
				t.Fatal(err)
			}
			r.Header.Set("Ssl-Client-Verify", "SUCCESS")
			r.Header.Set("ssl-client-subject-dn", "CN=ledger-writer")
			r.Header.Set("X-Client-Cert", "CN=ledger-writer")
			r.Header.Set("X-Keep", "1")
			p, err := a.AuthenticateNative(context.Background(), r)
			if err != nil || p.ID != string(idReconciler) {
				t.Fatalf("AuthenticateNative = %q, %v", p.ID, err)
			}
			for _, h := range []string{"X-Forwarded-Client-Cert", "Ssl-Client-Verify", "Ssl-Client-Subject-Dn", "X-Client-Cert"} {
				if _, ok := r.Header[h]; ok {
					t.Errorf("header %s reaches authorization", h)
				}
			}
			if r.Header.Get("X-Keep") != "1" {
				t.Error("an unrelated header was removed")
			}
		})
	}
}

// TestCloseAfter: only an expired connection record and a credential refused
// on an open connection close it.
func TestCloseAfter(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want bool
	}{
		{mtls.ErrConnectionExpired, true},
		{&adapter.NativeDenial{Reason: adapter.DenialCredentialRejected}, true},
		{&adapter.NativeDenial{Reason: adapter.DenialNoCredential}, false},
		{adapter.ErrDependencyUnavailable, false},
		{nil, false},
	} {
		rec := httptest.NewRecorder()
		if got := mtls.CloseAfter(rec, tc.err); got != tc.want || (rec.Header().Get("Connection") == "close") != tc.want {
			t.Errorf("CloseAfter(%v) = %t, header %q; want %t", tc.err, got, rec.Header().Get("Connection"), tc.want)
		}
	}
	if !errors.Is(mtls.ErrConnectionExpired, adapter.ErrDependencyUnavailable) {
		t.Error("ErrConnectionExpired is not a dependency error: the result must be DEFERRED")
	}
}
