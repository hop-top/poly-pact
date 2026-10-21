package mtls_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/enroll"
	enrollmem "hop.top/pact-go/adapter/enroll/memory"
	"hop.top/pact-go/adapter/installed"
	"hop.top/pact-go/adapters/memory"
	"hop.top/pact-go/adapters/mtls"
	"hop.top/pact-go/core"
	"hop.top/pact-go/core/clock"
)

// TestListAcceptance covers MTLS-11 and MTLS-12 (a) to (g): a list that fails
// a condition is not adopted and the held snapshot stays.
func TestListAcceptance(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	w := testWorld(t, "direct", now, now.Add(-10*time.Second))
	ca := w.authorities["workload-ca"]
	rogueKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// The same key under another subject name, and another CA.
	tmpl := *ca.cert
	tmpl.Subject, tmpl.RawSubject, tmpl.RawIssuer = pkix.Name{CommonName: "Other Name"}, nil, nil
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &ca.key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	sameKeyOtherName, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	other := otherCAWithKey(t, now, rogueKey)

	list := func(number int64, this, next time.Time, issuer *x509.Certificate, key *ecdsa.PrivateKey, mod func(*x509.RevocationList)) []byte {
		rl := &x509.RevocationList{Number: big.NewInt(number), ThisUpdate: this, NextUpdate: next}
		if mod != nil {
			mod(rl)
		}
		der, err := x509.CreateRevocationList(rand.Reader, rl, issuer, key)
		if err != nil {
			t.Fatal(err)
		}
		return der
	}
	good := func(n int64) []byte { return list(n, now.Add(-time.Second), now.Add(time.Hour), ca.cert, ca.key, nil) }
	critical := func(oid asn1.ObjectIdentifier) func(*x509.RevocationList) {
		return func(rl *x509.RevocationList) {
			rl.ExtraExtensions = append(rl.ExtraExtensions, pkix.Extension{Id: oid, Critical: true, Value: []byte{0x02, 0x01, 0x01}})
		}
	}
	entry := func(e x509.RevocationListEntry) func(*x509.RevocationList) {
		return func(rl *x509.RevocationList) { rl.RevokedCertificateEntries = append(rl.RevokedCertificateEntries, e) }
	}
	tampered := good(5)
	tampered[len(tampered)-3] ^= 0xFF

	for _, tc := range []struct {
		name string
		der  []byte
	}{
		{"(a) bad signature", tampered},
		{"(a) list of another CA", list(5, now.Add(-time.Second), now.Add(time.Hour), other, rogueKey, nil)},
		{"(b) same key, another issuer name", list(5, now.Add(-time.Second), now.Add(time.Hour), sameKeyOtherName, ca.key, nil)},
		{"(c) nextUpdate passed", list(5, now.Add(-2*time.Hour), now.Add(-time.Second), ca.cert, ca.key, nil)},
		{"(c) thisUpdate ahead of the clock", list(5, now.Add(6*time.Second), now.Add(time.Hour), ca.cert, ca.key, nil)},
		{"(d) critical unknown extension", list(5, now.Add(-time.Second), now.Add(time.Hour), ca.cert, ca.key, critical(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}))},
		{"(d) critical delta CRL indicator", list(5, now.Add(-time.Second), now.Add(time.Hour), ca.cert, ca.key, critical(asn1.ObjectIdentifier{2, 5, 29, 27}))},
		{"(d) critical issuing distribution point", list(5, now.Add(-time.Second), now.Add(time.Hour), ca.cert, ca.key, critical(asn1.ObjectIdentifier{2, 5, 29, 28}))},
		{"(d) critical entry extension", list(5, now.Add(-time.Second), now.Add(time.Hour), ca.cert, ca.key, entry(x509.RevocationListEntry{
			SerialNumber: big.NewInt(7), RevocationTime: now.Add(-time.Minute),
			ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 29}, Critical: true, Value: []byte{0x30, 0x00}}},
		}))},
		{"(e) removeFromCRL", list(5, now.Add(-time.Second), now.Add(time.Hour), ca.cert, ca.key, entry(x509.RevocationListEntry{
			SerialNumber: big.NewInt(7), RevocationTime: now.Add(-time.Minute), ReasonCode: 8,
		}))},
		{"(f) same CRL number", good(3)},
		{"(f) lower CRL number", good(2)},
		{"(g) oversize", list(5, now.Add(-time.Second), now.Add(time.Hour), ca.cert, ca.key, entry(x509.RevocationListEntry{
			SerialNumber: big.NewInt(7), RevocationTime: now.Add(-time.Minute), ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 2}, Value: make([]byte, 5000)}},
		}))},
		{"armored list", pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: good(5)})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ref, err := memoryOf(w, clock.NewFake(now))
			if err != nil {
				t.Fatal(err)
			}
			a, err := adapterOf(w, mtls.Config{Origin: "https://gateway.acme.example", Registry: ref, Permissions: commonPolicy{}, Clock: clock.NewFake(now), MaxCRLBytes: 2048})
			if err != nil {
				t.Fatal(err)
			}
			if err := a.Adopt("workload-ca-2026", good(3)); err != nil {
				t.Fatalf("held list: %v", err)
			}
			err = a.Adopt("workload-ca-2026", tc.der)
			if !errors.Is(err, mtls.ErrListRefused) {
				t.Fatalf("Adopt = %v, want ErrListRefused", err)
			}
			// The held snapshot, number 3, stays: a list numbered 4 is still
			// greater than it.
			if err := a.Adopt("workload-ca-2026", good(4)); err != nil {
				t.Errorf("the held snapshot changed: %v", err)
			}
		})
	}
	t.Run("control: a greater CRL number is adopted", func(t *testing.T) {
		a := testAdapter(t, w, clock.NewFake(now))
		if err := a.Adopt("workload-ca-2026", good(3)); err != nil {
			t.Fatal(err)
		}
		if err := a.Adopt("workload-ca-2026", good(4)); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("not a pinned CA", func(t *testing.T) {
		a := testAdapter(t, w, clock.NewFake(now))
		if err := a.Adopt("partner-ca-2026", good(3)); !errors.Is(err, mtls.ErrListRefused) {
			t.Errorf("Adopt = %v", err)
		}
	})
}

// otherCAWithKey is a self-signed CA with the subject text of the test
// world's CA and the key key.
func otherCAWithKey(t *testing.T, now time.Time, key *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(99), Subject: pkix.Name{CommonName: "Acme Workload CA 2026"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), BasicConstraintsValid: true, IsCA: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestEnrollmentRefusesSecondAgentOnWorkload is part (a) of MTLS-24: the
// enrollment that would add a second agent to a certificate-derived workload
// is refused, so the workload keeps one agent, which alone binds (IM-19).
func TestEnrollmentRefusesSecondAgentOnWorkload(t *testing.T) {
	ctx := context.Background()
	realm := adapter.Realm{TenantID: "acme", EnvironmentID: "https://gateway.acme.example/environments/reconciliation"}
	admin := enroll.Actor{Kind: enroll.Admin, ID: "identity-admin-1", Realm: realm}
	agentA := "https://agents.acme.example/reconciliation-assistant"
	agentB := "https://agents.acme.example/ledger-assistant"
	reg := enrollmem.New()
	if err := reg.Enroll(ctx, admin, enrollmem.Enrollment{
		AgentID: agentA, OperatorID: "https://operators.acme.example/finance-ops",
		Workload: idReconciler, HolderJKT: core.Digest("xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M"),
	}); err != nil {
		t.Fatalf("first agent: Enroll() = %v", err)
	}
	err := reg.Enroll(ctx, admin, enrollmem.Enrollment{
		AgentID: agentB, OperatorID: "https://operators.acme.example/finance-ops",
		Workload: idReconciler, HolderJKT: core.Digest("ahxE1XEYqxvLIZy3r4nx9RE4E0683KndykyuZTK9xQg"),
	})
	if !errors.Is(err, enroll.ErrWorkloadInUse) {
		t.Fatalf("second agent on the workload: Enroll() = %v, want ErrWorkloadInUse", err)
	}
	now := time.Now().Truncate(time.Second)
	w := testWorld(t, "direct", now, now)
	a, err := adapterOf(w, mtls.Config{Origin: "https://gateway.acme.example", Registry: reg, Permissions: commonPolicy{}, Clock: clock.NewFake(now)})
	if err != nil {
		t.Fatal(err)
	}
	b, err := a.ResolveAgentBinding(ctx, realm, idReconciler, adapter.AgentID(agentA))
	if err != nil || b.Status != adapter.BindingActive {
		t.Errorf("agent A: %+v, %v; want ACTIVE", b, err)
	}
	b, err = a.ResolveAgentBinding(ctx, realm, idReconciler, adapter.AgentID(agentB))
	if err != nil || b.Status != adapter.BindingUnknown || b.HolderJKT != "" {
		t.Errorf("agent B: %+v, %v; want UNKNOWN", b, err)
	}
}

// TestWorkloadClaim is MTLS-30: /attributes/environment/workload_id is the
// authenticated identifier with the times its authentication established; a
// direct listener gives the first evaluation of the connection as the
// observation time and u of its record as the status time, a terminated
// listener no observation time; another principal is refused.
func TestWorkloadClaim(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	u := now.Add(-30 * time.Second)
	for _, role := range []string{"direct", "terminated"} {
		t.Run(role, func(t *testing.T) {
			clk := clock.NewFake(now)
			w := testWorld(t, role, now, u)
			w.st.Forwarded = [][][]string{{{"Cert", "@cert:reconciler"}}}
			a := testAdapter(t, w, clk)
			r := a.Arrive(requestOf(t))
			ref := map[string]string{"direct": "reconciler", "terminated": "terminator"}[role]
			if err := w.Credential(r, ref); err != nil {
				t.Fatal(err)
			}
			p, err := a.AuthenticateNative(context.Background(), r)
			if err != nil {
				t.Fatal(err)
			}
			clk.Set(now.Add(10 * time.Second))
			c, err := a.ReadNativeClaim(context.Background(), mtls.PathWorkloadID, adapter.ClaimContext{Principal: p})
			if err != nil {
				t.Fatal(err)
			}
			wantObserved := now
			if role == "terminated" {
				wantObserved = time.Time{}
			}
			if c.Value != string(idReconciler) || !c.StatusCheckedAt.Equal(u) || !c.ObservedAt.Equal(wantObserved) || c.SourceID == "" {
				t.Errorf("claim = %+v; want %s, observed %v, status %v", c, idReconciler, wantObserved, u)
			}
			other := p
			other.Mechanism = "basic"
			if _, err := a.ReadNativeClaim(context.Background(), mtls.PathWorkloadID, adapter.ClaimContext{Principal: other}); !errors.Is(err, adapter.ErrContextMismatch) {
				t.Errorf("principal of another mechanism: %v, want CONTEXT_MISMATCH", err)
			}
			noTimes := p
			noTimes.Attributes = map[string]any{}
			if _, err := a.ReadNativeClaim(context.Background(), mtls.PathWorkloadID, adapter.ClaimContext{Principal: noTimes}); !errors.Is(err, adapter.ErrDependencyUnavailable) {
				t.Errorf("principal without times: %v, want DEPENDENCY_UNAVAILABLE", err)
			}
			if _, err := a.ReadNativeClaim(context.Background(), "/attributes/environment/business_unit", adapter.ClaimContext{Principal: p}); !errors.Is(err, adapter.ErrUnsupportedRequirement) {
				t.Errorf("path with no installed source: %v, want UNSUPPORTED_REQUIREMENT", err)
			}
		})
	}
}

// TestNoCheckOfItsOwn is MTLS-31: native-principal-binding-v1 is the
// validator's; the adapter does not answer it.
func TestNoCheckOfItsOwn(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	w := testWorld(t, "direct", now, now)
	a := testAdapter(t, w, clock.NewFake(now))
	out := a.CheckContext(context.Background(), "native-principal-binding-v1", adapter.CheckInput{Operation: core.OperationContext{PrincipalID: string(idReconciler)}})
	if out.Result != adapter.VerdictUnknown || out.ReasonCode != string(adapter.CodeUnsupportedRequirement) {
		t.Errorf("CheckContext = %+v, want UNKNOWN UNSUPPORTED_REQUIREMENT", out)
	}
}

// TestIdentifier pins the identifier of MTLS-6 against the example of
// identity-mapping section 3.3.
func TestIdentifier(t *testing.T) {
	got := mtls.Identifier("internal-ca-2026", mtls.SANKindURI, "spiffe://example.org/ns/prod/sa/runner")
	if want := adapter.Workload("mtls:internal-ca-2026:uri:spiffe%3A%2F%2Fexample.org%2Fns%2Fprod%2Fsa%2Frunner"); got != want {
		t.Errorf("Identifier = %s, want %s", got, want)
	}
}

func TestNewRefusesConfiguration(t *testing.T) {
	now := time.Now()
	w := testWorld(t, "direct", now, now)
	base := func() mtls.Config {
		return mtls.Config{Origin: "https://gateway.acme.example", Registry: enrollmem.New(), Permissions: commonPolicy{}, Clock: clock.NewFake(now)}
	}
	for name, mod := range map[string]func(*mtls.Config){
		"terminators on a direct listener": func(c *mtls.Config) { c.Terminators = []adapter.Workload{idTerminator} },
		"claim source for the workload id": func(c *mtls.Config) { c.Claims = map[string]installed.ClaimSource{mtls.PathWorkloadID: nil} },
	} {
		cfg := base()
		mod(&cfg)
		if _, err := adapterOf(w, cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	cfg := base()
	cfg.PinnedCAs = []mtls.CAEntry{{CAID: "x", Certificate: w.authorities["workload-ca"].cert, SANKind: "email"}}
	cfg.Role, cfg.Realm = mtls.RoleDirect, adapter.Realm{TenantID: "acme", EnvironmentID: "e"}
	if _, err := mtls.New(cfg); err == nil {
		t.Error("a pinned CA of san-kind email is accepted")
	}
}

// memoryOf is the reference enrollment source of the world's records.
func memoryOf(w *world, clk clock.Clock) (referenceRegistry, error) {
	ref, err := memory.New(w.commonState(), clk)
	return referenceRegistry{ref}, err
}

// rfc7638N is the modulus of the example key of RFC 7638, section 3.1, whose
// thumbprint is NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs.
const rfc7638N = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAt" +
	"VT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn6" +
	"4tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FD" +
	"W2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n9" +
	"1CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINH" +
	"aQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"

// TestKeyThumbprints is MTLS-9 for RSA and Ed25519 leaves: cnf.jkt is the
// RFC 7638 thumbprint of the leaf key, checked against the examples of RFC
// 7638, section 3.1, and RFC 8037, appendix A.3.
func TestKeyThumbprints(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	w := testWorld(t, "direct", now, now.Add(-10*time.Second))
	n, err := base64.RawURLEncoding.DecodeString(rfc7638N)
	if err != nil {
		t.Fatal(err)
	}
	x, err := base64.RawURLEncoding.DecodeString("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo")
	if err != nil {
		t.Fatal(err)
	}
	ca := w.authorities["workload-ca"]
	san, err := sanExtension([]string{uriReconciler}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		pub  any
		want string
	}{
		{"RSA", &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: 65537}, "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"},
		{"Ed25519", ed25519.PublicKey(x), "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tmpl := &x509.Certificate{
				SerialNumber: big.NewInt(5001), Subject: pkix.Name{CommonName: "reconciler"},
				NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, KeyUsage: x509.KeyUsageDigitalSignature,
				ExtraExtensions: []pkix.Extension{san},
			}
			der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, tc.pub, ca.key)
			if err != nil {
				t.Fatal(err)
			}
			leaf, err := x509.ParseCertificate(der)
			if err != nil {
				t.Fatal(err)
			}
			a := testAdapter(t, w, clock.NewFake(now))
			r := a.Arrive(requestOf(t))
			r.TLS = w.tlsState([]*x509.Certificate{leaf})
			p, err := a.AuthenticateNative(context.Background(), r)
			if err != nil {
				t.Fatal(err)
			}
			cnf, _ := p.Attributes[mtls.AttrConfirmation].(map[string]any)
			if cnf["jkt"] != tc.want {
				t.Errorf("cnf = %v, want %s", cnf, tc.want)
			}
		})
	}
}

// TestForwardedLeafStatus is MTLS-25: the status of a forwarded leaf is tested
// for every request; a revoked one is refused while the terminator's own
// connection stays served, and the refusal does not close the connection's
// record for the next request.
func TestForwardedLeafStatus(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	w := testWorld(t, "terminated", now, now.Add(-10*time.Second))
	w.st.Forwarded = [][][]string{{{"Cert", "@cert:reconciler"}}}
	clk := clock.NewFake(now)
	a := testAdapter(t, w, clk)
	r := a.Arrive(requestOf(t))
	auth := func() error {
		req := r.Clone(r.Context())
		if err := w.Credential(req, "terminator"); err != nil {
			t.Fatal(err)
		}
		_, err := a.AuthenticateNative(context.Background(), req)
		return err
	}
	if err := auth(); err != nil {
		t.Fatalf("first request: %v", err)
	}
	clk.Set(now.Add(5 * time.Second))
	if err := a.Adopt("workload-ca-2026", w.mintCRLAt(t, 2, clk.Now(), []int64{4097})); err != nil {
		t.Fatal(err)
	}
	var d *adapter.NativeDenial
	if err := auth(); !errors.As(err, &d) || d.PublicReason() != adapter.DenialCredentialRejected {
		t.Errorf("request forwarding a leaf revoked after the connection opened: %v, want CREDENTIAL_REJECTED", err)
	}
}
