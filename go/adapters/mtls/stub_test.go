package mtls_test

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/adaptertest"
	"hop.top/pact-go/core"
	"hop.top/pact-go/core/clock"
)

// stub is the red baseline of the mTLS cases: the adapter a gateway gets by
// wiring client certificates in the obvious way. It trusts the TLS stack's
// handshake and reads nothing else: it takes the identity from the
// forwarded-certificate header whenever one is present, without asking who
// sent it, and otherwise from the first peer certificate; it names the
// workload by the issuer's subject text and the first name of the
// certificate, checks no purpose, validity, revocation, TLS version or
// resumption, reports no key, and resolves the first enrollment of the
// workload as active whatever agent is named.
//
// Every mTLS case except those of stubPasses must fail against it; see
// TestStubFailsTheMTLSCases.
type stub struct {
	w   *world
	clk clock.Clock
}

// stubPasses are the mTLS cases that the stub passes: the one enrollment of a
// workload is also the first one, and a request without TLS has no
// certificate to read.
var stubPasses = map[string]bool{"MTLS-24.dedicated": true, "MTLS-08.cleartext": true}

// stubFactory builds the stub for an mtls/1 case; it realizes no other model.
func stubFactory(_ testing.TB, env adaptertest.Env) (adaptertest.Subject, error) {
	model, err := modelOf(env.State)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	if model != mtlsModel {
		return adaptertest.Subject{}, fmt.Errorf("stub: model %q is not realized", model)
	}
	w, err := loadWorld(env.State)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	s := &stub{w: w, clk: env.Clock}
	return adaptertest.Subject{
		Adapter:    s,
		Arrive:     func(r *http.Request) *http.Request { return r },
		Credential: w.Credential,
	}, nil
}

func (s *stub) Describe() adapter.Descriptor {
	return adapter.Descriptor{Protocol: "mtls", Version: "1.3", MappingRevision: "pact-mtls-1"}
}

func (s *stub) realm() adapter.Realm {
	return adapter.Realm{TenantID: s.w.st.Listener.TenantID, EnvironmentID: s.w.st.Listener.EnvironmentID}
}

// forwarded returns the first Cert of the forwarded header, if it decodes.
func forwarded(r *http.Request) *x509.Certificate {
	for _, pair := range strings.FieldsFunc(r.Header.Get(xfccHeader), func(c rune) bool { return c == ';' || c == ',' }) {
		k, v, _ := strings.Cut(pair, "=")
		if !strings.EqualFold(k, "Cert") {
			continue
		}
		raw, err := url.PathUnescape(strings.Trim(v, `"`))
		if err != nil {
			return nil
		}
		b, _ := pem.Decode([]byte(raw))
		if b == nil {
			return nil
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil
		}
		return c
	}
	return nil
}

func (s *stub) AuthenticateNative(_ context.Context, r *http.Request) (adapter.Principal, error) {
	cert := forwarded(r)
	if cert == nil && r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		cert = r.TLS.PeerCertificates[0]
	}
	if cert == nil {
		return adapter.Principal{}, &adapter.NativeDenial{Reason: adapter.DenialNoCredential}
	}
	kind, name := "dns", ""
	if len(cert.URIs) > 0 {
		kind, name = "uri", cert.URIs[0].String()
	} else if len(cert.DNSNames) > 0 {
		name = cert.DNSNames[0]
	}
	id := "mtls:" + url.PathEscape(cert.Issuer.CommonName) + ":" + kind + ":" + url.PathEscape(name)
	return adapter.Principal{
		ID: id, Realm: s.realm(), Workload: adapter.Workload(id), Mechanism: "mtls", AuthenticatedAt: s.clk.Now(),
	}, nil
}

func (s *stub) ResolveAgentBinding(_ context.Context, realm adapter.Realm, workload adapter.Workload, _ adapter.AgentID) (adapter.AgentBinding, error) {
	for _, e := range s.w.st.Enrollments {
		if e.Workload != string(workload) || e.Realm.TenantID != realm.TenantID || e.Realm.EnvironmentID != realm.EnvironmentID {
			continue
		}
		return adapter.AgentBinding{
			AgentID: e.AgentID, OperatorID: e.OperatorID, HolderJKT: core.Digest(e.HolderJKT),
			Status: adapter.BindingActive, SourceID: e.SourceID, SourceRef: e.SourceRef,
			ObservedAt: s.clk.Now(), StatusCheckedAt: s.clk.Now(),
		}, nil
	}
	return adapter.AgentBinding{Status: adapter.BindingUnknown}, nil
}

func (s *stub) MapOperation(context.Context, *http.Request, adapter.Principal, string) (core.OperationContext, error) {
	return core.OperationContext{}, adapter.ErrUnsupportedRequirement
}

func (s *stub) ReadNativeClaim(_ context.Context, _ string, c adapter.ClaimContext) (adapter.NativeClaim, error) {
	return adapter.NativeClaim{Value: string(c.Principal.Workload), ObservedAt: s.clk.Now(), SourceID: "stub"}, nil
}

func (s *stub) CheckContext(context.Context, string, adapter.CheckInput) adapter.CheckOutcome {
	return adapter.CheckOutcome{Result: adapter.VerdictPass, ReasonCode: "REQUIREMENT_SATISFIED", SourceID: "stub", ObservedAt: s.clk.Now()}
}

func (s *stub) AuthorizeNative(context.Context, adapter.Principal, core.OperationContext) (adapter.Decision, error) {
	return adapter.Decision{Effect: adapter.EffectAllow, SourceID: "stub"}, nil
}

func (s *stub) RecordOutcome(context.Context, adapter.Observation) (adapter.Recorded, error) {
	return adapter.NoVisibility{Reason: "stub"}, nil
}

// TestStubFailsTheMTLSCases is the red baseline: the mTLS cases catch the
// naive adapter. Every mTLS case fails against the stub except those of
// stubPasses, which pass.
func TestStubFailsTheMTLSCases(t *testing.T) {
	results, err := adaptertest.Evaluate(t, stubFactory, adaptertest.Options{Adapter: "mtls"})
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, r := range results {
		if !strings.HasPrefix(r.ID, "MTLS-") {
			continue
		}
		seen++
		switch {
		case stubPasses[r.ID] && !r.Passed():
			t.Errorf("%s fails against the stub, which is expected to pass it: %v", r.ID, r.Failures)
		case !stubPasses[r.ID] && r.Passed():
			t.Errorf("%s passes against the stub: the case does not catch the naive adapter", r.ID)
		}
	}
	if seen == 0 {
		t.Fatal("no mTLS case ran")
	}
}
