package saml_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/adaptertest"
	"hop.top/pact-go/core"
	"hop.top/pact-go/core/clock"
)

// stub is the red baseline of the SAML cases: the adapter a broker gets by
// wiring a SAML session to an agent in the obvious way. It never checks the
// enforcement marker; it names the principal from an X-Principal header (the
// principal the request or its profile claims), else from a session cookie
// the request carries, else from the user the grant of the task records,
// without reading the grant's session, and an agent with a valid broker token
// and no grant becomes a principal of its own; it resolves the first
// enrollment of a workload, labels a membership fact with the login time of
// the session, passes every check, and allows every operation.
//
// Every SAML case except those of stubPasses must fail against it; see
// TestStubFailsTheSAMLCases.
type stub struct {
	w   *world
	clk clock.Clock
}

// stubPasses are the SAML cases that the stub passes: positive cases in which
// the user the grant records is the principal of its live session, and the
// token's workload is the workload, and the usable grant, which a check that
// passes everything passes.
var stubPasses = map[string]bool{
	"SAML-02.session-unchanged": true,
	"SAML-04.before-expiry":     true,
	"SAML-07.usable":            true,
	"SAML-17.idp-realm":         true,
	"SAML-17.other-user":        true,
}

// stubFactory builds the stub for a saml/1 case; it realizes no other model.
func stubFactory(_ testing.TB, env adaptertest.Env) (adaptertest.Subject, error) {
	model, err := modelOf(env.State)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	if model != samlModel {
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
		Credential: func(r *http.Request, ref string) error { return attachCredential(w.st.Agents, r, ref) },
	}, nil
}

func (s *stub) Describe() adapter.Descriptor {
	return adapter.Descriptor{Protocol: "saml", Version: "2.0", MappingRevision: "pact-saml-1"}
}

func (s *stub) grant(task string) (grantRecord, bool) {
	for _, g := range s.w.st.Grants {
		if g.TaskID == task {
			return g, true
		}
	}
	return grantRecord{}, false
}

func (s *stub) AuthenticateNative(_ context.Context, r *http.Request) (adapter.Principal, error) {
	p := adapter.Principal{Realm: s.w.realm(), Mechanism: "saml", AuthenticatedAt: s.clk.Now()}
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	for _, a := range s.w.st.Agents {
		if token != "" && a.Token == token {
			p.Workload = adapter.Workload(a.Workload)
		}
	}
	if token != "" && p.Workload == "" {
		return adapter.Principal{}, fmt.Errorf("stub: unknown broker token %q: %w", token, adapter.ErrDependencyUnavailable)
	}
	if v := r.Header.Get("X-Principal"); v != "" {
		p.ID = v
		return p, nil
	}
	if c, err := r.Cookie("portal_session"); err == nil {
		for _, ss := range s.w.sessions {
			if ss.Credential == c.Value {
				p.ID = ss.Principal
				return p, nil
			}
		}
	}
	if p.Workload == "" {
		return adapter.Principal{}, &adapter.NativeDenial{Reason: adapter.DenialNoCredential}
	}
	if task, ok := taskOfPath(r.URL.EscapedPath()); ok {
		if g, ok := s.grant(task); ok {
			p.ID = g.User
			return p, nil
		}
	}
	p.ID = string(p.Workload)
	return p, nil
}

func (s *stub) ResolveAgentBinding(_ context.Context, realm adapter.Realm, workload adapter.Workload, _ adapter.AgentID) (adapter.AgentBinding, error) {
	for _, e := range s.w.st.Enrollments {
		if e.Workload == string(workload) {
			return adapter.AgentBinding{
				AgentID: e.AgentID, OperatorID: e.OperatorID, HolderJKT: core.Digest(e.HolderJKT),
				Status: adapter.BindingStatus(e.Status), SourceID: e.SourceID,
				ObservedAt: s.clk.Now(), StatusCheckedAt: s.clk.Now(),
			}, nil
		}
	}
	return adapter.AgentBinding{Status: adapter.BindingUnknown}, nil
}

func (s *stub) MapOperation(_ context.Context, r *http.Request, p adapter.Principal, _ string) (core.OperationContext, error) {
	return core.OperationContext{
		OperationID: "op-stub", EnvironmentID: s.w.st.Gateway.EnvironmentID, PrincipalID: p.ID,
		Action: "record.read", Resources: []string{"record"}, Method: r.Method,
		TargetURI: s.w.st.Gateway.Origin + r.URL.Path, BodyDigest: "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU",
		Headers: map[string]string{},
	}, nil
}

func (s *stub) ReadNativeClaim(_ context.Context, nativePath string, c adapter.ClaimContext) (adapter.NativeClaim, error) {
	login := s.clk.Now()
	if g, ok := s.grant(c.Intent.TaskID); ok {
		if ss, ok := s.w.session(g.SessionID); ok {
			login = time.Unix(ss.AuthnInstant, 0)
		}
	}
	for _, rec := range s.w.st.Claims {
		if rec.Path == nativePath && rec.Principal == c.Principal.ID {
			var v any
			if err := json.Unmarshal(rec.Value, &v); err != nil {
				return adapter.NativeClaim{}, err
			}
			return adapter.NativeClaim{Value: v, ObservedAt: login, StatusCheckedAt: login, SourceID: rec.SourceID}, nil
		}
	}
	return adapter.NativeClaim{Value: c.Principal.ID, ObservedAt: login, StatusCheckedAt: login, SourceID: sessionSource}, nil
}

func (s *stub) CheckContext(context.Context, string, adapter.CheckInput) adapter.CheckOutcome {
	return adapter.CheckOutcome{Result: adapter.VerdictPass, ReasonCode: "REQUIREMENT_SATISFIED", SourceID: grantSource, ObservedAt: s.clk.Now()}
}

func (s *stub) AuthorizeNative(context.Context, adapter.Principal, core.OperationContext) (adapter.Decision, error) {
	return adapter.Decision{Effect: adapter.EffectAllow, SourceID: "portal-policy"}, nil
}

func (s *stub) RecordOutcome(context.Context, adapter.Observation) (adapter.Recorded, error) {
	return nil, adapter.ErrUnsupportedRequirement
}

// TestStubFailsTheSAMLCases is the red baseline: the SAML cases catch the
// naive adapter. Every SAML case fails against the stub except those of
// stubPasses, which pass.
func TestStubFailsTheSAMLCases(t *testing.T) {
	results, err := adaptertest.Evaluate(t, stubFactory, adaptertest.Options{Adapter: "saml"})
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, r := range results {
		if !strings.HasPrefix(r.ID, "SAML-") {
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
		t.Fatal("no SAML case ran")
	}
}

// TestStubFailsSAML03WithAProfilePrincipal is the mutation rule of the SAML-03
// cases: an adapter that takes the principal from the principal the request
// claims fails each of them.
func TestStubFailsSAML03WithAProfilePrincipal(t *testing.T) {
	results, err := adaptertest.Evaluate(t, stubFactory, adaptertest.Options{Adapter: "saml"})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range results {
		if strings.HasPrefix(r.ID, "SAML-03.") && r.Passed() {
			t.Errorf("%s passes against the stub that names the claimed principal", r.ID)
		}
	}
}
