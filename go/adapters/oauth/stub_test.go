package oauth_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/adaptertest"
	"hop.top/pact-go/core"
	"hop.top/pact-go/core/clock"
)

// stub is the red baseline of the OAuth cases: the adapter a gateway gets by
// wiring bearer tokens in the obvious way. It takes the first Authorization
// value, whatever its scheme, or the access_token query parameter; it decodes
// a JWT's claims without checking the signature, the algorithm, the issuer,
// the tenant, the audience, the client, the scope or the times; it trusts an
// introspection response whose active is true and reads nothing else of it,
// and treats an endpoint that does not answer as a denial; it ignores the
// enforcement marker and sender constraints, reports no token facts, and
// resolves the first enrollment of a workload as active whatever agent is
// named.
//
// Every OAuth case except those of stubPasses must fail against it; see
// TestStubFailsTheOAuthCases.
type stub struct {
	w   *world
	clk clock.Clock
}

// stubPasses are the OAuth cases the stub passes, each because the stub's one
// check is the case's whole requirement: no Authorization value and no query
// token is no credential; active false and an unknown token are refused; a
// token in a form body is never seen; a JWS-shaped token on a form I route is
// introspected; the one enrollment of a workload is also the first; a
// workload with no enrollment has none; and a five-segment token is no JWS to
// the stub, which asks an introspection endpoint that a form G state does not
// have, and refuses.
var stubPasses = map[string]bool{
	"OAUTH-01.no-header":                  true,
	"OAUTH-01.body-only":                  true,
	"OAUTH-01.jwt-route-no-header":        true,
	"OAUTH-03.inactive":                   true,
	"OAUTH-03.inactive-with-facts":        true,
	"OAUTH-20.introspection":              true,
	"OAUTH-24.jwt-on-introspection-route": true,
	"OAUTH-25.inactive":                   true,
	"OAUTH-28.dedicated":                  true,
	"OAUTH-19.same-client-binding":        true,
	"OAUTH-25.not-enrolled":               true,
	"OAUTH-35.jwe":                        true,
	"OAUTH-39.bound":                      true,
}

// stubFactory builds the stub for an oauth/1 case; it realizes no other model.
func stubFactory(_ testing.TB, env adaptertest.Env) (adaptertest.Subject, error) {
	model, err := modelOf(env.State)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	if model != oauthModel {
		return adaptertest.Subject{}, fmt.Errorf("stub: model %q is not realized", model)
	}
	w, err := loadWorld(env.State, env.Hooks)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	w.attachProof = func(r *http.Request, _ string) *http.Request { return r }
	s := &stub{w: w, clk: env.Clock}
	return adaptertest.Subject{
		Adapter:    s,
		Arrive:     func(r *http.Request) *http.Request { return r },
		Credential: w.Credential,
	}, nil
}

func (s *stub) Describe() adapter.Descriptor {
	return adapter.Descriptor{Protocol: "oauth-introspection", Version: "rfc7662", MappingRevision: "pact-oauth-1"}
}

func (s *stub) realm() adapter.Realm {
	return adapter.Realm{TenantID: s.w.st.Gateway.TenantID, EnvironmentID: s.w.st.Gateway.EnvironmentID}
}

// entry returns the entry of the route whose method and path template match
// the request.
func (s *stub) entry(r *http.Request) (entryState, bool) {
	segs := strings.Split(r.URL.Path, "/")
	for _, rt := range s.w.st.Routes {
		tmpl := strings.Split(rt.Path, "/")
		if rt.Method != r.Method || len(tmpl) != len(segs) {
			continue
		}
		match := true
		for i, t := range tmpl {
			if !strings.HasPrefix(t, "{") && t != segs[i] {
				match = false
			}
		}
		if !match {
			continue
		}
		for _, e := range s.w.st.Entries {
			if e.ID == rt.Entry {
				return e, true
			}
		}
	}
	return entryState{}, false
}

func ident(issuer, tenant, local string) string {
	return "oauth:" + url.QueryEscape(issuer) + ":" + url.QueryEscape(tenant) + ":" + url.QueryEscape(local)
}

func (s *stub) AuthenticateNative(ctx context.Context, r *http.Request) (adapter.Principal, error) {
	token := ""
	if v := r.Header.Get("Authorization"); v != "" {
		_, token, _ = strings.Cut(v, " ")
	} else {
		token = r.URL.Query().Get("access_token")
	}
	if token == "" {
		return adapter.Principal{}, &adapter.NativeDenial{Reason: adapter.DenialNoCredential}
	}
	e, ok := s.entry(r)
	if !ok {
		return adapter.Principal{}, &adapter.NativeDenial{Reason: adapter.DenialCredentialRejected}
	}
	reject := &adapter.NativeDenial{Reason: adapter.DenialCredentialRejected}
	if parts := strings.Split(token, "."); len(parts) == 3 && e.Form != "introspection" {
		raw, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			return adapter.Principal{}, reject
		}
		var c map[string]any
		if json.Unmarshal(raw, &c) != nil {
			return adapter.Principal{}, reject
		}
		str := func(names ...string) string {
			for _, n := range names {
				if v, ok := c[n].(string); ok && v != "" {
					return v
				}
			}
			return ""
		}
		iss, tid := str("iss"), str("tid")
		id := ident(iss, tid, str("oid", "sub"))
		return adapter.Principal{ID: id, Realm: s.realm(), Workload: adapter.Workload(ident(iss, tid, str("azp", "appid"))),
			Mechanism: "oauth", AuthenticatedAt: s.clk.Now()}, nil
	}
	if e.IntrospectionEndpoint == "" {
		// A token that is not a JWT goes to the first introspection
		// endpoint the gateway knows.
		for _, other := range s.w.st.Entries {
			if other.IntrospectionEndpoint != "" {
				e = other
				break
			}
		}
	}
	form := url.Values{"token": {token}, "token_type_hint": {"access_token"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.IntrospectionEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return adapter.Principal{}, reject
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape(e.GatewayClientID), url.QueryEscape(e.GatewayClientSecret))
	resp, err := s.w.client().Do(req)
	if err != nil {
		return adapter.Principal{}, reject
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	var ir map[string]any
	if json.Unmarshal(body, &ir) != nil || ir["active"] != true {
		return adapter.Principal{}, reject
	}
	sub, _ := ir["sub"].(string)
	client, _ := ir["client_id"].(string)
	tenant := e.Tenant
	return adapter.Principal{ID: ident(e.Issuer, tenant, sub), Realm: s.realm(), Workload: adapter.Workload(ident(e.Issuer, tenant, client)),
		Mechanism: "oauth", AuthenticatedAt: s.clk.Now()}, nil
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

// TestStubFailsTheOAuthCases is the red baseline: the OAuth cases catch the
// naive adapter. Every OAuth case fails against the stub except those of
// stubPasses, which pass. Among them, the cases of profile section 10 that a
// stub trusting active true alone and skipping aud must fail: a missing aud
// (OAUTH-04.no-aud), another resource (OAUTH-05.other-resource), and a token
// for Microsoft Graph (OAUTH-10.graph).
func TestStubFailsTheOAuthCases(t *testing.T) {
	results, err := adaptertest.Evaluate(t, stubFactory, adaptertest.Options{Adapter: "oauth"})
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, r := range results {
		if !strings.HasPrefix(r.ID, "OAUTH-") {
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
		t.Fatal("no OAuth case ran")
	}
	for _, id := range []string{"OAUTH-04.no-aud", "OAUTH-05.other-resource", "OAUTH-10.graph"} {
		if stubPasses[id] {
			t.Errorf("%s must catch a stub that trusts active true alone and skips aud", id)
		}
	}
}
