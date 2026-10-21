package graph_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/adaptertest"
	"hop.top/pact-go/core"
	"hop.top/pact-go/core/binding"
	"hop.top/pact-go/core/clock"
)

// fallbackStub is the red baseline of the Graph cases and the mutant of the
// profile's mutation rule: the executor a deployment gets by wiring Graph in
// the obvious way. It maps every query of the mail routes and forwards it,
// follows any page token as given, passes every check, reads the claim at the
// time of the read, allows every operation and declares no execution
// visibility. Its executor exchanges token A by OBO and, when that fails,
// falls back to the client credentials grant of the executor application; it
// keeps the first token B it obtains for later operations, copies the
// client's headers downstream and runs no preflight.
type fallbackStub struct {
	form      string
	origin    string
	envID     string
	registry  []bindingRec
	cloud     *fakeCloud
	clk       clock.Clock
	frontDoor adapter.NativeAuthenticator
	cached    string
}

// stubPasses are the Graph cases the stub passes: the mapped controls, the
// requests that match no route, and the checks that pass.
var stubPasses = map[string]bool{
	"GRAPH-01.exact-query":        true,
	"GRAPH-01.app-exact-query":    true,
	"GRAPH-02.other-user-path":    true,
	"GRAPH-02.mailbox-header":     true,
	"GRAPH-06.delegated-binding":  true,
	"GRAPH-12.app-mailbox-header": true,
	"GRAPH-16.settled":            true,
	"GRAPH-10.continuation":       true,
	"GRAPH-10.app-continuation":   true,
}

// stubFactory builds the stub for a graph/1 case; it realizes no other model.
func stubFactory(t testing.TB, env adaptertest.Env) (adaptertest.Subject, error) {
	model, err := modelOf(env.State)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	if model != graphModel {
		return adaptertest.Subject{}, fmt.Errorf("stub: model %q is not realized", model)
	}
	st, err := parseState(env.State)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	s := &fallbackStub{form: st.Form, origin: st.Gateway.Origin, envID: st.Gateway.EnvironmentID, registry: st.Registry, cloud: newCloud(t, env.Hooks), clk: env.Clock}
	return adaptertest.Subject{
		Adapter:    s,
		Arrive:     func(r *http.Request) *http.Request { return r },
		Credential: func(*http.Request, string) error { return errors.New("stub: no credentials") },
	}, nil
}

// stubBrokerFactory is the stub as a broker of the unit tier.
func stubBrokerFactory(_ testing.TB, w *unitWorld) (broker, error) {
	return &fallbackStub{form: w.form, origin: uOrigin, envID: uEnv, registry: w.registry, cloud: w.cloud, clk: w.clk, frontDoor: w.frontDoor}, nil
}

func (s *fallbackStub) Describe() adapter.Descriptor {
	if s.form == formDelegated {
		return adapter.Descriptor{Protocol: "graph-delegated-obo", Version: "v1.0", MappingRevision: revision}
	}
	return adapter.Descriptor{Protocol: "graph-app-only", Version: "v1.0", MappingRevision: revision}
}

func (s *fallbackStub) AuthenticateNative(ctx context.Context, r *http.Request) (adapter.Principal, error) {
	if s.frontDoor != nil {
		return s.frontDoor.AuthenticateNative(ctx, r)
	}
	return adapter.Principal{}, &adapter.NativeDenial{Reason: adapter.DenialNoCredential}
}

func (s *fallbackStub) ResolveAgentBinding(context.Context, adapter.Realm, adapter.Workload, adapter.AgentID) (adapter.AgentBinding, error) {
	return adapter.AgentBinding{Status: adapter.BindingUnknown}, nil
}

func (s *fallbackStub) mailbox() string {
	for _, b := range s.registry {
		if b.MailboxID != "" {
			return b.MailboxID
		}
	}
	return ""
}

func (s *fallbackStub) MapOperation(_ context.Context, r *http.Request, p adapter.Principal, version string) (core.OperationContext, error) {
	cfg := binding.Config{Origin: s.origin, HeaderAllowlist: []string{"accept"}, HeaderNormalizationID: "stub-1", MappingVersion: version, MaxBody: 1 << 20}
	var resource string
	switch r.URL.Path {
	case "/mail/messages":
		resource = "mailbox:" + p.ID
	case "/mailbox/messages":
		resource = "mailbox:" + s.mailbox()
	default:
		return core.OperationContext{}, adapter.ErrUnsupportedRequirement
	}
	op, err := binding.FromRequest(cfg, r, p.ID, mailAction, []string{resource})
	if err != nil {
		return core.OperationContext{}, fmt.Errorf("%w: %w", err, adapter.ErrInvalidMessage)
	}
	op.OperationID = "stub-" + r.URL.RawQuery
	op.EnvironmentID = s.envID
	return op, nil
}

func (s *fallbackStub) ReadNativeClaim(_ context.Context, _ string, _ adapter.ClaimContext) (adapter.NativeClaim, error) {
	now := s.clk.Now()
	for _, b := range s.registry {
		return adapter.NativeClaim{Value: b.AppID, ObservedAt: now, StatusCheckedAt: now, SourceID: sourceRegistry}, nil
	}
	return adapter.NativeClaim{}, adapter.ErrUnsupportedRequirement
}

func (s *fallbackStub) CheckContext(context.Context, string, adapter.CheckInput) adapter.CheckOutcome {
	return adapter.CheckOutcome{Result: adapter.VerdictPass, ReasonCode: "REQUIREMENT_SATISFIED", SourceID: sourceRegistry, ObservedAt: s.clk.Now()}
}

func (s *fallbackStub) AuthorizeNative(context.Context, adapter.Principal, core.OperationContext) (adapter.Decision, error) {
	return adapter.Decision{Effect: adapter.EffectAllow, SourceID: "stub-policy"}, nil
}

func (s *fallbackStub) RecordOutcome(context.Context, adapter.Observation) (adapter.Recorded, error) {
	return adapter.NoVisibility{Reason: "the stub does not report"}, nil
}

func (s *fallbackStub) preflight(context.Context) {}

// token posts a token request and returns the access token.
func (s *fallbackStub) token(ctx context.Context, form url.Values) (string, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+loginHost+"/"+uTID+"/oauth2/v2.0/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := s.cloud.client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	var body struct {
		AccessToken string `json:"access_token"`
	}
	if resp.StatusCode != 200 || json.NewDecoder(resp.Body).Decode(&body) != nil || body.AccessToken == "" {
		return "", errors.New("token request failed")
	}
	return body.AccessToken, nil
}

func (s *fallbackStub) execute(ctx context.Context, in execInput) execution {
	tokenB := s.cached
	if tokenB == "" {
		var err error
		if s.form == formDelegated {
			tokenA := strings.TrimPrefix(in.req.Header.Get("Authorization"), "Bearer ")
			tokenB, err = s.token(ctx, url.Values{"grant_type": {grantOBO}, "client_id": {uGatewayApp}, "client_secret": {secretOBO},
				"assertion": {tokenA}, "scope": {scopeMail}, "requested_token_use": {"on_behalf_of"}})
		}
		if s.form != formDelegated || err != nil {
			tokenB, err = s.token(ctx, url.Values{"grant_type": {grantCC}, "client_id": {uExecApp}, "client_secret": {secretExecutor}, "scope": {scopeDefault}})
		}
		if err != nil {
			return execution{status: 503, err: err}
		}
		s.cached = tokenB
	}
	path := "/v1.0/me/messages"
	if s.form != formDelegated {
		path = "/v1.0/users/" + s.mailbox() + "/messages"
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, graphOrigin+path+"?"+in.req.URL.RawQuery, http.NoBody)
	for k, v := range in.req.Header {
		req.Header[k] = v
	}
	req.Header.Set("Authorization", "Bearer "+tokenB)
	resp, err := s.cloud.client.Do(req)
	if err != nil {
		return execution{status: 503, err: err}
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return execution{status: resp.StatusCode, err: errors.New("graph refused")}
	}
	return execution{status: 200, messages: raw, report: &report{kind: core.EventExecution, result: core.OutcomeSuccess, dimension: core.DimensionReliability}}
}
