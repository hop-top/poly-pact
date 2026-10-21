package k8s_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/adaptertest"
	"hop.top/pact-go/core"
	"hop.top/pact-go/core/clock"
)

// stub is the red baseline of the Kubernetes cases: the adapter a gateway gets
// by wiring TokenReview in the obvious way. It sends the caller's bearer token
// to TokenReview with the gateway audience, forwarding the caller's other
// headers as a proxy would, and accepts any answer with authenticated true:
// it reads no status.audiences, no uid, no groups and no pod claim, reads no
// pod, runs no preflight and ignores the enforcement marker. It names the
// principal k8s:{cluster-id}:{username}, resolves the first enrollment of a
// workload as active whatever agent is named, answers every claim with the
// workload, passes every check and allows every operation.
//
// With omitAudiences set it also leaves spec.audiences out of the review, so
// that the API server reviews the token for its own audience.
//
// Every Kubernetes case except those of stubPasses must fail against it; see
// TestStubFailsTheK8sCases.
type stub struct {
	w             *world
	clk           clock.Clock
	omitAudiences bool
}

// stubPasses are the Kubernetes cases the stub passes, each because the
// stub's one check is the case's whole requirement: a token the pinned API
// server does not authenticate for the gateway audience is refused (a token
// of another cluster, a token for another audience); a request no route
// matches is unsupported, because the stub maps nothing; the one enrollment of
// a workload is also its first; and the executor of the registered account
// passes the check that the stub passes always.
var stubPasses = map[string]bool{
	"K8S-07.registered-account":  true,
	"K8S-02.other-audience":      true,
	"K8S-03.other-cluster-token": true,
	"K8S-10.other-namespace":     true,
	"K8S-10.bad-name":            true,
	"K8S-14.dedicated":           true,
}

// stubFactory builds the stub for a k8s/1 case; it realizes no other model.
func stubFactory(omitAudiences bool) adaptertest.Factory {
	return func(tb testing.TB, env adaptertest.Env) (adaptertest.Subject, error) {
		model, err := modelOf(env.State)
		if err != nil {
			return adaptertest.Subject{}, err
		}
		if model != k8sModel {
			return adaptertest.Subject{}, fmt.Errorf("stub: model %q is not realized", model)
		}
		w, err := loadWorld(tb, env.State, env.Clock.Now())
		if err != nil {
			return adaptertest.Subject{}, err
		}
		s := &stub{w: w, clk: env.Clock, omitAudiences: omitAudiences}
		return adaptertest.Subject{
			Adapter:    s,
			Arrive:     func(r *http.Request) *http.Request { return r },
			Credential: w.Credential,
		}, nil
	}
}

func (s *stub) Describe() adapter.Descriptor {
	return adapter.Descriptor{Protocol: "kubernetes-serviceaccount", Version: "authentication.k8s.io/v1+authorization.k8s.io/v1", MappingRevision: "pact-k8s-1"}
}

func (s *stub) realm() adapter.Realm {
	return adapter.Realm{TenantID: s.w.st.Gateway.TenantID, EnvironmentID: s.w.st.Gateway.EnvironmentID}
}

func (s *stub) AuthenticateNative(ctx context.Context, r *http.Request) (adapter.Principal, error) {
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || token == "" {
		return adapter.Principal{}, &adapter.NativeDenial{Reason: adapter.DenialNoCredential}
	}
	reject := &adapter.NativeDenial{Reason: adapter.DenialCredentialRejected}
	spec := map[string]any{"token": token}
	if !s.omitAudiences {
		spec["audiences"] = []string{s.w.st.Cluster.GatewayAudience}
	}
	body, _ := json.Marshal(map[string]any{"apiVersion": "authentication.k8s.io/v1", "kind": "TokenReview", "spec": spec})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.w.apiServer()+pathTokenReviews, bytes.NewReader(body))
	if err != nil {
		return adapter.Principal{}, reject
	}
	for name, values := range r.Header {
		if !strings.EqualFold(name, "Authorization") {
			req.Header[name] = values
		}
	}
	req.Header.Set("Authorization", "Bearer "+s.w.st.GatewayAccount.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.w.client().Do(req)
	if err != nil {
		return adapter.Principal{}, reject
	}
	defer func() { _ = resp.Body.Close() }()
	var tr struct {
		Status struct {
			Authenticated bool `json:"authenticated"`
			User          struct {
				Username string `json:"username"`
			} `json:"user"`
		} `json:"status"`
	}
	if json.NewDecoder(resp.Body).Decode(&tr) != nil || !tr.Status.Authenticated {
		return adapter.Principal{}, reject
	}
	id := "k8s:" + s.w.st.Cluster.ClusterID + ":" + tr.Status.User.Username
	return adapter.Principal{ID: id, Realm: s.realm(), Workload: adapter.Workload(id), Mechanism: "kubernetes-serviceaccount", AuthenticatedAt: s.clk.Now()}, nil
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

// TestStubFailsTheK8sCases is the red baseline: the Kubernetes cases catch the
// naive adapter. Every Kubernetes case fails against the stub except those of
// stubPasses, which pass. Among them, the audience cases of profile section
// 10 (K8S-02) that a stub reading no status.audiences must fail.
func TestStubFailsTheK8sCases(t *testing.T) {
	results, err := adaptertest.Evaluate(t, stubFactory(false), adaptertest.Options{Adapter: "k8s"})
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, r := range results {
		if !strings.HasPrefix(r.ID, "K8S-") {
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
		t.Fatal("no Kubernetes case ran")
	}
	for _, id := range []string{"K8S-02.empty-audiences", "K8S-02.lacks-gateway-audience", "K8S-02.requirements-endpoint"} {
		if stubPasses[id] {
			t.Errorf("%s must catch a stub that reads no status.audiences", id)
		}
	}
}

// TestOmittedAudienceFailsK8S02 is the other half of the mutation rule of the
// audience cases: a stub that also leaves spec.audiences out of the review,
// so that the API server reviews the token for its own audience, accepts the
// token for the API server's audience and fails K8S-02.other-audience, the
// case the first stub passes. The first stub fails the other three.
func TestOmittedAudienceFailsK8S02(t *testing.T) {
	results, err := adaptertest.Evaluate(t, stubFactory(true), adaptertest.Options{Adapter: "k8s"})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range results {
		if r.ID == "K8S-02.other-audience" {
			if r.Passed() {
				t.Error("K8S-02.other-audience passes against a stub that omits spec.audiences")
			}
			return
		}
	}
	t.Fatal("K8S-02.other-audience did not run")
}
