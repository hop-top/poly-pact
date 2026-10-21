package files_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/adaptertest"
	"hop.top/pact-go/adapter/installed"
	"hop.top/pact-go/core"
	"hop.top/pact-go/core/binding"
	"hop.top/pact-go/core/clock"
)

// stub is a naive file broker: the red baseline of the files cases. It
// believes an identity header, names the principal by the bare user SID,
// keeps a connection's context forever, resolves the first enrollment of an
// account as active whatever agent is named, maps any method and query, reads
// claims at the time of the read, passes every check, and opens the
// configured path without any check of the object it opened.
//
// In mode stubFallback it impersonates the user and, when that fails, opens
// as the service account: the broader-account fallback that profile B2
// closes. In mode stubService it never impersonates and opens every file as
// the service account.
type stub struct {
	w    *world
	mode string
	clk  clock.Clock
}

const (
	stubFallback = "fallback"
	stubService  = "service"
)

// stubControls are the files cases that every stub passes: the controls that
// show a correct broker is not refusing everything.
var stubControls = map[string]bool{
	"FILES-01.check-impersonated": true,
	"FILES-06.read-mapped":        true,
	"FILES-10.agent-a":            true,
}

type stubConnKey struct{}

func stubFactory(mode string) adaptertest.Factory {
	return func(_ testing.TB, env adaptertest.Env) (adaptertest.Subject, error) {
		model, err := modelOf(env.State)
		if err != nil {
			return adaptertest.Subject{}, err
		}
		if model != filesModel {
			return adaptertest.Subject{}, fmt.Errorf("stub: model %q is not realized", model)
		}
		w, err := loadWorld(env.State)
		if err != nil {
			return adaptertest.Subject{}, err
		}
		w.hooks = env.Hooks
		s := &stub{w: w, mode: mode, clk: env.Clock}
		return adaptertest.Subject{
			Adapter: s,
			Arrive: func(r *http.Request) *http.Request {
				if c := w.st.Connection; c != nil {
					return r.WithContext(context.WithValue(r.Context(), stubConnKey{}, c.Account))
				}
				return r
			},
			Credential: w.Credential,
		}, nil
	}
}

func (s *stub) Describe() adapter.Descriptor {
	return adapter.Descriptor{Protocol: "http", Version: "1.1", MappingRevision: "pact-files-1"}
}

func (s *stub) principalOf(a *accountState) adapter.Principal {
	id := "files:" + a.SID
	return adapter.Principal{ID: id, Realm: s.w.realm(), Workload: adapter.Workload(id), Mechanism: "negotiate", AuthenticatedAt: s.clk.Now()}
}

func (s *stub) AuthenticateNative(_ context.Context, r *http.Request) (adapter.Principal, error) {
	if ref := r.Header.Get("X-Remote-User"); ref != "" {
		if a, ok := s.w.byRef[strings.TrimPrefix(ref, `ACME\`)]; ok {
			return s.principalOf(a), nil
		}
	}
	h := r.Header.Get("Authorization")
	if tok, ok := strings.CutPrefix(h, "Negotiate "); ok {
		if a, ok := s.w.byToken[tok]; ok {
			return s.principalOf(a), nil
		}
		return adapter.Principal{}, fmt.Errorf("stub: token %s rejected: %w", tok, &adapter.NativeDenial{Reason: adapter.DenialCredentialRejected})
	}
	if h != "" {
		return adapter.Principal{}, &adapter.NativeDenial{Reason: adapter.DenialCredentialRejected}
	}
	if ref, ok := r.Context().Value(stubConnKey{}).(string); ok {
		return s.principalOf(s.w.byRef[ref]), nil
	}
	return adapter.Principal{}, &adapter.NativeDenial{Reason: adapter.DenialNoCredential}
}

func (s *stub) ResolveAgentBinding(_ context.Context, _ adapter.Realm, workload adapter.Workload, _ adapter.AgentID) (adapter.AgentBinding, error) {
	for _, raw := range s.w.st.Enrollments {
		var e struct {
			Workload   string `json:"workload"`
			AgentID    string `json:"agent_id"`
			OperatorID string `json:"operator_id"`
			HolderJKT  string `json:"holder_jkt"`
			SourceID   string `json:"source_id"`
		}
		if err := json.Unmarshal(raw, &e); err != nil {
			return adapter.AgentBinding{}, err
		}
		if e.Workload != string(workload) {
			continue
		}
		return adapter.AgentBinding{
			AgentID: e.AgentID, OperatorID: e.OperatorID, HolderJKT: core.Digest(e.HolderJKT),
			Status: adapter.BindingActive, SourceID: e.SourceID, ObservedAt: s.clk.Now(), StatusCheckedAt: s.clk.Now(),
		}, nil
	}
	return adapter.AgentBinding{Status: adapter.BindingUnknown}, nil
}

func (s *stub) MapOperation(_ context.Context, r *http.Request, p adapter.Principal, version string) (core.OperationContext, error) {
	routes := []installed.Route{
		{Method: http.MethodGet, Path: "/files/{file_id}/content", Action: "file.read", Resource: "file:{file_id}"},
		{Method: http.MethodPut, Path: "/files/{file_id}/content", Action: "file.write", Resource: "file:{file_id}"},
		{Method: http.MethodDelete, Path: "/files/{file_id}/content", Action: "file.delete", Resource: "file:{file_id}"},
		{Method: http.MethodGet, Path: "/files/{file_id}/content/raw", Action: "file.read", Resource: "file:{file_id}"},
	}
	cfg := binding.Config{Origin: s.w.st.Gateway.Origin, HeaderAllowlist: s.w.st.Gateway.HeaderAllowlist,
		HeaderNormalizationID: "pact-files-header-normalization-1", MappingVersion: version, MaxBody: 1 << 20}
	return installed.MapRequest(cfg, routes, s.w.st.Gateway.EnvironmentID, r, p)
}

func (s *stub) account(p adapter.Principal) *accountState {
	return s.w.bySID[p.ID[strings.LastIndex(p.ID, ":")+1:]]
}

func (s *stub) ReadNativeClaim(_ context.Context, path string, cc adapter.ClaimContext) (adapter.NativeClaim, error) {
	a := s.account(cc.Principal)
	if a == nil {
		return adapter.NativeClaim{}, adapter.ErrContextMismatch
	}
	var v any = cc.Principal.ID
	if path != "/attributes/environment/principal_id" {
		gs := []any{}
		for _, g := range a.Groups {
			gs = append(gs, "files:"+g)
		}
		v = gs
	}
	return adapter.NativeClaim{Value: v, ObservedAt: s.clk.Now(), StatusCheckedAt: s.clk.Now(), SourceID: "stub-token"}, nil
}

func (s *stub) CheckContext(context.Context, string, adapter.CheckInput) adapter.CheckOutcome {
	return adapter.CheckOutcome{Result: adapter.VerdictPass, ReasonCode: "REQUIREMENT_SATISFIED", SourceID: "stub", ObservedAt: s.clk.Now()}
}

func (s *stub) AuthorizeNative(_ context.Context, p adapter.Principal, op core.OperationContext) (adapter.Decision, error) {
	var path string
	for _, r := range s.w.st.Registry {
		if len(op.Resources) > 0 && op.Resources[0] == "file:"+r.FileID {
			path = r.Path
		}
	}
	imp := fakeImpersonator{w: s.w}
	impersonated := false
	if a := s.account(p); s.mode == stubFallback && a != nil && s.hasContext(a.Ref) {
		impersonated = imp.Impersonate(&fakeToken{acc: a}) == nil
	}
	h, err := fakeFS{w: s.w}.Open(path, "read")
	if impersonated {
		_ = imp.Revert()
	}
	d := adapter.Decision{SourceID: s.w.st.OpenSourceID, DecidedAt: s.clk.Now()}
	if err != nil {
		d.Effect = adapter.EffectDeny
		return d, nil
	}
	_ = h.Close()
	d.Effect = adapter.EffectAllow
	return d, nil
}

func (s *stub) hasContext(ref string) bool {
	for _, c := range s.w.st.Contexts {
		if c.Account == ref {
			return true
		}
	}
	return false
}

func (s *stub) RecordOutcome(context.Context, adapter.Observation) (adapter.Recorded, error) {
	return adapter.NoVisibility{Reason: "stub"}, nil
}

// TestStubsFailTheFilesCases is the red baseline: every files case fails
// against at least one of the naive brokers, except the controls of
// stubControls, which every stub passes. FILES-01 fails against the stub that
// opens as the service account when impersonation fails.
func TestStubsFailTheFilesCases(t *testing.T) {
	failed := map[string][]string{}
	seen := map[string]bool{}
	for _, mode := range []string{stubFallback, stubService} {
		results, err := adaptertest.Evaluate(t, stubFactory(mode), adaptertest.Options{Adapter: "files", SharedWorkloads: true})
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range results {
			if !strings.HasPrefix(r.ID, "FILES-") {
				continue
			}
			seen[r.ID] = true
			if !r.Passed() {
				failed[r.ID] = append(failed[r.ID], mode)
			}
		}
	}
	if len(seen) == 0 {
		t.Fatal("no files case ran")
	}
	for id := range seen {
		switch {
		case stubControls[id] && len(failed[id]) > 0:
			t.Errorf("%s fails against the %v stub, which it is expected to pass", id, failed[id])
		case !stubControls[id] && len(failed[id]) == 0:
			t.Errorf("%s passes against every stub: the case does not catch a naive broker", id)
		}
	}
	for _, id := range []string{"FILES-01.enter-fails", "FILES-01.no-context", "FILES-01.executor-is-service"} {
		if !slices.Contains(failed[id], stubFallback) {
			t.Errorf("%s passes against the stub that opens as the service account on impersonation failure", id)
		}
	}
}
