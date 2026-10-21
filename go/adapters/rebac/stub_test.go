package rebac_test

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
)

// stub is the red baseline of the ReBAC cases: the adapter a gateway gets by
// wiring OpenFGA in the obvious way. It maps every document request to a
// read; looks the principal and the document up in any realm, and falls back
// to the last path segment for a document it cannot find; always Checks
// viewer; takes the model id from the request when it names one and omits it
// otherwise; sends no consistency preference; turns a membership named in the
// request into a contextual tuple; reads every failed call as a denial;
// denies when the stored membership of the document's project is absent,
// ignoring direct shares; names no policy revision; and runs the read as soon
// as the Check allows.
//
// Every ReBAC case except those of stubPasses must fail against it; see
// TestStubFailsTheReBACCases. The membership rule is the mutant of the task
// that a remaining direct share catches (REBAC-05.direct-share).
type stub struct {
	w     *world
	store *fakeStore
	hooks *adaptertest.Hooks
}

// stubPasses are the ReBAC cases the stub passes: a Check that has no path,
// which a stub that denies more passes as well.
var stubPasses = map[string]bool{
	"REBAC-05.no-remaining-path": true,
	"REBAC-11":                   true,
}

// stubFactory builds the stub for a rebac/1 case; it realizes no other model.
func stubFactory(t testing.TB, env adaptertest.Env) (adaptertest.Subject, error) {
	model, err := modelOf(env.State)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	if model != rebacModel {
		return adaptertest.Subject{}, fmt.Errorf("stub: model %q is not realized", model)
	}
	fsys, err := fixtures()
	if err != nil {
		return adaptertest.Subject{}, err
	}
	w, err := loadWorld(env.State, fsys)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	store, err := newFakeStore(w, env.Hooks)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	t.Cleanup(store.Close)
	s := &stub{w: w, store: store, hooks: env.Hooks}
	return adaptertest.Subject{
		Adapter: s,
		Arrive:  func(r *http.Request) *http.Request { return r },
		Credential: func(*http.Request, string) error {
			return errors.New("stub: no credentials")
		},
	}, nil
}

func (s *stub) Describe() adapter.Descriptor {
	return adapter.Descriptor{Protocol: "openfga-http", Version: "1.x", MappingRevision: "pact-rebac-1"}
}

func (s *stub) AuthenticateNative(context.Context, *http.Request) (adapter.Principal, error) {
	return adapter.Principal{}, &adapter.NativeDenial{Reason: adapter.DenialNoCredential}
}

func (s *stub) ResolveAgentBinding(context.Context, adapter.Realm, adapter.Workload, adapter.AgentID) (adapter.AgentBinding, error) {
	return adapter.AgentBinding{Status: adapter.BindingUnknown}, nil
}

func (s *stub) MapOperation(_ context.Context, r *http.Request, p adapter.Principal, _ string) (core.OperationContext, error) {
	id := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
	return core.OperationContext{
		OperationID: "op-stub", EnvironmentID: s.w.st.Gateway.EnvironmentID, PrincipalID: p.ID,
		Action: "document.read", Resources: []string{"https://docs.northstar.example/documents/" + id},
		Method: r.Method, TargetURI: s.w.st.Gateway.Origin + r.URL.Path,
		BodyDigest: core.Digest("47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"), Headers: map[string]string{},
	}, nil
}

func (s *stub) ReadNativeClaim(context.Context, string, adapter.ClaimContext) (adapter.NativeClaim, error) {
	return adapter.NativeClaim{}, adapter.ErrUnsupportedRequirement
}

func (s *stub) CheckContext(context.Context, string, adapter.CheckInput) adapter.CheckOutcome {
	return adapter.CheckOutcome{Result: adapter.VerdictUnknown, ReasonCode: "UNSUPPORTED_REQUIREMENT", SourceID: "stub"}
}

func (s *stub) RecordOutcome(context.Context, adapter.Observation) (adapter.Recorded, error) {
	return nil, adapter.ErrUnsupportedRequirement
}

func (s *stub) AuthorizeNative(ctx context.Context, p adapter.Principal, op core.OperationContext) (adapter.Decision, error) {
	deny := adapter.Decision{Effect: adapter.EffectDeny, SourceID: "openfga"}
	subject := ""
	for _, e := range s.w.st.Subjects {
		if e.Principal == p.ID {
			subject = "user:" + e.SubjectID
			break
		}
	}
	resource := ""
	if len(op.Resources) > 0 {
		resource = op.Resources[0]
	}
	object := ""
	for _, e := range s.w.st.Objects {
		if e.Resource == resource {
			object = "document:" + e.ObjectID
			break
		}
	}
	if object == "" {
		object = "document:" + resource[strings.LastIndex(resource, "/")+1:]
	}
	body := map[string]any{"tuple_key": map[string]string{"user": subject, "relation": "viewer", "object": object}}
	var contextual []map[string]string
	if u, err := url.Parse(op.TargetURI); err == nil {
		if id := u.Query().Get("authorization_model_id"); id != "" {
			body["authorization_model_id"] = id
		}
		if m := u.Query().Get("member"); m != "" {
			contextual = append(contextual, map[string]string{"user": subject, "relation": "member", "object": m})
		}
	}
	if h := op.Headers["x-relationship"]; h != "" {
		obj, _, _ := strings.Cut(h, "#")
		contextual = append(contextual, map[string]string{"user": subject, "relation": "member", "object": obj})
	}
	if contextual != nil {
		body["contextual_tuples"] = map[string]any{"tuple_keys": contextual}
	}
	resp, err := postCheck(ctx, s.store, s.w.st.StoreCredential, body)
	if err != nil {
		return deny, nil
	}
	defer func() { _ = resp.Body.Close() }()
	var answer struct {
		Allowed bool `json:"allowed"`
	}
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || json.Unmarshal(raw, &answer) != nil || !answer.Allowed {
		return deny, nil
	}
	// The membership rule: no stored membership of the parent project, no
	// allow.
	member := false
	for _, parent := range s.w.st.Store.Tuples {
		if parent.Relation != "parent" || parent.Object != object {
			continue
		}
		for _, m := range s.w.st.Store.Tuples {
			member = member || m.Relation == "member" && m.Object == parent.User && m.User == subject
		}
	}
	if !member {
		return deny, nil
	}
	s.hooks.Fire(hookExecute)
	return adapter.Decision{Effect: adapter.EffectAllow, SourceID: "openfga"}, nil
}

// TestStubFailsTheReBACCases is the red baseline: the ReBAC cases catch the
// naive adapter. Every ReBAC case fails against the stub except those of
// stubPasses, which pass.
func TestStubFailsTheReBACCases(t *testing.T) {
	results, err := adaptertest.Evaluate(t, stubFactory, adaptertest.Options{Adapter: "rebac"})
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, r := range results {
		if !strings.HasPrefix(r.ID, "REBAC-") {
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
		t.Fatal("no ReBAC case ran")
	}
}
