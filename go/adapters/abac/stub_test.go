package abac_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/adaptertest"
	"hop.top/pact-go/core"
	"hop.top/pact-go/core/clock"
)

// stub is the red baseline of the ABAC cases: the decision client a gateway
// gets by wiring a PDP in the obvious way. It builds the policy input from
// whatever the request offers first, a principal attribute, a header or the
// operation's extensions, and falls back to the fact sources; it reads every
// fact as it is, ignoring its times and its source's availability; it decodes
// the answer leniently, takes a missing result as a denial, and drops the
// obligations of a denial. Its check reports PASS for any decision that came
// back. It realizes no other model and implements no other function.
//
// Every ABAC case except those of stubPasses must fail against it; see
// TestStubFailsTheABACCases.
type stub struct {
	w   *world
	clk clock.Clock
}

// stubPasses are the ABAC cases the stub passes, each because the stub's
// obvious wiring is the case's whole requirement: with no agent value in the
// request and every fact fresh, its input is the authoritative one, so the
// allow and deny controls and the policy's own comparisons pass; a PDP that
// answers an error status, times out or refuses is an error; and a decision of
// another version or with an unknown obligation type is returned as it is;
// and the check of a well-formed decision, an allow or a denial, is PASS.
var stubPasses = map[string]bool{
	"ABAC-02.control":        true,
	"ABAC-05.at-limits":      true,
	"ABAC-06.at-skew":        true,
	"ABAC-09.classification": true,
	"ABAC-09.clearance":      true,
	"ABAC-10.rank-denies":    true,
	"ABAC-10.rank-permits":   true,
	"ABAC-14.other-version":  true,
	"ABAC-15.redirect":       true,
	"ABAC-15.refused":        true,
	"ABAC-15.status-204":     true,
	"ABAC-15.status-400":     true,
	"ABAC-15.status-404":     true,
	"ABAC-15.status-500":     true,
	"ABAC-15.timeout":        true,
	"ABAC-18.builtin-error":  true,
	"ABAC-19.native-deny":    true,
	"ABAC-28.unknown-type":   true,
	"ABAC-37.provenance":     true,
	"ABAC-38.check-allow":    true,
	"ABAC-38.check-deny":     true,
}

// inputMutationCases are the cases that a stub passing agent-supplied values
// as PDP input must fail (the mutation rule of the conformance task): the
// clearance, department, classification, device and zone that the request
// offers never reach the input or a claim.
var inputMutationCases = []string{
	"ABAC-01.claim",
	"ABAC-01.decision",
	"ABAC-02.classification",
	"ABAC-02.department",
	"ABAC-02.device",
	"ABAC-03.claim",
	"ABAC-03.forwarded-zone",
}

// stubFactory builds the stub for an abac/1 case.
func stubFactory(tb testing.TB, env adaptertest.Env) (adaptertest.Subject, error) {
	model, err := modelOf(env.State)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	if model != abacModel {
		return adaptertest.Subject{}, fmt.Errorf("stub: model %q is not realized", model)
	}
	w, err := loadWorld(tb, env.State, env.Hooks)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	return adaptertest.Subject{
		Adapter: &stub{w: w, clk: env.Clock},
		Arrive:  func(r *http.Request) *http.Request { return r },
	}, nil
}

var errStub = errors.New("stub: not implemented")

func (s *stub) Describe() adapter.Descriptor {
	return adapter.Descriptor{Protocol: "opa-data-api", Version: "v1", MappingRevision: "pact-abac-1"}
}

func (s *stub) AuthenticateNative(context.Context, *http.Request) (adapter.Principal, error) {
	return adapter.Principal{}, errStub
}

func (s *stub) ResolveAgentBinding(context.Context, adapter.Realm, adapter.Workload, adapter.AgentID) (adapter.AgentBinding, error) {
	return adapter.AgentBinding{Status: adapter.BindingUnknown}, nil
}

func (s *stub) MapOperation(context.Context, *http.Request, adapter.Principal, string) (core.OperationContext, error) {
	return core.OperationContext{}, errStub
}

// CheckContext is the check as the obvious wiring has it: PASS when a decision
// came back, whatever it says, whichever policy version and whichever
// obligations it carries; UNKNOWN when none did.
func (s *stub) CheckContext(ctx context.Context, _ string, in adapter.CheckInput) adapter.CheckOutcome {
	d, err := s.AuthorizeNative(ctx, in.Principal, in.Operation)
	if err != nil {
		return adapter.CheckOutcome{Result: adapter.VerdictUnknown, ReasonCode: string(adapter.CodeDependencyUnavailable)}
	}
	return adapter.CheckOutcome{Result: adapter.VerdictPass, ReasonCode: "REQUIREMENT_SATISFIED", SourceID: d.SourceID, SourceRef: d.SourceRef}
}

func (s *stub) RecordOutcome(context.Context, adapter.Observation) (adapter.Recorded, error) {
	return nil, errStub
}

// offered returns a value the request offers for the fact named name: a
// principal attribute, a header, or a member of the extensions.
func offered(p adapter.Principal, op core.OperationContext, ext core.Object, name string) (any, bool) {
	if v, ok := p.Attributes[name]; ok {
		return v, true
	}
	for k, v := range op.Headers {
		if strings.Contains(k, strings.ReplaceAll(name, "_", "-")) {
			return v, true
		}
	}
	if v, ok := ext[name]; ok {
		return v, true
	}
	if v, ok := op.Extensions[name]; ok {
		return v, true
	}
	return nil, false
}

// value returns the stub's value of a fact: what the request offers, or the
// source's record whatever its times and availability.
func (s *stub) value(p adapter.Principal, op core.OperationContext, ext core.Object, path string) any {
	name := path[strings.LastIndex(path, "/")+1:]
	if v, ok := offered(p, op, ext, name); ok {
		return v
	}
	switch path {
	case pathNetworkZone:
		peer, _ := p.Attributes["peer_address"].(string)
		if fwd, ok := op.Headers["x-forwarded-for"]; ok {
			peer = fwd
		}
		addr, err := netip.ParseAddr(peer)
		if err != nil {
			return ""
		}
		z, _ := s.w.zoneOf(addr)
		return z
	case pathTime:
		return s.clk.Now().Unix()
	case pathDeviceCompliant:
		dev, _ := p.Attributes["device_id"].(string)
		if h, ok := op.Headers["x-device-id"]; ok {
			dev = h
		}
		f, _ := s.w.fact(path, dev)
		v, _ := f.value()
		return v
	}
	key := p.ID
	if strings.HasPrefix(path, "/resource/") && len(op.Resources) > 0 {
		key = op.Resources[0]
	}
	f, _ := s.w.fact(path, key)
	v, _ := f.value()
	return v
}

func (s *stub) ReadNativeClaim(_ context.Context, path string, cc adapter.ClaimContext) (adapter.NativeClaim, error) {
	now := s.clk.Now()
	return adapter.NativeClaim{
		Value: s.value(cc.Principal, cc.Operation, cc.Intent.Extensions, path), ObservedAt: now, StatusCheckedAt: now,
		SourceID: "stub",
	}, nil
}

func (s *stub) AuthorizeNative(ctx context.Context, p adapter.Principal, op core.OperationContext) (adapter.Decision, error) {
	v := func(path string) any { return s.value(p, op, nil, path) }
	input := map[string]any{
		"subject": map[string]any{"principal_id": p.ID, "department": v(pathDepartment), "clearance": v(pathClearance)},
		"resource": map[string]any{
			"id": strings.Join(op.Resources, ","), "classification": v(pathClassification),
			"owning_department": v(pathOwningDepartment),
		},
		"action": map[string]any{"id": op.Action},
		"environment": map[string]any{
			"device": map[string]any{"compliant": v(pathDeviceCompliant)}, "network_zone": v(pathNetworkZone), "time": v(pathTime),
		},
	}
	body, _ := json.Marshal(map[string]any{"input": input})
	ctx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		s.w.pdp.URL+"/v1/data/"+s.w.st.PDP.DecisionPath+"?strict-builtin-errors=true", bytes.NewReader(body))
	if err != nil {
		return adapter.Decision{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.w.pdp.Client.Do(req)
	if err != nil {
		return adapter.Decision{}, fmt.Errorf("stub: %w: %w", adapter.ErrDependencyUnavailable, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return adapter.Decision{}, fmt.Errorf("stub: status %d: %w", resp.StatusCode, adapter.ErrDependencyUnavailable)
	}
	var ans struct {
		DecisionID string `json:"decision_id"`
		Result     *struct {
			Allow       bool `json:"allow"`
			Obligations []struct {
				Type   string         `json:"type"`
				Params map[string]any `json:"params"`
			} `json:"obligations"`
			PolicyVersion string `json:"policy_version"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&ans); err != nil {
		return adapter.Decision{Effect: adapter.EffectDeny, SourceID: s.w.st.PDP.SourceID}, nil
	}
	d := adapter.Decision{Effect: adapter.EffectDeny, SourceID: s.w.st.PDP.SourceID, SourceRef: ans.DecisionID}
	if ans.Result == nil {
		return d, nil
	}
	d.PolicyRevision = ans.Result.PolicyVersion
	if !ans.Result.Allow {
		return d, nil
	}
	d.Effect = adapter.EffectAllow
	for _, o := range ans.Result.Obligations {
		d.Obligations = append(d.Obligations, adapter.Obligation{ID: o.Type, Attributes: o.Params})
	}
	return d, nil
}

// TestStubFailsTheABACCases shows that the ABAC cases catch the obvious
// wiring: every ABAC case but those of stubPasses fails against the stub, and
// so does every case of the input mutation rule.
func TestStubFailsTheABACCases(t *testing.T) {
	results, err := adaptertest.Evaluate(t, stubFactory, adaptertest.Options{Adapter: "abac"})
	if err != nil {
		t.Fatal(err)
	}
	failed := map[string]bool{}
	seen := 0
	for _, r := range results {
		if !strings.HasPrefix(r.ID, "ABAC-") {
			continue
		}
		seen++
		failed[r.ID] = !r.Passed()
		switch {
		case stubPasses[r.ID] && !r.Passed():
			t.Errorf("%s: the stub is expected to pass, but fails: %v", r.ID, r.Failures)
		case !stubPasses[r.ID] && r.Passed():
			t.Errorf("%s: the stub passes; the case does not catch the obvious wiring", r.ID)
		}
	}
	if seen == 0 {
		t.Fatal("no ABAC case loaded")
	}
	for _, id := range inputMutationCases {
		if !failed[id] {
			t.Errorf("%s: a stub that passes agent-supplied values as PDP input does not fail it", id)
		}
	}
}
