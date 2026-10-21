package installed_test

import (
	"context"
	"testing"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/installed"
	"hop.top/pact-go/core"
	"hop.top/pact-go/core/clock"
)

// probe is a check that records the input it was consulted with.
type probe struct{ got *adapter.CheckInput }

func (p probe) Consult(_ context.Context, in adapter.CheckInput) (installed.CheckRecord, error) {
	*p.got = in
	return installed.CheckRecord{Result: adapter.VerdictPass, ReasonCode: installed.CodeRequirementSatisfied, SourceID: "approvals"}, nil
}

// TestRunCheckPassesTheInput: the check is consulted with the principal, the
// binding, the intent and the operation of the call as the validator
// established them (draft 17.1), and with a copy of the evidence references.
func TestRunCheckPassesTheInput(t *testing.T) {
	var got adapter.CheckInput
	checks := map[string]installed.InstalledCheck{"approval-v1": {Check: probe{&got}}}
	refs := []string{"native-record:1"}
	in := adapter.CheckInput{
		Principal:    adapter.Principal{ID: "https://idp.example/alice", Attributes: map[string]any{"device_id": "dev-1"}},
		Binding:      adapter.AgentBinding{AgentID: "https://agents.example/a", OperatorID: "https://ops.example/o", Status: adapter.BindingActive},
		Intent:       core.Intent{TaskID: "task-1"},
		Operation:    core.OperationContext{OperationID: "op-1", PrincipalID: "https://idp.example/alice"},
		EvidenceRefs: refs,
	}
	out := installed.RunCheck(context.Background(), checks, nil, clock.NewFake(time.Unix(1792080000, 0)), "approval-v1", in)
	if out.Result != adapter.VerdictPass {
		t.Fatalf("outcome %+v, want PASS", out)
	}
	if got.Principal.ID != in.Principal.ID || got.Principal.Attributes["device_id"] != "dev-1" {
		t.Errorf("principal %+v, want the call's with its attributes", got.Principal)
	}
	if got.Binding != in.Binding {
		t.Errorf("binding %+v, want %+v", got.Binding, in.Binding)
	}
	if got.Intent.TaskID != "task-1" || got.Operation.OperationID != "op-1" {
		t.Errorf("intent %+v, operation %+v", got.Intent, got.Operation)
	}
	refs[0] = "changed"
	if got.EvidenceRefs[0] != "native-record:1" {
		t.Errorf("evidence references %v alias the caller's slice", got.EvidenceRefs)
	}
}

// TestRunCheckNotInstalled: a check that is not installed is never consulted.
func TestRunCheckNotInstalled(t *testing.T) {
	var got adapter.CheckInput
	checks := map[string]installed.InstalledCheck{"approval-v1": {Check: probe{&got}}}
	out := installed.RunCheck(context.Background(), checks, nil, clock.NewFake(time.Unix(1792080000, 0)), "approval-v2", adapter.CheckInput{})
	if out.Result != adapter.VerdictUnknown || out.ReasonCode != string(adapter.CodeUnsupportedRequirement) {
		t.Errorf("outcome %+v, want UNKNOWN UNSUPPORTED_REQUIREMENT", out)
	}
	if got.Operation.OperationID != "" || got.Principal.ID != "" {
		t.Errorf("a check that is not installed was consulted: %+v", got)
	}
}
