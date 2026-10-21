package basic_test

import (
	"context"
	"errors"
	"testing"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/adaptertest"
	"hop.top/pact-go/adapter/enroll"
	enrollmem "hop.top/pact-go/adapter/enroll/memory"
	"hop.top/pact-go/core"
)

// TestConformance runs the conformance suite, the common cases and the Basic
// cases of spec/v1.0/fixtures/adapters/basic, against the adapter under test. The
// Basic profile does not support workloads shared by several agents, so the
// dedicated cases run.
func TestConformance(t *testing.T) {
	adaptertest.Run(t, basicFactory, adaptertest.Options{Adapter: "basic"})
}

// TestEnrollmentRefusesSecondAgentOnAccount is part (a) of BASIC-07: the
// enrollment that would add a second agent to a Basic account is refused, so
// the account keeps one agent, which alone binds (identity mapping IM-19).
func TestEnrollmentRefusesSecondAgentOnAccount(t *testing.T) {
	ctx := context.Background()
	realm := adapter.Realm{TenantID: "northstar", EnvironmentID: "https://gateway.northstar.example/environments/invoices"}
	account := adapter.Workload("basic:legacy-accounts:20417")
	admin := enroll.Actor{Kind: enroll.Admin, ID: "identity-admin-1", Realm: realm}
	agentA := "https://agents.northstar.example/invoice-assistant"
	agentB := "https://agents.northstar.example/invoice-assistant-b"
	reg := enrollmem.New()

	if err := reg.Enroll(ctx, admin, enrollmem.Enrollment{
		AgentID: agentA, OperatorID: "https://operators.northstar.example/finance-ops",
		Workload: account, HolderJKT: core.Digest("xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M"),
	}); err != nil {
		t.Fatalf("first agent: Enroll() = %v", err)
	}
	err := reg.Enroll(ctx, admin, enrollmem.Enrollment{
		AgentID: agentB, OperatorID: "https://operators.northstar.example/finance-ops",
		Workload: account, HolderJKT: core.Digest("ahxE1XEYqxvLIZy3r4nx9RE4E0683KndykyuZTK9xQg"),
	})
	if !errors.Is(err, enroll.ErrWorkloadInUse) {
		t.Fatalf("second agent on the account: Enroll() = %v, want ErrWorkloadInUse", err)
	}

	res := enroll.Resolver{Registry: reg}
	a, err := res.ResolveAgentBinding(ctx, realm, account, adapter.AgentID(agentA))
	if err != nil || a.Status != adapter.BindingActive || a.HolderJKT != "xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M" {
		t.Errorf("agent A: binding %+v, error %v; want ACTIVE with A's key", a, err)
	}
	b, err := res.ResolveAgentBinding(ctx, realm, account, adapter.AgentID(agentB))
	if err != nil || b.Status != adapter.BindingUnknown || b.HolderJKT != "" {
		t.Errorf("agent B: binding %+v, error %v; want UNKNOWN with no key", b, err)
	}
}
