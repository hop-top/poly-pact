package aws_test

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

// replaced are the common authenticate_native cases whose expected principal
// or denial reason an IAM context cannot carry, each with the AWS case that
// shows the same property (profile section 10, "Replaced common cases").
var replaced = map[string]adaptertest.Replacement{
	"COMMON-01.credential-wins": {
		By:     "AWS-01.forged-identity",
		Reason: "expects https://idp.acme.example/bob with a workload of another form; AR-9 derives an aws: identifier that is also the workload",
	},
	"COMMON-02.via-enforcement-point": {
		By:     "AWS-01.own-role",
		Reason: "expects https://idp.acme.example/alice; the identifier comes from the IAM context under AR-9",
	},
	"COMMON-09.authenticate-realm": {
		By:     "AWS-01.own-role",
		Reason: "expects a globex principal id that no IAM context yields; the realm is the gateway's configuration",
	},
	"COMMON-10.authenticate-error": {
		By:     "AWS-05.iam-user",
		Reason: "pins CREDENTIAL_REJECTED for a bearer token and a cookie; the only credential is the IAM context of the event, and none is NO_CREDENTIAL (AR-5)",
	},
	"IDENT-01.authenticate": {
		By:     "AWS-03.same-name-other-path",
		Reason: "expects a basic: account identifier; another role authenticates as its own aws: workload, selected by its unique ID (AR-8)",
	},
	"IDENT-02.authenticate": {
		By:     "AWS-03.same-name-other-path",
		Reason: "expects an oauth: identifier of another tenant; under IAM the same role name under another path is another workload (AR-8, AR-9)",
	},
	"IDENT-03.authenticate": {
		By:     "AWS-01.own-role",
		Reason: "splits user and client; under IAM the principal is the role's workload (identity-mapping 3.4)",
	},
	"IDENT-05.authenticate": {
		By:     "AWS-04.other-agent-name",
		Reason: "expects a basic: account identifier; the session name, the display-name analogue, never selects a workload (AR-10)",
	},
}

// TestConformance runs the conformance suite, the common cases and the AWS
// cases of spec/v1.0/fixtures/adapters/aws, with the eight replaced common cases
// declared. The AWS profile does not support workloads shared by several
// agents, so the dedicated cases run.
func TestConformance(t *testing.T) {
	adaptertest.Run(t, awsFactory, adaptertest.Options{Adapter: "aws", Replaced: replaced})
}

// TestEnrollmentRefusesSecondAgentOnRole is part (a) of AWS-14: the
// enrollment that would add a second agent to the workload of one role entry
// is refused, so the role keeps one agent, which alone binds (identity
// mapping IM-19, profile AR-12).
func TestEnrollmentRefusesSecondAgentOnRole(t *testing.T) {
	ctx := context.Background()
	realm := adapter.Realm{TenantID: "northwind", EnvironmentID: "https://api.metrics.example/environments/operations"}
	role := adapter.Workload("aws:111122223333:arn%3Aaws%3Aiam%3A%3A111122223333%3Arole%2Fagents%2Fmetrics-reader:unreported")
	admin := enroll.Actor{Kind: enroll.Admin, ID: "identity-admin-1", Realm: realm}
	agentA := "https://agents.northwind.example/metrics-assistant"
	agentB := "https://agents.northwind.example/report-builder"
	reg := enrollmem.New()

	if err := reg.Enroll(ctx, admin, enrollmem.Enrollment{
		AgentID: agentA, OperatorID: "https://operators.northwind.example/sre",
		Workload: role, HolderJKT: core.Digest("xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M"),
	}); err != nil {
		t.Fatalf("first agent: Enroll() = %v", err)
	}
	err := reg.Enroll(ctx, admin, enrollmem.Enrollment{
		AgentID: agentB, OperatorID: "https://operators.northwind.example/sre",
		Workload: role, HolderJKT: core.Digest("ahxE1XEYqxvLIZy3r4nx9RE4E0683KndykyuZTK9xQg"),
	})
	if !errors.Is(err, enroll.ErrWorkloadInUse) {
		t.Fatalf("second agent on the role: Enroll() = %v, want ErrWorkloadInUse", err)
	}
	res := enroll.Resolver{Registry: reg}
	a, err := res.ResolveAgentBinding(ctx, realm, role, adapter.AgentID(agentA))
	if err != nil || a.Status != adapter.BindingActive || a.HolderJKT != "xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M" {
		t.Errorf("agent A: binding %+v, error %v; want ACTIVE with A's key", a, err)
	}
	b, err := res.ResolveAgentBinding(ctx, realm, role, adapter.AgentID(agentB))
	if err != nil || b.Status != adapter.BindingUnknown || b.HolderJKT != "" {
		t.Errorf("agent B: binding %+v, error %v; want UNKNOWN with no key", b, err)
	}
}
