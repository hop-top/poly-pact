package k8s_test

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
// a reviewed service-account token cannot yield, each with the Kubernetes
// case that shows the same property (profile section 10, "Replaced common
// cases").
var replaced = map[string]adaptertest.Replacement{
	"COMMON-01.credential-wins": {
		By:     "K8S-01.impersonation-headers",
		Reason: "expects https://idp.acme.example/bob with a workload of another form; KR-7 derives a k8s: identifier that is also the workload",
	},
	"COMMON-02.via-enforcement-point": {
		By:     "K8S-01.own-token",
		Reason: "expects https://idp.acme.example/alice; the identifier comes from the reviewed service account under KR-7",
	},
	"COMMON-09.authenticate-realm": {
		By:     "K8S-01.own-token",
		Reason: "expects a globex principal id that no review yields; the realm is the gateway's configuration",
	},
	"IDENT-01.authenticate": {
		By:     "K8S-04.same-name-other-namespace",
		Reason: "expects a basic: account identifier; another account authenticates as its own k8s: workload",
	},
	"IDENT-02.authenticate": {
		By:     "K8S-04.same-name-other-namespace",
		Reason: "expects an oauth: identifier of another tenant; the same account name in another namespace is another workload (KR-7)",
	},
	"IDENT-03.authenticate": {
		By:     "K8S-01.own-token",
		Reason: "splits user and client; a service account is both the principal and the workload (identity-mapping 3.4)",
	},
	"COMMON-06.allow-no-execution": {
		By:     "K8S-11.binding-present",
		Reason: "expects an obligation; a SubjectAccessReview status carries allowed, denied, reason and evaluationError only (KR-12)",
	},
	"COMMON-06.deny-unchanged": {
		By:     "K8S-11.binding-removed",
		Reason: "expects an obligation with the denial; a SubjectAccessReview status carries none (KR-12)",
	},
	"COMMON-06.decision-provenance": {
		By:     "K8S-11.binding-present",
		Reason: "expects a decision record, a decision time and a policy revision; a SubjectAccessReview status carries none of them (KR-12)",
	},
	"IDENT-05.authenticate": {
		By:     "K8S-05.pod-name-not-identity",
		Reason: "expects a basic: account identifier; the pod name, the display-name analogue, never selects a workload (KR-6)",
	},
}

// TestConformance runs the conformance suite, the common cases and the
// Kubernetes cases of spec/v1.0/fixtures/adapters/k8s, with the ten replaced
// common cases declared. The profile does not support service accounts
// shared by several agents, so the dedicated cases run.
func TestConformance(t *testing.T) {
	adaptertest.Run(t, k8sFactory, adaptertest.Options{Adapter: "k8s", Replaced: replaced})
}

// TestEnrollmentRefusesSecondAgentOnAccount is part (a) of K8S-14: the
// enrollment that would add a second agent to the workload of one registered
// account is refused, so the account keeps one agent, which alone binds
// (identity mapping IM-19, profile KR-10).
func TestEnrollmentRefusesSecondAgentOnAccount(t *testing.T) {
	ctx := context.Background()
	realm := adapter.Realm{TenantID: "northstar", EnvironmentID: "https://ops-gateway.northstar.example/environments/operations"}
	account := adapter.Workload("k8s:northstar-prod:system:serviceaccount:operations:release-observer")
	admin := enroll.Actor{Kind: enroll.Admin, ID: "cluster-admin-1", Realm: realm}
	agentA := "https://agents.northstar.example/release-observer"
	agentB := "https://agents.northstar.example/build-reporter"
	reg := enrollmem.New()

	if err := reg.Enroll(ctx, admin, enrollmem.Enrollment{
		AgentID: agentA, OperatorID: "https://operators.northstar.example/platform",
		Workload: account, HolderJKT: core.Digest("xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M"),
	}); err != nil {
		t.Fatalf("first agent: Enroll() = %v", err)
	}
	err := reg.Enroll(ctx, admin, enrollmem.Enrollment{
		AgentID: agentB, OperatorID: "https://operators.northstar.example/platform",
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
