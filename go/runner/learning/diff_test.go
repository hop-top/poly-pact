package learning

import (
	"strings"
	"testing"

	"hop.top/pact-go/core"
	"hop.top/pact-go/runner/evalcase"
)

func wantReg() evalcase.Registry {
	p := "signed/a.jws"
	return evalcase.Registry{
		Artifacts: map[string]core.LifecycleState{"signed/a.jws": core.StateActive, "signed/b.jws": core.StateShadow},
		Active: []evalcase.ActiveEntry{
			{Context: ctx("department-finance-invoice"), Artifact: &p},
			{Context: ctx("department-finance-ledger")},
		},
		Acknowledgments:      []evalcase.AckEntry{{Step: 1, Status: core.AckAccepted}, {Step: 2, Status: core.AckDuplicate}},
		Rejections:           []evalcase.RejectionEntry{{Step: 3, Code: CodeLearningRejected, ReasonCodes: []string{ReasonPolicyExpired, ReasonObserveMode}}, {Step: 4, Code: CodeIDConflict, ReasonCodes: []string{}}},
		Holds:                []string{"h1", "h2"},
		ReevaluationRequired: []string{"signed/b.jws"},
	}
}

func clone(r evalcase.Registry) evalcase.Registry {
	out := evalcase.Registry{Artifacts: map[string]core.LifecycleState{}}
	for k, v := range r.Artifacts {
		out.Artifacts[k] = v
	}
	out.Active = append(out.Active, r.Active...)
	out.Acknowledgments = append(out.Acknowledgments, r.Acknowledgments...)
	for _, x := range r.Rejections {
		x.ReasonCodes = append([]string{}, x.ReasonCodes...)
		out.Rejections = append(out.Rejections, x)
	}
	out.Holds = append(out.Holds, r.Holds...)
	out.ReevaluationRequired = append(out.ReevaluationRequired, r.ReevaluationRequired...)
	return out
}

func TestDiffEqual(t *testing.T) {
	if d := Diff(wantReg(), clone(wantReg())); len(d) != 0 {
		t.Fatalf("equal registries differ: %q", d)
	}
}

// The order of the entries and of the reason codes is not significant.
func TestDiffIgnoresOrder(t *testing.T) {
	got := clone(wantReg())
	got.Active[0], got.Active[1] = got.Active[1], got.Active[0]
	got.Acknowledgments[0], got.Acknowledgments[1] = got.Acknowledgments[1], got.Acknowledgments[0]
	got.Rejections[0], got.Rejections[1] = got.Rejections[1], got.Rejections[0]
	got.Rejections[1].ReasonCodes = []string{ReasonObserveMode, ReasonPolicyExpired}
	got.Holds = []string{"h2", "h1"}
	if d := Diff(wantReg(), got); len(d) != 0 {
		t.Fatalf("a reordering is reported: %q", d)
	}
}

func TestDiffReportsEachDifference(t *testing.T) {
	other := "signed/b.jws"
	tests := []struct {
		name string
		edit func(*evalcase.Registry)
		want []string
	}{
		{"artifact state", func(r *evalcase.Registry) { r.Artifacts["signed/a.jws"] = core.StateShadow }, []string{"signed/a.jws", "SHADOW", "ACTIVE"}},
		{"artifact missing", func(r *evalcase.Registry) { delete(r.Artifacts, "signed/b.jws") }, []string{"signed/b.jws", "SHADOW", "absent"}},
		{"artifact unexpected", func(r *evalcase.Registry) { r.Artifacts["signed/c.jws"] = core.StateCandidate }, []string{"signed/c.jws", "CANDIDATE", "unexpected"}},
		{"active artifact", func(r *evalcase.Registry) { r.Active[0].Artifact = &other }, []string{"department-finance-invoice", "signed/b.jws", "signed/a.jws"}},
		{"active should be conservative", func(r *evalcase.Registry) { r.Active[1].Artifact = &other }, []string{"department-finance-ledger", "signed/b.jws", "conservative"}},
		{"active should be set", func(r *evalcase.Registry) { r.Active[0].Artifact = nil }, []string{"department-finance-invoice", "conservative", "signed/a.jws"}},
		{"active context missing", func(r *evalcase.Registry) { r.Active = r.Active[:1] }, []string{"department-finance-ledger", "no entry"}},
		{"active context unexpected", func(r *evalcase.Registry) {
			r.Active = append(r.Active, evalcase.ActiveEntry{Context: ctx("department-finance-budget")})
		}, []string{"department-finance-budget", "unexpected"}},
		{"ack status", func(r *evalcase.Registry) { r.Acknowledgments[1].Status = core.AckAccepted }, []string{"acknowledgments", "step 2", "ACCEPTED", "DUPLICATE"}},
		{"ack missing", func(r *evalcase.Registry) { r.Acknowledgments = r.Acknowledgments[:1] }, []string{"acknowledgments", "step 2", "missing"}},
		{"ack unexpected", func(r *evalcase.Registry) {
			r.Acknowledgments = append(r.Acknowledgments, evalcase.AckEntry{Step: 9, Status: core.AckAccepted})
		}, []string{"acknowledgments", "step 9", "unexpected"}},
		{"ack twice", func(r *evalcase.Registry) { r.Acknowledgments = append(r.Acknowledgments, r.Acknowledgments[0]) }, []string{"acknowledgments", "step 1", "twice"}},
		{"rejection code", func(r *evalcase.Registry) { r.Rejections[1].Code = CodeInvalidMessage }, []string{"rejections", "step 4", "INVALID_MESSAGE", "ID_CONFLICT"}},
		{"rejection reason codes", func(r *evalcase.Registry) { r.Rejections[0].ReasonCodes = []string{ReasonPolicyExpired} }, []string{"rejections", "step 3", "POLICY_EXPIRED", "OBSERVE_MODE"}},
		{"rejection reason code added", func(r *evalcase.Registry) { r.Rejections[1].ReasonCodes = []string{ReasonGateNotMet} }, []string{"rejections", "step 4", "GATE_NOT_MET"}},
		{"rejection twice", func(r *evalcase.Registry) { r.Rejections = append(r.Rejections, r.Rejections[1]) }, []string{"rejections", "step 4", "twice"}},
		{"active twice for one context", func(r *evalcase.Registry) { r.Active = append(r.Active, r.Active[1]) }, []string{"department-finance-ledger", "2 entries"}},
		{"rejection missing", func(r *evalcase.Registry) { r.Rejections = r.Rejections[:1] }, []string{"rejections", "step 4", "missing"}},
		{"rejection unexpected", func(r *evalcase.Registry) {
			r.Rejections = append(r.Rejections, evalcase.RejectionEntry{Step: 7, Code: CodeLearningRejected})
		}, []string{"rejections", "step 7", "unexpected"}},
		{"step both acknowledged and rejected", func(r *evalcase.Registry) {
			r.Rejections = append(r.Rejections, evalcase.RejectionEntry{Step: 1, Code: CodeLearningRejected})
		}, []string{"rejections", "step 1", "unexpected"}},
		{"hold cleared", func(r *evalcase.Registry) { r.Holds = r.Holds[:1] }, []string{"holds", "h2", "missing"}},
		{"hold added", func(r *evalcase.Registry) { r.Holds = append(r.Holds, "h3") }, []string{"holds", "h3", "unexpected"}},
		{"reevaluation missing", func(r *evalcase.Registry) { r.ReevaluationRequired = nil }, []string{"reevaluation_required", "signed/b.jws", "missing"}},
		{"reevaluation added", func(r *evalcase.Registry) { r.ReevaluationRequired = append(r.ReevaluationRequired, "signed/a.jws") }, []string{"reevaluation_required", "signed/a.jws", "unexpected"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := clone(wantReg())
			tc.edit(&got)
			d := Diff(wantReg(), got)
			if len(d) != 1 {
				t.Fatalf("%d details %q, want one", len(d), d)
			}
			for _, s := range tc.want {
				if !strings.Contains(d[0], s) {
					t.Errorf("detail %q does not mention %q", d[0], s)
				}
			}
		})
	}
}

// Two contexts that differ in a member other than the resource class are
// two contexts.
func TestDiffContextsAreWholeContexts(t *testing.T) {
	got := clone(wantReg())
	c := ctx("department-finance-ledger")
	c.ActionClass = "invoice.write"
	got.Active[1].Context = c
	d := Diff(wantReg(), got)
	if len(d) != 2 || !strings.Contains(d[0], "invoice.read on department-finance-ledger]: no entry") ||
		!strings.Contains(d[1], "invoice.write on department-finance-ledger]: unexpected entry") {
		t.Errorf("details %q", d)
	}
}
