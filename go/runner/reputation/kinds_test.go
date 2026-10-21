package reputation_test

import (
	"slices"
	"testing"

	"hop.top/pact-go/core"
	"hop.top/pact-go/runner/evalcase"
	"hop.top/pact-go/runner/reputation"
)

var uNoAssessment = verdict{evalcase.Unqualified, reputation.ReasonNoAssessmentRecord}

// TestVerifiedFeedback: the verified feedback row of Section 14.5. An
// evaluator's or the task owner's FEEDBACK on task_quality counts as an
// assessment and cites the completed assessment it conveys; the agent's
// own is a diagnostic that is never positive (Section 14.6 rule 11) and
// needs no record. The policy adherence row asks the same evidence.
func TestVerifiedFeedback(t *testing.T) {
	tq, pa := core.DimensionTaskQuality, core.DimensionPolicyAdherence
	runRuleCases(t, []ruleCase{
		{name: "evaluator's positive feedback", reports: []edit{feedback(evaluator, "evaluator", tq, core.OutcomeSuccess)},
			want: map[int]verdict{0: qMapped}, listed: []int{0}, dim: tq, score: 6666, conf: 476},
		{name: "task owner's negative feedback", reports: []edit{feedback(taskOwner, "task_owner", tq, core.OutcomeFailure)},
			want: map[int]verdict{0: qMapped}, listed: []int{0}, dim: tq, score: 3333, conf: 476},
		{name: "evaluator's feedback without an assessment", reports: []edit{chain(feedback(evaluator, "evaluator", tq, core.OutcomeSuccess), refs())},
			want: map[int]verdict{0: uNoAssessment}, dim: tq, score: 5000, conf: 0},
		{name: "task owner's feedback citing an execution record", reports: []edit{chain(feedback(taskOwner, "task_owner", tq, core.OutcomeFailure), refs(readRecord))},
			want: map[int]verdict{0: uNoAssessment}, dim: tq, score: 5000, conf: 0},
		{name: "feedback citing the assessment of another task", reports: []edit{chain(feedback(evaluator, "evaluator", tq, core.OutcomeSuccess), refs("native-review:other-task"))},
			want: map[int]verdict{0: uNoAssessment}, dim: tq, score: 5000, conf: 0},
		{name: "agent's own positive feedback", reports: []edit{feedback(agentSelf, "agent", tq, core.OutcomeSuccess)},
			want: map[int]verdict{0: qMapped}, dim: tq, score: 5000, conf: 0},
		{name: "agent's own negative feedback", reports: []edit{feedback(agentSelf, "agent", tq, core.OutcomeFailure)},
			want: map[int]verdict{0: qMapped}, listed: []int{0}, dim: tq, score: 3333, conf: 476},
		{name: "feedback on policy_adherence without an assessment", reports: []edit{chain(feedback(evaluator, "evaluator", pa, core.OutcomeSuccess), refs())},
			want: map[int]verdict{0: uNoAssessment}, dim: pa, score: 5000, conf: 0},
		{name: "agent's own positive feedback on policy_adherence", reports: []edit{feedback(agentSelf, "agent", pa, core.OutcomeSuccess)},
			want: map[int]verdict{0: qMapped}, dim: pa, score: 5000, conf: 0},
		{name: "agent's own negative feedback on policy_adherence", reports: []edit{feedback(agentSelf, "agent", pa, core.OutcomeFailure)},
			want: map[int]verdict{0: qMapped}, listed: []int{0}, dim: pa, score: 3333, conf: 476},
		{name: "feedback correction without an assessment", reports: []edit{
			feedback(evaluator, "evaluator", tq, core.OutcomeFailure),
			chain(feedback(evaluator, "evaluator", tq, core.OutcomeSuccess), correcting(core.OutcomeSuccess, "event-a"), refs()),
		}, want: map[int]verdict{1: uNoAssessment}, listed: []int{0}, dim: tq, score: 3333, conf: 476},
		{name: "evaluator, agent and recordless feedback", reports: []edit{
			feedback(evaluator, "evaluator", tq, core.OutcomeSuccess),
			feedback(agentSelf, "agent", tq, core.OutcomeSuccess),
			chain(feedback(evaluator, "evaluator", tq, core.OutcomeSuccess), refs(), func(x *core.OutcomeReport) { x.OperationID = "invoice-read-operation-0002" }),
		}, want: map[int]verdict{0: qMapped, 1: qMapped, 2: uNoAssessment}, listed: []int{0}, dim: tq, score: 6666, conf: 476},
	})
}

// TestFeedbackAffiliation: rule 6 of Section 14.6 covers positive FEEDBACK
// of an affiliated evaluator or task owner; negative reports are
// unaffected.
func TestFeedbackAffiliation(t *testing.T) {
	tq := core.DimensionTaskQuality
	affiliated := func(iss string) func(*evalcase.OutcomesConfig) {
		return func(c *evalcase.OutcomesConfig) {
			c.Affiliations = []evalcase.Affiliation{{EvaluatorIss: iss, OperatorID: acmeOperator}}
		}
	}
	uAffiliated := verdict{evalcase.Unqualified, reputation.ReasonAffiliatedEvaluator}
	runRuleCases(t, []ruleCase{
		{name: "affiliated evaluator, positive feedback", cfg: affiliated(evaluator), reports: []edit{feedback(evaluator, "evaluator", tq, core.OutcomeSuccess)},
			want: map[int]verdict{0: uAffiliated}, dim: tq, score: 5000, conf: 0},
		{name: "affiliated evaluator, negative feedback", cfg: affiliated(evaluator), reports: []edit{feedback(evaluator, "evaluator", tq, core.OutcomeFailure)},
			want: map[int]verdict{0: qMapped}, listed: []int{0}, dim: tq, score: 3333, conf: 476},
		{name: "affiliated task owner, positive feedback", cfg: affiliated(taskOwner), reports: []edit{feedback(taskOwner, "task_owner", tq, core.OutcomeSuccess)},
			want: map[int]verdict{0: uAffiliated}, dim: tq, score: 5000, conf: 0},
		{name: "affiliated evaluator, positive and negative feedback", cfg: affiliated(evaluator), reports: []edit{
			feedback(evaluator, "evaluator", tq, core.OutcomeSuccess),
			chain(feedback(evaluator, "evaluator", tq, core.OutcomeFailure), func(x *core.OutcomeReport) { x.OperationID = "invoice-read-operation-0002" }),
		}, want: map[int]verdict{0: uAffiliated, 1: qMapped}, listed: []int{1}, dim: tq, score: 3333, conf: 476},
	})
}

// TestFeedbackReciprocity: rule 7 of Section 14.6 covers positive FEEDBACK:
// the two endorsements of the committed reciprocal case, sent as feedback or
// one of each kind, are both DISPUTED.
func TestFeedbackReciprocity(t *testing.T) {
	c, err := evalcase.ReadOutcomes(repoFixtures, "outcomes/qualification/reciprocal-endorsements")
	if err != nil {
		t.Fatal(err)
	}
	for name, kinds := range map[string][2]core.EventKind{
		"both feedback":        {core.EventFeedback, core.EventFeedback},
		"quality and feedback": {core.EventQuality, core.EventFeedback},
	} {
		t.Run(name, func(t *testing.T) {
			o := reputation.NewOracle(c.Config, c.Native)
			for i, id := range []string{"quality-event-0001", "quality-event-0002"} {
				r := c.Reports[id]
				r.EventKind = kinds[i]
				if a := o.Ingest(r, now); a.Ack != core.AckAccepted {
					t.Fatal(a)
				}
			}
			for _, id := range []string{"quality-event-0001", "quality-event-0002"} {
				wantVerdict(t, o, id, evalcase.Disputed, reputation.ReasonReciprocalEndorsement)
			}
		})
	}
}

// TestHoldSurvivesCorrection: a correction of a confirmed SECURITY report
// supersedes it in provenance and leaves its hold in place, whoever signs
// it and whatever its result; only a hold clearance authority's remediation
// naming the original event_id clears it (Section 15.4).
func TestHoldSurvivesCorrection(t *testing.T) {
	cfg, native, tmpl := fixture(t)
	sec := func(x *core.OutcomeReport) {
		x.EventKind, x.Result, x.Dimension, x.Issuer, x.ReporterRole = core.EventSecurity, core.OutcomeFailure, core.DimensionNone, security, "security_authority"
		x.EvidenceRefs = []string{incident}
	}
	corr := func(iss string, result core.OutcomeResult) edit {
		return func(x *core.OutcomeReport) {
			sec(x)
			x.Issuer = iss
			x.EventKind, x.Result, x.Supersedes = core.EventCorrection, result, []string{"event-a"}
		}
	}
	rem := func(names string) edit {
		return func(x *core.OutcomeReport) {
			x.EventKind, x.Result, x.Dimension, x.Issuer, x.ReporterRole = core.EventRemediation, core.OutcomeSuccess, core.DimensionNone, security, "security_authority"
			x.EvidenceRefs = []string{names, remediated}
		}
	}
	type want struct {
		status     core.SecurityStatus
		holds      []string
		superseded []string
	}
	check := func(name string, o *reputation.Oracle, rs []core.OutcomeReport, w want) {
		t.Helper()
		s := snap(t, o, query(tmpl), now)
		var sup [][2]string
		for _, r := range rs {
			if slices.Contains(w.superseded, r.EventID) {
				sup = append(sup, [2]string{r.Issuer, r.JTI})
			}
		}
		if sup == nil {
			sup = [][2]string{}
		}
		if s.Value.SecurityStatus != w.status || !slices.Equal(s.Value.HoldRefs, w.holds) || !slices.Equal(s.Manifest.SupersededEventIDs, sup) ||
			len(s.Manifest.QualifiedEventIDs) != 0 {
			t.Errorf("%s: %s %v, superseded %v, qualified %v; want %s %v, superseded %v", name, s.Value.SecurityStatus, s.Value.HoldRefs,
				s.Manifest.SupersededEventIDs, s.Manifest.QualifiedEventIDs, w.status, w.holds, sup)
		}
	}
	for _, tc := range []struct {
		name       string
		correction edit
		clears     edit
	}{
		{"its authority retracts it", corr(security, core.OutcomeUnknown), rem("event-a")},
		{"its authority confirms it again", corr(security, core.OutcomeFailure), rem("event-a")},
		{"another authority retracts it", corr(soc, core.OutcomeUnknown), rem("event-a")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := reputation.NewOracle(cfg, native)
			rs := []core.OutcomeReport{report(tmpl, 0, sec), report(tmpl, 1, tc.correction)}
			for _, r := range rs {
				if a := o.Ingest(r, now); a.Ack != core.AckAccepted {
					t.Fatalf("%s: %+v", r.EventID, a)
				}
			}
			wantVerdict(t, o, "event-b", evalcase.Qualified, reputation.ReasonCorrection)
			check("after the correction", o, rs, want{core.SecurityHold, []string{"event-a"}, []string{"event-a"}})
			// A remediation that names the correction clears nothing.
			wrong := reputation.NewOracle(cfg, native)
			for _, r := range append(slices.Clone(rs), report(tmpl, 2, rem("event-b"))) {
				wrong.Ingest(r, now)
			}
			check("remediation naming the correction", wrong, rs, want{core.SecurityHold, []string{"event-a"}, []string{"event-a"}})
			r := report(tmpl, 2, tc.clears)
			if a := o.Ingest(r, now); a.Ack != core.AckAccepted {
				t.Fatalf("remediation: %+v", a)
			}
			check("after the remediation", o, rs, want{core.SecurityClear, []string{}, []string{"event-a"}})
		})
	}
}
