package reputation_test

import (
	"slices"
	"testing"

	"hop.top/pact-go/core"
	"hop.top/pact-go/reputation"
)

// TestVerifiedFeedback: the verified feedback row of Section 14.5: an
// evaluator's FEEDBACK on task_quality counts as an assessment and cites
// the completed assessment it conveys; the agent's own feedback needs no
// record and is never positive (Section 14.6 rule 11).
func TestVerifiedFeedback(t *testing.T) {
	feedback := func(iss string, role core.ReporterRole, res core.OutcomeResult, op string, refs ...string) func(*core.OutcomeReport) {
		return func(r *core.OutcomeReport) {
			r.Issuer, r.ReporterRole, r.EventKind, r.Result, r.Dimension = iss, role, core.EventFeedback, res, core.DimensionTaskQuality
			r.EvidenceRefs, r.OperationID, r.ObservedAt = append([]string{}, refs...), op, t0
		}
	}
	e := newEnv(t, nil)
	verified := e.report(feedback(evaluator, core.ReporterEvaluator, core.OutcomeSuccess, operation, reviewRef))
	own := e.report(feedback(agent, core.ReporterAgent, core.OutcomeSuccess, operation))
	recordless := e.report(feedback(evaluator, core.ReporterEvaluator, core.OutcomeSuccess, "invoice-read-operation-0002"))
	owner := e.report(feedback(owner, core.ReporterTaskOwner, core.OutcomeFailure, "invoice-read-operation-0003", readRef))
	for _, r := range []core.OutcomeReport{verified, own, recordless, owner} {
		e.mustAck(r, t0, core.AckAccepted)
	}
	cls, err := e.svc.Classifications()
	if err != nil {
		t.Fatal(err)
	}
	for r, rule := range map[string]string{verified.EventID: reputation.RuleMapped, own.EventID: reputation.RuleMapped,
		recordless.EventID: reputation.RuleNoAssessment, owner.EventID: reputation.RuleNoAssessment} {
		want := reputation.Qualified
		if rule != reputation.RuleMapped {
			want = reputation.Unqualified
		}
		if v := cls[r]; v.Qualification != want || v.Rule != rule {
			t.Errorf("%s: %+v, want %s %s", r, v, want, rule)
		}
	}
	s := e.query(t0)
	if d := s.Claims.Value.Dimensions.TaskQuality; d.ScoreBPS != 6666 || d.ConfidenceBPS != 476 || d.QualifiedEvents != 1 || d.IndependentTasks != 1 {
		t.Errorf("task_quality %+v, want 6666/476, one event of one task", d)
	}
	if q := s.Provenance.QualifiedEventIDs; len(q) != 1 || q[0][1] != verified.JTI {
		t.Errorf("listed %v, want the evaluator's feedback only", q)
	}
	// The agent's own failure is an attributable failure.
	e = newEnv(t, nil)
	e.mustAck(e.report(feedback(agent, core.ReporterAgent, core.OutcomeFailure, operation)), t0, core.AckAccepted)
	if d := e.query(t0).Claims.Value.Dimensions.TaskQuality; d.ScoreBPS != 3333 || d.ConfidenceBPS != 476 {
		t.Errorf("agent's own failure: %+v, want 3333/476", d)
	}
}

// TestAffiliatedFeedback: rule 6 of Section 14.6 covers the positive
// FEEDBACK of an affiliated evaluator; its negative feedback counts.
func TestAffiliatedFeedback(t *testing.T) {
	e := newEnv(t, func(c *reputation.Config) {
		c.Affiliations = []reputation.Affiliation{{EvaluatorIss: evaluator, OperatorID: "https://identity.example/operators/acme"}}
	})
	fb := func(res core.OutcomeResult, op string) core.OutcomeReport {
		return e.report(func(r *core.OutcomeReport) {
			r.Issuer, r.ReporterRole, r.EventKind, r.Result, r.Dimension = evaluator, core.ReporterEvaluator, core.EventFeedback, res, core.DimensionTaskQuality
			r.EvidenceRefs, r.OperationID, r.ObservedAt = []string{reviewRef}, op, t0
		})
	}
	praise, blame := fb(core.OutcomeSuccess, operation), fb(core.OutcomeFailure, "invoice-read-operation-0002")
	e.mustAck(praise, t0, core.AckAccepted)
	e.mustAck(blame, t0, core.AckAccepted)
	cls, _ := e.svc.Classifications()
	if v := cls[praise.EventID]; v.Qualification != reputation.Unqualified || v.Rule != reputation.RuleAffiliatedEvaluator {
		t.Errorf("positive feedback %+v, want UNQUALIFIED affiliated-evaluator", v)
	}
	if v := cls[blame.EventID]; v.Qualification != reputation.Qualified || v.Rule != reputation.RuleMapped {
		t.Errorf("negative feedback %+v, want QUALIFIED mapped", v)
	}
	if d := e.query(t0).Claims.Value.Dimensions.TaskQuality; d.ScoreBPS != 3333 || d.ConfidenceBPS != 476 {
		t.Errorf("task_quality %+v, want 3333/476", d)
	}
}

// TestHoldSurvivesCorrection: a correction of a confirmed incident
// supersedes it in provenance and leaves its hold, under the original
// event_id, until a clearance authority's remediation names that event_id
// (Section 15.4).
func TestHoldSurvivesCorrection(t *testing.T) {
	for _, result := range []core.OutcomeResult{core.OutcomeUnknown, core.OutcomeFailure} {
		t.Run(string(result), func(t *testing.T) {
			e := newEnv(t, nil)
			hold := e.report(securityReport())
			e.mustAck(hold, t0, core.AckAccepted)
			corr := e.report(func(r *core.OutcomeReport) {
				securityReport()(r)
				r.EventKind, r.Result, r.Supersedes = core.EventCorrection, result, []string{hold.EventID}
			})
			e.mustAck(corr, t0, core.AckAccepted)
			if cls, _ := e.svc.Classifications(); cls[corr.EventID].Rule != reputation.RuleCorrection {
				t.Fatalf("correction %+v, want QUALIFIED correction", cls[corr.EventID])
			}
			s := e.query(t0)
			if v := s.Claims.Value; v.SecurityStatus != core.SecurityHold || !slices.Equal(v.HoldRefs, []string{hold.EventID}) {
				t.Errorf("after the correction %s %v, want HOLD on %s", v.SecurityStatus, v.HoldRefs, hold.EventID)
			}
			if m := s.Provenance; len(m.SupersededEventIDs) != 1 || m.SupersededEventIDs[0][1] != hold.JTI || len(m.QualifiedEventIDs) != 0 {
				t.Errorf("manifest %+v, want the incident superseded, nothing listed", m)
			}
			e.mustAck(e.report(func(r *core.OutcomeReport) {
				r.Issuer, r.ReporterRole, r.EventKind, r.Result, r.Dimension = security, core.ReporterSecurityAuthority, core.EventRemediation, core.OutcomeSuccess, core.DimensionNone
				r.EvidenceRefs = []string{hold.EventID, fixRef}
			}), t0, core.AckAccepted)
			if v := e.query(t0).Claims.Value; v.SecurityStatus != core.SecurityClear || len(v.HoldRefs) != 0 {
				t.Errorf("after the remediation %s %v, want CLEAR", v.SecurityStatus, v.HoldRefs)
			}
		})
	}
}
