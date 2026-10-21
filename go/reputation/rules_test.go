package reputation_test

import (
	"testing"

	"hop.top/pact-go/core"
	"hop.top/pact-go/reputation"
)

// TestCorrectionRetracts: an UNKNOWN correction keeps the dimension of the
// event it supersedes and retracts it: the snapshot has neither, and lists
// the success as superseded (Appendix A.2, Section 14.6 rule 10, 15.2).
func TestCorrectionRetracts(t *testing.T) {
	e := newEnv(t, nil)
	first := e.report(func(r *core.OutcomeReport) { r.ObservedAt = t0 - 20 })
	e.mustAck(first, t0, core.AckAccepted)
	if d := e.query(t0).Claims.Value.Dimensions.Reliability; d.ScoreBPS != 6666 || d.ConfidenceBPS != 476 {
		t.Fatalf("before: %+v, want 6666/476", d)
	}
	retraction := e.report(func(r *core.OutcomeReport) {
		r.EventKind, r.Result, r.Supersedes, r.ObservedAt = core.EventCorrection, core.OutcomeUnknown, []string{first.EventID}, t0-20
	})
	e.mustAck(retraction, t0, core.AckAccepted)
	s := e.query(t0)
	if d := s.Claims.Value.Dimensions.Reliability; d.ScoreBPS != 5000 || d.ConfidenceBPS != 0 || d.QualifiedEvents != 0 || d.IndependentTasks != 0 {
		t.Errorf("after: %+v, want 5000/0, no event", d)
	}
	if m := s.Provenance; len(m.QualifiedEventIDs) != 0 || len(m.SupersededEventIDs) != 1 || m.SupersededEventIDs[0][1] != first.JTI {
		t.Errorf("manifest %+v", m)
	}
	cls, err := e.svc.Classifications()
	if err != nil {
		t.Fatal(err)
	}
	if v := cls[retraction.EventID]; v.Qualification != reputation.Qualified || v.Rule != reputation.RuleCorrection {
		t.Errorf("retraction %+v", v)
	}
}

// TestPolicyViolation: a gateway's detected policy violation is one
// policy_adherence failure and no hold; a gateway SECURITY SUCCESS is
// UNQUALIFIED; a violation citing a denial record is record-mismatch
// (Sections 14.2, 14.5, 14.6 rule 12, 15.4).
func TestPolicyViolation(t *testing.T) {
	violation := func(r *core.OutcomeReport) {
		r.Issuer, r.ReporterRole, r.EventKind, r.Result, r.Dimension, r.EvidenceRefs = gateway, core.ReporterGateway,
			core.EventSecurity, core.OutcomeFailure, core.DimensionPolicyAdherence, []string{violationRef}
		r.ObservedAt = t0 - 20
	}
	e := newEnv(t, nil)
	v := e.report(violation)
	e.mustAck(v, t0, core.AckAccepted)
	s := e.query(t0)
	if d := s.Claims.Value.Dimensions.PolicyAdherence; d.ScoreBPS != 3333 || d.ConfidenceBPS != 476 || d.QualifiedEvents != 1 {
		t.Errorf("policy_adherence %+v, want 3333/476, one event", d)
	}
	if s.Claims.Value.SecurityStatus != core.SecurityClear || len(s.Claims.Value.HoldRefs) != 0 {
		t.Errorf("status %s %v, want CLEAR", s.Claims.Value.SecurityStatus, s.Claims.Value.HoldRefs)
	}
	e = newEnv(t, nil)
	clean := e.report(func(r *core.OutcomeReport) { violation(r); r.Result = core.OutcomeSuccess })
	denial := e.report(func(r *core.OutcomeReport) { violation(r); r.OperationID = "op-2"; r.EvidenceRefs = []string{readRef} })
	e.mustAck(clean, t0, core.AckAccepted)
	e.mustAck(denial, t0, core.AckAccepted)
	cls, err := e.svc.Classifications()
	if err != nil {
		t.Fatal(err)
	}
	if c := cls[clean.EventID]; c.Qualification != reputation.Unqualified || c.Rule != reputation.RuleNotEligible {
		t.Errorf("gateway SECURITY SUCCESS: %+v", c)
	}
	if c := cls[denial.EventID]; c.Qualification != reputation.Unqualified || c.Rule != reputation.RuleRecordMismatch {
		t.Errorf("violation citing another record: %+v", c)
	}
	if d := e.query(t0).Claims.Value.Dimensions.PolicyAdherence; d.ScoreBPS != 5000 || d.ConfidenceBPS != 0 {
		t.Errorf("policy_adherence %+v, want 5000/0", d)
	}
}

// TestPolicyAdherenceAssessment: an evaluator's QUALITY report on
// policy_adherence counts positively, its FEEDBACK failure negatively
// (Section 14.5).
func TestPolicyAdherenceAssessment(t *testing.T) {
	e := newEnv(t, nil)
	for _, res := range []core.OutcomeResult{core.OutcomeSuccess, core.OutcomeFailure} {
		kind, refs := core.EventQuality, []string{reviewRef}
		if res == core.OutcomeFailure {
			// Verified feedback cites the assessment it conveys.
			kind = core.EventFeedback
		}
		e.mustAck(e.report(func(r *core.OutcomeReport) {
			r.Issuer, r.ReporterRole, r.EventKind, r.Result, r.Dimension, r.EvidenceRefs = evaluator, core.ReporterEvaluator, kind, res, core.DimensionPolicyAdherence, refs
			r.ObservedAt = t0
		}), t0, core.AckAccepted)
	}
	// alpha 2, beta 2: 5000; effective weight 2: floor(10000 * 2 / 22).
	if d := e.query(t0).Claims.Value.Dimensions.PolicyAdherence; d.ScoreBPS != 5000 || d.ConfidenceBPS != 909 || d.QualifiedEvents != 2 {
		t.Errorf("policy_adherence %+v, want 5000/909, two events", d)
	}
}
