package learning

import (
	"slices"
	"testing"

	"hop.top/pact-go/core"
	"hop.top/pact-go/runner/evalcase"
)

// The rules of draft Sections 16.3, 16.5 and Appendix A.2 on promotion over
// an active artifact, re-evaluation, rejection codes and the evaluation
// check; each expected value is the one the draft text states.

// Section 16.5: a promotion replaces only the conservative set. An ACTIVE
// event naming an active artifact as expected_active_digest is invalid
// (Appendix A.2); one naming null fails the compare-and-swap; once the
// active artifact has left ACTIVE by its own event, the promotion is
// accepted.
func TestPromotionReplacesOnlyTheConservativeSet(t *testing.T) {
	f := shadowed(t, nil, "a", "b")
	wantAck(t, f.do("a", core.TransitionActive, core.StateShadow, shadowDone), core.AckAccepted)
	over := func(e *core.LearningEvent) { e.ExpectedActiveDigest = ptr(f.arts["a"]) }
	wantReject(t, f.do("b", core.TransitionActive, core.StateShadow, shadowDone+10, over), CodeInvalidMessage)
	wantReject(t, f.do("b", core.TransitionActive, core.StateShadow, shadowDone+20), CodeLearningRejected, ReasonVersionConflict)
	if f.state("a") != core.StateActive || f.state("b") != core.StateShadow {
		t.Fatalf("a=%s b=%s after the rejected promotions, want ACTIVE and SHADOW", f.state("a"), f.state("b"))
	}
	if got := f.activeIn("department-finance-invoice"); got == nil || *got != f.arts["a"] {
		t.Fatalf("active %v, want a", got)
	}
	wantAck(t, f.do("a", core.TransitionRetired, core.StateActive, shadowDone+30, over), core.AckAccepted)
	wantAck(t, f.do("b", core.TransitionActive, core.StateShadow, shadowDone+40), core.AckAccepted)
	if f.state("a") != core.StateRetired || f.state("b") != core.StateActive {
		t.Errorf("a=%s b=%s, want RETIRED and ACTIVE", f.state("a"), f.state("b"))
	}
	if got := f.activeIn("department-finance-invoice"); got == nil || *got != f.arts["b"] {
		t.Errorf("active %v, want b", got)
	}
}

// flagCorrection ingests exec-1 and its correction, which require the
// re-evaluation of every ACTIVE or SHADOW artifact whose source data
// manifest lists exec-1.
func flagCorrection(f *fixture, at int64) {
	f.t.Helper()
	wantAck(f.t, f.report(report("exec-1", "EXECUTION"), "executor", at), core.AckAccepted)
	wantAck(f.t, f.report(report("corr-1", "CORRECTION", func(r *core.OutcomeReport) { r.Supersedes = []string{"exec-1"}; r.Result = core.OutcomeFailure }), "executor", at+1), core.AckAccepted)
}

func sourceOf(names ...string) func(*fixture) {
	return func(f *fixture) {
		f.cfg.SourceDataManifests = map[string][]string{}
		for _, n := range names {
			f.cfg.SourceDataManifests[string(dg("source:"+n))] = []string{"exec-1"}
		}
	}
}

// Section 16.5: re-evaluation of a SHADOW artifact is its SHADOW to
// EVALUATED event, which ends the requirement; the artifact then needs a new
// shadow phase before promotion.
func TestShadowArtifactIsReevaluated(t *testing.T) {
	f := shadowed(t, sourceOf("a"), "a")
	flagCorrection(f, t0+130)
	if got := f.m.State().Reevaluate; !slices.Equal(got, []core.Digest{f.arts["a"]}) {
		t.Fatalf("reevaluation_required %v, want [a]", got)
	}
	wantAck(t, f.do("a", core.TransitionEvaluated, core.StateShadow, t0+200), core.AckAccepted)
	if f.state("a") != core.StateEvaluated {
		t.Errorf("state %s, want EVALUATED", f.state("a"))
	}
	if got := f.m.State().Reevaluate; len(got) != 0 {
		t.Errorf("reevaluation_required %v after the re-evaluation, want none", got)
	}
	wantAck(t, f.do("a", core.TransitionShadow, core.StateEvaluated, t0+300), core.AckAccepted)
	wantReject(t, f.do("a", core.TransitionActive, core.StateShadow, t0+300+86399), CodeLearningRejected, ReasonGateNotMet)
	wantAck(t, f.do("a", core.TransitionActive, core.StateShadow, t0+300+86400), core.AckAccepted)
}

// Section 16.3: the re-evaluation is an evaluation like any other; the
// controller's own result does not record it.
func TestReevaluationNeedsAnIndependentResult(t *testing.T) {
	f := shadowed(t, sourceOf("a"), "a")
	flagCorrection(f, t0+130)
	wantReject(t, f.do("a", core.TransitionEvaluated, core.StateShadow, t0+200, func(e *core.LearningEvent) { e.EvaluationRefs = []string{"ref:self"} }),
		CodeLearningRejected, ReasonSelfEvaluated)
	if f.state("a") != core.StateShadow || len(f.m.State().Reevaluate) != 1 {
		t.Errorf("state %s, reevaluation_required %v, want SHADOW and [a]", f.state("a"), f.m.State().Reevaluate)
	}
}

// Section 16.5: until its re-evaluation, an artifact is not promoted.
func TestArtifactAwaitingReevaluationIsNotPromoted(t *testing.T) {
	f := shadowed(t, sourceOf("a"), "a")
	flagCorrection(f, t0+130)
	wantReject(t, f.do("a", core.TransitionActive, core.StateShadow, shadowDone), CodeLearningRejected, ReasonGateNotMet)
	if f.state("a") != core.StateShadow {
		t.Errorf("state %s, want SHADOW", f.state("a"))
	}
	if got := f.activeIn("department-finance-invoice"); got != nil {
		t.Errorf("active %v, want the conservative set", *got)
	}
}

// Section 16.5: until its re-evaluation, an artifact does not meet condition
// 3 of a compatible rollback artifact; the conservative fallback stays open.
func TestArtifactAwaitingReevaluationIsNotACompatibleFallback(t *testing.T) {
	f := compatible(t, nil, sourceOf("b"))
	flagCorrection(f, shadowDone+10)
	if got := f.m.State().Reevaluate; !slices.Equal(got, []core.Digest{f.arts["b"]}) {
		t.Fatalf("reevaluation_required %v, want [b]", got)
	}
	wantReject(t, f.rollback("b", shadowDone+100), CodeLearningRejected, ReasonFallbackIncompatible)
	wantAck(t, f.rollback("", shadowDone+110), core.AckAccepted)
}

// Section 16.3: registration of a manifest whose model_type or
// implementation_id the policy does not permit is rejected
// LEARNING_REJECTED IMPLEMENTATION_NOT_PERMITTED, and nothing is registered;
// with a control outside adaptive_fields too, both codes are listed, in the
// order of the Section 16.5 table.
func TestRegistrationOfAnUnpermittedImplementation(t *testing.T) {
	tests := []struct {
		name string
		mod  func(*core.LearningArtifact)
		want []string
	}{
		{"model type", func(a *core.LearningArtifact) { a.ModelType = core.ArtifactCalibrator }, []string{ReasonImplementationNotPermitted}},
		{"implementation", func(a *core.LearningArtifact) { a.ImplementationID = "unlisted-v1" }, []string{ReasonImplementationNotPermitted}},
		{"model type and implementation", func(a *core.LearningArtifact) {
			a.ModelType, a.ImplementationID = core.ArtifactCalibrator, "unlisted-v1"
		}, []string{ReasonImplementationNotPermitted}},
		{"implementation and control", func(a *core.LearningArtifact) {
			a.ImplementationID = "unlisted-v1"
			a.OutputControls = []string{"supervisor-approval-required", "native-role-grant"}
		}, []string{ReasonControlNotAdaptive, ReasonImplementationNotPermitted}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t).start()
			wantNoResult(t, f.install())
			r := f.register("a", t0, tc.mod)
			wantReject(t, r, CodeLearningRejected, tc.want...)
			if !slices.Equal(r.Rejection.ReasonCodes, tc.want) {
				t.Errorf("reason codes %v, want %v in table order", r.Rejection.ReasonCodes, tc.want)
			}
			if got := f.m.State().Artifacts; len(got) != 0 {
				t.Errorf("artifacts %v, want none registered", got)
			}
		})
	}
	t.Run("permitted", func(t *testing.T) {
		f := newFixture(t).start()
		wantNoResult(t, f.install())
		wantAck(t, f.register("a", t0, func(a *core.LearningArtifact) {
			a.ModelType, a.ImplementationID = core.ArtifactScore, "finance-selector-v1"
		}), core.AckAccepted)
	})
}

// Section 16.3: an EVALUATED event is checked for an independent result, not
// for the release gates, which the ACTIVE event meets.
func TestReleaseGatesAreCheckedAtPromotion(t *testing.T) {
	f := newFixture(t)
	f.gate("a", func(g *evalcase.Gate) { g.IndependentTasks = 0; g.TestSuitesPassed = nil })
	f.start()
	wantNoResult(t, f.install())
	wantAck(t, f.register("a", t0), core.AckAccepted)
	wantAck(t, f.do("a", core.TransitionEvaluated, core.StateCandidate, t0+60), core.AckAccepted)
	wantAck(t, f.do("a", core.TransitionShadow, core.StateEvaluated, t0+120), core.AckAccepted)
	wantReject(t, f.do("a", core.TransitionActive, core.StateShadow, shadowDone), CodeLearningRejected, ReasonGateNotMet)
}

// Section 16.3: a result of the candidate's controller does not count, also
// when another controller signs the EVALUATED event, and also when the
// policy lists that controller among its evaluators.
func TestEvaluationByTheCandidatesController(t *testing.T) {
	for name, pre := range map[string]func(*fixture){
		"policy requires the independent evaluator": nil,
		"policy lists the candidate's controller":   func(f *fixture) { f.pol.EvaluationPolicy.RequiredEvaluatorIDs = []string{ctrl, evaluator} },
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.gate("a")
			if pre != nil {
				pre(f)
			}
			f.start()
			wantNoResult(t, f.install())
			wantAck(t, f.register("a", t0), core.AckAccepted)
			r := f.do("a", core.TransitionEvaluated, core.StateCandidate, t0+60, func(e *core.LearningEvent) {
				e.Issuer = ctrl2
				e.EvaluationRefs = []string{"ref:self"}
			})
			wantReject(t, r, CodeLearningRejected, ReasonSelfEvaluated)
			wantAck(t, f.do("a", core.TransitionEvaluated, core.StateCandidate, t0+70, func(e *core.LearningEvent) { e.Issuer = ctrl2 }), core.AckAccepted)
		})
	}
}

// Section 16.5: a signer that is not a controller of the installed policy,
// or any signer while no policy is installed, gets CONTROLLER_NOT_AUTHORIZED
// and no other reason code.
func TestEventFromASignerThatIsNotAController(t *testing.T) {
	f := newFixture(t).start()
	f.body["a"], f.arts["a"] = baseArtifact("a"), dg("artifact-jws:a")
	wantReject(t, f.m.Event(Msg[core.LearningEvent]{Claims: f.ev("a", core.TransitionRetired, core.StateCandidate), ArtifactDigest: dg("event")}, t0),
		CodeLearningRejected, ReasonControllerNotAuthorized)
	g := shadowed(t, func(f *fixture) { f.pol.Mode = core.LearningObserve }, "a")
	r := g.do("a", core.TransitionActive, core.StateShadow, shadowDone, func(e *core.LearningEvent) { e.Issuer = "https://learning.example/controllers/other" })
	wantReject(t, r, CodeLearningRejected, ReasonControllerNotAuthorized)
}

// Section 16.5: an ACTIVE event outside the artifact's intended contexts is
// CONTEXT_NOT_INTENDED, beside the other reasons that apply.
func TestContextNotIntendedAccumulates(t *testing.T) {
	f := shadowed(t, func(f *fixture) { f.pol.Mode = core.LearningObserve }, "a")
	r := f.do("a", core.TransitionActive, core.StateShadow, shadowDone, func(e *core.LearningEvent) {
		e.ScopeContexts = []core.ReputationContext{ctx("department-finance-invoice"), ctx("department-finance-ledger")}
	})
	wantReject(t, r, CodeLearningRejected, ReasonObserveMode, ReasonContextNotIntended)
}

// Appendix A.2: a report whose reporter_role the receiver has not registered
// for its signer is acknowledged and changes nothing: no hold, no clearance,
// no correction.
func TestReportOfAnUnregisteredRoleChangesNothing(t *testing.T) {
	f := newFixture(t).start()
	wantNoResult(t, f.install())
	wantAck(t, f.report(report("security-0", "SECURITY", asSecurity), "", t0+5), core.AckAccepted)
	if got := f.m.State().Holds; len(got) != 0 {
		t.Errorf("holds %v after a SECURITY report of an unregistered role, want none", got)
	}
	wantAck(t, f.report(report("security-1", "SECURITY", asSecurity), "security_authority", t0+10), core.AckAccepted)
	remediation := report("remediation-1", "REMEDIATION", func(r *core.OutcomeReport) {
		asSecurity(r)
		r.Result = core.OutcomeSuccess
		r.EvidenceRefs = []string{"security-1", "completion-evidence:1"}
	})
	wantAck(t, f.report(remediation, "", t0+20), core.AckAccepted)
	if got := f.m.State().Holds; !slices.Equal(got, []string{"security-1"}) {
		t.Errorf("holds %v after a REMEDIATION of an unregistered role, want [security-1]", got)
	}

	g := shadowed(t, sourceOf("a"), "a")
	wantAck(t, g.report(report("exec-1", "EXECUTION"), "executor", t0+130), core.AckAccepted)
	wantAck(t, g.report(report("corr-1", "CORRECTION", func(r *core.OutcomeReport) { r.Supersedes = []string{"exec-1"}; r.Result = core.OutcomeFailure }), "evaluator", t0+180), core.AckAccepted)
	if got := g.m.State().Reevaluate; len(got) != 0 {
		t.Errorf("reevaluation_required %v after a CORRECTION of an unregistered role, want none", got)
	}
	// A registered correction of a report that was not registered corrects
	// no qualified event.
	h := shadowed(t, sourceOf("a"), "a")
	wantAck(t, h.report(report("exec-1", "EXECUTION"), "", t0+130), core.AckAccepted)
	wantAck(t, h.report(report("corr-1", "CORRECTION", func(r *core.OutcomeReport) { r.Supersedes = []string{"exec-1"}; r.Result = core.OutcomeFailure }), "executor", t0+180), core.AckAccepted)
	if got := h.m.State().Reevaluate; len(got) != 0 {
		t.Errorf("reevaluation_required %v after correcting a report of an unregistered role, want none", got)
	}
}

// Appendix A.2: the reporter_role of a report is compared with every trust
// record of its signer, so a signer registered for two roles reports under
// either.
func TestReporterRoleOfASignerWithTwoRecords(t *testing.T) {
	trust := []evalcase.TrustRecord{
		{Iss: executor, Role: "reporter", ReporterRole: ptr("executor")},
		{Iss: executor, Role: "reporter", ReporterRole: ptr("evaluator")},
	}
	for claimed, want := range map[string]string{"executor": "executor", "evaluator": "evaluator", "security_authority": ""} {
		if got := reporterRole(trust, executor, claimed); got != want {
			t.Errorf("reporterRole(%s) = %q, want %q", claimed, got, want)
		}
	}
	if got := reporterRole(trust, "https://executor.example/other", "executor"); got != "" {
		t.Errorf("reporterRole of an unregistered signer = %q, want none", got)
	}
}
