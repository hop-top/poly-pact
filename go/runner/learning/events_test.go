package learning

import (
	"testing"

	"hop.top/pact-go/core"
	"hop.top/pact-go/runner/evalcase"
)

// shadowed returns a fixture with artifacts named in names registered,
// evaluated and in SHADOW from t0+120; policy and gates are the defaults
// unless pre changes the configuration before the machine starts.
func shadowed(t *testing.T, pre func(*fixture), names ...string) *fixture {
	t.Helper()
	f := newFixture(t)
	for _, n := range names {
		f.gate(n)
	}
	if pre != nil {
		pre(f)
	}
	f.start()
	wantNoResult(t, f.install())
	for _, n := range names {
		wantAck(t, f.register(n, t0), core.AckAccepted)
		wantAck(t, f.do(n, core.TransitionEvaluated, core.StateCandidate, t0+60), core.AckAccepted)
		wantAck(t, f.do(n, core.TransitionShadow, core.StateEvaluated, t0+120), core.AckAccepted)
	}
	return f
}

// Section 16.5: promotion is a compare-and-swap on the expected previous
// artifact; a conflicting transition is rejected VERSION_CONFLICT.
func TestConcurrentPromotionOneWins(t *testing.T) {
	f := shadowed(t, nil, "a", "b")
	wantAck(t, f.do("a", core.TransitionActive, core.StateShadow, shadowDone), core.AckAccepted)
	wantReject(t, f.do("b", core.TransitionActive, core.StateShadow, shadowDone), CodeLearningRejected, ReasonVersionConflict)
	if f.state("b") != core.StateShadow {
		t.Errorf("b is %s, want SHADOW", f.state("b"))
	}
	if got := f.activeIn("department-finance-invoice"); got == nil || *got != f.arts["a"] {
		t.Errorf("active %v, want a", got)
	}
}

func TestStaleExpectedStateConflicts(t *testing.T) {
	f := promoted(t)
	// The controller still believes the artifact is in SHADOW and retires it
	// from there.
	r := f.do("a", core.TransitionRetired, core.StateShadow, shadowDone+10, func(e *core.LearningEvent) { e.ExpectedActiveDigest = ptr(f.arts["a"]) })
	wantReject(t, r, CodeLearningRejected, ReasonVersionConflict)
	if f.state("a") != core.StateActive {
		t.Errorf("state %s, want ACTIVE", f.state("a"))
	}
}

func TestLeavingActiveNeedsTheOutgoingArtifactAsExpected(t *testing.T) {
	f := promoted(t)
	// expected_active_digest null while a is active: a compare-and-swap miss.
	wantReject(t, f.do("a", core.TransitionFrozen, core.StateActive, shadowDone+10), CodeLearningRejected, ReasonVersionConflict)
	wantAck(t, f.do("a", core.TransitionFrozen, core.StateActive, shadowDone+20, func(e *core.LearningEvent) { e.ExpectedActiveDigest = ptr(f.arts["a"]) }), core.AckAccepted)
}

func TestLeavingActiveReturnsTheContextToTheConservativeSet(t *testing.T) {
	for _, tr := range []core.Transition{core.TransitionFrozen, core.TransitionRetired, core.TransitionRolledBack} {
		t.Run(string(tr), func(t *testing.T) {
			f := promoted(t)
			r := f.do("a", tr, core.StateActive, shadowDone+10, func(e *core.LearningEvent) {
				e.ExpectedActiveDigest = ptr(f.arts["a"])
				if tr == core.TransitionRolledBack {
					e.ActivateArtifactDigest = nil
					e.ReasonCodes = []string{ReasonFallbackIncompatible}
				}
			})
			wantAck(t, r, core.AckAccepted)
			if got := f.activeIn("department-finance-invoice"); got != nil {
				t.Errorf("active %v, want the conservative set", *got)
			}
		})
	}
}

// Section 16.5, Appendix A.2: release gates. A gate that is present and not
// satisfied rejects the promotion GATE_NOT_MET.
func TestReleaseGates(t *testing.T) {
	tests := []struct {
		name string
		gate func(*evalcase.Gate)
		at   int64
		ok   bool
	}{
		{"all gates met", nil, shadowDone, true},
		{"shadow phase one second short", nil, t0 + 120 + 86399, false},
		{"shadow phase 86460 seconds", nil, shadowDone, true},
		{"shadow phase exactly the minimum", nil, t0 + 120 + 86400, true},
		{"99 independent tasks of 100", func(g *evalcase.Gate) { g.IndependentTasks = 99 }, shadowDone, false},
		{"100 independent tasks of 100", func(g *evalcase.Gate) { g.IndependentTasks = 100 }, shadowDone, true},
		{"observation one second short", func(g *evalcase.Gate) { g.ObservationSeconds = 604799 }, shadowDone, false},
		{"observation exactly the minimum", func(g *evalcase.Gate) { g.ObservationSeconds = 604800 }, shadowDone, true},
		{"immutable suite not passed", func(g *evalcase.Gate) { g.TestSuitesPassed = []core.Digest{dg("another")} }, shadowDone, false},
		{"no suite passed", func(g *evalcase.Gate) { g.TestSuitesPassed = nil }, shadowDone, false},
		{"upper bound exceeded", func(g *evalcase.Gate) { g.Metrics["admission-regression-rate"] = 0.011 }, shadowDone, false},
		{"upper bound met exactly", func(g *evalcase.Gate) { g.Metrics["admission-regression-rate"] = 0.01 }, shadowDone, true},
		{"native denial override above zero", func(g *evalcase.Gate) { g.Metrics["native-denial-override-count"] = 1 }, shadowDone, false},
		{"metric unobserved", func(g *evalcase.Gate) { delete(g.Metrics, "admission-regression-rate") }, shadowDone, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			if tc.gate != nil {
				f.gate("a", tc.gate)
			} else {
				f.gate("a")
			}
			f.start()
			wantNoResult(t, f.install())
			wantAck(t, f.register("a", t0), core.AckAccepted)
			wantAck(t, f.do("a", core.TransitionEvaluated, core.StateCandidate, t0+60), core.AckAccepted)
			wantAck(t, f.do("a", core.TransitionShadow, core.StateEvaluated, t0+120), core.AckAccepted)
			r := f.do("a", core.TransitionActive, core.StateShadow, tc.at)
			if tc.ok {
				wantAck(t, r, core.AckAccepted)
				return
			}
			wantReject(t, r, CodeLearningRejected, ReasonGateNotMet)
			if f.state("a") != core.StateShadow {
				t.Errorf("state %s after a rejected promotion, want SHADOW", f.state("a"))
			}
		})
	}
}

func TestLowerBoundMetric(t *testing.T) {
	for _, tc := range []struct {
		v  float64
		ok bool
	}{{0.89, false}, {0.9, true}, {0.95, true}} {
		f := newFixture(t)
		f.gate("a", func(g *evalcase.Gate) { g.Metrics["calibration"] = tc.v })
		f.pol.EvaluationPolicy.MetricBounds["calibration"] = core.MetricBound{Direction: core.BoundLower, Value: 0.9}
		f.start()
		wantNoResult(t, f.install())
		wantAck(t, f.register("a", t0), core.AckAccepted)
		wantAck(t, f.do("a", core.TransitionEvaluated, core.StateCandidate, t0+60), core.AckAccepted)
		wantAck(t, f.do("a", core.TransitionShadow, core.StateEvaluated, t0+120), core.AckAccepted)
		r := f.do("a", core.TransitionActive, core.StateShadow, shadowDone)
		if tc.ok {
			wantAck(t, r, core.AckAccepted)
		} else {
			wantReject(t, r, CodeLearningRejected, ReasonGateNotMet)
		}
	}
}

func TestNoObservationsForTheArtifactIsGateNotMet(t *testing.T) {
	f := newFixture(t).start()
	wantNoResult(t, f.install())
	wantAck(t, f.register("a", t0), core.AckAccepted)
	wantAck(t, f.do("a", core.TransitionEvaluated, core.StateCandidate, t0+60), core.AckAccepted)
	wantAck(t, f.do("a", core.TransitionShadow, core.StateEvaluated, t0+120), core.AckAccepted)
	wantReject(t, f.do("a", core.TransitionActive, core.StateShadow, shadowDone), CodeLearningRejected, ReasonGateNotMet)
}

// Section 16.3: the artifact that proposes a change MUST NOT be its sole
// source of promotion evidence.
func TestEvaluationIndependence(t *testing.T) {
	tests := []struct {
		name  string
		refs  []string
		pre   func(*fixture)
		codes []string
	}{
		{"only the controller's own evaluation", []string{"ref:self"}, nil, []string{ReasonSelfEvaluated}},
		{"own evaluation even when the policy lists the controller as an evaluator", []string{"ref:self"},
			func(f *fixture) { f.pol.EvaluationPolicy.RequiredEvaluatorIDs = []string{ctrl} }, []string{ReasonSelfEvaluated}},
		{"independent evaluation", []string{"ref:independent"}, nil, nil},
		{"own evaluation beside an independent one", []string{"ref:self", "ref:independent"}, nil, nil},
		{"no evaluation reference", []string{}, nil, []string{ReasonGateNotMet}},
		{"an evaluator the policy does not require", []string{"ref:other"}, nil, []string{ReasonGateNotMet}},
		{"an unresolved reference", []string{"ref:unknown"}, nil, []string{ReasonGateNotMet}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			f.gate("a")
			if tc.pre != nil {
				tc.pre(f)
			}
			f.start()
			wantNoResult(t, f.install())
			wantAck(t, f.register("a", t0), core.AckAccepted)
			r := f.do("a", core.TransitionEvaluated, core.StateCandidate, t0+60, func(e *core.LearningEvent) { e.EvaluationRefs = tc.refs })
			if tc.codes == nil {
				wantAck(t, r, core.AckAccepted)
				return
			}
			wantReject(t, r, CodeLearningRejected, tc.codes...)
			if f.state("a") != core.StateCandidate {
				t.Errorf("state %s, want CANDIDATE", f.state("a"))
			}
		})
	}
}

// Section 16.4: in observe mode no active selection changes.
func TestObserveModeRecordsButNeverActivates(t *testing.T) {
	f := shadowed(t, func(f *fixture) { f.pol.Mode = core.LearningObserve }, "a")
	wantReject(t, f.do("a", core.TransitionActive, core.StateShadow, shadowDone), CodeLearningRejected, ReasonObserveMode)
	if f.state("a") != core.StateShadow {
		t.Errorf("state %s, want SHADOW", f.state("a"))
	}
	if got := f.activeIn("department-finance-invoice"); got != nil {
		t.Errorf("active %v, want the conservative set", *got)
	}
}

// Section 16.5: after the policy's exp only transitions to FROZEN,
// ROLLED_BACK or RETIRED are accepted.
func TestPolicyExpiry(t *testing.T) {
	exp := basePolicy().Expiry
	for _, tc := range []struct {
		tr   core.Transition
		from core.LifecycleState
		ok   bool
	}{
		{core.TransitionEvaluated, core.StateCandidate, false},
		{core.TransitionShadow, core.StateEvaluated, false},
		{core.TransitionActive, core.StateShadow, false},
		{core.TransitionFrozen, core.StateActive, true},
		{core.TransitionRolledBack, core.StateActive, true},
		{core.TransitionRetired, core.StateActive, true},
		{core.TransitionRetired, core.StateCandidate, true},
	} {
		t.Run(string(tc.from)+"->"+string(tc.tr), func(t *testing.T) {
			f := reach(t, tc.from)
			r := f.do("a", tc.tr, tc.from, exp+1, func(e *core.LearningEvent) {
				if tc.from == core.StateActive {
					e.ExpectedActiveDigest = ptr(f.arts["a"])
				}
				if tc.tr == core.TransitionRolledBack {
					e.ActivateArtifactDigest = nil
					e.ReasonCodes = []string{ReasonFallbackIncompatible}
				}
			})
			if tc.ok {
				wantAck(t, r, core.AckAccepted)
				return
			}
			wantReject(t, r, CodeLearningRejected, ReasonPolicyExpired)
		})
	}
}

func TestPolicyExpiryBoundary(t *testing.T) {
	exp := basePolicy().Expiry
	f := reach(t, core.StateShadow)
	// One second before exp the policy is current; the event's own validity
	// is a separate matter.
	wantAck(t, f.do("a", core.TransitionActive, core.StateShadow, exp-1), core.AckAccepted)
	g := reach(t, core.StateShadow)
	wantReject(t, g.do("a", core.TransitionActive, core.StateShadow, exp), CodeLearningRejected, ReasonPolicyExpired)
}

func TestReasonsAccumulate(t *testing.T) {
	exp := basePolicy().Expiry
	f := shadowed(t, func(f *fixture) { f.pol.Mode = core.LearningObserve }, "a")
	wantReject(t, f.do("a", core.TransitionActive, core.StateShadow, exp+1), CodeLearningRejected, ReasonPolicyExpired, ReasonObserveMode)
}

// compatible builds a fixture with a ACTIVE and b SHADOW for the same
// context, b changed by mod before registration.
func compatible(t *testing.T, mod func(*core.LearningArtifact), pre func(*fixture)) *fixture {
	t.Helper()
	f := newFixture(t)
	f.gate("a")
	f.gate("b")
	if pre != nil {
		pre(f)
	}
	f.start()
	wantNoResult(t, f.install())
	wantAck(t, f.register("a", t0), core.AckAccepted)
	wantAck(t, f.register("b", t0, func(a *core.LearningArtifact) {
		if mod != nil {
			mod(a)
		}
	}), core.AckAccepted)
	for _, n := range []string{"a", "b"} {
		wantAck(t, f.do(n, core.TransitionEvaluated, core.StateCandidate, t0+60), core.AckAccepted)
		wantAck(t, f.do(n, core.TransitionShadow, core.StateEvaluated, t0+120), core.AckAccepted)
	}
	wantAck(t, f.do("a", core.TransitionActive, core.StateShadow, shadowDone), core.AckAccepted)
	return f
}

func (f *fixture) rollback(to string, at int64, mods ...func(*core.LearningEvent)) Result {
	f.t.Helper()
	return f.do("a", core.TransitionRolledBack, core.StateActive, at, append([]func(*core.LearningEvent){func(e *core.LearningEvent) {
		e.ExpectedActiveDigest = ptr(f.arts["a"])
		e.ReasonCodes = []string{"REGRESSION_LIMIT"}
		if to == "" {
			e.ActivateArtifactDigest = nil
			e.ReasonCodes = []string{ReasonFallbackIncompatible}
		} else {
			e.ActivateArtifactDigest = ptr(f.arts[to])
		}
	}}, mods...)...)
}

// Section 16.5: a compatible rollback artifact meets four conditions; a
// rollback that names one that does not is rejected FALLBACK_INCOMPATIBLE.
func TestCompatibleRollback(t *testing.T) {
	at := shadowDone + 100
	f := compatible(t, nil, nil)
	wantAck(t, f.rollback("b", at), core.AckAccepted)
	if f.state("a") != core.StateRolledBack || f.state("b") != core.StateActive {
		t.Errorf("states a=%s b=%s, want ROLLED_BACK and ACTIVE", f.state("a"), f.state("b"))
	}
	if got := f.activeIn("department-finance-invoice"); got == nil || *got != f.arts["b"] {
		t.Errorf("active %v, want b", got)
	}
}

// An artifact in force in another context is a compatible fallback when it
// meets the four conditions: "EVALUATED or later" is not limited to SHADOW.
func TestRollbackToAnArtifactActiveElsewhere(t *testing.T) {
	f := compatible(t, func(a *core.LearningArtifact) {
		a.IntendedContexts = []core.ReputationContext{ctx("department-finance-invoice"), ctx("department-finance-ledger")}
	}, nil)
	ledger := []core.ReputationContext{ctx("department-finance-ledger")}
	wantAck(t, f.do("b", core.TransitionActive, core.StateShadow, shadowDone+1, func(e *core.LearningEvent) { e.ScopeContexts = ledger }), core.AckAccepted)
	wantAck(t, f.rollback("b", shadowDone+100), core.AckAccepted)
	if got := f.activeIn("department-finance-invoice"); got == nil || *got != f.arts["b"] {
		t.Errorf("active %v, want b", got)
	}
}

func TestIncompatibleRollbackFallbacks(t *testing.T) {
	at := shadowDone + 100
	tests := []struct {
		name string
		mod  func(*core.LearningArtifact)
		pre  func(*fixture)
		to   func(*fixture) // brings b to another state before the rollback
	}{
		{name: "other base revision (condition 1)", mod: func(a *core.LearningArtifact) { a.BaseRevision = "finance-base-2" }},
		{name: "other model type (condition 1)", mod: func(a *core.LearningArtifact) { a.ModelType = core.ArtifactScore }},
		{name: "intended contexts do not cover the scope (condition 4)", mod: func(a *core.LearningArtifact) {
			a.IntendedContexts = []core.ReputationContext{ctx("department-finance-ledger")}
		}},
		{name: "retired (condition 3)", to: func(f *fixture) {
			wantAck(f.t, f.do("b", core.TransitionRetired, core.StateShadow, shadowDone+50, func(e *core.LearningEvent) { e.ExpectedActiveDigest = ptr(f.arts["a"]) }), core.AckAccepted)
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := compatible(t, tc.mod, tc.pre)
			if tc.to != nil {
				tc.to(f)
			}
			wantReject(t, f.rollback("b", at), CodeLearningRejected, ReasonFallbackIncompatible)
			if f.state("a") != core.StateActive {
				t.Errorf("a is %s after the rejected rollback, want ACTIVE", f.state("a"))
			}
		})
	}
}

// Section 16.5, condition 2: the fallback's implementation_id is permitted
// by the installed policy. Registration already requires it (Section 16.3),
// so the condition fails alone after a policy that no longer permits the
// implementation replaces the one b was registered under, b's shadow phase
// having run again under the new policy.
func TestRollbackFallbackImplementationNoLongerPermitted(t *testing.T) {
	for name, keep := range map[string]bool{"still permitted": true, "no longer permitted": false} {
		t.Run(name, func(t *testing.T) {
			f := compatible(t, func(a *core.LearningArtifact) { a.ImplementationID = "unlisted-v1" }, func(f *fixture) {
				f.pol.PermittedImplementationIDs = append(f.pol.PermittedImplementationIDs, "unlisted-v1")
			})
			wantNoResult(t, f.install(func(p *core.LearningPolicy) {
				p.JTI = "policy-jti-000000000002"
				if !keep {
					p.PermittedImplementationIDs = []string{"beta-decay-v1", "finance-selector-v1"}
				}
			}))
			over := func(e *core.LearningEvent) { e.ExpectedActiveDigest = ptr(f.arts["a"]) }
			wantAck(t, f.do("b", core.TransitionEvaluated, core.StateShadow, shadowDone+10, over), core.AckAccepted)
			wantAck(t, f.do("b", core.TransitionShadow, core.StateEvaluated, shadowDone+20, over), core.AckAccepted)
			r := f.rollback("b", shadowDone+20+86400+10)
			if keep {
				wantAck(t, r, core.AckAccepted)
				return
			}
			wantReject(t, r, CodeLearningRejected, ReasonFallbackIncompatible)
		})
	}
}

func TestRollbackFallbackNeedsACompletedShadowPhase(t *testing.T) {
	// b is shadowed 10 seconds after a was promoted.
	f := newFixture(t)
	f.gate("a")
	f.gate("b")
	f.start()
	wantNoResult(t, f.install())
	wantAck(t, f.register("a", t0), core.AckAccepted)
	wantAck(t, f.register("b", t0), core.AckAccepted)
	wantAck(t, f.do("a", core.TransitionEvaluated, core.StateCandidate, t0+60), core.AckAccepted)
	wantAck(t, f.do("a", core.TransitionShadow, core.StateEvaluated, t0+120), core.AckAccepted)
	wantAck(t, f.do("b", core.TransitionEvaluated, core.StateCandidate, t0+60), core.AckAccepted)
	wantAck(t, f.do("a", core.TransitionActive, core.StateShadow, shadowDone), core.AckAccepted)
	// b has been evaluated and not shadowed: no shadow phase.
	wantReject(t, f.rollback("b", shadowDone+100), CodeLearningRejected, ReasonFallbackIncompatible)
	shadowAt := shadowDone + 200
	wantAck(t, f.do("b", core.TransitionShadow, core.StateEvaluated, shadowAt, func(e *core.LearningEvent) { e.ExpectedActiveDigest = ptr(f.arts["a"]) }), core.AckAccepted)
	wantReject(t, f.rollback("b", shadowAt+86399), CodeLearningRejected, ReasonFallbackIncompatible)
	wantAck(t, f.rollback("b", shadowAt+86400), core.AckAccepted)
}

func TestRollbackFallbackShadowPhaseIsUnderTheCurrentPolicy(t *testing.T) {
	f := compatible(t, nil, nil)
	// A renewed policy has another digest: b's shadow phase ran under the old
	// one (Section 16.5, condition 3).
	f.pol.JTI = "policy-jti-000000000002"
	wantNoResult(t, f.install())
	wantReject(t, f.rollback("b", shadowDone+100), CodeLearningRejected, ReasonFallbackIncompatible)
}

func TestRollbackToTheConservativeSet(t *testing.T) {
	f := compatible(t, nil, nil)
	wantAck(t, f.rollback("", shadowDone+100), core.AckAccepted)
	if f.state("a") != core.StateRolledBack || f.state("b") != core.StateShadow {
		t.Errorf("a=%s b=%s, want ROLLED_BACK and SHADOW", f.state("a"), f.state("b"))
	}
	if got := f.activeIn("department-finance-invoice"); got != nil {
		t.Errorf("active %v, want the conservative set", *got)
	}
}

// Appendix A.2: a rollback to null records FALLBACK_INCOMPATIBLE; a rollback
// to an artifact does not name itself as its fallback.
func TestRollbackNullNeedsTheReasonCode(t *testing.T) {
	f := compatible(t, nil, nil)
	r := f.rollback("", shadowDone+100, func(e *core.LearningEvent) { e.ReasonCodes = []string{"REGRESSION_LIMIT"} })
	wantReject(t, r, CodeInvalidMessage)
}

func TestRollbackToItselfIsIncompatible(t *testing.T) {
	f := compatible(t, nil, nil)
	wantReject(t, f.rollback("a", shadowDone+100), CodeLearningRejected, ReasonFallbackIncompatible)
}

// Section 16.5: a frozen artifact requires a new successful evaluation and
// shadow phase before reactivation.
func TestFrozenNeedsNewEvaluationAndShadow(t *testing.T) {
	f := reach(t, core.StateFrozen)
	at := shadowDone + 1000
	// Outside the table: invalid on their face (Appendix A.2).
	wantReject(t, f.do("a", core.TransitionActive, core.StateFrozen, at), CodeInvalidMessage)
	wantReject(t, f.do("a", core.TransitionShadow, core.StateFrozen, at), CodeInvalidMessage)
	wantAck(t, f.do("a", core.TransitionEvaluated, core.StateFrozen, at+1), core.AckAccepted)
	// Evaluated again, not yet shadowed: ACTIVE is outside the table.
	wantReject(t, f.do("a", core.TransitionActive, core.StateEvaluated, at+2), CodeInvalidMessage)
	wantAck(t, f.do("a", core.TransitionShadow, core.StateEvaluated, at+3), core.AckAccepted)
	// The earlier shadow phase does not count: the new one starts at at+3.
	wantReject(t, f.do("a", core.TransitionActive, core.StateShadow, at+3+86399), CodeLearningRejected, ReasonGateNotMet)
	wantAck(t, f.do("a", core.TransitionActive, core.StateShadow, at+3+86460), core.AckAccepted)
}

func TestFrozenArtifactNeedsIndependentEvaluationAgain(t *testing.T) {
	f := reach(t, core.StateFrozen)
	r := f.do("a", core.TransitionEvaluated, core.StateFrozen, shadowDone+1000, func(e *core.LearningEvent) { e.EvaluationRefs = []string{"ref:self"} })
	wantReject(t, r, CodeLearningRejected, ReasonSelfEvaluated)
}

func TestActivationOutsideIntendedContextsIsRejected(t *testing.T) {
	f := shadowed(t, nil, "a")
	r := f.do("a", core.TransitionActive, core.StateShadow, shadowDone, func(e *core.LearningEvent) {
		e.ScopeContexts = []core.ReputationContext{ctx("department-finance-ledger")}
	})
	wantReject(t, r, CodeLearningRejected, ReasonContextNotIntended)
}

func TestEventForAnUnregisteredArtifact(t *testing.T) {
	f := shadowed(t, nil, "a")
	r := f.do("a", core.TransitionRetired, core.StateShadow, shadowDone, func(e *core.LearningEvent) { e.ArtifactDigest = dg("unregistered") })
	// An unregistered artifact is in no expected_state (Section 16.5).
	wantReject(t, r, CodeLearningRejected, ReasonVersionConflict)
}

func TestControllerAuthority(t *testing.T) {
	f := shadowed(t, nil, "a")
	wantReject(t, f.do("a", core.TransitionRetired, core.StateShadow, shadowDone, func(e *core.LearningEvent) { e.Issuer = "https://learning.example/controllers/other" }), CodeLearningRejected, ReasonControllerNotAuthorized)
	wantAck(t, f.do("a", core.TransitionRetired, core.StateShadow, shadowDone+1, func(e *core.LearningEvent) { e.Issuer = ctrl2 }), core.AckAccepted)
}

func TestEventNeedsTheInstalledPolicy(t *testing.T) {
	f := shadowed(t, nil, "a")
	wantReject(t, f.do("a", core.TransitionActive, core.StateShadow, shadowDone, func(e *core.LearningEvent) { e.PolicyDigest = dg("another policy") }), CodeLearningRejected, ReasonVersionConflict)
}

func TestEventSubIsTheArtifactURI(t *testing.T) {
	f := shadowed(t, nil, "a")
	wantReject(t, f.do("a", core.TransitionActive, core.StateShadow, shadowDone, func(e *core.LearningEvent) { e.Subject = "https://learning.example/artifacts/other" }), CodeInvalidMessage)
}

func TestEventActivationMembers(t *testing.T) {
	f := shadowed(t, nil, "a")
	wantReject(t, f.do("a", core.TransitionActive, core.StateShadow, shadowDone, func(e *core.LearningEvent) { e.ActivateArtifactDigest = nil }), CodeInvalidMessage)
	wantReject(t, f.do("a", core.TransitionRetired, core.StateShadow, shadowDone, func(e *core.LearningEvent) { e.ActivateArtifactDigest = ptr(f.arts["a"]) }), CodeInvalidMessage)
	wantReject(t, f.do("a", core.TransitionRetired, core.StateShadow, shadowDone, func(e *core.LearningEvent) { e.ReasonCodes = nil }), CodeInvalidMessage)
	// Appendix A.2: previous_artifact_digest equals expected_active_digest,
	// both null for an ACTIVE event.
	wantReject(t, f.do("a", core.TransitionActive, core.StateShadow, shadowDone, func(e *core.LearningEvent) { e.PreviousArtifactDigest = ptr(dg("other")) }), CodeInvalidMessage)
	if f.state("a") != core.StateShadow {
		t.Errorf("state %s, want SHADOW", f.state("a"))
	}
}

// Appendix A.2: an event that leaves ACTIVE names the outgoing artifact as
// both its previous and its expected active artifact; null, or another
// artifact, as previous_artifact_digest is invalid.
func TestEventPreviousArtifactIsTheExpectedActive(t *testing.T) {
	for name, prev := range map[string]*core.Digest{"null": nil, "another artifact": ptr(dg("other"))} {
		t.Run(name, func(t *testing.T) {
			f := promoted(t)
			e := f.ev("a", core.TransitionFrozen, core.StateActive, func(e *core.LearningEvent) { e.ExpectedActiveDigest = ptr(f.arts["a"]) })
			e.PreviousArtifactDigest = prev
			wantReject(t, f.send(e, shadowDone+10), CodeInvalidMessage)
			if f.state("a") != core.StateActive {
				t.Errorf("state %s, want ACTIVE", f.state("a"))
			}
		})
	}
}

// Section 16.5: an event that leaves ACTIVE names every context its artifact
// is in force in. An artifact ACTIVE for invoices and ledgers that is
// frozen, rolled back or retired for ledgers alone fails the
// compare-and-swap, VERSION_CONFLICT, and changes nothing; named for both, it
// leaves ACTIVE in both, which return to the conservative set.
func TestLeavingActiveNamesEveryContext(t *testing.T) {
	both := []core.ReputationContext{ctx("department-finance-invoice"), ctx("department-finance-ledger")}
	for _, tr := range []core.Transition{core.TransitionFrozen, core.TransitionRolledBack, core.TransitionRetired} {
		t.Run(string(tr), func(t *testing.T) {
			f := newFixture(t)
			f.gate("a")
			f.start()
			wantNoResult(t, f.install())
			wantAck(t, f.register("a", t0, func(a *core.LearningArtifact) { a.IntendedContexts = both }), core.AckAccepted)
			wantAck(t, f.do("a", core.TransitionEvaluated, core.StateCandidate, t0+60), core.AckAccepted)
			wantAck(t, f.do("a", core.TransitionShadow, core.StateEvaluated, t0+120), core.AckAccepted)
			wantAck(t, f.do("a", core.TransitionActive, core.StateShadow, shadowDone), core.AckAccepted)
			leave := func(scope ...core.ReputationContext) func(*core.LearningEvent) {
				return func(e *core.LearningEvent) {
					e.ScopeContexts = scope
					e.ExpectedActiveDigest = ptr(f.arts["a"])
					if tr == core.TransitionRolledBack {
						e.ReasonCodes = []string{ReasonFallbackIncompatible}
					}
				}
			}
			wantReject(t, f.do("a", tr, core.StateActive, shadowDone+10, leave(both[1])), CodeLearningRejected, ReasonVersionConflict)
			if f.state("a") != core.StateActive {
				t.Fatalf("state %s after the partial event, want ACTIVE", f.state("a"))
			}
			for _, res := range []string{"department-finance-invoice", "department-finance-ledger"} {
				if got := f.activeIn(res); got == nil || *got != f.arts["a"] {
					t.Fatalf("%s: active %v after the partial event, want a", res, got)
				}
			}
			wantAck(t, f.do("a", tr, core.StateActive, shadowDone+20, leave(both...)), core.AckAccepted)
			for _, res := range []string{"department-finance-invoice", "department-finance-ledger"} {
				if got := f.activeIn(res); got != nil {
					t.Errorf("%s: active %v, want the conservative set", res, *got)
				}
			}
		})
	}
}

func TestEventThatDidNotChangeStateIsNotRecorded(t *testing.T) {
	f := shadowed(t, nil, "a")
	e := f.ev("a", core.TransitionActive, core.StateShadow)
	// Rejected for a short shadow phase; the same message (same jti) is
	// processed again later, since a rejection is not durable.
	wantReject(t, f.send(e, t0+200), CodeLearningRejected, ReasonGateNotMet)
	wantAck(t, f.send(e, shadowDone), core.AckAccepted)
}
