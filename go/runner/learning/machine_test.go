package learning

import (
	"fmt"
	"slices"
	"testing"

	"hop.top/pact-go/core"
	"hop.top/pact-go/core/digest"
	"hop.top/pact-go/runner/evalcase"
)

// The tests drive the state machine with typed messages, as the replay of a
// case does after it has verified the signatures. Every expected value comes
// from draft Sections 16.3 to 16.5 and Appendix A.2, not from the machine.

const (
	svcID     = "https://learning.example/finance"
	envID     = "https://gateway.example/environments/finance"
	authority = "https://trust.example/issuers/finance"
	ctrl      = "https://learning.example/controllers/finance"
	ctrl2     = "https://learning.example/controllers/finance-replica"
	evaluator = "https://learning.example/evaluators/independent"
	security  = "https://security.example/finance"
	executor  = "https://executor.example/finance"

	t0 int64 = 1792080000
	// shadowDone is a time clear of the 86400-second minimum shadow phase
	// after a SHADOW event at t0+120.
	shadowDone = t0 + 120 + 86460
)

func ctx(resource string) core.ReputationContext {
	return core.ReputationContext{
		TenantID: "acme", EnvironmentID: envID, AgentID: "https://identity.example/agents/invoice-assistant",
		PurposeID: "https://policies.example/purposes/invoice-summary/v1", ActionClass: "invoice.read",
		ResourceClass: resource, RuntimeClass: "managed-v1",
	}
}

func dg(label string) core.Digest { return digest.BytesDigest([]byte(label)) }

func ptr[T any](v T) *T { return &v }

func baseConfig() evalcase.LearningConfig {
	return evalcase.LearningConfig{
		Now: t0, ClockSkewSeconds: 5,
		LearningService: evalcase.LearningService{ServiceID: svcID, TenantID: "acme", EnvironmentID: envID},
		Evaluations: map[string]evalcase.Evaluator{
			"ref:independent": {EvaluatorID: evaluator},
			"ref:self":        {EvaluatorID: ctrl},
			"ref:other":       {EvaluatorID: "https://learning.example/evaluators/other"},
		},
		SourceDataManifests: map[string][]string{},
		ReputationService:   &evalcase.LearningService{ServiceID: "https://reputation.example/finance", TenantID: "acme", EnvironmentID: envID},
	}
}

func basePolicy() core.LearningPolicy {
	return core.LearningPolicy{
		PactVersion: core.Version, Issuer: authority, Subject: envID, Audience: svcID, JTI: "policy-jti-000000000001",
		IssuedAt: t0, NotBefore: t0, Expiry: t0 + 30*86400, TenantID: "acme", PolicyID: "finance-admission-learning-v1",
		EnvironmentID: envID, Mode: core.LearningBoundedAutonomous, ControllerIDs: []string{ctrl, ctrl2},
		BaseRevision: "finance-base-3", ConservativeSet: "supervised", AllowedRequirementSets: []string{"supervised", "established"},
		AdaptiveFields:             []core.AdaptiveControl{{ControlID: "supervisor-approval-required", AllowRelaxation: true}},
		PermittedArtifactTypes:     []core.ArtifactType{core.ArtifactBaseline, core.ArtifactScore},
		PermittedImplementationIDs: []string{"beta-decay-v1", "finance-selector-v1"},
		DataPolicy: core.DataPolicy{QualificationPolicyID: "pact-qualification-v1", IngestionWindowSeconds: 604800, PositiveWeightCapPerTask: 1,
			MaximumFailureWeight: 5, TaskAttributionSource: "native-task-registry", ReporterIndependencePolicyID: "pact-reporter-independence-v1"},
		EvaluationPolicy: core.EvaluationPolicy{
			MinimumIndependentTasks: 100, MinimumObservationSeconds: 604800, MinimumShadowSeconds: 86400, HoldoutPolicyID: "time-separated-holdout-v1",
			ImmutableTestSuiteDigests: []core.Digest{dg("suite")},
			MetricBounds: map[string]core.MetricBound{
				"native-denial-override-count": {Direction: core.BoundUpper, Value: 0},
				"admission-regression-rate":    {Direction: core.BoundUpper, Value: 0.01},
			},
			MaximumRolloutPercent: 10, RequiredEvaluatorIDs: []string{evaluator}, RollbackConditionIDs: []string{"any-native-denial-override"},
		},
		HoldClearanceAuthorities: []string{security},
	}
}

func baseArtifact(name string) core.LearningArtifact {
	id := "https://learning.example/artifacts/" + name
	return core.LearningArtifact{
		PactVersion: core.Version, Issuer: ctrl, Subject: id, Audience: svcID, JTI: "artifact-jti-" + fmt.Sprintf("%09d", len(name)) + name,
		IssuedAt: t0, NotBefore: t0, Expiry: t0 + 30*86400, TenantID: "acme", ArtifactID: id, Version: "1", ModelType: core.ArtifactBaseline,
		ImplementationID: "beta-decay-v1", ContentDigest: dg("content:" + name), SourceDataManifestDigest: dg("source:" + name),
		FeatureSchemaDigest: dg("feature"), TrainingConfigurationDigest: dg("training"), EvaluationReportDigest: dg("report:" + name),
		IntendedContexts: []core.ReputationContext{ctx("department-finance-invoice")}, BaseRevision: "finance-base-3",
		OutputControls: []string{"supervisor-approval-required"}, ArtifactStoreRef: "configured-store:" + name,
	}
}

// fixture is a machine with a policy installed unless the test says otherwise.
type fixture struct {
	t    *testing.T
	m    *Machine
	cfg  evalcase.LearningConfig
	pol  core.LearningPolicy
	seq  int
	arts map[string]core.Digest
	body map[string]core.LearningArtifact
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{t: t, cfg: baseConfig(), pol: basePolicy(), arts: map[string]core.Digest{}, body: map[string]core.LearningArtifact{}}
	return f
}

// start builds the machine, from the configuration as the test left it.
func (f *fixture) start() *fixture {
	f.t.Helper()
	f.m = NewMachine(f.cfg)
	return f
}

func (f *fixture) install(mods ...func(*core.LearningPolicy)) Result {
	f.t.Helper()
	if f.m == nil {
		f.start()
	}
	for _, mod := range mods {
		mod(&f.pol)
	}
	return f.m.InstallPolicy(Msg[core.LearningPolicy]{Claims: f.pol, ArtifactDigest: dg(fmt.Sprintf("policy:%s:%d", f.pol.JTI, f.pol.Expiry))}, t0)
}

func (f *fixture) policyDigest() core.Digest {
	return dg(fmt.Sprintf("policy:%s:%d", f.pol.JTI, f.pol.Expiry))
}

func (f *fixture) gate(name string, mods ...func(*evalcase.Gate)) {
	f.t.Helper()
	g := evalcase.Gate{ArtifactID: "https://learning.example/artifacts/" + name, Version: "1", IndependentTasks: 120, ObservationSeconds: 691200,
		TestSuitesPassed: []core.Digest{dg("suite")}, Metrics: map[string]float64{"native-denial-override-count": 0, "admission-regression-rate": 0.004}}
	for _, mod := range mods {
		mod(&g)
	}
	f.cfg.Gates = append(f.cfg.Gates, g)
}

// register registers the artifact name with good gate observations, unless a
// gate for it was set before start.
func (f *fixture) register(name string, at int64, mods ...func(*core.LearningArtifact)) Result {
	f.t.Helper()
	a := baseArtifact(name)
	for _, mod := range mods {
		mod(&a)
	}
	f.body[name] = a
	f.arts[name] = dg("artifact-jws:" + name + a.JTI)
	return f.m.Register(Msg[core.LearningArtifact]{Claims: a, ArtifactDigest: f.arts[name]}, at)
}

func (f *fixture) ev(name string, tr core.Transition, expected core.LifecycleState, mods ...func(*core.LearningEvent)) core.LearningEvent {
	f.seq++
	a := f.body[name]
	e := core.LearningEvent{
		PactVersion: core.Version, Issuer: ctrl, Subject: a.ArtifactID, Audience: svcID, JTI: fmt.Sprintf("event-jti-%013d", f.seq),
		IssuedAt: t0, NotBefore: t0, Expiry: t0 + 300, TenantID: "acme", EventID: fmt.Sprintf("event-%d", f.seq), EnvironmentID: envID,
		ArtifactDigest: f.arts[name], PolicyDigest: f.policyDigest(), Transition: tr, ExpectedState: expected,
		EffectiveAt: t0, ScopeContexts: a.IntendedContexts, EvaluationRefs: []string{}, ReasonCodes: []string{"EVALUATION_GATES_PASSED"},
	}
	switch tr {
	case core.TransitionEvaluated:
		e.EvaluationRefs = []string{"ref:independent"}
	case core.TransitionActive:
		e.ActivateArtifactDigest = ptr(f.arts[name])
	}
	for _, mod := range mods {
		mod(&e)
	}
	// Appendix A.2: previous_artifact_digest is expected_active_digest,
	// unless the test names another.
	if e.PreviousArtifactDigest == nil {
		e.PreviousArtifactDigest = e.ExpectedActiveDigest
	}
	return e
}

// send submits the event issued at at, which is also the service clock
// unless now is given, with exp 300 seconds later.
func (f *fixture) send(e core.LearningEvent, at int64, now ...int64) Result {
	f.t.Helper()
	e.IssuedAt, e.NotBefore, e.Expiry = at, at, at+300
	return f.m.Event(Msg[core.LearningEvent]{Claims: e, ArtifactDigest: dg("event-jws:" + e.JTI)}, append(now, at)[0])
}

func (f *fixture) do(name string, tr core.Transition, expected core.LifecycleState, at int64, mods ...func(*core.LearningEvent)) Result {
	f.t.Helper()
	return f.send(f.ev(name, tr, expected, mods...), at)
}

func (f *fixture) state(name string) core.LifecycleState {
	f.t.Helper()
	for _, a := range f.m.State().Artifacts {
		if a.Digest == f.arts[name] {
			return a.State
		}
	}
	f.t.Fatalf("artifact %s is not registered", name)
	return ""
}

func (f *fixture) activeIn(resource string) *core.Digest {
	f.t.Helper()
	for _, a := range f.m.State().Active {
		if a.Context.ResourceClass == resource {
			return a.Artifact
		}
	}
	f.t.Fatalf("no active entry for %s", resource)
	return nil
}

func wantAck(t *testing.T, r Result, status core.AckStatus) {
	t.Helper()
	if r.Rejection != nil || r.Ack != status {
		t.Fatalf("result %s, want ack %s", describe(r), status)
	}
}

func describe(r Result) string {
	if r.Rejection != nil {
		return fmt.Sprintf("rejection %s %v", r.Rejection.Code, r.Rejection.ReasonCodes)
	}
	return fmt.Sprintf("ack %q", r.Ack)
}

func wantReject(t *testing.T, r Result, code string, reasons ...string) {
	t.Helper()
	if r.Ack != "" || r.Rejection == nil {
		t.Fatalf("result %s, want rejection %s %v", describe(r), code, reasons)
	}
	got := slices.Clone(r.Rejection.ReasonCodes)
	slices.Sort(got)
	want := slices.Clone(reasons)
	slices.Sort(want)
	if r.Rejection.Code != code || !slices.Equal(got, want) {
		t.Fatalf("rejection %+v, want %s %v", *r.Rejection, code, reasons)
	}
}

// promoted returns a fixture with artifact "a" ACTIVE in the invoice context.
func promoted(t *testing.T) *fixture {
	t.Helper()
	f := newFixture(t).start()
	f.gate("a")
	f.m = NewMachine(f.cfg)
	wantNoResult(t, f.install())
	wantAck(t, f.register("a", t0), core.AckAccepted)
	wantAck(t, f.do("a", core.TransitionEvaluated, core.StateCandidate, t0+60), core.AckAccepted)
	wantAck(t, f.do("a", core.TransitionShadow, core.StateEvaluated, t0+120), core.AckAccepted)
	wantAck(t, f.do("a", core.TransitionActive, core.StateShadow, shadowDone), core.AckAccepted)
	return f
}

// expectedActive is the digest active in the invoice context, nil for the
// conservative set: what a controller names as expected_active_digest.
func (f *fixture) expectedActive(string) *core.Digest {
	f.t.Helper()
	return f.activeIn("department-finance-invoice")
}

// reach returns a fixture whose artifact "a" is in state from, by the events
// of Section 16.5, all accepted.
func reach(t *testing.T, from core.LifecycleState) *fixture {
	t.Helper()
	f := newFixture(t)
	f.gate("a")
	f.start()
	wantNoResult(t, f.install())
	wantAck(t, f.register("a", t0), core.AckAccepted)
	step := func(tr core.Transition, exp core.LifecycleState, at int64, mods ...func(*core.LearningEvent)) {
		t.Helper()
		wantAck(t, f.do("a", tr, exp, at, mods...), core.AckAccepted)
	}
	switch from {
	case core.StateCandidate:
	case core.StateRetired:
		step(core.TransitionRetired, core.StateCandidate, t0+60)
	default:
		step(core.TransitionEvaluated, core.StateCandidate, t0+60)
		if from == core.StateEvaluated {
			break
		}
		step(core.TransitionShadow, core.StateEvaluated, t0+120)
		if from == core.StateShadow {
			break
		}
		step(core.TransitionActive, core.StateShadow, shadowDone)
		if from == core.StateActive {
			break
		}
		out := func(e *core.LearningEvent) { e.ExpectedActiveDigest = ptr(f.arts["a"]) }
		switch from {
		case core.StateFrozen:
			step(core.TransitionFrozen, core.StateActive, shadowDone+10, out)
		case core.StateRolledBack:
			step(core.TransitionRolledBack, core.StateActive, shadowDone+10, out, func(e *core.LearningEvent) {
				e.ActivateArtifactDigest = nil
				e.ReasonCodes = []string{ReasonFallbackIncompatible}
			})
		default:
			t.Fatalf("no path to %s", from)
		}
	}
	if got := f.state("a"); got != from {
		t.Fatalf("reached %s, want %s", got, from)
	}
	return f
}

func wantNoResult(t *testing.T, r Result) {
	t.Helper()
	if r.Ack != "" || r.Rejection != nil {
		t.Fatalf("result %+v, want neither acknowledgment nor rejection", r)
	}
}

func TestNormalActivationPath(t *testing.T) {
	f := promoted(t)
	if f.state("a") != core.StateActive {
		t.Errorf("state %s, want ACTIVE", f.state("a"))
	}
	if got := f.activeIn("department-finance-invoice"); got == nil || *got != f.arts["a"] {
		t.Errorf("active %v, want the artifact", got)
	}
}

func TestNewArtifactIsCandidateAndConservativeSetInForce(t *testing.T) {
	f := newFixture(t).start()
	wantNoResult(t, f.install())
	wantAck(t, f.register("a", t0), core.AckAccepted)
	if f.state("a") != core.StateCandidate {
		t.Errorf("state %s, want CANDIDATE", f.state("a"))
	}
	if got := f.activeIn("department-finance-invoice"); got != nil {
		t.Errorf("active %v, want the conservative set (nil)", *got)
	}
}

// Section 16.5 table: the thirteen permitted transitions are accepted and
// every other (from, to) pair is invalid (INVALID_MESSAGE, Appendix A.2).
func TestTransitionTable(t *testing.T) {
	states := []core.LifecycleState{core.StateCandidate, core.StateEvaluated, core.StateShadow, core.StateActive, core.StateFrozen, core.StateRolledBack, core.StateRetired}
	targets := []core.Transition{core.TransitionEvaluated, core.TransitionShadow, core.TransitionActive, core.TransitionFrozen, core.TransitionRolledBack, core.TransitionRetired}
	allowed := map[[2]string]bool{
		{"CANDIDATE", "EVALUATED"}: true, {"EVALUATED", "SHADOW"}: true, {"SHADOW", "ACTIVE"}: true,
		{"ACTIVE", "FROZEN"}: true, {"ACTIVE", "ROLLED_BACK"}: true, {"ACTIVE", "RETIRED"}: true, {"FROZEN", "EVALUATED"}: true, {"SHADOW", "EVALUATED"}: true,
		{"CANDIDATE", "RETIRED"}: true, {"EVALUATED", "RETIRED"}: true, {"SHADOW", "RETIRED"}: true, {"FROZEN", "RETIRED"}: true,
		{"ROLLED_BACK", "RETIRED"}: true,
	}
	if len(allowed) != 13 {
		t.Fatalf("the table has %d rows, want 13", len(allowed))
	}
	for _, from := range states {
		for _, to := range targets {
			t.Run(string(from)+"->"+string(to), func(t *testing.T) {
				f := reach(t, from)
				expectedActive := f.expectedActive("a")
				e := f.ev("a", to, from, func(e *core.LearningEvent) {
					e.ExpectedActiveDigest = expectedActive
					if to == core.TransitionRolledBack {
						e.ActivateArtifactDigest = nil
						e.ReasonCodes = []string{ReasonFallbackIncompatible}
					}
				})
				r := f.send(e, shadowDone+1000)
				if allowed[[2]string{string(from), string(to)}] {
					wantAck(t, r, core.AckAccepted)
					if f.state("a") != core.LifecycleState(to) {
						t.Errorf("state %s, want %s", f.state("a"), to)
					}
					return
				}
				wantReject(t, r, CodeInvalidMessage)
				if f.state("a") != from {
					t.Errorf("state %s after the rejection, want %s", f.state("a"), from)
				}
			})
		}
	}
}
