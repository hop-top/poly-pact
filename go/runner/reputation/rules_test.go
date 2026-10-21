package reputation_test

import (
	"slices"
	"testing"

	"hop.top/pact-go/core"
	"hop.top/pact-go/runner/evalcase"
	"hop.top/pact-go/runner/reputation"
)

const (
	violationRecord = "native-gateway-record:scope-violation-0001"
	failedRecord    = "native-execution-log:finance-read-0001/reconciled"
	taskOwner       = "https://owner.example/finance"
	acmeOperator    = "https://identity.example/operators/acme"
)

// ruleFixture is fixture with a task owner and the gateway's record of a
// violating request of the template's task and operation.
func ruleFixture(t *testing.T) (evalcase.OutcomesConfig, evalcase.OutcomesNative, core.OutcomeReport) {
	t.Helper()
	cfg, native, tmpl := fixture(t)
	cfg.Trust = append(cfg.Trust, evalcase.TrustRecord{Iss: taskOwner, Role: "reporter", ReporterRole: strp("task_owner")})
	native.Records[violationRecord] = evalcase.NativeRecord{Kind: "violation", State: "recorded", TaskID: tmpl.TaskID, OperationID: tmpl.OperationID}
	native.Records["native-gateway-record:other-operation"] = evalcase.NativeRecord{Kind: "violation", State: "recorded", TaskID: tmpl.TaskID,
		OperationID: "invoice-read-operation-0002"}
	tmpl.ObservedAt = now - 20
	return cfg, native, tmpl
}

type edit = func(*core.OutcomeReport)

func chain(edits ...edit) edit {
	return func(x *core.OutcomeReport) {
		for _, e := range edits {
			if e != nil {
				e(x)
			}
		}
	}
}

func quality(d core.Dimension, result core.OutcomeResult) edit {
	return func(x *core.OutcomeReport) {
		x.EventKind, x.Result, x.Dimension, x.Issuer, x.ReporterRole = core.EventQuality, result, d, evaluator, "evaluator"
		x.EvidenceRefs = []string{review}
	}
}

// feedback is a FEEDBACK report: from an evaluator or the task owner it
// cites the completed assessment it conveys, from the agent itself nothing
// (Section 14.5, verified feedback).
func feedback(iss, role string, d core.Dimension, result core.OutcomeResult) edit {
	return func(x *core.OutcomeReport) {
		x.EventKind, x.Result, x.Dimension, x.Issuer, x.ReporterRole = core.EventFeedback, result, d, iss, core.ReporterRole(role)
		x.EvidenceRefs = []string{}
		if role != "agent" {
			x.EvidenceRefs = []string{review}
		}
	}
}

// violation is the gateway's detected policy violation of Section 14.5.
func violation(x *core.OutcomeReport) {
	x.EventKind, x.Result, x.Dimension, x.Issuer, x.ReporterRole = core.EventSecurity, core.OutcomeFailure, core.DimensionPolicyAdherence, gateway, "gateway"
	x.EvidenceRefs = []string{violationRecord}
}

// correcting makes a report a CORRECTION of the events named.
func correcting(result core.OutcomeResult, events ...string) edit {
	return func(x *core.OutcomeReport) {
		x.EventKind, x.Result, x.Supersedes = core.EventCorrection, result, events
	}
}

func refs(rs ...string) edit {
	return func(x *core.OutcomeReport) { x.EvidenceRefs = append([]string{}, rs...) }
}

func by(iss, role string) edit {
	return func(x *core.OutcomeReport) { x.Issuer, x.ReporterRole = iss, core.ReporterRole(role) }
}

func dimension(d core.Dimension) edit { return func(x *core.OutcomeReport) { x.Dimension = d } }

func causal(c core.CausalAssessment) edit {
	return func(x *core.OutcomeReport) { x.Attribution.CausalAssessment = c }
}

type verdict struct{ qualification, reason string }

type ruleCase struct {
	name    string
	cfg     func(*evalcase.OutcomesConfig)
	reports []edit
	// acks are the expected acknowledgments, ACCEPTED when nil.
	acks       []core.AckStatus
	want       map[int]verdict
	superseded []int
	listed     []int
	dim        core.Dimension
	score      int64
	conf       int64
	status     core.SecurityStatus
}

func pairs(rs []core.OutcomeReport, idx []int) [][2]string {
	out := [][2]string{}
	for _, i := range idx {
		out = append(out, [2]string{rs[i].Issuer, rs[i].JTI})
	}
	reputation.SortPairs(out)
	return out
}

func dimStats(v core.ReputationValue, d core.Dimension) core.DimensionStats {
	switch d {
	case core.DimensionTaskQuality:
		return v.Dimensions.TaskQuality
	case core.DimensionPolicyAdherence:
		return v.Dimensions.PolicyAdherence
	}
	return v.Dimensions.Reliability
}

func runRuleCases(t *testing.T, cases []ruleCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, native, tmpl := ruleFixture(t)
			if tc.cfg != nil {
				tc.cfg(&cfg)
			}
			o := reputation.NewOracle(cfg, native)
			var rs []core.OutcomeReport
			for i, e := range tc.reports {
				r := report(tmpl, i, e)
				rs = append(rs, r)
				want := core.AckAccepted
				if tc.acks != nil {
					want = tc.acks[i]
				}
				if a := o.Ingest(r, now); a.Ack != want {
					t.Fatalf("%s: answer %+v, want %s", r.EventID, a, want)
				}
			}
			for i, w := range tc.want {
				wantVerdict(t, o, rs[i].EventID, w.qualification, w.reason)
			}
			s := snap(t, o, query(tmpl), now)
			if got, want := s.Manifest.SupersededEventIDs, pairs(rs, tc.superseded); !slices.Equal(got, want) {
				t.Errorf("superseded %v, want %v", got, want)
			}
			if got, want := s.Manifest.QualifiedEventIDs, pairs(rs, tc.listed); !slices.Equal(got, want) {
				t.Errorf("listed %v, want %v", got, want)
			}
			if d := dimStats(s.Value, tc.dim); d.ScoreBPS != tc.score || d.ConfidenceBPS != tc.conf {
				t.Errorf("%s %d/%d, want %d/%d", tc.dim, d.ScoreBPS, d.ConfidenceBPS, tc.score, tc.conf)
			}
			status := tc.status
			if status == "" {
				status = core.SecurityClear
			}
			if s.Value.SecurityStatus != status {
				t.Errorf("security status %s, want %s", s.Value.SecurityStatus, status)
			}
		})
	}
}

var (
	qMapped     = verdict{evalcase.Qualified, reputation.ReasonMapped}
	qCorrection = verdict{evalcase.Qualified, reputation.ReasonCorrection}
	uMismatch   = verdict{evalcase.Unqualified, reputation.ReasonCorrectionMismatch}
	uNotAllowed = verdict{evalcase.Unqualified, reputation.ReasonReporterNotAuthorized}
	uRecord     = verdict{evalcase.Unqualified, reputation.ReasonRecordMismatch}
	uInvalid    = verdict{evalcase.Unqualified, reputation.ReasonInvalidReport}
)

// TestCorrectionRules: rule 10 of Section 14.6 as amended: a correction
// carries the dimension of the events it supersedes, an UNKNOWN one
// retracts them (Appendix A.2), its targets share one event_kind and are
// QUALIFIED or DISPUTED, and it is classified as a report of that kind from
// its signer, so it adds nothing its signer could not report.
func TestCorrectionRules(t *testing.T) {
	affiliated := func(c *evalcase.OutcomesConfig) {
		c.Affiliations = []evalcase.Affiliation{{EvaluatorIss: evaluator, OperatorID: acmeOperator}}
	}
	runRuleCases(t, []ruleCase{
		{name: "unknown retracts", reports: []edit{nil, chain(correcting(core.OutcomeUnknown, "event-a"), refs(readRecord))},
			want: map[int]verdict{0: qMapped, 1: qCorrection}, superseded: []int{0}, listed: nil, dim: core.DimensionReliability, score: 5000, conf: 0},
		{name: "unknown retraction citing no executor record", reports: []edit{nil, chain(correcting(core.OutcomeUnknown, "event-a"), refs())},
			want:   map[int]verdict{1: {evalcase.Unqualified, reputation.ReasonNoExecutorRecord}},
			listed: []int{0}, dim: core.DimensionReliability, score: 6666, conf: 476},
		{name: "failure correction citing the completed record", reports: []edit{nil, chain(correcting(core.OutcomeFailure, "event-a"), refs(readRecord))},
			want:   map[int]verdict{1: {evalcase.Unqualified, reputation.ReasonNoCompletionRecord}},
			listed: []int{0}, dim: core.DimensionReliability, score: 6666, conf: 476},
		{name: "unknown on none", reports: []edit{nil, chain(correcting(core.OutcomeUnknown, "event-a"), dimension(core.DimensionNone))},
			want: map[int]verdict{1: uMismatch}, listed: []int{0}, dim: core.DimensionReliability, score: 6666, conf: 476},
		{name: "target not qualified", reports: []edit{
			chain(quality(core.DimensionTaskQuality, core.OutcomeSuccess), by(executor, "executor")),
			chain(quality(core.DimensionTaskQuality, core.OutcomeSuccess), by(executor, "executor"), correcting(core.OutcomeSuccess, "event-a")),
		}, want: map[int]verdict{0: uNotAllowed, 1: uMismatch}, dim: core.DimensionTaskQuality, score: 5000, conf: 0},
		{name: "targets of two kinds", reports: []edit{
			quality(core.DimensionTaskQuality, core.OutcomeSuccess),
			feedback(evaluator, "evaluator", core.DimensionTaskQuality, core.OutcomeSuccess),
			chain(quality(core.DimensionTaskQuality, core.OutcomeFailure), correcting(core.OutcomeFailure, "event-a", "event-b")),
		}, want: map[int]verdict{2: uMismatch}, listed: []int{0, 1}, dim: core.DimensionTaskQuality, score: 6666, conf: 476},
		{name: "affiliated evaluator turns its failure into a success", cfg: affiliated, reports: []edit{
			quality(core.DimensionTaskQuality, core.OutcomeFailure),
			chain(quality(core.DimensionTaskQuality, core.OutcomeSuccess), correcting(core.OutcomeSuccess, "event-a")),
		}, want: map[int]verdict{0: qMapped, 1: {evalcase.Unqualified, reputation.ReasonAffiliatedEvaluator}},
			listed: []int{0}, dim: core.DimensionTaskQuality, score: 3333, conf: 476},
		{name: "affiliated evaluator retracts its failure", cfg: affiliated, reports: []edit{
			quality(core.DimensionTaskQuality, core.OutcomeFailure),
			chain(quality(core.DimensionTaskQuality, core.OutcomeUnknown), correcting(core.OutcomeUnknown, "event-a")),
		}, want: map[int]verdict{1: qCorrection}, superseded: []int{0}, dim: core.DimensionTaskQuality, score: 5000, conf: 0},
		{name: "quality correction without an assessment", reports: []edit{
			quality(core.DimensionTaskQuality, core.OutcomeFailure),
			chain(quality(core.DimensionTaskQuality, core.OutcomeSuccess), correcting(core.OutcomeSuccess, "event-a"), refs()),
		}, want: map[int]verdict{1: {evalcase.Unqualified, reputation.ReasonNoAssessmentRecord}},
			listed: []int{0}, dim: core.DimensionTaskQuality, score: 3333, conf: 476},
		{name: "evaluator corrects its failure", reports: []edit{
			quality(core.DimensionTaskQuality, core.OutcomeFailure),
			chain(quality(core.DimensionTaskQuality, core.OutcomeSuccess), correcting(core.OutcomeSuccess, "event-a")),
		}, want: map[int]verdict{1: qCorrection}, superseded: []int{0}, listed: []int{1}, dim: core.DimensionTaskQuality, score: 6666, conf: 476},
		{name: "agent's positive correction weighs nothing", reports: []edit{
			feedback(agentSelf, "agent", core.DimensionTaskQuality, core.OutcomeFailure),
			chain(feedback(agentSelf, "agent", core.DimensionTaskQuality, core.OutcomeSuccess), correcting(core.OutcomeSuccess, "event-a")),
		}, want: map[int]verdict{1: qCorrection}, superseded: []int{0}, dim: core.DimensionTaskQuality, score: 5000, conf: 0},
		{name: "security authority corrects a correction", reports: []edit{
			nil,
			chain(correcting(core.OutcomeFailure, "event-a"), refs(failedRecord)),
			chain(correcting(core.OutcomeUnknown, "event-b"), refs(readRecord), by(security, "security_authority")),
		}, want: map[int]verdict{1: qCorrection, 2: qCorrection}, superseded: []int{0, 1}, dim: core.DimensionReliability, score: 5000, conf: 0},
		{name: "security authority's correction keeps the record rule", reports: []edit{
			nil,
			chain(correcting(core.OutcomeFailure, "event-a"), refs(), by(security, "security_authority")),
		}, want: map[int]verdict{1: {evalcase.Unqualified, reputation.ReasonNoExecutorRecord}}, listed: []int{0},
			dim: core.DimensionReliability, score: 6666, conf: 476},
	})
}

// TestCorrectionReciprocity: rule 7 applies to positive corrections of
// QUALITY events: two evaluators that turn their failures on each other's
// agents into successes are both DISPUTED. Each correction still
// supersedes the failure it names, which its signer could retract.
func TestCorrectionReciprocity(t *testing.T) {
	c, err := evalcase.ReadOutcomes(repoFixtures, "outcomes/qualification/reciprocal-endorsements")
	if err != nil {
		t.Fatal(err)
	}
	o := reputation.NewOracle(c.Config, c.Native)
	var corrections []string
	for i, id := range []string{"quality-event-0001", "quality-event-0002"} {
		r := c.Reports[id]
		r.Result = core.OutcomeFailure
		if a := o.Ingest(r, now); a.Ack != core.AckAccepted {
			t.Fatal(a)
		}
		x := r
		x.EventID, x.JTI = "correction-"+id, "jti-of-a-test-correction-"+string(rune('a'+i))
		x.EventKind, x.Result, x.Supersedes = core.EventCorrection, core.OutcomeSuccess, []string{id}
		if a := o.Ingest(x, now); a.Ack != core.AckAccepted {
			t.Fatal(a)
		}
		corrections = append(corrections, x.EventID)
	}
	for _, id := range corrections {
		wantVerdict(t, o, id, evalcase.Disputed, reputation.ReasonReciprocalEndorsement)
	}
	r := c.Reports["quality-event-0001"]
	q := core.ReputationQuery{AgentID: r.Subject, HolderJKT: evalcase.DefaultHolderJKT, Context: r.Context, Audience: "https://gateway.example/finance"}
	s := snap(t, o, q, now)
	if d := s.Value.Dimensions.TaskQuality; d.ScoreBPS != 5000 || d.ConfidenceBPS != 0 || len(s.Manifest.QualifiedEventIDs) != 0 || len(s.Manifest.SupersededEventIDs) != 1 {
		t.Errorf("task_quality %+v, manifest %+v; want 5000/0, nothing listed, the failure superseded", d, s.Manifest)
	}
}

// TestPolicyViolations: a gateway's detected policy violation is SECURITY
// FAILURE on policy_adherence citing its violation record, one attributable
// failure and never a hold; any other gateway SECURITY report is
// UNQUALIFIED (Sections 14.2, 14.5, 14.6 rule 12, 15.4).
func TestPolicyViolations(t *testing.T) {
	runRuleCases(t, []ruleCase{
		{name: "violation", reports: []edit{violation}, want: map[int]verdict{0: qMapped}, listed: []int{0},
			dim: core.DimensionPolicyAdherence, score: 3333, conf: 476},
		{name: "environmental violation", reports: []edit{chain(violation, causal(core.CausalEnvironment))},
			want: map[int]verdict{0: {evalcase.Qualified, reputation.ReasonCausalZeroWeight}}, dim: core.DimensionPolicyAdherence, score: 5000, conf: 0},
		{name: "mixed violation", reports: []edit{chain(violation, causal(core.CausalMixed))},
			want: map[int]verdict{0: {evalcase.Qualified, reputation.ReasonCausalZeroWeight}}, dim: core.DimensionPolicyAdherence, score: 5000, conf: 0},
		{name: "no violation observed", reports: []edit{chain(violation, func(x *core.OutcomeReport) { x.Result = core.OutcomeSuccess })},
			want: map[int]verdict{0: uNotAllowed}, dim: core.DimensionPolicyAdherence, score: 5000, conf: 0},
		{name: "gateway security on none", reports: []edit{chain(violation, dimension(core.DimensionNone))},
			want: map[int]verdict{0: uNotAllowed}, dim: core.DimensionPolicyAdherence, score: 5000, conf: 0},
		{name: "gateway security on reliability", reports: []edit{chain(violation, dimension(core.DimensionReliability))},
			acks: []core.AckStatus{""}, want: map[int]verdict{0: uInvalid}, dim: core.DimensionReliability, score: 5000, conf: 0},
		{name: "violation citing a denial", reports: []edit{chain(violation, refs(denied))},
			want: map[int]verdict{0: uRecord}, dim: core.DimensionPolicyAdherence, score: 5000, conf: 0},
		{name: "violation citing nothing", reports: []edit{chain(violation, refs())},
			want: map[int]verdict{0: uRecord}, dim: core.DimensionPolicyAdherence, score: 5000, conf: 0},
		{name: "violation record of another operation", reports: []edit{chain(violation, refs("native-gateway-record:other-operation"))},
			want: map[int]verdict{0: uRecord}, dim: core.DimensionPolicyAdherence, score: 5000, conf: 0},
		{name: "violation from an evaluator", reports: []edit{chain(violation, by(evaluator, "evaluator"))},
			want: map[int]verdict{0: uNotAllowed}, dim: core.DimensionPolicyAdherence, score: 5000, conf: 0},
		{name: "security authority on policy_adherence weighs nothing and holds nothing", reports: []edit{chain(violation, by(security, "security_authority"), refs(incident))},
			want: map[int]verdict{0: uNotAllowed}, dim: core.DimensionPolicyAdherence, score: 5000, conf: 0},
		{name: "second violation of the task and operation", reports: []edit{violation, violation},
			acks: []core.AckStatus{core.AckAccepted, core.AckDuplicate}, want: map[int]verdict{0: qMapped, 1: {"", reputation.ReasonDuplicate}},
			listed: []int{0}, dim: core.DimensionPolicyAdherence, score: 3333, conf: 476},
		{name: "gateway retracts its violation", reports: []edit{violation, chain(violation, correcting(core.OutcomeUnknown, "event-a"))},
			want: map[int]verdict{1: qCorrection}, superseded: []int{0}, dim: core.DimensionPolicyAdherence, score: 5000, conf: 0},
		{name: "gateway retraction without the violation record", reports: []edit{violation, chain(violation, correcting(core.OutcomeUnknown, "event-a"), refs())},
			want: map[int]verdict{1: uRecord}, listed: []int{0}, dim: core.DimensionPolicyAdherence, score: 3333, conf: 476},
		{name: "gateway corrects its violation to a success", reports: []edit{violation, chain(violation, correcting(core.OutcomeSuccess, "event-a"))},
			want: map[int]verdict{1: uNotAllowed}, listed: []int{0}, dim: core.DimensionPolicyAdherence, score: 3333, conf: 476},
		{name: "gateway corrects the cause of its violation", reports: []edit{violation, chain(violation, correcting(core.OutcomeFailure, "event-a"), causal(core.CausalEnvironment))},
			want: map[int]verdict{1: qCorrection}, superseded: []int{0}, dim: core.DimensionPolicyAdherence, score: 5000, conf: 0},
		{name: "security authority's correction of a violation weighs nothing", reports: []edit{violation,
			chain(violation, correcting(core.OutcomeFailure, "event-a"), by(security, "security_authority"))},
			want: map[int]verdict{1: qCorrection}, superseded: []int{0}, dim: core.DimensionPolicyAdherence, score: 5000, conf: 0},
		{name: "security authority's correction of a violation citing an incident", reports: []edit{violation,
			chain(violation, correcting(core.OutcomeFailure, "event-a"), by(security, "security_authority"), refs(incident))},
			want: map[int]verdict{1: uRecord}, listed: []int{0}, dim: core.DimensionPolicyAdherence, score: 3333, conf: 476},
	})
}

// TestPolicyAdherenceAssessments: an evaluator's or task owner's QUALITY or
// FEEDBACK report on policy_adherence counts, positively or negatively,
// under the eligibility rules of a quality assessment (Sections 14.2, 14.5,
// 14.6 rules 5 to 9).
func TestPolicyAdherenceAssessments(t *testing.T) {
	pa := core.DimensionPolicyAdherence
	runRuleCases(t, []ruleCase{
		{name: "positive quality", reports: []edit{quality(pa, core.OutcomeSuccess)}, want: map[int]verdict{0: qMapped}, listed: []int{0}, dim: pa, score: 6666, conf: 476},
		{name: "negative quality", reports: []edit{quality(pa, core.OutcomeFailure)}, want: map[int]verdict{0: qMapped}, listed: []int{0}, dim: pa, score: 3333, conf: 476},
		{name: "positive feedback", reports: []edit{feedback(evaluator, "evaluator", pa, core.OutcomeSuccess)}, want: map[int]verdict{0: qMapped}, listed: []int{0}, dim: pa, score: 6666, conf: 476},
		{name: "task owner's negative feedback", reports: []edit{feedback(taskOwner, "task_owner", pa, core.OutcomeFailure)}, want: map[int]verdict{0: qMapped}, listed: []int{0}, dim: pa, score: 3333, conf: 476},
		{name: "quality without an assessment", reports: []edit{chain(quality(pa, core.OutcomeSuccess), refs())},
			want: map[int]verdict{0: {evalcase.Unqualified, reputation.ReasonNoAssessmentRecord}}, dim: pa, score: 5000, conf: 0},
		{name: "affiliated evaluator, positive", cfg: func(c *evalcase.OutcomesConfig) {
			c.Affiliations = []evalcase.Affiliation{{EvaluatorIss: evaluator, OperatorID: acmeOperator}}
		}, reports: []edit{quality(pa, core.OutcomeSuccess)}, want: map[int]verdict{0: {evalcase.Unqualified, reputation.ReasonAffiliatedEvaluator}}, dim: pa, score: 5000, conf: 0},
		{name: "executor as evaluator", reports: []edit{nil, chain(quality(pa, core.OutcomeSuccess), by(executor, "evaluator"))}, cfg: func(c *evalcase.OutcomesConfig) {
			c.Trust = append(c.Trust, evalcase.TrustRecord{Iss: executor, Role: "reporter", ReporterRole: strp("evaluator")})
		}, want: map[int]verdict{1: {evalcase.Unqualified, reputation.ReasonSelfPraise}}, listed: []int{0}, dim: pa, score: 5000, conf: 0},
		{name: "environmental negative assessment", reports: []edit{chain(quality(pa, core.OutcomeFailure), causal(core.CausalEnvironment))},
			want: map[int]verdict{0: {evalcase.Qualified, reputation.ReasonCausalZeroWeight}}, dim: pa, score: 5000, conf: 0},
		{name: "assessment beside a violation", reports: []edit{violation, quality(pa, core.OutcomeSuccess)},
			want: map[int]verdict{0: qMapped, 1: qMapped}, listed: []int{0, 1}, dim: pa, score: 5000, conf: 909},
	})
}
