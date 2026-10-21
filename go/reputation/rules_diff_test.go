package reputation_test

import (
	"slices"
	"testing"

	"hop.top/pact-go/core"
	"hop.top/pact-go/runner/evalcase"
)

const (
	owner           = "https://owner.example/finance"
	violationRef    = "native-gateway-record:violation-0001"
	failedRef       = "native-execution-log:finance-read-0001/reconciled"
	completedRef    = "native-execution-log:finance-read-0001"
	otherViolation  = "native-gateway-record:other-operation"
	otherIncident   = "native-incident:other-operation"
	deniedRef       = "native-authorization:denied"
	acmeOperatorIss = "https://identity.example/operators/acme"
)

// ruleWorld is world with a task owner and the gateway's records of
// violating requests.
func ruleWorld(t *testing.T) (evalcase.OutcomesConfig, evalcase.OutcomesNative, core.OutcomeReport) {
	t.Helper()
	cfg, native, tmpl := world(t)
	r := "task_owner"
	cfg.Trust = append(slices.Clone(cfg.Trust), evalcase.TrustRecord{Iss: owner, Role: "reporter", ReporterRole: &r, Keys: []string{"keys/learning-controller.jwk.json"}})
	native.Records[violationRef] = evalcase.NativeRecord{Kind: "violation", State: "recorded", TaskID: task, OperationID: operation}
	native.Records[otherViolation] = evalcase.NativeRecord{Kind: "violation", State: "recorded", TaskID: task, OperationID: "invoice-read-operation-0002"}
	native.Records[otherIncident] = evalcase.NativeRecord{Kind: "incident", State: "confirmed", TaskID: task, OperationID: "invoice-read-operation-0002"}
	return cfg, native, tmpl
}

type rep = func(*core.OutcomeReport)

func all(edits ...rep) rep {
	return func(x *core.OutcomeReport) {
		for _, e := range edits {
			if e != nil {
				e(x)
			}
		}
	}
}

func assess(kind core.EventKind, iss string, role core.ReporterRole, d core.Dimension, res core.OutcomeResult) rep {
	return func(x *core.OutcomeReport) {
		x.EventKind, x.Issuer, x.ReporterRole, x.Dimension, x.Result = kind, iss, role, d, res
		// An assessment, or the verified feedback of an evaluator or the
		// task owner, cites the completed assessment (Section 14.5); the
		// agent's own diagnostic cites nothing.
		x.EvidenceRefs = []string{}
		if kind == core.EventQuality || role != core.ReporterAgent {
			x.EvidenceRefs = []string{reviewRef}
		}
	}
}

func violates(x *core.OutcomeReport) {
	x.EventKind, x.Result, x.Dimension, x.Issuer, x.ReporterRole = core.EventSecurity, core.OutcomeFailure, core.DimensionPolicyAdherence, gateway, core.ReporterGateway
	x.EvidenceRefs = []string{violationRef}
}

func corrects(res core.OutcomeResult, events ...*core.OutcomeReport) rep {
	return func(x *core.OutcomeReport) {
		x.EventKind, x.Result = core.EventCorrection, res
		x.Supersedes = nil
		for _, e := range events {
			x.Supersedes = append(x.Supersedes, e.EventID)
		}
	}
}

func cites(refs ...string) rep {
	return func(x *core.OutcomeReport) { x.EvidenceRefs = append([]string{}, refs...) }
}

func signedBy(iss string, role core.ReporterRole) rep {
	return func(x *core.OutcomeReport) { x.Issuer, x.ReporterRole = iss, role }
}

func cause(c core.CausalAssessment) rep {
	return func(x *core.OutcomeReport) { x.Attribution.CausalAssessment = c }
}

// seq ingests reports built in order, each edit seeing the reports before
// it, then queries.
func seq(edits ...func(prev []*core.OutcomeReport) rep) func(b *builder) []step {
	return func(b *builder) []step {
		var prev []*core.OutcomeReport
		var steps []step
		for _, e := range edits {
			r := b.report(e(prev))
			prev = append(prev, r)
			steps = append(steps, ingestAt(r, t0))
		}
		return append(steps, queryAt(b.query(nil), t0))
	}
}

func plain(e rep) func([]*core.OutcomeReport) rep {
	return func([]*core.OutcomeReport) rep { return e }
}

// correctionOf builds a correction of the reports at the indexes.
func correctionOf(res core.OutcomeResult, edit rep, idx ...int) func([]*core.OutcomeReport) rep {
	return func(prev []*core.OutcomeReport) rep {
		var events []*core.OutcomeReport
		for _, i := range idx {
			events = append(events, prev[i])
		}
		return all(edit, corrects(res, events...))
	}
}

// ruleScenarios are rules 10 and 12 of Section 14.6 and the
// policy_adherence rows of Section 14.5, applied to both implementations.
func ruleScenarios() []scenario {
	pa, tq := core.DimensionPolicyAdherence, core.DimensionTaskQuality
	quality := func(d core.Dimension, res core.OutcomeResult) rep {
		return assess(core.EventQuality, evaluator, core.ReporterEvaluator, d, res)
	}
	affiliated := func(c *evalcase.OutcomesConfig) {
		c.Affiliations = []evalcase.Affiliation{{EvaluatorIss: evaluator, OperatorID: acmeOperatorIss}}
	}
	return []scenario{
		{"retraction", nil, seq(plain(nil), correctionOf(core.OutcomeUnknown, cites(completedRef), 0))},
		{"retraction citing nothing", nil, seq(plain(nil), correctionOf(core.OutcomeUnknown, cites(), 0))},
		{"failure correction citing a completion", nil, seq(plain(nil), correctionOf(core.OutcomeFailure, cites(completedRef), 0))},
		{"unknown correction on none", nil, seq(plain(nil), correctionOf(core.OutcomeUnknown, func(x *core.OutcomeReport) { x.Dimension = core.DimensionNone }, 0))},
		{"correction of an unqualified report", nil, seq(
			plain(all(quality(tq, core.OutcomeSuccess), signedBy(executor, core.ReporterExecutor))),
			correctionOf(core.OutcomeSuccess, all(quality(tq, core.OutcomeSuccess), signedBy(executor, core.ReporterExecutor)), 0))},
		{"correction of two kinds", nil, seq(
			plain(quality(tq, core.OutcomeSuccess)),
			plain(assess(core.EventFeedback, evaluator, core.ReporterEvaluator, tq, core.OutcomeSuccess)),
			correctionOf(core.OutcomeFailure, quality(tq, core.OutcomeFailure), 0, 1))},
		{"affiliated evaluator's positive correction", affiliated, seq(
			plain(quality(tq, core.OutcomeFailure)), correctionOf(core.OutcomeSuccess, quality(tq, core.OutcomeSuccess), 0))},
		{"affiliated evaluator's retraction", affiliated, seq(
			plain(quality(tq, core.OutcomeFailure)), correctionOf(core.OutcomeUnknown, quality(tq, core.OutcomeUnknown), 0))},
		{"quality correction without an assessment", nil, seq(
			plain(quality(tq, core.OutcomeFailure)), correctionOf(core.OutcomeSuccess, all(quality(tq, core.OutcomeSuccess), cites()), 0))},
		{"evaluator's positive correction", nil, seq(
			plain(quality(tq, core.OutcomeFailure)), correctionOf(core.OutcomeSuccess, quality(tq, core.OutcomeSuccess), 0))},
		{"agent's positive correction", nil, seq(
			plain(assess(core.EventFeedback, agent, core.ReporterAgent, tq, core.OutcomeFailure)),
			correctionOf(core.OutcomeSuccess, assess(core.EventFeedback, agent, core.ReporterAgent, tq, core.OutcomeSuccess), 0))},
		{"authority corrects a correction", nil, seq(
			plain(nil),
			correctionOf(core.OutcomeFailure, cites(failedRef), 0),
			correctionOf(core.OutcomeUnknown, all(cites(completedRef), signedBy(security, core.ReporterSecurityAuthority)), 1))},
		{"authority correction without a record", nil, seq(
			plain(nil), correctionOf(core.OutcomeFailure, all(cites(), signedBy(security, core.ReporterSecurityAuthority)), 0))},
		{"violation", nil, seq(plain(violates))},
		{"environmental violation", nil, seq(plain(all(violates, cause(core.CausalEnvironment))))},
		{"no violation observed", nil, seq(plain(all(violates, func(x *core.OutcomeReport) { x.Result = core.OutcomeSuccess })))},
		{"gateway security on none", nil, seq(plain(all(violates, func(x *core.OutcomeReport) { x.Dimension = core.DimensionNone })))},
		{"violation citing a denial", nil, seq(plain(all(violates, cites(deniedRef))))},
		{"violation citing nothing", nil, seq(plain(all(violates, cites())))},
		{"violation of another operation's record", nil, seq(plain(all(violates, cites(otherViolation))))},
		{"violation from an evaluator", nil, seq(plain(all(violates, signedBy(evaluator, core.ReporterEvaluator))))},
		{"authority security on policy_adherence", nil, seq(plain(all(violates, signedBy(security, core.ReporterSecurityAuthority), cites(incidentRef))))},
		{"second violation", nil, seq(plain(violates), plain(violates))},
		{"gateway retracts its violation", nil, seq(plain(violates), correctionOf(core.OutcomeUnknown, violates, 0))},
		{"gateway retraction without the record", nil, seq(plain(violates), correctionOf(core.OutcomeUnknown, all(violates, cites()), 0))},
		{"gateway corrects its violation to a success", nil, seq(plain(violates), correctionOf(core.OutcomeSuccess, violates, 0))},
		{"gateway corrects the cause", nil, seq(plain(violates), correctionOf(core.OutcomeFailure, all(violates, cause(core.CausalEnvironment)), 0))},
		{"authority corrects a violation", nil, seq(plain(violates),
			correctionOf(core.OutcomeFailure, all(violates, signedBy(security, core.ReporterSecurityAuthority)), 0))},
		{"authority corrects a violation citing an incident", nil, seq(plain(violates),
			correctionOf(core.OutcomeFailure, all(violates, signedBy(security, core.ReporterSecurityAuthority), cites(incidentRef)), 0))},
		{"positive policy adherence assessment", nil, seq(plain(quality(pa, core.OutcomeSuccess)))},
		{"negative policy adherence assessment", nil, seq(plain(quality(pa, core.OutcomeFailure)))},
		{"positive policy adherence feedback", nil, seq(plain(assess(core.EventFeedback, evaluator, core.ReporterEvaluator, pa, core.OutcomeSuccess)))},
		{"task owner's negative policy adherence feedback", nil, seq(plain(assess(core.EventFeedback, owner, core.ReporterTaskOwner, pa, core.OutcomeFailure)))},
		{"policy adherence assessment without a record", nil, seq(plain(all(quality(pa, core.OutcomeSuccess), cites())))},
		{"affiliated policy adherence assessment", affiliated, seq(plain(quality(pa, core.OutcomeSuccess)))},
		{"assessment beside a violation", nil, seq(plain(violates), plain(quality(pa, core.OutcomeSuccess)))},
	}
}

// kindScenarios are the dimension rule of Appendix A.2, the verified
// feedback row of Section 14.5, rules 6 and 7 of Section 14.6 through
// FEEDBACK, the confirmed incident row and the hold that outlives a
// correction (Section 15.4), applied to both implementations.
func kindScenarios() []scenario {
	pa, tq := core.DimensionPolicyAdherence, core.DimensionTaskQuality
	fb := func(iss string, role core.ReporterRole, d core.Dimension, res core.OutcomeResult) rep {
		return assess(core.EventFeedback, iss, role, d, res)
	}
	incident := func(x *core.OutcomeReport) {
		x.EventKind, x.Result, x.Dimension, x.Issuer, x.ReporterRole = core.EventSecurity, core.OutcomeFailure, core.DimensionNone, security, core.ReporterSecurityAuthority
		x.EvidenceRefs = []string{incidentRef}
	}
	affiliated := func(c *evalcase.OutcomesConfig) {
		c.Affiliations = []evalcase.Affiliation{{EvaluatorIss: evaluator, OperatorID: acmeOperatorIss}}
	}
	op2 := func(x *core.OutcomeReport) { x.OperationID = "invoice-read-operation-0002" }
	offRow := func(edit rep) func([]*core.OutcomeReport) rep { return plain(edit) }
	return []scenario{
		{"off-row pairs", nil, seq(
			offRow(func(x *core.OutcomeReport) { x.Dimension = core.DimensionPolicyAdherence }),
			offRow(func(x *core.OutcomeReport) {
				x.Result, x.Dimension, x.EvidenceRefs = core.OutcomeFailure, tq, []string{failedRef}
			}),
			offRow(all(assess(core.EventQuality, evaluator, core.ReporterEvaluator, core.DimensionReliability, core.OutcomeSuccess))),
			offRow(fb(evaluator, core.ReporterEvaluator, core.DimensionReliability, core.OutcomeFailure)),
			offRow(all(incident, func(x *core.OutcomeReport) { x.Dimension = tq })),
			offRow(func(x *core.OutcomeReport) {
				x.EventKind, x.Issuer, x.ReporterRole, x.EvidenceRefs = core.EventRemediation, security, core.ReporterSecurityAuthority, []string{fixRef}
			}),
			plain(nil))},
		{"execution then execution on policy_adherence", nil, seq(plain(nil), plain(func(x *core.OutcomeReport) { x.Dimension = pa }))},
		{"evaluator's feedback", nil, seq(plain(fb(evaluator, core.ReporterEvaluator, tq, core.OutcomeSuccess)))},
		{"task owner's negative feedback", nil, seq(plain(fb(owner, core.ReporterTaskOwner, tq, core.OutcomeFailure)))},
		{"feedback without an assessment", nil, seq(plain(all(fb(evaluator, core.ReporterEvaluator, tq, core.OutcomeSuccess), cites())))},
		{"feedback citing an execution record", nil, seq(plain(all(fb(owner, core.ReporterTaskOwner, tq, core.OutcomeFailure), cites(completedRef))))},
		{"policy adherence feedback without an assessment", nil, seq(plain(all(fb(evaluator, core.ReporterEvaluator, pa, core.OutcomeFailure), cites())))},
		{"agent's own policy adherence feedback", nil, seq(plain(fb(agent, core.ReporterAgent, pa, core.OutcomeFailure)),
			plain(all(fb(agent, core.ReporterAgent, pa, core.OutcomeSuccess), op2)))},
		{"evaluator, agent and recordless feedback", nil, seq(
			plain(fb(evaluator, core.ReporterEvaluator, tq, core.OutcomeSuccess)),
			plain(fb(agent, core.ReporterAgent, tq, core.OutcomeSuccess)),
			plain(all(fb(evaluator, core.ReporterEvaluator, tq, core.OutcomeSuccess), cites(), op2)))},
		{"feedback correction without an assessment", nil, seq(
			plain(fb(evaluator, core.ReporterEvaluator, tq, core.OutcomeFailure)),
			correctionOf(core.OutcomeSuccess, all(fb(evaluator, core.ReporterEvaluator, tq, core.OutcomeSuccess), cites()), 0))},
		{"affiliated feedback", affiliated, seq(
			plain(fb(evaluator, core.ReporterEvaluator, tq, core.OutcomeSuccess)),
			plain(all(fb(evaluator, core.ReporterEvaluator, tq, core.OutcomeFailure), op2)))},
		{"incident", nil, seq(plain(incident))},
		{"incident without a record", nil, seq(plain(all(incident, cites())))},
		{"incident citing an execution record", nil, seq(plain(all(incident, cites(completedRef))))},
		{"incident of another operation", nil, seq(plain(all(incident, cites(otherIncident))))},
		{"incident on policy_adherence", nil, seq(plain(all(incident, func(x *core.OutcomeReport) { x.Dimension = pa })))},
		{"incident unknown", nil, seq(plain(all(incident, func(x *core.OutcomeReport) { x.Result = core.OutcomeUnknown })))},
		{"hold survives its retraction", nil, func(b *builder) []step {
			h := b.report(incident)
			c := b.report(all(incident, corrects(core.OutcomeUnknown, h)))
			again := b.report(all(incident, corrects(core.OutcomeFailure, h), signedBy(soc, core.ReporterSecurityAuthority)))
			fix := b.report(func(x *core.OutcomeReport) {
				x.EventKind, x.Result, x.Dimension, x.Issuer, x.ReporterRole = core.EventRemediation, core.OutcomeSuccess, core.DimensionNone, security, core.ReporterSecurityAuthority
				x.EvidenceRefs = []string{h.EventID, fixRef}
			})
			return []step{ingestAt(h, t0), queryAt(b.query(nil), t0), ingestAt(c, t0), queryAt(b.query(nil), t0),
				ingestAt(again, t0), queryAt(b.query(nil), t0), ingestAt(fix, t0), queryAt(b.query(nil), t0)}
		}},
		{"remediation naming the correction", nil, func(b *builder) []step {
			h := b.report(incident)
			c := b.report(all(incident, corrects(core.OutcomeUnknown, h)))
			fix := b.report(func(x *core.OutcomeReport) {
				x.EventKind, x.Result, x.Dimension, x.Issuer, x.ReporterRole = core.EventRemediation, core.OutcomeSuccess, core.DimensionNone, security, core.ReporterSecurityAuthority
				x.EvidenceRefs = []string{c.EventID, fixRef}
			})
			return []step{ingestAt(h, t0), ingestAt(c, t0), ingestAt(fix, t0), queryAt(b.query(nil), t0)}
		}},
	}
}

// correctionReciprocity is rule 7 over corrections: the two evaluators of
// the committed reciprocal case turn failures on each other's agents into
// successes.
func correctionReciprocity() scenario {
	return scenario{"reciprocal corrections", nil, func(b *builder) []step {
		c, _ := evalcase.ReadOutcomes(repoFixtures, "outcomes/qualification/reciprocal-endorsements")
		var steps []step
		for i, id := range []string{"quality-event-0001", "quality-event-0002"} {
			r := c.Reports[id]
			r.Result = core.OutcomeFailure
			x := r
			x.EventID, x.JTI = "correction-"+id, "reciprocal-correction-jti-"+string(rune('a'+i))
			x.EventKind, x.Result, x.Supersedes = core.EventCorrection, core.OutcomeSuccess, []string{id}
			steps = append(steps, ingestAt(&r, t0), ingestAt(&x, t0))
		}
		return append(steps, queryAt(b.query(nil), t0))
	}}
}
