package reputation_test

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"hop.top/pact-go/core"
	"hop.top/pact-go/runner/evalcase"
	"hop.top/pact-go/runner/reputation"
)

const (
	now        int64 = 1792080000
	executor         = "https://executor.example/finance"
	security         = "https://security.example/finance"
	soc              = "https://security.example/soc"
	evaluator        = "https://evaluator.example/quality"
	gateway          = "https://gateway.example/finance"
	agentSelf        = "https://identity.example/agents/invoice-assistant"
	readRecord       = "native-execution-log:finance-read-0001"
	review           = "native-review:read-0001"
	incident         = "native-incident-record:finance-0001"
	remediated       = "native-remediation-record:finance-0001"
	denied           = "native-authorization-log:finance-read-0001"
)

func strp(s string) *string { return &s }

// fixture returns the configuration and native records of
// outcomes/qualification/correction-recompute with more reporters, records
// and a hold clearance authority, and its first report as a template.
func fixture(t *testing.T) (evalcase.OutcomesConfig, evalcase.OutcomesNative, core.OutcomeReport) {
	t.Helper()
	c, err := evalcase.ReadOutcomes(repoFixtures, "outcomes/qualification/correction-recompute")
	if err != nil {
		t.Fatal(err)
	}
	cfg := c.Config
	for _, r := range []struct{ iss, role string }{
		{security, "security_authority"}, {soc, "security_authority"}, {evaluator, "evaluator"}, {gateway, "gateway"}, {agentSelf, "agent"},
	} {
		cfg.Trust = append(cfg.Trust, evalcase.TrustRecord{Iss: r.iss, Role: "reporter", ReporterRole: strp(r.role)})
	}
	cfg.HoldClearanceAuthorities = []string{security}
	native := c.Native
	native.Records = map[string]evalcase.NativeRecord{}
	for k, v := range c.Native.Records {
		native.Records[k] = v
	}
	task, op := "native-task:september-summary-007", "invoice-read-operation-0001"
	native.Records[review] = evalcase.NativeRecord{Kind: "assessment", State: "completed", TaskID: task, OperationID: op}
	native.Records[incident] = evalcase.NativeRecord{Kind: "incident", State: "confirmed", TaskID: task, OperationID: op}
	native.Records[remediated] = evalcase.NativeRecord{Kind: "remediation", State: "completed", TaskID: task, OperationID: op}
	native.Records["native-execution-log:anonymous"] = evalcase.NativeRecord{Kind: "execution", State: "completed", Returned: strp("data"), TaskID: task, OperationID: op}
	native.Records["native-review:other-task"] = evalcase.NativeRecord{Kind: "assessment", State: "completed", TaskID: "native-task:ledger-review-0042", OperationID: op}
	native.Records[denied] = evalcase.NativeRecord{Kind: "authorization", State: "denied", TaskID: task, OperationID: op,
		Executor: &evalcase.RecordExecutor{Class: "delegated-user", PrincipalID: "https://identity.example/principals/alice"}}
	return cfg, native, c.Reports["execution-event-0001"]
}

// report derives a report from the template: a new event and jti, and the
// edits.
func report(tmpl core.OutcomeReport, n int, edit func(*core.OutcomeReport)) core.OutcomeReport {
	r := tmpl
	r.EventID = "event-" + string(rune('a'+n))
	r.JTI = "jti-of-the-test-report-" + string(rune('a'+n))
	r.EvidenceRefs = append([]string(nil), tmpl.EvidenceRefs...)
	r.Supersedes = []string{}
	if edit != nil {
		edit(&r)
	}
	return r
}

func query(tmpl core.OutcomeReport) core.ReputationQuery {
	return core.ReputationQuery{AgentID: tmpl.Subject, HolderJKT: evalcase.DefaultHolderJKT, Context: tmpl.Context, Audience: "https://gateway.example/finance"}
}

func snap(t *testing.T, o *reputation.Oracle, q core.ReputationQuery, at int64) *reputation.Snapshot {
	t.Helper()
	s, code := o.Query(q, at)
	if s == nil {
		t.Fatalf("query refused %s", code)
	}
	return s
}

func wantVerdict(t *testing.T, o *reputation.Oracle, event, qualification, reason string) {
	t.Helper()
	if v := o.Verdicts()[event]; v.Qualification != qualification || v.Reason != reason {
		t.Errorf("%s: %+v, want %s %s", event, v, qualification, reason)
	}
}

// TestIngestRefusals: the codes of draft Section 13.4 for a report that
// breaks Appendix A.2 or A.3, the time rules or the receiving context, and
// the Section 7.5 deduplication.
func TestIngestRefusals(t *testing.T) {
	cfg, native, tmpl := fixture(t)
	for _, tc := range []struct {
		name string
		edit func(*core.OutcomeReport)
		at   int64
		code string
	}{
		{"admission on a dimension", func(r *core.OutcomeReport) { r.EventKind, r.ReporterRole = core.EventAdmission, "gateway" }, now, reputation.CodeInvalidMessage},
		{"authorization on a dimension", func(r *core.OutcomeReport) { r.EventKind = core.EventAuthorization }, now, reputation.CodeInvalidMessage},
		{"unknown on a dimension", func(r *core.OutcomeReport) { r.Result = core.OutcomeUnknown }, now, reputation.CodeInvalidMessage},
		{"execution success on task_quality", func(r *core.OutcomeReport) { r.Dimension = core.DimensionTaskQuality }, now, reputation.CodeInvalidMessage},
		{"execution failure on task_quality", func(r *core.OutcomeReport) { r.Result, r.Dimension = core.OutcomeFailure, core.DimensionTaskQuality }, now, reputation.CodeInvalidMessage},
		{"execution success on policy_adherence", func(r *core.OutcomeReport) { r.Dimension = core.DimensionPolicyAdherence }, now, reputation.CodeInvalidMessage},
		{"execution failure on policy_adherence", func(r *core.OutcomeReport) {
			r.Result, r.Dimension = core.OutcomeFailure, core.DimensionPolicyAdherence
		}, now, reputation.CodeInvalidMessage},
		{"quality on reliability", func(r *core.OutcomeReport) { r.EventKind = core.EventQuality }, now, reputation.CodeInvalidMessage},
		{"feedback on reliability", func(r *core.OutcomeReport) { r.EventKind, r.Result = core.EventFeedback, core.OutcomeFailure }, now, reputation.CodeInvalidMessage},
		{"quality on none", func(r *core.OutcomeReport) { r.EventKind, r.Dimension = core.EventQuality, core.DimensionNone }, now, reputation.CodeInvalidMessage},
		{"security on reliability", func(r *core.OutcomeReport) { r.EventKind, r.Result = core.EventSecurity, core.OutcomeFailure }, now, reputation.CodeInvalidMessage},
		{"security on task_quality", func(r *core.OutcomeReport) {
			r.EventKind, r.Result, r.Dimension = core.EventSecurity, core.OutcomeFailure, core.DimensionTaskQuality
		}, now, reputation.CodeInvalidMessage},
		{"remediation on reliability", func(r *core.OutcomeReport) { r.EventKind = core.EventRemediation }, now, reputation.CodeInvalidMessage},
		{"correction without supersedes", func(r *core.OutcomeReport) { r.EventKind = core.EventCorrection }, now, reputation.CodeInvalidMessage},
		{"supersedes outside a correction", func(r *core.OutcomeReport) { r.Supersedes = []string{"x"} }, now, reputation.CodeInvalidMessage},
		{"valid for longer than 300 s", func(r *core.OutcomeReport) { r.Expiry = r.IssuedAt + 301 }, now, reputation.CodeInvalidMessage},
		{"issued in the future", func(r *core.OutcomeReport) { r.IssuedAt, r.NotBefore, r.Expiry = now+6, now+6, now+100 }, now, reputation.CodeInvalidMessage},
		{"nbf in the future", func(r *core.OutcomeReport) { r.NotBefore = now + 6 }, now, reputation.CodeInvalidMessage},
		{"expired", nil, now + 300, reputation.CodeExpired},
		{"another audience", func(r *core.OutcomeReport) { r.Audience = "https://reputation.example/other" }, now, reputation.CodeContextMismatch},
		{"another tenant", func(r *core.OutcomeReport) { r.TenantID = "globex" }, now, reputation.CodeContextMismatch},
		{"another environment", func(r *core.OutcomeReport) { r.EnvironmentID = "https://gateway.example/environments/hr" }, now, reputation.CodeContextMismatch},
		{"observed in the future", func(r *core.OutcomeReport) { r.ObservedAt = now + 6 }, now, reputation.CodeInvalidMessage},
		{"observed before the window", func(r *core.OutcomeReport) { r.ObservedAt = now - 604801 }, now, reputation.CodeInvalidMessage},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := reputation.NewOracle(cfg, native)
			r := report(tmpl, 0, tc.edit)
			if a := o.Ingest(r, tc.at); a.Code != tc.code || a.Ack != "" {
				t.Fatalf("answer %+v, want %s", a, tc.code)
			}
			v := o.Verdicts()[r.EventID]
			if !v.Refused || v.Code != tc.code {
				t.Errorf("verdict %+v, want refused %s", v, tc.code)
			}
			if s := snap(t, o, query(tmpl), now); len(s.Manifest.QualifiedEventIDs) != 0 || s.Value.Dimensions.Reliability.QualifiedEvents != 0 {
				t.Errorf("a refused report counts: %+v", s.Manifest)
			}
		})
	}
	// The boundaries themselves are accepted.
	for name, tc := range map[string]struct {
		edit func(*core.OutcomeReport)
		at   int64
	}{
		"observed at the edge of the window": {func(r *core.OutcomeReport) { r.ObservedAt = now - 604800 }, now},
		"within the clock skew": {func(r *core.OutcomeReport) {
			r.ObservedAt, r.IssuedAt, r.NotBefore, r.Expiry = now+5, now+5, now+5, now+305
		}, now},
		"one second before exp": {nil, now + 299},
	} {
		o := reputation.NewOracle(cfg, native)
		if a := o.Ingest(report(tmpl, 1, tc.edit), tc.at); a.Ack != core.AckAccepted {
			t.Errorf("%s: %+v, want ACCEPTED", name, a)
		}
	}
}

// TestIngestDeduplication: an identical retry of an (iss, jti) is DUPLICATE
// and changes nothing; another payload under it, or another report under a
// used event_id, is ID_CONFLICT; a report repeating the tuple of an earlier
// registered report is DUPLICATE and casts no vote (Sections 7.5, 14.3,
// 14.6 rule 4).
func TestIngestDeduplication(t *testing.T) {
	cfg, native, tmpl := fixture(t)
	o := reputation.NewOracle(cfg, native)
	r := report(tmpl, 0, nil)
	if a := o.Ingest(r, now); a.Ack != core.AckAccepted {
		t.Fatalf("first: %+v", a)
	}
	before := snap(t, o, query(tmpl), now)
	if a := o.Ingest(r, now+1); a.Ack != core.AckDuplicate {
		t.Errorf("identical retry: %+v, want DUPLICATE", a)
	}
	changed := r
	changed.Details = "another payload"
	if a := o.Ingest(changed, now); a.Code != reputation.CodeIDConflict {
		t.Errorf("another payload under the (iss, jti): %+v, want ID_CONFLICT", a)
	}
	reused := report(tmpl, 1, func(x *core.OutcomeReport) { x.EventID = r.EventID; x.OperationID = "invoice-read-operation-0009" })
	if a := o.Ingest(reused, now); a.Code != reputation.CodeIDConflict {
		t.Errorf("a used event_id: %+v, want ID_CONFLICT", a)
	}
	tuple := report(tmpl, 2, nil)
	if a := o.Ingest(tuple, now); a.Ack != core.AckDuplicate {
		t.Errorf("same tuple, another jti: %+v, want DUPLICATE", a)
	}
	wantVerdict(t, o, tuple.EventID, "", reputation.ReasonDuplicate)
	after := snap(t, o, query(tmpl), now)
	if !reflect.DeepEqual(after.Value.Dimensions, before.Value.Dimensions) || len(after.Manifest.QualifiedEventIDs) != 1 {
		t.Errorf("a duplicate changed the snapshot: %+v", after.Manifest)
	}
	// Another dimension or reporter is another tuple.
	other := report(tmpl, 3, func(x *core.OutcomeReport) {
		x.EventKind, x.Dimension, x.Issuer, x.ReporterRole = core.EventQuality, core.DimensionTaskQuality, evaluator, "evaluator"
		x.EvidenceRefs = []string{review}
	})
	if a := o.Ingest(other, now); a.Ack != core.AckAccepted {
		t.Errorf("another tuple: %+v", a)
	}
	// An unregistered reporter takes no tuple.
	o = reputation.NewOracle(cfg, native)
	stranger := report(tmpl, 4, func(x *core.OutcomeReport) { x.ReporterRole = "evaluator" })
	if a := o.Ingest(stranger, now); a.Ack != core.AckAccepted {
		t.Fatalf("unregistered: %+v", a)
	}
	wantVerdict(t, o, stranger.EventID, evalcase.Unqualified, reputation.ReasonReporterNotAuthorized)
	honest := report(tmpl, 5, nil)
	if a := o.Ingest(honest, now); a.Ack != core.AckAccepted {
		t.Errorf("a registered report after an unregistered one of the same tuple: %+v, want ACCEPTED", a)
	}
	wantVerdict(t, o, honest.EventID, evalcase.Qualified, reputation.ReasonMapped)
}

// TestClassificationRules: rules of Sections 14.2, 14.5 and 14.6 that the
// committed cases do not reach.
func TestClassificationRules(t *testing.T) {
	cfg, native, tmpl := fixture(t)
	quality := func(x *core.OutcomeReport) {
		x.EventKind, x.Dimension, x.Issuer, x.ReporterRole = core.EventQuality, core.DimensionTaskQuality, evaluator, "evaluator"
		x.EvidenceRefs = []string{review}
	}
	for _, tc := range []struct {
		name          string
		edit          func(*core.OutcomeReport)
		cfg           func(*evalcase.OutcomesConfig)
		qualification string
		reason        string
	}{
		{"quality from an executor", func(x *core.OutcomeReport) {
			quality(x)
			x.Issuer, x.ReporterRole = executor, "executor"
		}, nil, evalcase.Unqualified, reputation.ReasonReporterNotAuthorized},
		{"execution from a security authority", func(x *core.OutcomeReport) { x.Issuer, x.ReporterRole = security, "security_authority" }, nil,
			evalcase.Unqualified, reputation.ReasonReporterNotAuthorized},
		{"execution from the gateway", func(x *core.OutcomeReport) { x.Issuer, x.ReporterRole = gateway, "gateway" }, nil,
			evalcase.Unqualified, reputation.ReasonReporterNotAuthorized},
		{"security from an executor", func(x *core.OutcomeReport) {
			x.EventKind, x.Result, x.Dimension, x.EvidenceRefs = core.EventSecurity, core.OutcomeFailure, core.DimensionNone, []string{incident}
		}, nil, evalcase.Unqualified, reputation.ReasonReporterNotAuthorized},
		{"quality without an assessment", func(x *core.OutcomeReport) { quality(x); x.EvidenceRefs = []string{readRecord} }, nil,
			evalcase.Unqualified, reputation.ReasonNoAssessmentRecord},
		{"affiliated evaluator, positive", quality, func(c *evalcase.OutcomesConfig) {
			c.Affiliations = []evalcase.Affiliation{{EvaluatorIss: evaluator, OperatorID: "https://identity.example/operators/acme"}}
		}, evalcase.Unqualified, reputation.ReasonAffiliatedEvaluator},
		{"affiliated evaluator, negative", func(x *core.OutcomeReport) { quality(x); x.Result = core.OutcomeFailure }, func(c *evalcase.OutcomesConfig) {
			c.Affiliations = []evalcase.Affiliation{{EvaluatorIss: evaluator, OperatorID: "https://identity.example/operators/acme"}}
		}, evalcase.Qualified, reputation.ReasonMapped},
		{"affiliated with another operator", quality, func(c *evalcase.OutcomesConfig) {
			c.Affiliations = []evalcase.Affiliation{{EvaluatorIss: evaluator, OperatorID: "https://identity.example/operators/ledgerworks"}}
		}, evalcase.Qualified, reputation.ReasonMapped},
		{"another agent than the task's", func(x *core.OutcomeReport) {
			x.Subject = "https://identity.example/agents/ledger-reviewer"
			x.Context.AgentID = x.Subject
		}, nil, evalcase.Unqualified, reputation.ReasonTaskUnreconciled},
		{"a context of another agent", func(x *core.OutcomeReport) { x.Context.AgentID = "https://identity.example/agents/ledger-reviewer" }, nil,
			evalcase.Unqualified, reputation.ReasonTaskUnreconciled},
		{"a context of another tenant", func(x *core.OutcomeReport) { x.Context.TenantID = "globex" }, nil,
			evalcase.Unqualified, reputation.ReasonTaskUnreconciled},
		{"executor id differs", nil, func(c *evalcase.OutcomesConfig) {
			c.ExecutorClasses = []evalcase.ExecutorClass{{TaskID: tmpl.TaskID, OperationID: tmpl.OperationID, Class: "delegated-user", ExecutorID: strp("https://identity.example/apps/other")}}
		}, evalcase.Unqualified, reputation.ReasonExecutorClassMismatch},
		{"executor id matches", nil, func(c *evalcase.OutcomesConfig) {
			c.ExecutorClasses = []evalcase.ExecutorClass{{TaskID: tmpl.TaskID, OperationID: tmpl.OperationID, Class: "delegated-user", ExecutorID: strp("https://identity.example/principals/alice")}}
		}, evalcase.Qualified, reputation.ReasonMapped},
		{"no installed executor class", nil, func(c *evalcase.OutcomesConfig) { c.ExecutorClasses = nil },
			evalcase.Unqualified, reputation.ReasonExecutorClassMismatch},
		{"record of another operation", func(x *core.OutcomeReport) { x.OperationID = "invoice-read-operation-0002" }, nil,
			evalcase.Unqualified, reputation.ReasonNoExecutorRecord},
		{"failure citing a completed record", func(x *core.OutcomeReport) { x.Result = core.OutcomeFailure }, nil,
			evalcase.Unqualified, reputation.ReasonNoCompletionRecord},
		{"authorization allow citing a denial", func(x *core.OutcomeReport) {
			x.EventKind, x.Dimension, x.Issuer, x.ReporterRole, x.EvidenceRefs = core.EventAuthorization, core.DimensionNone, gateway, "gateway", []string{denied}
		}, nil, evalcase.Unqualified, reputation.ReasonRecordMismatch},
		{"unknown execution from the gateway with visibility", func(x *core.OutcomeReport) {
			x.Issuer, x.ReporterRole, x.Result, x.Dimension, x.EvidenceRefs = gateway, "gateway", core.OutcomeUnknown, core.DimensionNone, []string{}
		}, nil, evalcase.Unqualified, reputation.ReasonNoExecutorRecord},
		{"mixed causal failure", func(x *core.OutcomeReport) {
			x.Result, x.EvidenceRefs = core.OutcomeFailure, []string{"native-execution-log:finance-read-0001/reconciled"}
			x.Attribution.CausalAssessment = core.CausalMixed
		}, nil, evalcase.Qualified, reputation.ReasonCausalZeroWeight},
		{"admission from an executor", func(x *core.OutcomeReport) {
			x.EventKind, x.Dimension, x.EvidenceRefs = core.EventAdmission, core.DimensionNone, []string{}
		}, nil, evalcase.Unqualified, reputation.ReasonReporterNotAuthorized},
		{"gateway unknown citing a record, no visibility", func(x *core.OutcomeReport) {
			x.Issuer, x.ReporterRole, x.Result, x.Dimension = gateway, "gateway", core.OutcomeUnknown, core.DimensionNone
		}, func(c *evalcase.OutcomesConfig) { c.Visibility = "none" }, evalcase.Unqualified, reputation.ReasonReporterNotAuthorized},
		{"gateway success on none, no visibility", func(x *core.OutcomeReport) {
			x.Issuer, x.ReporterRole, x.Dimension, x.EvidenceRefs = gateway, "gateway", core.DimensionNone, []string{}
		}, func(c *evalcase.OutcomesConfig) { c.Visibility = "none" }, evalcase.Unqualified, reputation.ReasonNoExecutorRecord},
		{"record without executor", func(x *core.OutcomeReport) { x.EvidenceRefs = []string{"native-execution-log:anonymous"} }, nil,
			evalcase.Unqualified, reputation.ReasonNoExecutorRecord},
		{"assessment of another task", func(x *core.OutcomeReport) { quality(x); x.EvidenceRefs = []string{"native-review:other-task"} }, nil,
			evalcase.Unqualified, reputation.ReasonNoAssessmentRecord},
		{"evaluator with an earlier quality report", func(x *core.OutcomeReport) { quality(x); x.Result = core.OutcomeFailure }, func(c *evalcase.OutcomesConfig) {
			c.Trust = append(c.Trust, evalcase.TrustRecord{Iss: evaluator, Role: "reporter", ReporterRole: strp("executor")})
		}, evalcase.Qualified, reputation.ReasonMapped},
		{"confirmed incident, unknown cause", func(x *core.OutcomeReport) {
			x.EventKind, x.Result, x.Dimension, x.Issuer, x.ReporterRole, x.EvidenceRefs = core.EventSecurity, core.OutcomeFailure, core.DimensionNone, security, "security_authority", []string{incident}
			x.Attribution.CausalAssessment = core.CausalUnknown
		}, nil, evalcase.Qualified, reputation.ReasonMapped},
		{"agent feedback", func(x *core.OutcomeReport) {
			x.EventKind, x.Dimension, x.Issuer, x.ReporterRole, x.EvidenceRefs = core.EventFeedback, core.DimensionTaskQuality, agentSelf, "agent", []string{}
		}, nil, evalcase.Qualified, reputation.ReasonMapped},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := cfg
			if tc.cfg != nil {
				tc.cfg(&c)
			}
			o := reputation.NewOracle(c, native)
			r := report(tmpl, 0, tc.edit)
			if a := o.Ingest(r, now); a.Ack != core.AckAccepted {
				t.Fatalf("answer %+v", a)
			}
			wantVerdict(t, o, r.EventID, tc.qualification, tc.reason)
		})
	}
}

// TestWeights: what a qualified report adds to its dimension (Sections
// 14.5, 14.6 rules 8, 9 and 11, and 15.3).
func TestWeights(t *testing.T) {
	cfg, native, tmpl := fixture(t)
	failed := "native-execution-log:finance-read-0001/reconciled"
	for _, tc := range []struct {
		name        string
		edit        func(*core.OutcomeReport)
		listed      bool
		score, conf int64
		dimension   core.Dimension
	}{
		{"success", nil, true, 6666, 476, core.DimensionReliability},
		{"agent failure", func(x *core.OutcomeReport) { x.Result, x.EvidenceRefs = core.OutcomeFailure, []string{failed} }, true, 3333, 476, core.DimensionReliability},
		{"environmental failure", func(x *core.OutcomeReport) {
			x.Result, x.EvidenceRefs, x.Attribution.CausalAssessment = core.OutcomeFailure, []string{failed}, core.CausalEnvironment
		}, false, 5000, 0, core.DimensionReliability},
		{"unknown causal failure", func(x *core.OutcomeReport) {
			x.Result, x.EvidenceRefs, x.Attribution.CausalAssessment = core.OutcomeFailure, []string{failed}, core.CausalUnknown
		}, false, 5000, 0, core.DimensionReliability},
		{"agent's own positive feedback", func(x *core.OutcomeReport) {
			x.EventKind, x.Dimension, x.Issuer, x.ReporterRole, x.EvidenceRefs = core.EventFeedback, core.DimensionTaskQuality, agentSelf, "agent", []string{}
		}, false, 5000, 0, core.DimensionTaskQuality},
		{"agent's own negative feedback", func(x *core.OutcomeReport) {
			x.EventKind, x.Dimension, x.Issuer, x.ReporterRole, x.EvidenceRefs = core.EventFeedback, core.DimensionTaskQuality, agentSelf, "agent", []string{}
			x.Result = core.OutcomeFailure
		}, true, 3333, 476, core.DimensionTaskQuality},
		{"confirmed incident", func(x *core.OutcomeReport) {
			x.EventKind, x.Result, x.Dimension, x.Issuer, x.ReporterRole, x.EvidenceRefs = core.EventSecurity, core.OutcomeFailure, core.DimensionNone, security, "security_authority", []string{incident}
		}, false, 5000, 0, core.DimensionReliability},
		{"remediation", func(x *core.OutcomeReport) {
			x.EventKind, x.Dimension, x.Issuer, x.ReporterRole, x.EvidenceRefs = core.EventRemediation, core.DimensionNone, security, "security_authority", []string{remediated}
		}, false, 5000, 0, core.DimensionReliability},
		{"evaluator's feedback", func(x *core.OutcomeReport) {
			x.EventKind, x.Dimension, x.Issuer, x.ReporterRole, x.EvidenceRefs = core.EventFeedback, core.DimensionTaskQuality, evaluator, "evaluator", []string{review}
		}, true, 6666, 476, core.DimensionTaskQuality},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := reputation.NewOracle(cfg, native)
			r := report(tmpl, 0, func(x *core.OutcomeReport) {
				x.ObservedAt = now
				if tc.edit != nil {
					tc.edit(x)
				}
			})
			if a := o.Ingest(r, now); a.Ack != core.AckAccepted {
				t.Fatalf("answer %+v", a)
			}
			if v := o.Verdicts()[r.EventID]; v.Qualification != evalcase.Qualified {
				t.Fatalf("verdict %+v, want QUALIFIED", v)
			}
			s := snap(t, o, query(tmpl), now)
			d := s.Value.Dimensions.Reliability
			if tc.dimension == core.DimensionTaskQuality {
				d = s.Value.Dimensions.TaskQuality
			}
			if (len(s.Manifest.QualifiedEventIDs) == 1) != tc.listed || d.ScoreBPS != tc.score || d.ConfidenceBPS != tc.conf {
				t.Errorf("listed %v, %s %d %d; want listed %v, %d %d", s.Manifest.QualifiedEventIDs, tc.dimension, d.ScoreBPS, d.ConfidenceBPS, tc.listed, tc.score, tc.conf)
			}
			if tc.listed && (d.QualifiedEvents != 1 || d.IndependentTasks != 1 || d.NewestEventAt == nil || *d.NewestEventAt != now) {
				t.Errorf("stats %+v, want one event of one task, newest at %d", d, now)
			}
			if !tc.listed && (d.QualifiedEvents != 0 || d.IndependentTasks != 0 || d.NewestEventAt != nil) {
				t.Errorf("stats %+v, want none", d)
			}
		})
	}
}

// TestNewestEvent: newest_event_at is the latest observation listed in the
// dimension, whatever the order of ingestion.
func TestNewestEvent(t *testing.T) {
	cfg, native, tmpl := fixture(t)
	observed := []int64{now - 100, now - 50, now - 200}
	var reports []core.OutcomeReport
	for i, at := range observed {
		ref := fmt.Sprintf("native-execution-log:read-%d", i)
		r := report(tmpl, i, func(x *core.OutcomeReport) {
			x.ObservedAt, x.OperationID, x.EvidenceRefs = at, fmt.Sprintf("invoice-read-operation-%04d", i+1), []string{ref}
		})
		native.Records[ref] = evalcase.NativeRecord{Kind: "execution", State: "completed", Returned: strp("data"),
			TaskID: r.TaskID, OperationID: r.OperationID, Executor: &evalcase.RecordExecutor{Class: "delegated-user"}}
		cfg.ExecutorClasses = append(cfg.ExecutorClasses, evalcase.ExecutorClass{TaskID: r.TaskID, OperationID: r.OperationID, Class: "delegated-user"})
		reports = append(reports, r)
	}
	o := reputation.NewOracle(cfg, native)
	for _, r := range reports {
		if a := o.Ingest(r, now); a.Ack != core.AckAccepted {
			t.Fatalf("%s: %+v", r.EventID, a)
		}
	}
	d := snap(t, o, query(tmpl), now).Value.Dimensions.Reliability
	if d.NewestEventAt == nil || *d.NewestEventAt != now-50 || d.QualifiedEvents != 3 || d.IndependentTasks != 1 {
		t.Errorf("reliability %+v, want 3 events of 1 task, newest at %d", d, now-50)
	}
}

// TestSnapshotClaims: the claims and pins of a snapshot (Sections 15.2 and
// Appendix A.2).
func TestSnapshotClaims(t *testing.T) {
	cfg, native, tmpl := fixture(t)
	o := reputation.NewOracle(cfg, native)
	q := query(tmpl)
	s := snap(t, o, q, now+7)
	c := s.Claims
	if c.Issuer != cfg.ReputationService.ServiceID || c.Subject != q.AgentID || c.Audience != q.Audience || c.HolderJKT != q.HolderJKT ||
		c.IssuedAt != now+7 || c.NotBefore != now+7 || c.Expiry != now+7+300 || c.TenantID != "acme" || c.PactVersion != "0.1" {
		t.Errorf("claims %+v", c)
	}
	v := s.Value
	if v.EvidenceCutoff != now+7 || s.Manifest.EvidenceCutoff != now+7 || v.ScoringPolicyRevision != "finance-scoring-1" ||
		s.Manifest.ScoringPolicyRevision != v.ScoringPolicyRevision || s.Manifest.QualificationPolicyID != "pact-qualification-v1" ||
		v.SecurityStatus != core.SecurityClear || v.HoldRefs == nil || len(v.HoldRefs) != 0 {
		t.Errorf("value %+v manifest %+v", v, s.Manifest)
	}
	for _, bad := range []func(*core.ReputationQuery){
		func(q *core.ReputationQuery) { q.Context.TenantID = "globex" },
		func(q *core.ReputationQuery) { q.Context.EnvironmentID = "https://gateway.example/environments/hr" },
		func(q *core.ReputationQuery) { q.AgentID = "https://identity.example/agents/ledger-reviewer" },
	} {
		q := query(tmpl)
		bad(&q)
		if s, code := o.Query(q, now); s != nil || code != reputation.CodeContextMismatch {
			t.Errorf("query %+v: %v %s, want CONTEXT_MISMATCH", q, s, code)
		}
	}
}

// TestHolds: a hold is placed only by a qualified SECURITY FAILURE of a
// registered security authority, applies to the agent in every context and
// under every holder key, does not decay, and is cleared only by a later
// remediation of a hold clearance authority that names it beside completed
// remediation evidence (Section 15.4).
func TestHolds(t *testing.T) {
	cfg, native, tmpl := fixture(t)
	sec := func(n int, edit func(*core.OutcomeReport)) core.OutcomeReport {
		return report(tmpl, n, func(x *core.OutcomeReport) {
			x.EventKind, x.Result, x.Dimension, x.Issuer, x.ReporterRole = core.EventSecurity, core.OutcomeFailure, core.DimensionNone, security, "security_authority"
			x.EvidenceRefs = []string{incident}
			if edit != nil {
				edit(x)
			}
		})
	}
	rem := func(n int, edit func(*core.OutcomeReport)) core.OutcomeReport {
		return report(tmpl, n, func(x *core.OutcomeReport) {
			x.EventKind, x.Result, x.Dimension, x.Issuer, x.ReporterRole = core.EventRemediation, core.OutcomeSuccess, core.DimensionNone, security, "security_authority"
			x.EvidenceRefs = []string{"event-a", remediated}
			if edit != nil {
				edit(x)
			}
		})
	}
	status := func(o *reputation.Oracle, q core.ReputationQuery, at int64) (core.SecurityStatus, []string) {
		s := snap(t, o, q, at)
		return s.Value.SecurityStatus, s.Value.HoldRefs
	}
	ingest := func(o *reputation.Oracle, rs ...core.OutcomeReport) {
		for _, r := range rs {
			if a := o.Ingest(r, now); a.Ack == "" {
				t.Fatalf("%s: %+v", r.EventID, a)
			}
		}
	}
	held := func(name string, o *reputation.Oracle, want bool) {
		t.Helper()
		st, refs := status(o, query(tmpl), now)
		if want && (st != core.SecurityHold || len(refs) != 1 || refs[0] != "event-a") || !want && (st != core.SecurityClear || len(refs) != 0) {
			t.Errorf("%s: %s %v, want hold %v", name, st, refs, want)
		}
	}
	o := reputation.NewOracle(cfg, native)
	ingest(o, sec(0, nil))
	held("confirmed incident", o, true)
	other := query(tmpl)
	other.Context.ActionClass, other.HolderJKT = "payment.approve", "ahxE1XEYqxvLIZy3r4nx9RE4E0683KndykyuZTK9xQg"
	if st, _ := status(o, other, now+400*86400); st != core.SecurityHold {
		t.Errorf("another context and holder key, 400 days later: %s, want HOLD", st)
	}
	another := query(tmpl)
	another.AgentID = "https://identity.example/agents/ledger-reviewer"
	another.Context.AgentID = another.AgentID
	if st, refs := status(o, another, now); st != core.SecurityClear || len(refs) != 0 {
		t.Errorf("another agent: %s %v, want CLEAR", st, refs)
	}
	ingest(o, rem(1, func(x *core.OutcomeReport) { x.Issuer = soc }))
	held("remediation of another security authority", o, true)
	ingest(o, rem(4, nil))
	held("authorized remediation", o, false)
	// Each failed clearance on its own oracle: a second remediation of the
	// same authority, task and operation repeats the deduplication tuple of
	// the first (rule 4).
	for name, r := range map[string]core.OutcomeReport{
		"remediation without completion evidence": rem(2, func(x *core.OutcomeReport) { x.EvidenceRefs = []string{"event-a"} }),
		"remediation of another hold":             rem(3, func(x *core.OutcomeReport) { x.EvidenceRefs = []string{"event-z", remediated} }),
	} {
		o := reputation.NewOracle(cfg, native)
		ingest(o, sec(0, nil), r)
		held(name, o, true)
	}

	native.Records["native-incident-record:other-operation"] = evalcase.NativeRecord{Kind: "incident", State: "confirmed", TaskID: tmpl.TaskID,
		OperationID: "invoice-read-operation-0002"}
	for name, tc := range map[string]struct {
		r      core.OutcomeReport
		reason string
	}{
		"security success":                    {sec(0, func(x *core.OutcomeReport) { x.Result = core.OutcomeSuccess }), reputation.ReasonReporterNotAuthorized},
		"security unknown":                    {sec(0, func(x *core.OutcomeReport) { x.Result = core.OutcomeUnknown }), reputation.ReasonReporterNotAuthorized},
		"unregistered security authority":     {sec(0, func(x *core.OutcomeReport) { x.Issuer = "https://security.example/rogue" }), reputation.ReasonReporterNotAuthorized},
		"security report of an executor":      {sec(0, func(x *core.OutcomeReport) { x.Issuer, x.ReporterRole = executor, "executor" }), reputation.ReasonReporterNotAuthorized},
		"security report of another task":     {sec(0, func(x *core.OutcomeReport) { x.TaskID = "native-task:unknown" }), reputation.ReasonTaskUnreconciled},
		"security report about another agent": {sec(0, func(x *core.OutcomeReport) { x.Subject = "https://identity.example/agents/ledger-reviewer" }), reputation.ReasonTaskUnreconciled},
		"incident without record":             {sec(0, func(x *core.OutcomeReport) { x.EvidenceRefs = []string{} }), reputation.ReasonRecordMismatch},
		"incident citing an execution record": {sec(0, func(x *core.OutcomeReport) { x.EvidenceRefs = []string{readRecord} }), reputation.ReasonRecordMismatch},
		"incident of another operation":       {sec(0, func(x *core.OutcomeReport) { x.EvidenceRefs = []string{"native-incident-record:other-operation"} }), reputation.ReasonRecordMismatch},
		"incident on a dimension":             {sec(0, func(x *core.OutcomeReport) { x.Dimension = core.DimensionPolicyAdherence }), reputation.ReasonReporterNotAuthorized},
	} {
		o := reputation.NewOracle(cfg, native)
		ingest(o, tc.r)
		held(name, o, false)
		wantVerdict(t, o, tc.r.EventID, evalcase.Unqualified, tc.reason)
	}
	// A remediation that is not qualified clears nothing.
	o = reputation.NewOracle(cfg, native)
	ingest(o, sec(0, nil), rem(4, func(x *core.OutcomeReport) { x.ReporterRole = "executor" }))
	held("unqualified remediation of the clearance authority", o, true)
	// A remediation before the hold clears nothing.
	o = reputation.NewOracle(cfg, native)
	ingest(o, rem(4, nil), sec(0, nil))
	held("remediation before the incident", o, true)
}

// TestCorrections: rule 10 of Section 14.6.
func TestCorrections(t *testing.T) {
	cfg, native, tmpl := fixture(t)
	failed := "native-execution-log:finance-read-0001/reconciled"
	corr := func(n int, edit func(*core.OutcomeReport)) core.OutcomeReport {
		return report(tmpl, n, func(x *core.OutcomeReport) {
			x.EventKind, x.Result, x.Supersedes, x.EvidenceRefs = core.EventCorrection, core.OutcomeFailure, []string{"event-a"}, []string{failed}
			if edit != nil {
				edit(x)
			}
		})
	}
	for _, tc := range []struct {
		name       string
		first      func(*core.OutcomeReport)
		correction core.OutcomeReport
		reason     string
		superseded bool
	}{
		{"same reporter", nil, corr(1, nil), reputation.ReasonCorrection, true},
		{"security authority", nil, corr(1, func(x *core.OutcomeReport) { x.Issuer, x.ReporterRole = security, "security_authority" }), reputation.ReasonCorrection, true},
		{"another reporter", func(x *core.OutcomeReport) {
			x.Issuer, x.ReporterRole = gateway, "gateway"
			x.EventKind, x.Dimension, x.EvidenceRefs = core.EventAuthorization, core.DimensionNone, []string{denied}
			x.Result = core.OutcomeFailure
		}, corr(1, func(x *core.OutcomeReport) { x.Dimension = core.DimensionNone; x.Result = core.OutcomeFailure }), reputation.ReasonCorrectionMismatch, false},
		{"another operation", nil, corr(1, func(x *core.OutcomeReport) { x.OperationID = "invoice-read-operation-0002" }), reputation.ReasonCorrectionMismatch, false},
		{"another dimension", nil, corr(1, func(x *core.OutcomeReport) { x.Dimension = core.DimensionPolicyAdherence }), reputation.ReasonCorrectionMismatch, false},
		{"an unknown event", nil, corr(1, func(x *core.OutcomeReport) { x.Supersedes = []string{"event-q"} }), reputation.ReasonCorrectionMismatch, false},
		{"an unregistered corrector", nil, corr(1, func(x *core.OutcomeReport) { x.ReporterRole = "evaluator" }), reputation.ReasonReporterNotAuthorized, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := reputation.NewOracle(cfg, native)
			first := report(tmpl, 0, tc.first)
			if a := o.Ingest(first, now); a.Ack != core.AckAccepted {
				t.Fatalf("first: %+v", a)
			}
			if a := o.Ingest(tc.correction, now); a.Ack != core.AckAccepted {
				t.Fatalf("correction: %+v", a)
			}
			q := evalcase.Qualified
			if tc.reason != reputation.ReasonCorrection {
				q = evalcase.Unqualified
			}
			wantVerdict(t, o, tc.correction.EventID, q, tc.reason)
			s := snap(t, o, query(tmpl), now)
			if (len(s.Manifest.SupersededEventIDs) == 1) != tc.superseded {
				t.Errorf("superseded %v, want superseded %v", s.Manifest.SupersededEventIDs, tc.superseded)
			}
		})
	}
	// A correction that names a later event supersedes nothing.
	o := reputation.NewOracle(cfg, native)
	early := corr(0, func(x *core.OutcomeReport) { x.Supersedes = []string{"event-b"} })
	if a := o.Ingest(early, now); a.Ack != core.AckAccepted {
		t.Fatal(a)
	}
	o.Ingest(report(tmpl, 1, nil), now)
	wantVerdict(t, o, early.EventID, evalcase.Unqualified, reputation.ReasonCorrectionMismatch)
}

// TestReciprocalWindow: rule 7 applies only within the ingestion window, and
// only to positive reports.
func TestReciprocalWindow(t *testing.T) {
	c, err := evalcase.ReadOutcomes(repoFixtures, "outcomes/qualification/reciprocal-endorsements")
	if err != nil {
		t.Fatal(err)
	}
	a, b := c.Reports["quality-event-0001"], c.Reports["quality-event-0002"]
	for name, tc := range map[string]struct {
		edit func(*core.OutcomeReport)
		cfg  func(*evalcase.OutcomesConfig)
		want string
	}{
		"within the window":  {nil, nil, evalcase.Disputed},
		"outside the window": {func(r *core.OutcomeReport) { r.ObservedAt = a.ObservedAt - 604801 }, nil, evalcase.Qualified},
		"negative":           {func(r *core.OutcomeReport) { r.Result = core.OutcomeFailure }, nil, evalcase.Qualified},
		"not the evaluator's own agent": {nil, func(c *evalcase.OutcomesConfig) {
			c.EvaluatorAgents = []evalcase.EvaluatorAgent{c.EvaluatorAgents[0], c.EvaluatorAgents[1]}
			c.EvaluatorAgents[0].AgentID = "https://identity.example/agents/other"
		}, evalcase.Qualified},
		"an evaluator another operator runs": {nil, func(c *evalcase.OutcomesConfig) {
			c.EvaluatorAgents = []evalcase.EvaluatorAgent{c.EvaluatorAgents[0], c.EvaluatorAgents[1]}
			c.EvaluatorAgents[1].OperatorID = "https://identity.example/operators/globex"
		}, evalcase.Qualified},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := c.Config
			if tc.cfg != nil {
				tc.cfg(&cfg)
			}
			o := reputation.NewOracle(cfg, c.Native)
			if ans := o.Ingest(a, now); ans.Ack != core.AckAccepted {
				t.Fatal(ans)
			}
			x := b
			if tc.edit != nil {
				tc.edit(&x)
			}
			// The window is checked between observations, so the second
			// report is ingested at a time its own observation allows.
			at := now
			if x.ObservedAt < now-604800 {
				at = x.ObservedAt + 10
				x.IssuedAt, x.NotBefore, x.Expiry = at, at, at+300
			}
			if ans := o.Ingest(x, at); ans.Ack != core.AckAccepted {
				t.Fatal(ans)
			}
			if v := o.Verdicts()["quality-event-0001"]; v.Qualification != tc.want {
				t.Errorf("first report %+v, want %s", v, tc.want)
			}
		})
	}
}

// TestLargeProvenance: a snapshot whose provenance manifest is beyond the
// 256 KiB decode limit of draft Section 20.1 is answered: the manifest is
// not a wire object and the draft bounds it by no size.
func TestLargeProvenance(t *testing.T) {
	cfg, native, tmpl := fixture(t)
	const n = 5000
	var reports []core.OutcomeReport
	for i := range n {
		op, ref := fmt.Sprintf("invoice-read-operation-%05d", i), fmt.Sprintf("native-execution-log:large-%05d", i)
		native.Records[ref] = evalcase.NativeRecord{Kind: "execution", State: "completed", Returned: strp("data"), TaskID: tmpl.TaskID, OperationID: op,
			Executor: &evalcase.RecordExecutor{Class: "delegated-user"}}
		cfg.ExecutorClasses = append(cfg.ExecutorClasses, evalcase.ExecutorClass{TaskID: tmpl.TaskID, OperationID: op, Class: "delegated-user"})
		r := tmpl
		r.EventID, r.JTI, r.OperationID, r.EvidenceRefs = fmt.Sprintf("large-%05d", i), fmt.Sprintf("large-report-jti-%08d", i), op, []string{ref}
		reports = append(reports, r)
	}
	o := reputation.NewOracle(cfg, native)
	for _, r := range reports {
		if a := o.Ingest(r, now); a.Ack != core.AckAccepted {
			t.Fatalf("%s: %+v", r.EventID, a)
		}
	}
	s, code := o.Query(query(tmpl), now)
	if s == nil {
		t.Fatalf("query refused %s", code)
	}
	if len(s.Manifest.QualifiedEventIDs) != n || s.Value.Dimensions.Reliability.QualifiedEvents != n || s.Value.ProvenanceDigest == "" {
		t.Errorf("listed %d, qualified_events %d, digest %q", len(s.Manifest.QualifiedEventIDs), s.Value.Dimensions.Reliability.QualifiedEvents, s.Value.ProvenanceDigest)
	}
	b, _ := json.Marshal(s.Manifest)
	if len(b) <= 256<<10 {
		t.Errorf("manifest of %d bytes does not cross the 256 KiB limit", len(b))
	}
}
