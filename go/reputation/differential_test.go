package reputation_test

// The library against the runner's reference oracle on synthetic reports
// the committed cases do not reach: every rule of draft Sections 14.2,
// 14.5, 14.6 and 15.4 that the oracle's own tests pin, applied to both, must
// give the same answers, classifications and snapshots. The oracle is an
// independent reading of the draft; it shares only the beta-decay-v1 scorer
// with the library.

import (
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"hop.top/pact-go/core"
	"hop.top/pact-go/core/jws"
	"hop.top/pact-go/reputation"
	"hop.top/pact-go/runner/evalcase"
	oracle "hop.top/pact-go/runner/reputation"
)

// step is one input of a scenario: a report ingested at a time, or a query
// at a time.
type step struct {
	report *core.OutcomeReport
	query  *core.ReputationQuery
	at     int64
}

type scenario struct {
	name  string
	cfg   func(*evalcase.OutcomesConfig)
	steps func(b *builder) []step
}

// builder makes reports from the template of a committed case.
type builder struct {
	tmpl core.OutcomeReport
	n    int
}

func (b *builder) report(edit func(*core.OutcomeReport)) *core.OutcomeReport {
	b.n++
	r := b.tmpl
	r.EventID = fmt.Sprintf("event-%04d", b.n)
	r.JTI = fmt.Sprintf("differential-jti-%06d", b.n)
	r.EvidenceRefs = append([]string(nil), b.tmpl.EvidenceRefs...)
	r.Supersedes = []string{}
	if edit != nil {
		edit(&r)
	}
	return &r
}

func (b *builder) query(edit func(*core.ReputationQuery)) *core.ReputationQuery {
	q := core.ReputationQuery{AgentID: b.tmpl.Subject, HolderJKT: evalcase.DefaultHolderJKT, Context: b.tmpl.Context, Audience: gateway}
	if edit != nil {
		edit(&q)
	}
	return &q
}

func ingestAt(r *core.OutcomeReport, at int64) step  { return step{report: r, at: at} }
func queryAt(q *core.ReputationQuery, at int64) step { return step{query: q, at: at} }

// world is the configuration both implementations get: a committed case's
// with more reporters and records.
func world(t *testing.T) (evalcase.OutcomesConfig, evalcase.OutcomesNative, core.OutcomeReport) {
	t.Helper()
	c, err := evalcase.ReadOutcomes(repoFixtures, "outcomes/qualification/correction-recompute")
	if err != nil {
		t.Fatal(err)
	}
	cfg := c.Config
	role := func(s string) *string { return &s }
	cfg.Trust = slices.Clone(cfg.Trust)
	for _, r := range []struct{ iss, role, key string }{
		{security, "security_authority", "keys/security-authority.jwk.json"}, {soc, "security_authority", "keys/adversarial.jwk.json"},
		{evaluator, "evaluator", "keys/evaluator.jwk.json"}, {gateway, "gateway", "keys/issuer.jwk.json"}, {agent, "agent", "keys/holder-2.jwk.json"},
	} {
		cfg.Trust = append(cfg.Trust, evalcase.TrustRecord{Iss: r.iss, Role: "reporter", ReporterRole: role(r.role), Keys: []string{r.key}})
	}
	cfg.HoldClearanceAuthorities = []string{security}
	native := c.Native
	native.Records = maps.Clone(c.Native.Records)
	ex := &evalcase.RecordExecutor{Class: "delegated-user", PrincipalID: "https://identity.example/principals/alice"}
	for ref, r := range map[string]evalcase.NativeRecord{
		reviewRef: {Kind: "assessment", State: "completed"}, incidentRef: {Kind: "incident", State: "confirmed"},
		fixRef: {Kind: "remediation", State: "completed"}, "native-authorization:denied": {Kind: "authorization", State: "denied", Executor: ex},
		"native-execution-log:anonymous": {Kind: "execution", State: "completed", Executor: nil},
		"native-review:other-task":       {Kind: "assessment", State: "completed", TaskID: "native-task:other"},
	} {
		if r.TaskID == "" {
			r.TaskID = task
		}
		r.OperationID = operation
		native.Records[ref] = r
	}
	return cfg, native, c.Reports["execution-event-0001"]
}

// library builds a Service from the configuration as the adapter does from
// a case's files.
func library(t *testing.T, cfg evalcase.OutcomesConfig, native evalcase.OutcomesNative) *reputation.Service {
	t.Helper()
	var reg reputation.StaticRegistry
	for _, tr := range cfg.Trust {
		r := reputation.Reporter{Iss: tr.Iss, Role: core.ReporterRole(*tr.ReporterRole)}
		for _, k := range tr.Keys {
			b, err := os.ReadFile(filepath.Join(repoFixtures, filepath.FromSlash(k)))
			if err != nil {
				t.Fatal(err)
			}
			jwk, err := jws.ParseJWK(b)
			if err != nil {
				t.Fatal(err)
			}
			r.Keys = append(r.Keys, jwk)
		}
		reg = append(reg, r)
	}
	var tasks reputation.StaticTasks
	for _, x := range native.Tasks {
		tasks = append(tasks, reputation.Task{TaskID: x.TaskID, AgentID: x.AgentID, OperatorID: x.OperatorID, PrincipalID: x.PrincipalID,
			IndependenceGroup: x.IndependenceGroup, HolderJKT: x.HolderJKT})
	}
	records := reputation.StaticRecords{}
	for ref, x := range native.Records {
		rec := reputation.Record{Kind: reputation.RecordKind(x.Kind), State: x.State, TaskID: x.TaskID, OperationID: x.OperationID, ObservedAt: x.ObservedAt}
		if x.Executor != nil {
			rec.Executor = &reputation.Executor{Class: x.Executor.Class, PrincipalID: x.Executor.PrincipalID}
		}
		records[ref] = rec
	}
	c := reputation.Config{
		ServiceID: cfg.ReputationService.ServiceID, TenantID: cfg.ReputationService.TenantID, EnvironmentID: cfg.ReputationService.EnvironmentID,
		ClockSkewSeconds: cfg.ClockSkewSeconds, DataPolicy: cfg.DataPolicy, ScoringArtifactDigest: cfg.Scoring.ScoringArtifactDigest,
		ScoringPolicyRevision: cfg.Scoring.ScoringPolicyRevision, ExecutionVisible: cfg.Visibility != "none", HoldClearanceAuthorities: cfg.HoldClearanceAuthorities,
	}
	for _, e := range cfg.ExecutorClasses {
		c.ExecutorClasses = append(c.ExecutorClasses, reputation.ExecutorClass{TaskID: e.TaskID, OperationID: e.OperationID, Class: e.Class, ExecutorID: e.ExecutorID})
	}
	for _, a := range cfg.Affiliations {
		c.Affiliations = append(c.Affiliations, reputation.Affiliation{EvaluatorIss: a.EvaluatorIss, OperatorID: a.OperatorID})
	}
	for _, e := range cfg.EvaluatorAgents {
		c.EvaluatorAgents = append(c.EvaluatorAgents, reputation.EvaluatorAgent{EvaluatorIss: e.EvaluatorIss, AgentID: e.AgentID, OperatorID: e.OperatorID})
	}
	signer, err := snapshotSigner(repoFixtures, "")
	if err != nil {
		t.Fatal(err)
	}
	svc, err := reputation.New(c, reputation.Deps{Registry: reg, Tasks: tasks, Records: records, Store: &reputation.MemoryStore{}, Signer: signer})
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

// signFor signs r with the private test key of the first trust record of
// its iss, or the adversarial key for a signer the configuration does not
// know.
func signFor(t *testing.T, cfg evalcase.OutcomesConfig, keys map[string]evalcase.Key, r core.OutcomeReport) string {
	t.Helper()
	k := keys["adversarial"]
	for _, tr := range cfg.Trust {
		if tr.Iss != r.Issuer || len(tr.Keys) == 0 {
			continue
		}
		b, err := os.ReadFile(filepath.Join(repoFixtures, filepath.FromSlash(tr.Keys[0])))
		if err != nil {
			t.Fatal(err)
		}
		pub, err := jws.ParseJWK(b)
		if err != nil {
			t.Fatal(err)
		}
		for _, x := range keys {
			if x.Public.Kid == pub.Kid {
				k = x
			}
		}
		break
	}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	out, err := jws.Sign(jws.Header{Typ: jws.TypOutcome, Kid: k.Public.Kid}, b, k.Private)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// oracleReason is the oracle's reason for a library rule.
func oracleReason(rule string) string {
	switch rule {
	case reputation.RuleNotRegistered, reputation.RuleNotEligible:
		return oracle.ReasonReporterNotAuthorized
	}
	return rule
}

// observable is what a snapshot says, without its jti and signature.
type observable struct {
	Dimensions core.ReputationDimensions
	Status     core.SecurityStatus
	Holds      []string
	Qualified  [][2]string
	Superseded [][2]string
}

func scenarios() []scenario {
	quality := func(x *core.OutcomeReport) {
		x.EventKind, x.Dimension, x.Issuer, x.ReporterRole = core.EventQuality, core.DimensionTaskQuality, evaluator, core.ReporterEvaluator
		x.EvidenceRefs = []string{reviewRef}
	}
	sec := func(x *core.OutcomeReport) {
		x.EventKind, x.Result, x.Dimension, x.Issuer, x.ReporterRole = core.EventSecurity, core.OutcomeFailure, core.DimensionNone, security, core.ReporterSecurityAuthority
		x.EvidenceRefs = []string{incidentRef}
	}
	rem := func(iss string, refs ...string) func(*core.OutcomeReport) {
		return func(x *core.OutcomeReport) {
			x.EventKind, x.Result, x.Dimension, x.Issuer, x.ReporterRole = core.EventRemediation, core.OutcomeSuccess, core.DimensionNone, iss, core.ReporterSecurityAuthority
			x.EvidenceRefs = refs
		}
	}
	failed := "native-execution-log:finance-read-0001/reconciled"
	one := func(edit func(*core.OutcomeReport)) func(b *builder) []step {
		return func(b *builder) []step {
			return []step{ingestAt(b.report(edit), t0), queryAt(b.query(nil), t0)}
		}
	}
	both := func(edits ...func(*core.OutcomeReport)) func(*core.OutcomeReport) {
		return func(x *core.OutcomeReport) {
			for _, e := range edits {
				e(x)
			}
		}
	}
	affiliated := func(c *evalcase.OutcomesConfig) {
		c.Affiliations = []evalcase.Affiliation{{EvaluatorIss: evaluator, OperatorID: "https://identity.example/operators/acme"}}
	}
	return []scenario{
		{"success", nil, one(nil)},
		{"agent failure", nil, one(func(x *core.OutcomeReport) { x.Result, x.EvidenceRefs = core.OutcomeFailure, []string{failed} })},
		{"environmental failure", nil, one(func(x *core.OutcomeReport) {
			x.Result, x.EvidenceRefs, x.Attribution.CausalAssessment = core.OutcomeFailure, []string{failed}, core.CausalEnvironment
		})},
		{"mixed failure", nil, one(func(x *core.OutcomeReport) {
			x.Result, x.EvidenceRefs, x.Attribution.CausalAssessment = core.OutcomeFailure, []string{failed}, core.CausalMixed
		})},
		{"quality from an executor", nil, one(both(quality, func(x *core.OutcomeReport) { x.Issuer, x.ReporterRole = executor, core.ReporterExecutor }))},
		{"execution from the gateway", nil, one(func(x *core.OutcomeReport) { x.Issuer, x.ReporterRole = gateway, core.ReporterGateway })},
		{"execution from a security authority", nil, one(func(x *core.OutcomeReport) { x.Issuer, x.ReporterRole = security, core.ReporterSecurityAuthority })},
		{"admission from an executor", nil, one(func(x *core.OutcomeReport) {
			x.EventKind, x.Dimension, x.EvidenceRefs = core.EventAdmission, core.DimensionNone, []string{}
		})},
		{"security from an executor", nil, one(both(sec, func(x *core.OutcomeReport) { x.Issuer, x.ReporterRole = executor, core.ReporterExecutor }))},
		{"unregistered role", nil, one(func(x *core.OutcomeReport) { x.ReporterRole = core.ReporterTaskOwner })},
		{"quality", nil, one(quality)},
		{"quality without assessment", nil, one(both(quality, func(x *core.OutcomeReport) { x.EvidenceRefs = []string{readRef} }))},
		{"assessment of another task", nil, one(both(quality, func(x *core.OutcomeReport) { x.EvidenceRefs = []string{"native-review:other-task"} }))},
		{"affiliated positive", affiliated, one(quality)},
		{"affiliated negative", affiliated, one(both(quality, func(x *core.OutcomeReport) { x.Result = core.OutcomeFailure }))},
		{"another agent", nil, one(func(x *core.OutcomeReport) {
			x.Subject = "https://identity.example/agents/other"
			x.Context.AgentID = x.Subject
		})},
		{"context of another agent", nil, one(func(x *core.OutcomeReport) { x.Context.AgentID = "https://identity.example/agents/other" })},
		{"context of another tenant", nil, one(func(x *core.OutcomeReport) { x.Context.TenantID = "globex" })},
		{"unknown task", nil, one(func(x *core.OutcomeReport) { x.TaskID = "native-task:unknown" })},
		{"executor id differs", func(c *evalcase.OutcomesConfig) {
			id := "https://identity.example/apps/other"
			c.ExecutorClasses = []evalcase.ExecutorClass{{TaskID: task, OperationID: operation, Class: "delegated-user", ExecutorID: &id}}
		}, one(nil)},
		{"no executor class", func(c *evalcase.OutcomesConfig) { c.ExecutorClasses = nil }, one(nil)},
		{"record of another operation", nil, one(func(x *core.OutcomeReport) { x.OperationID = "invoice-read-operation-0002" })},
		{"record without executor", nil, one(func(x *core.OutcomeReport) { x.EvidenceRefs = []string{"native-execution-log:anonymous"} })},
		{"failure citing a completion", nil, one(func(x *core.OutcomeReport) { x.Result = core.OutcomeFailure })},
		{"authorization allow citing a denial", nil, one(func(x *core.OutcomeReport) {
			x.EventKind, x.Dimension, x.Issuer, x.ReporterRole, x.EvidenceRefs = core.EventAuthorization, core.DimensionNone, gateway, core.ReporterGateway,
				[]string{"native-authorization:denied"}
		})},
		{"denial", nil, one(func(x *core.OutcomeReport) {
			x.EventKind, x.Dimension, x.Issuer, x.ReporterRole, x.EvidenceRefs = core.EventAuthorization, core.DimensionNone, gateway, core.ReporterGateway,
				[]string{"native-authorization:denied"}
			x.Result = core.OutcomeFailure
		})},
		{"no visibility, declared", func(c *evalcase.OutcomesConfig) { c.Visibility = "none" }, one(func(x *core.OutcomeReport) {
			x.Issuer, x.ReporterRole, x.Result, x.Dimension, x.EvidenceRefs = gateway, core.ReporterGateway, core.OutcomeUnknown, core.DimensionNone, []string{}
		})},
		{"no visibility, citing a record", func(c *evalcase.OutcomesConfig) { c.Visibility = "none" }, one(func(x *core.OutcomeReport) {
			x.Issuer, x.ReporterRole, x.Result, x.Dimension = gateway, core.ReporterGateway, core.OutcomeUnknown, core.DimensionNone
		})},
		{"no visibility, success on none", func(c *evalcase.OutcomesConfig) { c.Visibility = "none" }, one(func(x *core.OutcomeReport) {
			x.Issuer, x.ReporterRole, x.Dimension, x.EvidenceRefs = gateway, core.ReporterGateway, core.DimensionNone, []string{}
		})},
		{"agent positive feedback", nil, one(func(x *core.OutcomeReport) {
			x.EventKind, x.Dimension, x.Issuer, x.ReporterRole, x.EvidenceRefs = core.EventFeedback, core.DimensionTaskQuality, agent, core.ReporterAgent, []string{}
		})},
		{"agent negative feedback", nil, one(func(x *core.OutcomeReport) {
			x.EventKind, x.Dimension, x.Issuer, x.ReporterRole, x.EvidenceRefs = core.EventFeedback, core.DimensionTaskQuality, agent, core.ReporterAgent, []string{}
			x.Result = core.OutcomeFailure
		})},
		{"security failure on a dimension", nil, one(both(sec, func(x *core.OutcomeReport) { x.Dimension = core.DimensionReliability }))},
		{"self-praise after execution", func(c *evalcase.OutcomesConfig) {
			r := "evaluator"
			c.Trust = append(c.Trust, evalcase.TrustRecord{Iss: executor, Role: "reporter", ReporterRole: &r, Keys: []string{"keys/executor.jwk.json"}})
		}, func(b *builder) []step {
			return []step{ingestAt(b.report(nil), t0), ingestAt(b.report(both(quality, func(x *core.OutcomeReport) { x.Issuer = executor })), t0), queryAt(b.query(nil), t0)}
		}},
		{"self-praise before execution", func(c *evalcase.OutcomesConfig) {
			r := "evaluator"
			c.Trust = append(c.Trust, evalcase.TrustRecord{Iss: executor, Role: "reporter", ReporterRole: &r, Keys: []string{"keys/executor.jwk.json"}})
		}, func(b *builder) []step {
			q := b.report(both(quality, func(x *core.OutcomeReport) { x.Issuer = executor }))
			return []step{ingestAt(q, t0), queryAt(b.query(nil), t0), ingestAt(b.report(nil), t0), queryAt(b.query(nil), t0)}
		}},
		{"duplicate tuple and retry", nil, func(b *builder) []step {
			r := b.report(nil)
			return []step{ingestAt(r, t0), ingestAt(r, t0+1), ingestAt(b.report(nil), t0), queryAt(b.query(nil), t0)}
		}},
		{"another agent's query beside a hold", nil, func(b *builder) []step {
			return []step{ingestAt(b.report(sec), t0), queryAt(b.query(func(q *core.ReputationQuery) {
				q.AgentID = "https://identity.example/agents/other"
				q.Context.AgentID = q.AgentID
			}), t0)}
		}},
		{"unregistered after a registered report of the tuple", nil, func(b *builder) []step {
			return []step{ingestAt(b.report(nil), t0), ingestAt(b.report(func(x *core.OutcomeReport) { x.ReporterRole = core.ReporterTaskOwner }), t0), queryAt(b.query(nil), t0)}
		}},
		{"unregistered takes no tuple", nil, func(b *builder) []step {
			return []step{ingestAt(b.report(func(x *core.OutcomeReport) { x.ReporterRole = core.ReporterTaskOwner }), t0), ingestAt(b.report(nil), t0), queryAt(b.query(nil), t0)}
		}},
		{"hold and clearance", nil, func(b *builder) []step {
			h := b.report(sec)
			later := t0 + 400*86400
			fix := func(iss string, refs ...string) *core.OutcomeReport {
				return b.report(both(rem(iss, refs...), func(x *core.OutcomeReport) {
					x.ObservedAt, x.IssuedAt, x.NotBefore, x.Expiry = later-20, later, later, later+300
				}))
			}
			other := b.query(func(q *core.ReputationQuery) {
				q.HolderJKT = "ahxE1XEYqxvLIZy3r4nx9RE4E0683KndykyuZTK9xQg"
				q.Context.ActionClass = "payment.approve"
			})
			return []step{
				ingestAt(b.report(nil), t0), ingestAt(h, t0), queryAt(b.query(nil), t0), queryAt(other, later),
				ingestAt(fix(soc, h.EventID, fixRef), later), queryAt(b.query(nil), later),
				ingestAt(fix(security, h.EventID), later), queryAt(b.query(nil), later),
				queryAt(b.query(func(q *core.ReputationQuery) {
					q.AgentID = "https://identity.example/agents/other"
					q.Context.AgentID = q.AgentID
				}), t0),
			}
		}},
		{"hold cleared", nil, func(b *builder) []step {
			h := b.report(sec)
			return []step{ingestAt(h, t0), ingestAt(b.report(rem(security, h.EventID, fixRef)), t0), queryAt(b.query(nil), t0)}
		}},
		{"remediation before the hold", nil, func(b *builder) []step {
			r := b.report(rem(security, "event-0002", fixRef))
			return []step{ingestAt(r, t0), ingestAt(b.report(sec), t0), queryAt(b.query(nil), t0)}
		}},
		{"unqualified remediation", nil, func(b *builder) []step {
			h := b.report(sec)
			return []step{ingestAt(h, t0), ingestAt(b.report(both(rem(security, h.EventID, fixRef), func(x *core.OutcomeReport) { x.ReporterRole = core.ReporterExecutor })), t0),
				queryAt(b.query(nil), t0)}
		}},
		{"security success", nil, one(both(sec, func(x *core.OutcomeReport) { x.Result = core.OutcomeSuccess }))},
		{"security about another agent", nil, one(both(sec, func(x *core.OutcomeReport) { x.Subject = "https://identity.example/agents/other" }))},
		{"correction", nil, func(b *builder) []step {
			r := b.report(nil)
			return []step{ingestAt(r, t0), ingestAt(b.report(func(x *core.OutcomeReport) {
				x.EventKind, x.Result, x.Supersedes, x.EvidenceRefs = core.EventCorrection, core.OutcomeFailure, []string{r.EventID}, []string{failed}
			}), t0), queryAt(b.query(nil), t0)}
		}},
		{"correction by a security authority", nil, func(b *builder) []step {
			r := b.report(nil)
			return []step{ingestAt(r, t0), ingestAt(b.report(func(x *core.OutcomeReport) {
				x.EventKind, x.Result, x.Supersedes, x.Issuer, x.ReporterRole = core.EventCorrection, core.OutcomeFailure, []string{r.EventID}, security, core.ReporterSecurityAuthority
				// Section 14.2 applies to a correction of EXECUTION events:
				// a FAILURE cites the failed record (Section 14.6 rule 10).
				x.EvidenceRefs = []string{failed}
			}), t0), queryAt(b.query(nil), t0)}
		}},
		{"correction by another reporter", nil, func(b *builder) []step {
			r := b.report(nil)
			return []step{ingestAt(r, t0), ingestAt(b.report(func(x *core.OutcomeReport) {
				x.EventKind, x.Result, x.Supersedes, x.Issuer, x.ReporterRole = core.EventCorrection, core.OutcomeFailure, []string{r.EventID}, evaluator, core.ReporterEvaluator
			}), t0), queryAt(b.query(nil), t0)}
		}},
		{"correction of another dimension", nil, func(b *builder) []step {
			r := b.report(nil)
			return []step{ingestAt(r, t0), ingestAt(b.report(func(x *core.OutcomeReport) {
				x.EventKind, x.Result, x.Supersedes, x.Dimension = core.EventCorrection, core.OutcomeFailure, []string{r.EventID}, core.DimensionPolicyAdherence
			}), t0), queryAt(b.query(nil), t0)}
		}},
		{"correction of a later event", nil, func(b *builder) []step {
			c := b.report(func(x *core.OutcomeReport) {
				x.EventKind, x.Result, x.Supersedes = core.EventCorrection, core.OutcomeFailure, []string{"event-0002"}
			})
			return []step{ingestAt(c, t0), ingestAt(b.report(nil), t0), queryAt(b.query(nil), t0)}
		}},
		{"refusals", nil, func(b *builder) []step {
			return []step{
				ingestAt(b.report(nil), t0+300),
				ingestAt(b.report(func(x *core.OutcomeReport) { x.Expiry = x.IssuedAt + 301 }), t0),
				ingestAt(b.report(func(x *core.OutcomeReport) { x.Audience = "https://reputation.example/hr" }), t0),
				ingestAt(b.report(func(x *core.OutcomeReport) { x.ObservedAt = t0 - 604801 }), t0),
				ingestAt(b.report(func(x *core.OutcomeReport) { x.Dimension = core.DimensionTaskQuality }), t0),
				ingestAt(b.report(func(x *core.OutcomeReport) { x.Issuer = "https://rogue.example" }), t0),
				queryAt(b.query(nil), t0),
				queryAt(b.query(func(q *core.ReputationQuery) { q.Context.TenantID = "globex" }), t0),
			}
		}},
	}
}

// TestLibraryAgreesWithOracle: on every scenario, the library and the
// reference oracle give the same answer to each ingestion, the same
// snapshot content to each query and the same classification of each
// report.
func TestLibraryAgreesWithOracle(t *testing.T) {
	keys, err := evalcase.LoadKeys(repoFixtures)
	if err != nil {
		t.Fatal(err)
	}
	run := func(t *testing.T, sc scenario, base func(*testing.T) (evalcase.OutcomesConfig, evalcase.OutcomesNative, core.OutcomeReport)) {
		t.Run(sc.name, func(t *testing.T) {
			cfg, native, tmpl := base(t)
			if sc.cfg != nil {
				sc.cfg(&cfg)
			}
			lib, ref := library(t, cfg, native), oracle.NewOracle(cfg, native)
			for i, st := range sc.steps(&builder{tmpl: tmpl}) {
				if st.report != nil {
					ack, prob := lib.Ingest(signFor(t, cfg, keys, *st.report), st.at)
					var a oracle.Answer
					if knownSigner(cfg, st.report.Issuer) {
						a = ref.Ingest(*st.report, st.at)
					} else {
						a = ref.Refuse(st.report.EventID, oracle.CodeInvalidProof)
					}
					got := oracle.Answer{}
					if prob != nil {
						got.Code = prob.Code
					} else {
						got.Ack = ack.Status
					}
					if got != a {
						t.Errorf("step %d (%s): library %+v, oracle %+v", i, st.report.EventID, got, a)
					}
					continue
				}
				s, prob := lib.Query(*st.query, st.at)
				want, code := ref.Query(*st.query, st.at)
				switch {
				case prob != nil || want == nil:
					if prob == nil || want != nil || prob.Code != code {
						t.Errorf("step %d query: library %+v, oracle %v %s", i, prob, want, code)
					}
				default:
					got := observable{s.Claims.Value.Dimensions, s.Claims.Value.SecurityStatus, s.Claims.Value.HoldRefs, s.Provenance.QualifiedEventIDs, s.Provenance.SupersededEventIDs}
					exp := observable{want.Value.Dimensions, want.Value.SecurityStatus, want.Value.HoldRefs, want.Manifest.QualifiedEventIDs, want.Manifest.SupersededEventIDs}
					if !reflect.DeepEqual(got, exp) {
						t.Errorf("step %d query:\nlibrary %+v\noracle  %+v", i, got, exp)
					}
				}
			}
			cls, err := lib.Classifications()
			if err != nil {
				t.Fatal(err)
			}
			for id, v := range ref.Verdicts() {
				l, ok := cls[id]
				switch {
				case v.Refused || v.Reason == oracle.ReasonDuplicate:
					if ok {
						t.Errorf("%s: library classifies %+v, oracle %+v", id, l, v)
					}
				case !ok || string(l.Qualification) != v.Qualification || oracleReason(l.Rule) != v.Reason:
					t.Errorf("%s: library %+v, oracle %+v", id, l, v)
				}
			}
		})
	}
	for _, sc := range scenarios() {
		run(t, sc, world)
	}
	for _, sc := range reciprocalScenarios() {
		run(t, sc, reciprocalWorld)
	}
	run(t, correctionReciprocity(), reciprocalWorld)
	for _, sc := range ruleScenarios() {
		run(t, sc, ruleWorld)
	}
	for _, sc := range kindScenarios() {
		run(t, sc, ruleWorld)
	}
}

// reciprocalWorld is the configuration of the committed reciprocal
// endorsement case, whose first report is the template.
func reciprocalWorld(t *testing.T) (evalcase.OutcomesConfig, evalcase.OutcomesNative, core.OutcomeReport) {
	t.Helper()
	c, err := evalcase.ReadOutcomes(repoFixtures, "outcomes/qualification/reciprocal-endorsements")
	if err != nil {
		t.Fatal(err)
	}
	c.Config.EvaluatorAgents = slices.Clone(c.Config.EvaluatorAgents)
	return c.Config, c.Native, c.Reports["quality-event-0001"]
}

// reciprocalScenarios are rule 7 of Section 14.6 and its limits: the two
// endorsements of the committed case, then each condition broken alone.
func reciprocalScenarios() []scenario {
	second := func(b *builder, edit func(*core.OutcomeReport)) *core.OutcomeReport {
		c, _ := evalcase.ReadOutcomes(repoFixtures, "outcomes/qualification/reciprocal-endorsements")
		r := c.Reports["quality-event-0002"]
		if edit != nil {
			edit(&r)
		}
		return &r
	}
	pair := func(edit func(*core.OutcomeReport)) func(b *builder) []step {
		return func(b *builder) []step {
			first := b.tmpl
			return []step{ingestAt(&first, t0), queryAt(b.query(nil), t0), ingestAt(second(b, edit), t0), queryAt(b.query(nil), t0)}
		}
	}
	return []scenario{
		{"reciprocal", nil, pair(nil)},
		{"reciprocal outside the window", nil, func(b *builder) []step {
			first := b.tmpl
			old := second(b, nil)
			old.ObservedAt = first.ObservedAt - 604801
			at := old.ObservedAt + 10
			old.IssuedAt, old.NotBefore, old.Expiry = at, at, at+300
			return []step{ingestAt(&first, t0), ingestAt(old, at), queryAt(b.query(nil), t0)}
		}},
		{"reciprocal negative", nil, pair(func(r *core.OutcomeReport) { r.Result = core.OutcomeFailure })},
		{"not the evaluator's own agent", func(c *evalcase.OutcomesConfig) {
			c.EvaluatorAgents[0].AgentID = "https://identity.example/agents/other"
		}, pair(nil)},
		{"an evaluator another operator runs", func(c *evalcase.OutcomesConfig) {
			c.EvaluatorAgents[1].OperatorID = "https://identity.example/operators/globex"
		}, pair(nil)},
		{"reciprocal feedback", nil, func(b *builder) []step {
			first := b.tmpl
			first.EventKind = core.EventFeedback
			return []step{ingestAt(&first, t0), ingestAt(second(b, func(r *core.OutcomeReport) { r.EventKind = core.EventFeedback }), t0), queryAt(b.query(nil), t0)}
		}},
		{"reciprocal quality and feedback", nil, pair(func(r *core.OutcomeReport) { r.EventKind = core.EventFeedback })},
	}
}

func knownSigner(cfg evalcase.OutcomesConfig, iss string) bool {
	return slices.ContainsFunc(cfg.Trust, func(t evalcase.TrustRecord) bool { return t.Iss == iss })
}
