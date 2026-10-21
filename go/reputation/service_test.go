package reputation_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"hop.top/pact-go/core"
	"hop.top/pact-go/core/digest"
	"hop.top/pact-go/core/jws"
	"hop.top/pact-go/reputation"
	"hop.top/pact-go/runner/evalcase"
)

const (
	t0               int64 = 1792080000
	executor               = "https://executor.example/finance"
	evaluator              = "https://evaluator.example/quality"
	gateway                = "https://gateway.example/finance"
	security               = "https://security.example/finance"
	soc                    = "https://security.example/soc"
	agent                  = "https://identity.example/agents/invoice-assistant"
	holder                 = "xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M"
	task                   = "native-task:september-summary-007"
	operation              = "invoice-read-operation-0001"
	readRef                = "native-execution-log:read-0001"
	reviewRef              = "native-review:read-0001"
	incidentRef            = "native-incident:0001"
	otherIncidentRef       = "native-incident:other-operation"
	fixRef                 = "native-remediation:0001"
)

// env is a Service over a MemoryStore with the test keys of the fixtures:
// executor, evaluator, gateway, two security authorities and the
// reputation service.
type env struct {
	t     *testing.T
	keys  map[string]evalcase.Key
	svc   *reputation.Service
	store *reputation.MemoryStore
	tmpl  core.OutcomeReport
	n     int
}

var signers = map[string]string{executor: "executor", evaluator: "evaluator", gateway: "issuer", security: "security-authority", soc: "adversarial",
	agent: "holder-2", owner: "learning-controller"}

func newEnv(t *testing.T, edit func(*reputation.Config)) *env {
	t.Helper()
	keys, err := evalcase.LoadKeys(repoFixtures)
	if err != nil {
		t.Fatal(err)
	}
	reg := reputation.StaticRegistry{}
	for _, r := range []struct {
		iss  string
		role core.ReporterRole
	}{{executor, core.ReporterExecutor}, {evaluator, core.ReporterEvaluator}, {gateway, core.ReporterGateway},
		{security, core.ReporterSecurityAuthority}, {soc, core.ReporterSecurityAuthority}, {agent, core.ReporterAgent}, {owner, core.ReporterTaskOwner}} {
		reg = append(reg, reputation.Reporter{Iss: r.iss, Role: r.role, Keys: []jws.JWK{keys[signers[r.iss]].Public}})
	}
	cfg := reputation.Config{
		ServiceID: "https://reputation.example/finance", TenantID: "acme", EnvironmentID: "https://gateway.example/environments/finance",
		ClockSkewSeconds: 5, ScoringArtifactDigest: "Is5hAn87tiTQEbsbEPbL7oeEZWa74Gxmr4Xrp0SQUQ0", ScoringPolicyRevision: "finance-scoring-1",
		DataPolicy: core.DataPolicy{QualificationPolicyID: reputation.QualificationPolicyID, IngestionWindowSeconds: 604800, PositiveWeightCapPerTask: 1,
			MaximumFailureWeight: 5, TaskAttributionSource: "native-task-registry", ReporterIndependencePolicyID: reputation.ReporterIndependencePolicyID},
		ExecutionVisible: true, HoldClearanceAuthorities: []string{security},
		ExecutorClasses: []reputation.ExecutorClass{{TaskID: task, OperationID: operation, Class: "delegated-user"}},
	}
	if edit != nil {
		edit(&cfg)
	}
	ex := &reputation.Executor{Class: "delegated-user", PrincipalID: "https://identity.example/principals/alice"}
	records := reputation.StaticRecords{
		readRef:          {Kind: reputation.RecordExecution, State: "completed", TaskID: task, OperationID: operation, Executor: ex},
		reviewRef:        {Kind: reputation.RecordAssessment, State: "completed", TaskID: task, OperationID: operation},
		incidentRef:      {Kind: reputation.RecordIncident, State: "confirmed", TaskID: task, OperationID: operation},
		otherIncidentRef: {Kind: reputation.RecordIncident, State: "confirmed", TaskID: task, OperationID: "invoice-read-operation-0002"},
		fixRef:           {Kind: reputation.RecordRemediation, State: "completed", TaskID: task, OperationID: operation},
		failedRef:        {Kind: reputation.RecordExecution, State: "failed", TaskID: task, OperationID: operation, Executor: ex},
		violationRef:     {Kind: reputation.RecordViolation, State: "recorded", TaskID: task, OperationID: operation},
	}
	tasks := reputation.StaticTasks{{TaskID: task, AgentID: agent, OperatorID: "https://identity.example/operators/acme",
		PrincipalID: "https://identity.example/principals/alice", IndependenceGroup: "native-task-group:september-summary-007", HolderJKT: holder}}
	store := &reputation.MemoryStore{}
	rs := keys["reputation-service"]
	svc, err := reputation.New(cfg, reputation.Deps{Registry: reg, Tasks: tasks, Records: records, Store: store,
		Signer: reputation.ES256Signer{Kid: rs.Public.Kid, Key: rs.Private}})
	if err != nil {
		t.Fatal(err)
	}
	var tmpl core.OutcomeReport
	b, err := os.ReadFile(filepath.Join(repoFixtures, "outcomes", "qualification", "correction-recompute", "reports", "execution-event-0001.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &tmpl); err != nil {
		t.Fatal(err)
	}
	tmpl.EvidenceRefs = []string{readRef}
	return &env{t: t, keys: keys, svc: svc, store: store, tmpl: tmpl}
}

// report derives a new report from the template: a fresh event_id, jti and
// operation-independent edits.
func (e *env) report(edit func(*core.OutcomeReport)) core.OutcomeReport {
	e.n++
	r := e.tmpl
	r.EventID = fmt.Sprintf("event-%04d", e.n)
	r.JTI = fmt.Sprintf("test-report-jti-%07d", e.n)
	r.EvidenceRefs = append([]string(nil), e.tmpl.EvidenceRefs...)
	r.Supersedes = []string{}
	if edit != nil {
		edit(&r)
	}
	return r
}

// sign signs r with the key of its iss.
func (e *env) sign(r core.OutcomeReport) string {
	e.t.Helper()
	k := e.keys[signers[r.Issuer]]
	if k.Private == nil {
		k = e.keys["adversarial"]
	}
	b, err := json.Marshal(r)
	if err != nil {
		e.t.Fatal(err)
	}
	out, err := jws.Sign(jws.Header{Typ: jws.TypOutcome, Kid: k.Public.Kid}, b, k.Private)
	if err != nil {
		e.t.Fatal(err)
	}
	return out
}

func (e *env) ingest(r core.OutcomeReport, at int64) (*core.Acknowledgment, *core.Problem) {
	return e.svc.Ingest(e.sign(r), at)
}

func (e *env) mustAck(r core.OutcomeReport, at int64, want core.AckStatus) {
	e.t.Helper()
	ack, prob := e.ingest(r, at)
	if prob != nil || ack.Status != want || ack.ArtifactID != r.EventID || ack.ReceivedAt != at || len(ack.RequestID) != 22 {
		e.t.Fatalf("%s: ack %+v problem %+v, want %s", r.EventID, ack, prob, want)
	}
}

func (e *env) query(at int64) *reputation.Snapshot {
	e.t.Helper()
	s, prob := e.svc.Query(core.ReputationQuery{AgentID: agent, HolderJKT: holder, Context: e.tmpl.Context, Audience: gateway}, at)
	if prob != nil {
		e.t.Fatalf("query: %+v", prob)
	}
	return s
}

func securityReport() func(*core.OutcomeReport) {
	return func(r *core.OutcomeReport) {
		r.Issuer, r.ReporterRole, r.EventKind, r.Result, r.Dimension, r.EvidenceRefs = security, core.ReporterSecurityAuthority,
			core.EventSecurity, core.OutcomeFailure, core.DimensionNone, []string{incidentRef}
	}
}

// TestAdmissionNeverRaisesPerformance: passed admissions, native
// authorization and admission reports that claim a dimension leave every
// dimension at the empty history (draft Sections 14.3, 14.5, 15.3).
func TestAdmissionNeverRaisesPerformance(t *testing.T) {
	e := newEnv(t, nil)
	for i := range 50 {
		r := e.report(func(r *core.OutcomeReport) {
			r.Issuer, r.ReporterRole, r.EventKind, r.Dimension, r.EvidenceRefs = gateway, core.ReporterGateway, core.EventAdmission, core.DimensionNone, []string{}
			r.OperationID = fmt.Sprintf("op-%d", i)
		})
		e.mustAck(r, t0, core.AckAccepted)
	}
	auth := e.report(func(r *core.OutcomeReport) {
		r.Issuer, r.ReporterRole, r.EventKind, r.Dimension = gateway, core.ReporterGateway, core.EventAuthorization, core.DimensionNone
	})
	e.mustAck(auth, t0, core.AckAccepted)
	for _, d := range reputation.Dimensions {
		claim := e.report(func(r *core.OutcomeReport) {
			r.Issuer, r.ReporterRole, r.EventKind, r.Dimension, r.EvidenceRefs = gateway, core.ReporterGateway, core.EventAdmission, d, []string{}
		})
		if _, prob := e.ingest(claim, t0); prob == nil || prob.Code != reputation.CodeInvalidMessage {
			t.Errorf("an admission on %s: %+v, want INVALID_MESSAGE", d, prob)
		}
	}
	s := e.query(t0)
	v := s.Claims.Value.Dimensions
	for _, st := range []core.DimensionStats{v.Reliability, v.TaskQuality, v.PolicyAdherence} {
		if st.ScoreBPS != 5000 || st.ConfidenceBPS != 0 || st.QualifiedEvents != 0 || st.IndependentTasks != 0 || st.NewestEventAt != nil {
			t.Errorf("dimension %+v, want the empty history", st)
		}
	}
	if len(s.Provenance.QualifiedEventIDs) != 0 {
		t.Errorf("listed %v, want nothing", s.Provenance.QualifiedEventIDs)
	}
	cls, err := e.svc.Classifications()
	if err != nil {
		t.Fatal(err)
	}
	if len(cls) != 51 || cls["event-0001"].Qualification != reputation.Qualified {
		t.Errorf("%d classifications, event-0001 %+v; want 51, QUALIFIED with zero weight", len(cls), cls["event-0001"])
	}
}

// TestHoldSurvivesDecay: a hold is independent of the score, outlives the
// decay of every statistic, and only a clearance authority's remediation
// clears it (draft Section 15.4).
func TestHoldSurvivesDecay(t *testing.T) {
	e := newEnv(t, nil)
	e.mustAck(e.report(nil), t0, core.AckAccepted)
	hold := e.report(securityReport())
	e.mustAck(hold, t0, core.AckAccepted)
	before := e.query(t0)
	if v := before.Claims.Value; v.SecurityStatus != core.SecurityHold || len(v.HoldRefs) != 1 || v.HoldRefs[0] != hold.EventID ||
		v.Dimensions.Reliability.ScoreBPS != 6666 {
		t.Fatalf("value %+v, want HOLD on %s beside the score", v, hold.EventID)
	}
	later := t0 + 1000*86400
	after := e.query(later)
	if v := after.Claims.Value; v.SecurityStatus != core.SecurityHold || len(v.HoldRefs) != 1 || v.Dimensions.Reliability.ScoreBPS != 5000 {
		t.Errorf("1000 days later %+v, want the score decayed and the hold in force", v)
	}
	other := core.ReputationQuery{AgentID: agent, HolderJKT: "ahxE1XEYqxvLIZy3r4nx9RE4E0683KndykyuZTK9xQg", Context: e.tmpl.Context, Audience: gateway}
	other.Context.ActionClass = "payment.approve"
	if s, _ := e.svc.Query(other, later); s == nil || s.Claims.Value.SecurityStatus != core.SecurityHold {
		t.Errorf("another context and holder key: %+v, want HOLD", s)
	}
	fix := func(iss string) core.OutcomeReport {
		return e.report(func(r *core.OutcomeReport) {
			r.Issuer, r.ReporterRole, r.EventKind, r.Result, r.Dimension = iss, core.ReporterSecurityAuthority, core.EventRemediation, core.OutcomeSuccess, core.DimensionNone
			r.EvidenceRefs = []string{hold.EventID, fixRef}
			r.ObservedAt, r.IssuedAt, r.NotBefore, r.Expiry = later-20, later, later, later+300
		})
	}
	e.mustAck(fix(soc), later, core.AckAccepted)
	if holds, _ := e.svc.Holds(agent); len(holds) != 1 {
		t.Errorf("after a remediation of another security authority: holds %v, want the hold", holds)
	}
	e.mustAck(fix(security), later, core.AckAccepted)
	if holds, _ := e.svc.Holds(agent); len(holds) != 0 {
		t.Errorf("after the clearance authority's remediation: holds %v, want none", holds)
	}
	if v := e.query(later).Claims.Value; v.SecurityStatus != core.SecurityClear || len(v.HoldRefs) != 0 {
		t.Errorf("value %+v, want CLEAR", v)
	}
}

// TestHoldPlacement: only a SECURITY FAILURE on none of a registered
// security authority, citing the confirmed incident record of its task and
// operation, places a hold (Sections 14.5, 14.6 rule 12, 15.4).
func TestHoldPlacement(t *testing.T) {
	for name, tc := range map[string]struct {
		edit func(*core.OutcomeReport)
		rule string
	}{
		"success": {func(r *core.OutcomeReport) { r.Result = core.OutcomeSuccess }, reputation.RuleNotEligible},
		"unknown": {func(r *core.OutcomeReport) { r.Result = core.OutcomeUnknown }, reputation.RuleNotEligible},
		"from an executor": {func(r *core.OutcomeReport) {
			r.Issuer, r.ReporterRole = executor, core.ReporterExecutor
		}, reputation.RuleNotEligible},
		"claiming an unregistered role":            {func(r *core.OutcomeReport) { r.ReporterRole = core.ReporterEvaluator }, reputation.RuleNotRegistered},
		"without a record":                         {func(r *core.OutcomeReport) { r.EvidenceRefs = []string{} }, reputation.RuleRecordMismatch},
		"citing an execution record":               {func(r *core.OutcomeReport) { r.EvidenceRefs = []string{readRef} }, reputation.RuleRecordMismatch},
		"citing the incident of another operation": {func(r *core.OutcomeReport) { r.EvidenceRefs = []string{otherIncidentRef} }, reputation.RuleRecordMismatch},
		"on a dimension":                           {func(r *core.OutcomeReport) { r.Dimension = core.DimensionPolicyAdherence }, reputation.RuleNotEligible},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, nil)
			sec := securityReport()
			r := e.report(func(r *core.OutcomeReport) { sec(r); tc.edit(r) })
			e.mustAck(r, t0, core.AckAccepted)
			if holds, _ := e.svc.Holds(agent); len(holds) != 0 {
				t.Errorf("holds %v, want none", holds)
			}
			if cls, _ := e.svc.Classifications(); cls[r.EventID].Qualification != reputation.Unqualified || cls[r.EventID].Rule != tc.rule {
				t.Errorf("verdict %+v, want UNQUALIFIED %s", cls[r.EventID], tc.rule)
			}
		})
	}
}

// TestIngestAnswers: the codes of draft Section 13.4 and the deduplication
// of Sections 7.5 and 14.6 rule 4.
func TestIngestAnswers(t *testing.T) {
	e := newEnv(t, nil)
	r := e.report(nil)
	compact := e.sign(r)
	if ack, prob := e.svc.Ingest(compact, t0); prob != nil || ack.Status != core.AckAccepted {
		t.Fatalf("%+v %+v", ack, prob)
	}
	if ack, prob := e.svc.Ingest(compact, t0+1); prob != nil || ack.Status != core.AckDuplicate {
		t.Errorf("identical retry: %+v %+v, want DUPLICATE", ack, prob)
	}
	changed := r
	changed.Details = "changed"
	if _, prob := e.ingest(changed, t0); prob == nil || prob.Code != reputation.CodeIDConflict || prob.Status != 409 {
		t.Errorf("another payload under the (iss, jti): %+v, want ID_CONFLICT", prob)
	}
	reused := e.report(func(x *core.OutcomeReport) { x.EventID = r.EventID; x.OperationID = "op-9" })
	if _, prob := e.ingest(reused, t0); prob == nil || prob.Code != reputation.CodeIDConflict {
		t.Errorf("a used event_id: %+v, want ID_CONFLICT", prob)
	}
	e.mustAck(e.report(nil), t0, core.AckDuplicate)
	s := e.query(t0)
	if d := s.Claims.Value.Dimensions.Reliability; d.QualifiedEvents != 1 || d.ScoreBPS != 6666 {
		t.Errorf("reliability %+v after a retry and a duplicate tuple, want one event", d)
	}
	stranger := e.report(func(x *core.OutcomeReport) { x.ReporterRole = core.ReporterTaskOwner; x.OperationID = "op-2" })
	e.mustAck(stranger, t0, core.AckAccepted)
	cls, _ := e.svc.Classifications()
	if v := cls[stranger.EventID]; v.Qualification != reputation.Unqualified || v.Rule != reputation.RuleNotRegistered {
		t.Errorf("unregistered reporter role: %+v", v)
	}
	if _, ok := cls["event-0003"]; ok {
		t.Errorf("a duplicate is classified: %+v", cls["event-0003"])
	}

	for _, tc := range []struct {
		name string
		edit func(*core.OutcomeReport)
		at   int64
		code string
	}{
		{"expired", nil, t0 + 300, reputation.CodeExpired},
		{"valid too long", func(x *core.OutcomeReport) { x.Expiry = x.IssuedAt + 301 }, t0, reputation.CodeInvalidMessage},
		{"issued later", func(x *core.OutcomeReport) { x.IssuedAt, x.NotBefore, x.Expiry = t0+6, t0+6, t0+100 }, t0, reputation.CodeInvalidMessage},
		{"another audience", func(x *core.OutcomeReport) { x.Audience = "https://reputation.example/hr" }, t0, reputation.CodeContextMismatch},
		{"another tenant", func(x *core.OutcomeReport) { x.TenantID = "globex" }, t0, reputation.CodeContextMismatch},
		{"observed later", func(x *core.OutcomeReport) { x.ObservedAt = t0 + 6 }, t0, reputation.CodeInvalidMessage},
		{"observed before the window", func(x *core.OutcomeReport) { x.ObservedAt = t0 - 604801 }, t0, reputation.CodeInvalidMessage},
		{"unknown with a dimension", func(x *core.OutcomeReport) { x.Result = core.OutcomeUnknown }, t0, reputation.CodeInvalidMessage},
		{"execution success on task_quality", func(x *core.OutcomeReport) { x.Dimension = core.DimensionTaskQuality }, t0, reputation.CodeInvalidMessage},
		{"correction without supersedes", func(x *core.OutcomeReport) { x.EventKind = core.EventCorrection }, t0, reputation.CodeInvalidMessage},
		{"short jti", func(x *core.OutcomeReport) { x.JTI = "short" }, t0, reputation.CodeInvalidMessage},
		{"another pact_version", func(x *core.OutcomeReport) { x.PactVersion = "0.2" }, t0, reputation.CodeInvalidMessage},
		{"repeated evidence ref", func(x *core.OutcomeReport) { x.EvidenceRefs = []string{readRef, readRef} }, t0, reputation.CodeInvalidMessage},
		{"unknown signer", func(x *core.OutcomeReport) { x.Issuer = "https://rogue.example" }, t0, reputation.CodeInvalidProof},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, nil)
			if ack, prob := e.ingest(e.report(tc.edit), tc.at); prob == nil || prob.Code != tc.code || ack != nil || prob.RequestID == "" || prob.Type == "" {
				t.Errorf("ack %+v problem %+v, want %s", ack, prob, tc.code)
			}
		})
	}
	// A signature that does not verify, another typ, an unknown member.
	b, _ := json.Marshal(e.report(nil))
	ev := e.keys["executor"]
	other, _ := jws.Sign(jws.Header{Typ: jws.TypOutcome, Kid: ev.Public.Kid}, b, e.keys["evaluator"].Private)
	typ, _ := jws.Sign(jws.Header{Typ: jws.TypEvidence, Kid: ev.Public.Kid}, b, ev.Private)
	extra, _ := jws.Sign(jws.Header{Typ: jws.TypOutcome, Kid: ev.Public.Kid}, append(b[:len(b)-1], `,"note":1}`...), ev.Private)
	for name, tc := range map[string]struct{ compact, code string }{
		"another key": {other, reputation.CodeInvalidProof}, "another typ": {typ, reputation.CodeInvalidMessage},
		"unknown member": {extra, reputation.CodeInvalidMessage}, "not a JWS": {"x.y", reputation.CodeInvalidMessage},
	} {
		if _, prob := e.svc.Ingest(tc.compact, t0); prob == nil || prob.Code != tc.code {
			t.Errorf("%s: %+v, want %s", name, prob, tc.code)
		}
	}
}

// TestSnapshotForm: the snapshot is signed by the service for the query and
// carries its provenance digest (draft Sections 15.2, A.2).
func TestSnapshotForm(t *testing.T) {
	e := newEnv(t, nil)
	r := e.report(nil)
	e.mustAck(r, t0, core.AckAccepted)
	s := e.query(t0 + 10)
	ks, err := jws.NewKeySet(e.keys["reputation-service"].Public)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := jws.Verifier{Keys: jws.StaticResolver{KeySets: map[jws.Role]*jws.KeySet{jws.RoleReputationService: ks}}, Typ: jws.TypReputation}.Verify(s.Compact)
	if err != nil {
		t.Fatal(err)
	}
	var claims core.ReputationSnapshot
	if err := json.Unmarshal(parsed.Payload, &claims); err != nil {
		t.Fatal(err)
	}
	c := s.Claims
	if claims.JTI != c.JTI || len(c.JTI) != 22 || c.Issuer != "https://reputation.example/finance" || c.Subject != agent || c.Audience != gateway ||
		c.HolderJKT != holder || c.IssuedAt != t0+10 || c.Expiry != t0+310 || c.Value.EvidenceCutoff != t0+10 {
		t.Errorf("claims %+v", c)
	}
	d, err := digest.ObjectDigest(s.Provenance)
	if err != nil || d != c.Value.ProvenanceDigest {
		t.Errorf("provenance_digest %s, manifest digest %s", c.Value.ProvenanceDigest, d)
	}
	if m := s.Provenance; len(m.QualifiedEventIDs) != 1 || m.QualifiedEventIDs[0] != [2]string{r.Issuer, r.JTI} || m.QualificationPolicyID != reputation.QualificationPolicyID ||
		m.ScoringPolicyRevision != "finance-scoring-1" || m.EvidenceCutoff != t0+10 || m.SupersededEventIDs == nil {
		t.Errorf("manifest %+v", m)
	}
	if n := c.Value.Dimensions.Reliability.NewestEventAt; n == nil || *n != r.ObservedAt {
		t.Errorf("newest_event_at %v, want %d", n, r.ObservedAt)
	}
	q := core.ReputationQuery{AgentID: agent, HolderJKT: holder, Context: e.tmpl.Context, Audience: gateway}
	for name, edit := range map[string]func(*core.ReputationQuery){
		"another tenant":           func(q *core.ReputationQuery) { q.Context.TenantID = "globex" },
		"another agent in context": func(q *core.ReputationQuery) { q.Context.AgentID = "https://identity.example/agents/other" },
		"no audience":              func(q *core.ReputationQuery) { q.Audience = "" },
	} {
		qq := q
		edit(&qq)
		if s, prob := e.svc.Query(qq, t0); s != nil || prob == nil {
			t.Errorf("%s: %+v, want a Problem", name, s)
		}
	}
	// Another holder key gets the cold start (Sections 6.4, 15.4).
	qq := q
	qq.HolderJKT = "ahxE1XEYqxvLIZy3r4nx9RE4E0683KndykyuZTK9xQg"
	if s, _ := e.svc.Query(qq, t0); s == nil || s.Claims.Value.Dimensions.Reliability.ScoreBPS != 5000 {
		t.Errorf("another holder key: %+v", s)
	}
}

// TestCorrectionSupersedes: a qualified correction replaces the events it
// names and is listed in their place (Section 14.6 rule 10).
func TestCorrectionSupersedes(t *testing.T) {
	e := newEnv(t, nil)
	first := e.report(nil)
	e.mustAck(first, t0, core.AckAccepted)
	corr := e.report(func(r *core.OutcomeReport) {
		r.EventKind, r.Result, r.Supersedes = core.EventCorrection, core.OutcomeFailure, []string{first.EventID}
		r.EvidenceRefs = []string{failedRef} // a FAILURE cites the failed record (Section 14.2)
	})
	e.mustAck(corr, t0, core.AckAccepted)
	s := e.query(t0)
	if m := s.Provenance; len(m.SupersededEventIDs) != 1 || m.SupersededEventIDs[0][1] != first.JTI || len(m.QualifiedEventIDs) != 1 || m.QualifiedEventIDs[0][1] != corr.JTI {
		t.Errorf("manifest %+v", m)
	}
	if d := s.Claims.Value.Dimensions.Reliability; d.ScoreBPS != 3333 || d.QualifiedEvents != 1 {
		t.Errorf("reliability %+v, want one failure", d)
	}
	mismatch := e.report(func(r *core.OutcomeReport) {
		r.EventKind, r.Result, r.Supersedes, r.OperationID = core.EventCorrection, core.OutcomeFailure, []string{first.EventID}, "op-7"
	})
	e.mustAck(mismatch, t0, core.AckAccepted)
	if cls, _ := e.svc.Classifications(); cls[mismatch.EventID].Rule != reputation.RuleCorrectionMismatch {
		t.Errorf("correction of another operation: %+v", cls[mismatch.EventID])
	}
}

// failingStore is a MemoryStore whose reads fail while fail is set.
type failingStore struct {
	reputation.MemoryStore
	fail bool
}

func (f *failingStore) All() ([]reputation.Stored, error) {
	if f.fail {
		return nil, errors.New("store down")
	}
	return f.MemoryStore.All()
}

func (f *failingStore) ByKey(iss, jti string) (reputation.Stored, bool, error) {
	if f.fail {
		return reputation.Stored{}, false, errors.New("store down")
	}
	return f.MemoryStore.ByKey(iss, jti)
}

type failingSigner struct{}

func (failingSigner) SignSnapshot([]byte) (string, error) { return "", errors.New("hsm down") }

// TestDependencies: New refuses an incomplete or unsupported configuration,
// and an unavailable store or signer is DEPENDENCY_UNAVAILABLE.
func TestDependencies(t *testing.T) {
	e := newEnv(t, nil)
	base := reputation.Deps{Registry: reputation.StaticRegistry{}, Tasks: reputation.StaticTasks{}, Records: reputation.StaticRecords{},
		Store: &reputation.MemoryStore{}, Signer: failingSigner{}}
	good := reputation.Config{ServiceID: "s", TenantID: "t", EnvironmentID: "e", ScoringArtifactDigest: "d", ScoringPolicyRevision: "r",
		DataPolicy: core.DataPolicy{QualificationPolicyID: reputation.QualificationPolicyID, ReporterIndependencePolicyID: reputation.ReporterIndependencePolicyID,
			IngestionWindowSeconds: 1, PositiveWeightCapPerTask: 1, MaximumFailureWeight: 5, TaskAttributionSource: "x"}}
	if _, err := reputation.New(good, base); err != nil {
		t.Fatalf("control: %v", err)
	}
	for name, edit := range map[string]func(*reputation.Config, *reputation.Deps){
		"no service":            func(c *reputation.Config, _ *reputation.Deps) { c.ServiceID = "" },
		"another policy":        func(c *reputation.Config, _ *reputation.Deps) { c.DataPolicy.QualificationPolicyID = "other" },
		"another independence":  func(c *reputation.Config, _ *reputation.Deps) { c.DataPolicy.ReporterIndependencePolicyID = "other" },
		"no ingestion window":   func(c *reputation.Config, _ *reputation.Deps) { c.DataPolicy.IngestionWindowSeconds = 0 },
		"no scoring pins":       func(c *reputation.Config, _ *reputation.Deps) { c.ScoringPolicyRevision = "" },
		"snapshot too long":     func(c *reputation.Config, _ *reputation.Deps) { c.SnapshotLifetime = 301 },
		"negative skew":         func(c *reputation.Config, _ *reputation.Deps) { c.ClockSkewSeconds = -1 },
		"no store":              func(_ *reputation.Config, d *reputation.Deps) { d.Store = nil },
		"positive cap of 2":     func(c *reputation.Config, _ *reputation.Deps) { c.DataPolicy.PositiveWeightCapPerTask = 2 },
		"no attribution source": func(c *reputation.Config, _ *reputation.Deps) { c.DataPolicy.TaskAttributionSource = "" },
		"failure weight 6":      func(c *reputation.Config, _ *reputation.Deps) { c.DataPolicy.MaximumFailureWeight = 6 },
		"failure weight 0":      func(c *reputation.Config, _ *reputation.Deps) { c.DataPolicy.MaximumFailureWeight = 0 },
		"no signer":             func(_ *reputation.Config, d *reputation.Deps) { d.Signer = nil },
	} {
		c, d := good, base
		edit(&c, &d)
		if _, err := reputation.New(c, d); err == nil {
			t.Errorf("%s: New succeeded", name)
		}
	}
	// The signer fails.
	svc, err := reputation.New(good, base)
	if err != nil {
		t.Fatal(err)
	}
	if _, prob := svc.Query(core.ReputationQuery{AgentID: "a", HolderJKT: holder, Audience: "u", Context: core.ReputationContext{TenantID: "t", EnvironmentID: "e", AgentID: "a"}}, t0); prob == nil || prob.Code != reputation.CodeDependencyUnavailable || prob.Status != 503 {
		t.Errorf("failing signer: %+v, want DEPENDENCY_UNAVAILABLE", prob)
	}
	// The store fails.
	fs := &failingStore{fail: true}
	rs := e.keys["reputation-service"]
	cfgs := reputation.Config{ServiceID: "https://reputation.example/finance", TenantID: "acme", EnvironmentID: "https://gateway.example/environments/finance",
		ClockSkewSeconds: 5, ScoringArtifactDigest: "d", ScoringPolicyRevision: "r", DataPolicy: good.DataPolicy}
	cfgs.DataPolicy.IngestionWindowSeconds = 604800
	reg := reputation.StaticRegistry{{Iss: executor, Role: core.ReporterExecutor, Keys: []jws.JWK{e.keys["executor"].Public}}}
	svc, err = reputation.New(cfgs, reputation.Deps{Registry: reg, Tasks: reputation.StaticTasks{}, Records: reputation.StaticRecords{}, Store: fs,
		Signer: reputation.ES256Signer{Kid: rs.Public.Kid, Key: rs.Private}})
	if err != nil {
		t.Fatal(err)
	}
	if _, prob := svc.Ingest(e.sign(e.report(nil)), t0); prob == nil || prob.Code != reputation.CodeDependencyUnavailable {
		t.Errorf("failing store on ingest: %+v", prob)
	}
	if _, prob := svc.Query(core.ReputationQuery{AgentID: agent, HolderJKT: holder, Audience: gateway, Context: e.tmpl.Context}, t0); prob == nil || prob.Code != reputation.CodeDependencyUnavailable {
		t.Errorf("failing store on query: %+v", prob)
	}
	if _, err := svc.Classifications(); err == nil {
		t.Error("failing store: Classifications succeeded")
	}
}

// slowStore widens the window between a lookup and an append.
type slowStore struct{ reputation.MemoryStore }

func (s *slowStore) ByKey(iss, jti string) (reputation.Stored, bool, error) {
	st, ok, err := s.MemoryStore.ByKey(iss, jti)
	time.Sleep(5 * time.Millisecond)
	return st, ok, err
}

// TestConcurrentIngest: concurrent submissions of one report are accepted
// once; the others are duplicates, never a conflict of the store.
func TestConcurrentIngest(t *testing.T) {
	e := newEnv(t, nil)
	rs := e.keys["reputation-service"]
	reg := reputation.StaticRegistry{{Iss: executor, Role: core.ReporterExecutor, Keys: []jws.JWK{e.keys["executor"].Public}}}
	cfg := reputation.Config{ServiceID: "https://reputation.example/finance", TenantID: "acme", EnvironmentID: "https://gateway.example/environments/finance",
		ClockSkewSeconds: 5, ScoringArtifactDigest: "d", ScoringPolicyRevision: "r",
		DataPolicy: core.DataPolicy{QualificationPolicyID: reputation.QualificationPolicyID, ReporterIndependencePolicyID: reputation.ReporterIndependencePolicyID,
			IngestionWindowSeconds: 604800, PositiveWeightCapPerTask: 1, MaximumFailureWeight: 5, TaskAttributionSource: "x"}}
	svc, err := reputation.New(cfg, reputation.Deps{Registry: reg, Tasks: reputation.StaticTasks{}, Records: reputation.StaticRecords{}, Store: &slowStore{},
		Signer: reputation.ES256Signer{Kid: rs.Public.Kid, Key: rs.Private}})
	if err != nil {
		t.Fatal(err)
	}
	e.svc = svc
	compact := e.sign(e.report(nil))
	var wg sync.WaitGroup
	statuses := make([]core.AckStatus, 16)
	for i := range statuses {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ack, prob := e.svc.Ingest(compact, t0); prob == nil {
				statuses[i] = ack.Status
			}
		}()
	}
	wg.Wait()
	accepted := 0
	for _, s := range statuses {
		switch s {
		case core.AckAccepted:
			accepted++
		case core.AckDuplicate:
		default:
			t.Errorf("status %q", s)
		}
	}
	if accepted != 1 {
		t.Errorf("%d accepted, want 1: %v", accepted, statuses)
	}
}

// TestMemoryStoreConflicts: Append is atomic and refuses a stored key,
// event_id or taken tuple.
func TestMemoryStoreConflicts(t *testing.T) {
	var m reputation.MemoryStore
	r := core.OutcomeReport{Issuer: "i", JTI: "j", EventID: "e", TaskID: "t"}
	if err := m.Append(reputation.Stored{Report: r}, true); err != nil {
		t.Fatal(err)
	}
	for name, x := range map[string]core.OutcomeReport{
		"same key":   {Issuer: "i", JTI: "j", EventID: "e2", TaskID: "u"},
		"same event": {Issuer: "i", JTI: "k", EventID: "e", TaskID: "u"},
		"same tuple": {Issuer: "i", JTI: "k", EventID: "e3", TaskID: "t"},
	} {
		if err := m.Append(reputation.Stored{Report: x}, true); !errors.Is(err, reputation.ErrConflict) {
			t.Errorf("%s: %v, want ErrConflict", name, err)
		}
	}
	if err := m.Append(reputation.Stored{Report: core.OutcomeReport{Issuer: "i", JTI: "k", EventID: "e3", TaskID: "t"}}, false); err != nil {
		t.Errorf("same tuple, not taken: %v", err)
	}
	all, _ := m.All()
	if len(all) != 2 {
		t.Errorf("%d stored, want 2", len(all))
	}
	if taken, _ := m.TupleTaken(reputation.TupleOf(r)); !taken {
		t.Error("tuple not taken")
	}
	if _, ok, _ := m.ByKey("i", "k"); !ok {
		t.Error("(i, k) not stored")
	}
}

// TestValidateReport: the OutcomeReport schema rules of Appendix A.3 that
// strict decoding leaves to the receiver.
func TestValidateReport(t *testing.T) {
	e := newEnv(t, nil)
	if err := reputation.ValidateReport(e.tmpl); err != nil {
		t.Fatalf("control: %v", err)
	}
	for name, edit := range map[string]func(*core.OutcomeReport){
		"empty iss":            func(r *core.OutcomeReport) { r.Issuer = "" },
		"long task_id":         func(r *core.OutcomeReport) { r.TaskID = strings.Repeat("t", 1025) },
		"empty context member": func(r *core.OutcomeReport) { r.Context.RuntimeClass = "" },
		"empty group":          func(r *core.OutcomeReport) { r.Attribution.IndependenceGroup = "" },
		"causal assessment":    func(r *core.OutcomeReport) { r.Attribution.CausalAssessment = "SOMEONE" },
		"severity":             func(r *core.OutcomeReport) { r.Severity = "dire" },
		"long details":         func(r *core.OutcomeReport) { r.Details = strings.Repeat("d", 4097) },
		"iat at exp":           func(r *core.OutcomeReport) { r.IssuedAt = r.Expiry },
		"nbf at exp":           func(r *core.OutcomeReport) { r.NotBefore = r.Expiry },
		"negative observed_at": func(r *core.OutcomeReport) { r.ObservedAt = -1 },
		"null evidence_refs":   func(r *core.OutcomeReport) { r.EvidenceRefs = nil },
		// Appendix A.2: the dimensions Section 14.5 gives each event_kind.
		"execution success on task_quality":     func(r *core.OutcomeReport) { r.Dimension = core.DimensionTaskQuality },
		"execution failure on task_quality":     func(r *core.OutcomeReport) { r.Result, r.Dimension = core.OutcomeFailure, core.DimensionTaskQuality },
		"execution success on policy_adherence": func(r *core.OutcomeReport) { r.Dimension = core.DimensionPolicyAdherence },
		"execution failure on policy_adherence": func(r *core.OutcomeReport) {
			r.Result, r.Dimension = core.OutcomeFailure, core.DimensionPolicyAdherence
		},
		"quality on reliability":  func(r *core.OutcomeReport) { r.EventKind = core.EventQuality },
		"feedback on reliability": func(r *core.OutcomeReport) { r.EventKind, r.Result = core.EventFeedback, core.OutcomeFailure },
		"feedback on none":        func(r *core.OutcomeReport) { r.EventKind, r.Dimension = core.EventFeedback, core.DimensionNone },
		"security on reliability": func(r *core.OutcomeReport) { r.EventKind, r.Result = core.EventSecurity, core.OutcomeFailure },
		"security on task_quality": func(r *core.OutcomeReport) {
			r.EventKind, r.Result, r.Dimension = core.EventSecurity, core.OutcomeFailure, core.DimensionTaskQuality
		},
		"remediation on reliability": func(r *core.OutcomeReport) { r.EventKind = core.EventRemediation },
		"65 evidence refs": func(r *core.OutcomeReport) {
			r.EvidenceRefs = nil
			for i := range 65 {
				r.EvidenceRefs = append(r.EvidenceRefs, fmt.Sprint(i))
			}
		},
	} {
		r := e.tmpl
		r.EvidenceRefs = slices.Clone(e.tmpl.EvidenceRefs)
		edit(&r)
		if err := reputation.ValidateReport(r); err == nil {
			t.Errorf("%s: valid", name)
		}
	}
	// The pairs Section 14.5 gives are valid.
	for name, edit := range map[string]func(*core.OutcomeReport){
		"execution unknown on none": func(r *core.OutcomeReport) { r.Result, r.Dimension = core.OutcomeUnknown, core.DimensionNone },
		"quality on policy_adherence": func(r *core.OutcomeReport) {
			r.EventKind, r.Dimension = core.EventQuality, core.DimensionPolicyAdherence
		},
		"feedback on task_quality": func(r *core.OutcomeReport) { r.EventKind, r.Dimension = core.EventFeedback, core.DimensionTaskQuality },
		"security on none": func(r *core.OutcomeReport) {
			r.EventKind, r.Result, r.Dimension = core.EventSecurity, core.OutcomeFailure, core.DimensionNone
		},
		"security on policy_adherence": func(r *core.OutcomeReport) {
			r.EventKind, r.Result, r.Dimension = core.EventSecurity, core.OutcomeFailure, core.DimensionPolicyAdherence
		},
		"remediation on none": func(r *core.OutcomeReport) { r.EventKind, r.Dimension = core.EventRemediation, core.DimensionNone },
	} {
		r := e.tmpl
		edit(&r)
		if err := reputation.ValidateReport(r); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, edit := range map[string]func(*core.ReputationQuery){
		"no agent":      func(q *core.ReputationQuery) { q.AgentID, q.Context.AgentID = "", "" },
		"no holder_jkt": func(q *core.ReputationQuery) { q.HolderJKT = "" },
	} {
		q := core.ReputationQuery{AgentID: agent, HolderJKT: holder, Context: e.tmpl.Context, Audience: gateway}
		edit(&q)
		if s, prob := e.svc.Query(q, t0); s != nil || prob == nil || prob.Code != reputation.CodeInvalidMessage {
			t.Errorf("%s: %+v %+v, want INVALID_MESSAGE", name, s, prob)
		}
	}
}
