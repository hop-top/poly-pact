package reputation

import (
	"slices"

	"hop.top/pact-go/core"
)

// Verdict is the classification of a stored report: its qualification and
// the rule that decided it. A report that repeats the tuple of an earlier
// one is not classified: it casts no vote, and Duplicate is set.
type Verdict struct {
	Qualification Qualification
	Rule          string
	Duplicate     bool
}

// The rules a Verdict names.
const (
	RuleMapped              = "mapped"
	RuleNotRegistered       = "reporter-not-registered"
	RuleNotEligible         = "reporter-not-eligible"
	RuleTaskUnreconciled    = "task-unreconciled"
	RuleNoExecutorRecord    = "no-executor-record"
	RuleNoCompletionRecord  = "no-completion-record"
	RuleRecordMismatch      = "record-mismatch"
	RuleExecutorClass       = "executor-class-mismatch"
	RuleNoAssessment        = "no-assessment-record"
	RuleSelfPraise          = "self-praise"
	RuleAffiliatedEvaluator = "affiliated-evaluator"
	RuleReciprocal          = "reciprocal-endorsement"
	RuleCausalZeroWeight    = "causal-zero-weight"
	RuleCorrection          = "correction"
	RuleCorrectionMismatch  = "correction-mismatch"
)

// view is the service state a classification reads: the stored reports in
// arrival order and the configured records.
type view struct {
	cfg     Config
	tasks   Tasks
	records Records
	reg     Registry
	reports []Stored
	byEvent map[string]int
	// kinds is the event_kind each report is classified under: its own,
	// or for a correction that of the events it supersedes (Section 14.6
	// rule 10). classify fills it.
	kinds []core.EventKind
}

func newView(s *Service, reports []Stored) *view {
	v := &view{cfg: s.cfg, tasks: s.d.Tasks, records: s.d.Records, reg: s.d.Registry, reports: reports, byEvent: map[string]int{}}
	for i, r := range reports {
		v.byEvent[r.Report.EventID] = i
	}
	return v
}

// classify returns the verdict of every stored report, by position, and
// the positions of the reports a qualified correction supersedes. Reports
// are classified in arrival order, so the events a correction names, which
// were received before it, are classified first. The classification is
// recomputed from every report, so a later report can change an earlier
// one's, as rules 5 and 7 of Section 14.6 require. Rule 7 comes last: a
// correction it disputes still supersedes, since its signer could have
// retracted the events instead.
func (v *view) classify() ([]Verdict, map[int]bool) {
	out := make([]Verdict, len(v.reports))
	v.kinds = make([]core.EventKind, len(v.reports))
	for i, s := range v.reports {
		if s.Duplicate {
			out[i] = Verdict{Rule: "duplicate", Duplicate: true}
			continue
		}
		out[i] = v.single(i, out)
	}
	superseded := map[int]bool{}
	for i, s := range v.reports {
		if s.Report.EventKind == core.EventCorrection && out[i].Qualification == Qualified {
			for _, id := range s.Report.Supersedes {
				superseded[v.byEvent[id]] = true
			}
		}
	}
	v.disputeReciprocal(out)
	return out, superseded
}

func reject(rule string) Verdict { return Verdict{Qualification: Unqualified, Rule: rule} }

// single classifies the report at i, except for rule 7, given the verdicts
// of the reports before it.
func (v *view) single(i int, before []Verdict) Verdict {
	s := v.reports[i]
	r := s.Report
	if !s.Registered {
		// Appendix A.2: acknowledged, UNQUALIFIED; it places, clears and
		// corrects nothing.
		return reject(RuleNotRegistered)
	}
	task, ok := v.tasks.Task(r.TaskID)
	if !ok || task.AgentID != r.Subject || r.Context.AgentID != r.Subject || r.Context.TenantID != v.cfg.TenantID ||
		r.Context.EnvironmentID != v.cfg.EnvironmentID {
		// Rule 2: the task does not reconcile with the authoritative
		// record, or names another agent than the report's subject.
		return reject(RuleTaskUnreconciled)
	}
	kind := r.EventKind
	if kind == core.EventCorrection {
		k, ok := v.corrected(i, before)
		if !ok {
			return reject(RuleCorrectionMismatch)
		}
		// Rule 10: classified as a report of the corrected kind from its
		// signer, so it adds nothing its signer could not report.
		kind = k
	}
	v.kinds[i] = kind
	if rule := v.evidence(r, kind); rule != "" {
		return reject(rule)
	}
	if !v.eligible(r, kind) {
		return reject(RuleNotEligible)
	}
	if kind == core.EventSecurity && !v.citesSecurityRecord(r) {
		// Sections 14.2, 14.5 and 15.4: a detected policy violation cites
		// the gateway's record of the violating request, a confirmed
		// incident the incident record, each of its task and operation.
		return reject(RuleRecordMismatch)
	}
	if kind == core.EventQuality || kind == core.EventFeedback {
		if v.reportedExecution(r.Issuer, r.TaskID) {
			return reject(RuleSelfPraise)
		}
		if r.Result == core.OutcomeSuccess && slices.Contains(v.cfg.Affiliations, Affiliation{EvaluatorIss: r.Issuer, OperatorID: task.OperatorID}) {
			return reject(RuleAffiliatedEvaluator)
		}
	}
	switch {
	case r.EventKind == core.EventCorrection:
		return Verdict{Qualification: Qualified, Rule: RuleCorrection}
	case r.Result == core.OutcomeFailure && weighed(kind, r.ReporterRole) && r.Dimension != core.DimensionNone && r.Attribution.CausalAssessment != core.CausalAgent:
		return Verdict{Qualification: Qualified, Rule: RuleCausalZeroWeight}
	}
	return Verdict{Qualification: Qualified, Rule: RuleMapped}
}

// weighed reports whether reports classified under kind k, from a signer
// of the role, can carry dimension weight. An admission or authorization
// decision weighs nothing (Section 14.5); a SECURITY report weighs only as
// a gateway's detected policy violation (Section 14.6 rule 12); a hold and
// its remediation are independent of the statistics (Section 15.4).
func weighed(k core.EventKind, role core.ReporterRole) bool {
	switch k {
	case core.EventExecution, core.EventQuality, core.EventFeedback:
		return true
	case core.EventSecurity:
		return role == core.ReporterGateway
	}
	return false
}

// declaresNoVisibility reports whether r is the report of absent execution
// visibility of Section 14.5.
func (v *view) declaresNoVisibility(r core.OutcomeReport) bool {
	return !v.cfg.ExecutionVisible && r.EventKind == core.EventExecution && r.Result == core.OutcomeUnknown &&
		r.Dimension == core.DimensionNone && len(r.EvidenceRefs) == 0
}

// evidence checks what a report classified under kind cites (Sections
// 14.2, 14.5, 17.5): an EXECUTION or AUTHORIZATION report an immutable
// record of its task and operation that names the executor, in the state
// its result states (any state for an UNKNOWN correction), with the
// executor class the installed mapping declares; a QUALITY report, and the
// verified feedback of an evaluator or the task owner, a completed
// assessment of its task. The agent's own feedback, never positive, cites
// none.
func (v *view) evidence(r core.OutcomeReport, kind core.EventKind) string {
	switch kind {
	case core.EventExecution, core.EventAuthorization:
	case core.EventQuality, core.EventFeedback:
		if (kind == core.EventQuality || r.ReporterRole != core.ReporterAgent) && !v.cites(r, RecordAssessment, "completed") {
			return RuleNoAssessment
		}
		return ""
	default:
		return ""
	}
	if v.declaresNoVisibility(r) {
		return ""
	}
	record, want := RecordExecution, map[core.OutcomeResult]string{core.OutcomeSuccess: "completed", core.OutcomeFailure: "failed"}
	missing := RuleNoCompletionRecord
	if kind == core.EventAuthorization {
		record, want = RecordAuthorization, map[core.OutcomeResult]string{core.OutcomeSuccess: "allowed", core.OutcomeFailure: "denied"}
		missing = RuleRecordMismatch
	}
	var found []Record
	for _, ref := range r.EvidenceRefs {
		if rec, ok := v.records.Record(ref); ok && rec.Kind == record && rec.Executor != nil && rec.TaskID == r.TaskID && rec.OperationID == r.OperationID {
			found = append(found, rec)
		}
	}
	if len(found) == 0 {
		return RuleNoExecutorRecord
	}
	if state, ok := want[r.Result]; ok {
		found = slices.DeleteFunc(found, func(rec Record) bool { return rec.State != state })
		if len(found) == 0 {
			return missing
		}
	}
	ex := found[0].Executor
	for _, c := range v.cfg.ExecutorClasses {
		if c.TaskID == r.TaskID && c.OperationID == r.OperationID {
			if c.Class == ex.Class && (c.ExecutorID == nil || *c.ExecutorID == ex.PrincipalID) {
				return ""
			}
			return RuleExecutorClass
		}
	}
	return RuleExecutorClass
}

func (v *view) cites(r core.OutcomeReport, kind RecordKind, state string) bool {
	for _, ref := range r.EvidenceRefs {
		if rec, ok := v.records.Record(ref); ok && rec.Kind == kind && rec.State == state && rec.TaskID == r.TaskID {
			return true
		}
	}
	return false
}

// citesSecurityRecord reports whether r, classified under SECURITY, cites
// the record of its task and operation that its dimension requires: a
// violation record on policy_adherence, a confirmed incident record on
// none.
func (v *view) citesSecurityRecord(r core.OutcomeReport) bool {
	kind, state := RecordViolation, "recorded"
	switch r.Dimension {
	case core.DimensionPolicyAdherence:
	case core.DimensionNone:
		kind, state = RecordIncident, "confirmed"
	default:
		return false
	}
	for _, ref := range r.EvidenceRefs {
		if rec, ok := v.records.Record(ref); ok && rec.Kind == kind && rec.State == state && rec.TaskID == r.TaskID && rec.OperationID == r.OperationID {
			return true
		}
	}
	return false
}

// eligible applies who may report what to a report classified under kind
// (Section 14.2 and the rows of Section 14.5 that name a reporter). A
// security authority may correct any reporter's events (rule 10). A
// gateway reports a SECURITY event only as a detected policy violation,
// FAILURE on policy_adherence, which a correction of its own may also
// retract with UNKNOWN (rule 12); a security authority reports a SECURITY
// event only as a confirmed incident, FAILURE on none (Section 14.5). An
// evaluator or the task owner assesses task quality or policy adherence.
func (v *view) eligible(r core.OutcomeReport, kind core.EventKind) bool {
	role := r.ReporterRole
	if r.EventKind == core.EventCorrection && role == core.ReporterSecurityAuthority {
		return true
	}
	switch kind {
	case core.EventAdmission, core.EventAuthorization:
		return role == core.ReporterGateway
	case core.EventExecution:
		return role == core.ReporterExecutor || role == core.ReporterGateway && v.declaresNoVisibility(r)
	case core.EventQuality:
		return role == core.ReporterEvaluator || role == core.ReporterTaskOwner
	case core.EventFeedback:
		return role == core.ReporterEvaluator || role == core.ReporterTaskOwner || role == core.ReporterAgent
	case core.EventSecurity:
		if role != core.ReporterGateway {
			return role == core.ReporterSecurityAuthority && r.Result == core.OutcomeFailure && r.Dimension == core.DimensionNone
		}
		retracts := r.EventKind == core.EventCorrection && r.Result == core.OutcomeUnknown
		return r.Dimension == core.DimensionPolicyAdherence && (r.Result == core.OutcomeFailure || retracts)
	case core.EventRemediation:
		return role == core.ReporterSecurityAuthority
	default:
		return false
	}
}

// reportedExecution reports whether iss, registered as executor, reported
// the execution of the task: it is the task's executor and may not
// evaluate it (Section 14.6 rule 5).
func (v *view) reportedExecution(iss, task string) bool {
	for _, s := range v.reports {
		r := s.Report
		if s.Registered && r.Issuer == iss && r.ReporterRole == core.ReporterExecutor && r.EventKind == core.EventExecution && r.TaskID == task {
			return true
		}
	}
	return false
}

// disputeReciprocal applies rule 7: a positive report classified under
// QUALITY or FEEDBACK (a correction of such events included) of evaluator E on an
// agent, beside such a report on E's own agent by an evaluator the first
// agent's operator runs, both observed within the ingestion window of each
// other, makes both DISPUTED.
func (v *view) disputeReciprocal(out []Verdict) {
	positive := func(i int) bool {
		r := v.reports[i].Report
		k := v.kinds[i]
		return out[i].Qualification == Qualified && (k == core.EventQuality || k == core.EventFeedback) && r.Result == core.OutcomeSuccess
	}
	window := v.cfg.DataPolicy.IngestionWindowSeconds
	for i := range v.reports {
		if !positive(i) {
			continue
		}
		ri := v.reports[i].Report
		ti, _ := v.tasks.Task(ri.TaskID)
		for j := range v.reports {
			if j == i || !positive(j) {
				continue
			}
			rj := v.reports[j].Report
			tj, _ := v.tasks.Task(rj.TaskID)
			ownAgent := slices.ContainsFunc(v.cfg.EvaluatorAgents, func(e EvaluatorAgent) bool { return e.EvaluatorIss == ri.Issuer && e.AgentID == tj.AgentID })
			runByOperator := slices.ContainsFunc(v.cfg.EvaluatorAgents, func(e EvaluatorAgent) bool { return e.EvaluatorIss == rj.Issuer && e.OperatorID == ti.OperatorID })
			gap := ri.ObservedAt - rj.ObservedAt
			if ownAgent && runByOperator && gap <= window && -gap <= window {
				out[i] = Verdict{Qualification: Disputed, Rule: RuleReciprocal}
				out[j] = Verdict{Qualification: Disputed, Rule: RuleReciprocal}
			}
		}
	}
}

// corrected checks the events a correction names and returns the
// event_kind it is classified under, or false when rule 10 makes it
// UNQUALIFIED: each event was received before it, is QUALIFIED or DISPUTED,
// has its task, operation and dimension and the kind of the others (a
// correction among them counting as the kind it was classified under), and
// is from its signer unless a security authority corrects.
func (v *view) corrected(i int, before []Verdict) (core.EventKind, bool) {
	c := v.reports[i].Report
	var kind core.EventKind
	for n, id := range c.Supersedes {
		j, ok := v.byEvent[id]
		if !ok || j >= i {
			return "", false
		}
		if q := before[j].Qualification; q != Qualified && q != Disputed {
			return "", false
		}
		t := v.reports[j].Report
		if t.TaskID != c.TaskID || t.OperationID != c.OperationID || t.Dimension != c.Dimension ||
			t.Issuer != c.Issuer && c.ReporterRole != core.ReporterSecurityAuthority {
			return "", false
		}
		if n == 0 {
			kind = v.kinds[j]
		} else if v.kinds[j] != kind {
			return "", false
		}
	}
	return kind, kind != ""
}
