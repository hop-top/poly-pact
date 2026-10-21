package reputation

import (
	"slices"

	"hop.top/pact-go/core"
	"hop.top/pact-go/runner/evalcase"
)

// classification is the verdict of every report received, the reports a
// qualified correction supersedes, and the event_kind each report is
// classified under: its own, or for a correction the kind of the events it
// supersedes (Section 14.6 rule 10).
type classification struct {
	verdicts   map[*rec]Verdict
	superseded map[*rec]bool
	kind       map[*rec]core.EventKind
}

// classify classifies the reports in arrival order, so a correction is
// classified after the events it names, a correction among them. It
// applies, in order: reporter registration (Appendix A.2), task
// reconciliation (Section 14.6 rules 1 and 2), for a correction the events
// it supersedes (rule 10), the evidence a report cites (Sections 14.2 and
// 14.5), which reporter may report what (Section 14.2 and rule 12),
// self-praise and affiliation (rules 5 and 6), and last reciprocal
// endorsement (rule 7), which a correction it disputes still supersedes:
// its signer could have retracted.
func (o *Oracle) classify() classification {
	c := classification{verdicts: map[*rec]Verdict{}, superseded: map[*rec]bool{}, kind: map[*rec]core.EventKind{}}
	for _, x := range o.recs {
		switch {
		case x.duplicate:
			c.verdicts[x] = Verdict{Reason: ReasonDuplicate}
		case x.r.EventKind == core.EventCorrection:
			c.verdicts[x] = o.correction(x, &c)
		default:
			c.kind[x] = x.r.EventKind
			c.verdicts[x] = o.base(x)
		}
	}
	o.reciprocal(c)
	return c
}

func unqualified(reason string) Verdict {
	return Verdict{Qualification: evalcase.Unqualified, Reason: reason}
}

func qualified(reason string) Verdict {
	return Verdict{Qualification: evalcase.Qualified, Reason: reason}
}

// admitted applies reporter registration and task reconciliation, and
// returns the verdict of a report that fails them.
func (o *Oracle) admitted(x *rec) (Verdict, bool) {
	r := x.r
	if x.role == "" {
		return unqualified(ReasonReporterNotAuthorized), false
	}
	task, ok := o.native.Task(r.TaskID)
	svc := o.cfg.ReputationService
	if !ok || task.AgentID != r.Subject || r.Context.AgentID != r.Subject ||
		r.Context.TenantID != svc.TenantID || r.Context.EnvironmentID != svc.EnvironmentID {
		return unqualified(ReasonTaskUnreconciled), false
	}
	return Verdict{}, true
}

// checks applies to a report classified under kind the evidence it cites
// (Sections 14.2 and 14.5), who may report what (Section 14.2, rule 12),
// self-praise and affiliation (rules 5 and 6). It returns the reason of the
// first rule broken, or "".
func (o *Oracle) checks(x *rec, kind core.EventKind) string {
	r := x.r
	switch kind {
	case core.EventExecution, core.EventAuthorization:
		if reason := o.nativeEvidence(r, kind); reason != "" {
			return reason
		}
	case core.EventQuality:
		if !o.cites(r, "assessment", "completed") {
			return ReasonNoAssessmentRecord
		}
	case core.EventFeedback:
		// Verified feedback conveys a completed assessment; the agent's
		// own diagnostic, never positive, needs none (Section 14.5).
		if x.role != string(core.ReporterAgent) && !o.cites(r, "assessment", "completed") {
			return ReasonNoAssessmentRecord
		}
	}
	if !o.eligible(x, kind) {
		return ReasonReporterNotAuthorized
	}
	if kind == core.EventSecurity && !o.citesSecurityRecord(r) {
		return ReasonRecordMismatch
	}
	if kind == core.EventQuality || kind == core.EventFeedback {
		task, _ := o.native.Task(r.TaskID)
		if o.executorOf(r.Issuer, r.TaskID) {
			return ReasonSelfPraise
		}
		if r.Result == core.OutcomeSuccess && o.affiliated(r.Issuer, task.OperatorID) {
			return ReasonAffiliatedEvaluator
		}
	}
	return ""
}

// base classifies a report that is not a correction, before rule 7.
func (o *Oracle) base(x *rec) Verdict {
	if v, ok := o.admitted(x); !ok {
		return v
	}
	r := x.r
	if reason := o.checks(x, r.EventKind); reason != "" {
		return unqualified(reason)
	}
	if r.Result == core.OutcomeFailure && r.Dimension != core.DimensionNone && r.Attribution.CausalAssessment != core.CausalAgent && counts(r.EventKind, x.role) {
		return qualified(ReasonCausalZeroWeight)
	}
	return qualified(ReasonMapped)
}

// correction classifies a correction, before rule 7 (rule 10): its targets
// decide the kind it is classified under, and a qualified correction
// supersedes them.
func (o *Oracle) correction(x *rec, c *classification) Verdict {
	if v, ok := o.admitted(x); !ok {
		return v
	}
	targets, kind, ok := o.correctionTargets(x, c)
	if !ok {
		return unqualified(ReasonCorrectionMismatch)
	}
	c.kind[x] = kind
	if reason := o.checks(x, kind); reason != "" {
		return unqualified(reason)
	}
	for _, t := range targets {
		c.superseded[t] = true
	}
	return qualified(ReasonCorrection)
}

// counts reports whether a report classified under kind k, from a signer
// of the role, can carry dimension weight: a statistic of Section 15.3.
// Admission and authorization decisions have zero weight (Section 14.5); a
// SECURITY report weighs only as a gateway's detected policy violation
// (Section 14.6 rule 12), a security authority's hold and its remediation
// being independent of the statistical score (Section 15.4).
func counts(k core.EventKind, role string) bool {
	switch k {
	case core.EventExecution, core.EventQuality, core.EventFeedback:
		return true
	case core.EventSecurity:
		return role == string(core.ReporterGateway)
	}
	return false
}

// absentVisibility reports whether r is the Section 14.5 report of absent
// execution visibility: EXECUTION UNKNOWN on none with empty evidence_refs,
// from a gateway whose profile declares no execution visibility.
func (o *Oracle) absentVisibility(r core.OutcomeReport) bool {
	return r.EventKind == core.EventExecution && r.Result == core.OutcomeUnknown && r.Dimension == core.DimensionNone &&
		len(r.EvidenceRefs) == 0 && o.cfg.Visibility == "none"
}

// nativeEvidence checks the native record a report classified under
// EXECUTION or AUTHORIZATION cites (Sections 14.2, 14.5, 17.5 and Appendix
// A.2): an immutable record of the report's task and operation that
// identifies the executor, of a completed or failed execution for a
// SUCCESS or FAILURE, of the authorization decision the result states, and
// whose executor class is the class the installed mapping declares. An
// UNKNOWN correction may cite any such record of the task and operation.
// It returns the reason of the first rule broken, or "".
func (o *Oracle) nativeEvidence(r core.OutcomeReport, k core.EventKind) string {
	if o.absentVisibility(r) {
		return ""
	}
	kind := "execution"
	if k == core.EventAuthorization {
		kind = "authorization"
	}
	var cands []evalcase.NativeRecord
	for _, ref := range r.EvidenceRefs {
		rec, ok := o.native.Records[ref]
		if ok && rec.Kind == kind && rec.Executor != nil && rec.TaskID == r.TaskID && rec.OperationID == r.OperationID {
			cands = append(cands, rec)
		}
	}
	if len(cands) == 0 {
		return ReasonNoExecutorRecord
	}
	want := ""
	switch {
	case kind == "execution" && r.Result == core.OutcomeSuccess:
		want = "completed"
	case kind == "execution" && r.Result == core.OutcomeFailure:
		want = "failed"
	case kind == "authorization" && r.Result == core.OutcomeSuccess:
		want = "allowed"
	case kind == "authorization" && r.Result == core.OutcomeFailure:
		want = "denied"
	}
	if want != "" {
		i := slices.IndexFunc(cands, func(c evalcase.NativeRecord) bool { return c.State == want })
		if i < 0 {
			if kind == "execution" {
				return ReasonNoCompletionRecord
			}
			return ReasonRecordMismatch
		}
		cands = cands[i : i+1]
	}
	ex := cands[0].Executor
	i := slices.IndexFunc(o.cfg.ExecutorClasses, func(c evalcase.ExecutorClass) bool {
		return c.TaskID == r.TaskID && c.OperationID == r.OperationID
	})
	if i < 0 {
		return ReasonExecutorClassMismatch
	}
	ec := o.cfg.ExecutorClasses[i]
	if ec.Class != ex.Class || ec.ExecutorID != nil && *ec.ExecutorID != ex.PrincipalID {
		return ReasonExecutorClassMismatch
	}
	return ""
}

// cites reports whether r cites a native record of its task of the kind and
// state.
func (o *Oracle) cites(r core.OutcomeReport, kind, state string) bool {
	return slices.ContainsFunc(r.EvidenceRefs, func(ref string) bool {
		rec, ok := o.native.Records[ref]
		return ok && rec.Kind == kind && rec.State == state && rec.TaskID == r.TaskID
	})
}

// citesSecurityRecord reports whether a report classified under SECURITY
// cites the record its dimension requires, of its task and operation
// (Sections 14.2, 14.5 and 15.4): on policy_adherence the gateway's
// record of the violating request, on none the confirmed incident record.
// A correction cites the record a report of its dimension cites.
func (o *Oracle) citesSecurityRecord(r core.OutcomeReport) bool {
	switch r.Dimension {
	case core.DimensionPolicyAdherence:
		return o.citesOperation(r, "violation", "recorded")
	case core.DimensionNone:
		return o.citesOperation(r, "incident", "confirmed")
	}
	return false
}

// citesOperation reports whether r cites a native record of its task and
// operation of the kind and state.
func (o *Oracle) citesOperation(r core.OutcomeReport, kind, state string) bool {
	return slices.ContainsFunc(r.EvidenceRefs, func(ref string) bool {
		rec, ok := o.native.Records[ref]
		return ok && rec.Kind == kind && rec.State == state && rec.TaskID == r.TaskID && rec.OperationID == r.OperationID
	})
}

// eligible applies the table of Section 14.2 and the rows of Section 14.5
// that name a reporter to a report classified under kind: the gateway
// reports admission and authorization decisions, execution only to declare
// that it cannot see it, and detected policy violations, SECURITY FAILURE
// on policy_adherence (rule 12); a resource service or executor reports
// execution; an evaluator or the task owner reports quality and feedback,
// on task quality or policy adherence; the agent itself only feedback, as
// diagnostics; a security authority incidents, SECURITY FAILURE on none,
// and remediation. A correction is classified under the kind of the events
// it supersedes; a security authority may correct any reporter's events,
// and a gateway may retract its violation with UNKNOWN (rules 10 and 12).
func (o *Oracle) eligible(x *rec, kind core.EventKind) bool {
	r, role := x.r, core.ReporterRole(x.role)
	correction := r.EventKind == core.EventCorrection
	if correction && role == core.ReporterSecurityAuthority {
		return true
	}
	switch kind {
	case core.EventAdmission, core.EventAuthorization:
		return role == core.ReporterGateway
	case core.EventExecution:
		return role == core.ReporterExecutor || role == core.ReporterGateway && o.absentVisibility(r)
	case core.EventQuality:
		return role == core.ReporterEvaluator || role == core.ReporterTaskOwner
	case core.EventFeedback:
		return role == core.ReporterEvaluator || role == core.ReporterTaskOwner || role == core.ReporterAgent
	case core.EventSecurity:
		if role == core.ReporterGateway {
			return r.Dimension == core.DimensionPolicyAdherence && (r.Result == core.OutcomeFailure || correction && r.Result == core.OutcomeUnknown)
		}
		return role == core.ReporterSecurityAuthority && r.Dimension == core.DimensionNone && r.Result == core.OutcomeFailure
	case core.EventRemediation:
		return role == core.ReporterSecurityAuthority
	}
	return false
}

// executorOf reports whether iss is registered as executor for the task
// (Section 14.6 rule 5): a trust record registers it as executor, and it
// reported the task's execution in that role.
func (o *Oracle) executorOf(iss, task string) bool {
	return slices.ContainsFunc(o.recs, func(y *rec) bool {
		return y.role == string(core.ReporterExecutor) && y.r.Issuer == iss && y.r.EventKind == core.EventExecution && y.r.TaskID == task
	})
}

// affiliated reports whether the affiliation registry pairs the evaluator
// or task owner with the operator (rule 6): its positive QUALITY and
// FEEDBACK reports are UNQUALIFIED.
func (o *Oracle) affiliated(iss, operator string) bool {
	return slices.ContainsFunc(o.cfg.Affiliations, func(a evalcase.Affiliation) bool {
		return a.EvaluatorIss == iss && a.OperatorID == operator
	})
}

// reciprocal applies rule 7 to the qualified positive reports classified
// under QUALITY or FEEDBACK, corrections of such events among them: when evaluator
// E's report on an agent stands beside a report on E's own agent by an
// evaluator that the first agent's operator runs, observed within the
// ingestion window of each other, both are DISPUTED.
func (o *Oracle) reciprocal(c classification) {
	out := c.verdicts
	var pos []*rec
	for _, x := range o.recs {
		if out[x].Qualification == evalcase.Qualified && (c.kind[x] == core.EventQuality || c.kind[x] == core.EventFeedback) && x.r.Result == core.OutcomeSuccess {
			pos = append(pos, x)
		}
	}
	window := o.cfg.DataPolicy.IngestionWindowSeconds
	for _, a := range pos {
		ta, _ := o.native.Task(a.r.TaskID)
		for _, b := range pos {
			if a == b {
				continue
			}
			tb, _ := o.native.Task(b.r.TaskID)
			if !o.runsAgent(a.r.Issuer, tb.AgentID) || !o.operatorRuns(ta.OperatorID, b.r.Issuer) {
				continue
			}
			if d := a.r.ObservedAt - b.r.ObservedAt; d > window || -d > window {
				continue
			}
			out[a] = Verdict{Qualification: evalcase.Disputed, Reason: ReasonReciprocalEndorsement}
			out[b] = Verdict{Qualification: evalcase.Disputed, Reason: ReasonReciprocalEndorsement}
		}
	}
}

// runsAgent reports whether evaluator iss operates agent (evaluator_agents).
func (o *Oracle) runsAgent(iss, agent string) bool {
	return slices.ContainsFunc(o.cfg.EvaluatorAgents, func(e evalcase.EvaluatorAgent) bool {
		return e.EvaluatorIss == iss && e.AgentID == agent
	})
}

// operatorRuns reports whether the operator runs evaluator iss.
func (o *Oracle) operatorRuns(operator, iss string) bool {
	return slices.ContainsFunc(o.cfg.EvaluatorAgents, func(e evalcase.EvaluatorAgent) bool {
		return e.EvaluatorIss == iss && e.OperatorID == operator
	})
}

// correctionTargets returns the reports a correction supersedes and the
// event_kind they share, or false when rule 10 makes it UNQUALIFIED: every
// event it names was received before it, is QUALIFIED or DISPUTED (no
// dispute exists before rule 7, so QUALIFIED), has its task, operation and
// dimension and the event_kind of the others, a superseded correction
// counting as the kind of its own targets, and is from its signer unless a
// security authority corrects.
func (o *Oracle) correctionTargets(x *rec, c *classification) ([]*rec, core.EventKind, bool) {
	var out []*rec
	var kind core.EventKind
	at := slices.Index(o.recs, x)
	for _, id := range x.r.Supersedes {
		t, ok := o.byEvent[id]
		if !ok || slices.Index(o.recs, t) > at || c.verdicts[t].Qualification != evalcase.Qualified {
			return nil, "", false
		}
		r := t.r
		if r.TaskID != x.r.TaskID || r.OperationID != x.r.OperationID || r.Dimension != x.r.Dimension {
			return nil, "", false
		}
		if r.Issuer != x.r.Issuer && x.role != string(core.ReporterSecurityAuthority) {
			return nil, "", false
		}
		if k := c.kind[t]; kind == "" {
			kind = k
		} else if k != kind {
			return nil, "", false
		}
		out = append(out, t)
	}
	return out, kind, true
}
