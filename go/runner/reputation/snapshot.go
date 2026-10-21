package reputation

import (
	"slices"

	"hop.top/pact-go/core"
	score "hop.top/pact-go/reputation"
	"hop.top/pact-go/runner/evalcase"
)

// Dimensions are the mandatory dimensions of Section 15.1, in snapshot
// order.
var Dimensions = []core.Dimension{core.DimensionReliability, core.DimensionTaskQuality, core.DimensionPolicyAdherence}

// weight returns the weight units a qualified report, classified under
// kind, adds to its dimension before decay and the per-group cap (Sections
// 14.3, 14.5, 14.6 and 15.3): none for a kind without statistics, for
// dimension none and for UNKNOWN and NOT_APPLICABLE results, so a
// retracting correction weighs nothing (rule 10); a success weighs 1 unless
// the agent reported it about itself (rule 11); a failure weighs 1, the
// weight of a normal attributable failure, unless its causal assessment is
// not the agent's (rules 8 and 9: zero).
func weight(x *rec, kind core.EventKind) float64 {
	r := x.r
	if !counts(kind, x.role) || r.Dimension == core.DimensionNone {
		return 0
	}
	switch r.Result {
	case core.OutcomeSuccess:
		if x.role == string(core.ReporterAgent) {
			return 0
		}
		return 1
	case core.OutcomeFailure:
		if r.Attribution.CausalAssessment != core.CausalAgent {
			return 0
		}
		return 1
	}
	return 0
}

// Query answers a reputation query at the service time now (Sections 15.1
// to 15.4), or returns the Section 13.4 code of its refusal: a query for
// another tenant or environment than the service's, or whose context names
// another agent than it asks for, is CONTEXT_MISMATCH.
//
// The snapshot counts the qualified reports that a qualified correction has
// not superseded, whose task is the queried agent's under the queried
// holder key, and whose context is the queried one: no evidence moves
// between contexts (Section 15.1) or to a holder key the task did not bind
// (Section 6.4). In each dimension, a report of nonzero weight is listed in
// the provenance; the successes of one independence group add at most one
// unit, their decayed sum capped at 1, and each failure its decayed weight
// (Section 15.3). The security status is HOLD while a hold of the agent is
// active, whatever the context and the holder key.
func (o *Oracle) Query(q core.ReputationQuery, now int64) (*Snapshot, string) {
	svc := o.cfg.ReputationService
	if q.Context.TenantID != svc.TenantID || q.Context.EnvironmentID != svc.EnvironmentID || q.Context.AgentID != q.AgentID {
		return nil, CodeContextMismatch
	}
	c := o.classify()
	verdicts, superseded := c.verdicts, c.superseded
	inScope := func(x *rec) bool {
		task, ok := o.native.Task(x.r.TaskID)
		return ok && task.AgentID == q.AgentID && task.HolderJKT == q.HolderJKT && sameContext(x.r.Context, q.Context)
	}
	man := Manifest{QualifiedEventIDs: [][2]string{}, SupersededEventIDs: [][2]string{},
		QualificationPolicyID: o.cfg.DataPolicy.QualificationPolicyID, ScoringPolicyRevision: o.cfg.Scoring.ScoringPolicyRevision, EvidenceCutoff: now}
	type acc struct {
		groups  []string
		success map[string]float64
		beta    float64
		events  int64
		newest  *int64
	}
	accs := map[core.Dimension]*acc{}
	for _, d := range Dimensions {
		accs[d] = &acc{success: map[string]float64{}, beta: 1}
	}
	for _, x := range o.recs {
		if !inScope(x) {
			continue
		}
		pair := [2]string{x.r.Issuer, x.r.JTI}
		if superseded[x] {
			man.SupersededEventIDs = append(man.SupersededEventIDs, pair)
			continue
		}
		w := weight(x, c.kind[x])
		a := accs[x.r.Dimension]
		if verdicts[x].Qualification != evalcase.Qualified || w == 0 || a == nil {
			continue
		}
		man.QualifiedEventIDs = append(man.QualifiedEventIDs, pair)
		task, _ := o.native.Task(x.r.TaskID)
		g := task.IndependenceGroup
		if !slices.Contains(a.groups, g) {
			a.groups = append(a.groups, g)
		}
		a.events++
		if a.newest == nil || x.r.ObservedAt > *a.newest {
			t := x.r.ObservedAt
			a.newest = &t
		}
		dw := float64(w * score.Decay(now, x.r.ObservedAt))
		if x.r.Result == core.OutcomeSuccess {
			a.success[g] += dw
		} else {
			a.beta += dw
		}
	}
	SortPairs(man.QualifiedEventIDs)
	SortPairs(man.SupersededEventIDs)
	stats := map[core.Dimension]core.DimensionStats{}
	for _, d := range Dimensions {
		a := accs[d]
		alpha := 1.0
		for _, g := range a.groups {
			alpha += min(a.success[g], 1)
		}
		s, c := score.FromAlphaBeta(alpha, a.beta)
		stats[d] = core.DimensionStats{ScoreBPS: s, ConfidenceBPS: c, IndependentTasks: int64(len(a.groups)), QualifiedEvents: a.events, NewestEventAt: a.newest}
	}
	holds := o.holds(verdicts, q.AgentID)
	status := core.SecurityClear
	if len(holds) > 0 {
		status = core.SecurityHold
	}
	// The manifest is not a wire object: no decode limit of Section 20.1
	// bounds it, so its digest is taken without one.
	pd, err := score.ProvenanceManifest(man).Digest()
	if err != nil {
		return nil, CodeInvalidMessage
	}
	v := core.ReputationValue{
		Context:        q.Context,
		Dimensions:     core.ReputationDimensions{Reliability: stats[core.DimensionReliability], TaskQuality: stats[core.DimensionTaskQuality], PolicyAdherence: stats[core.DimensionPolicyAdherence]},
		EvidenceCutoff: now, ProvenanceDigest: pd, ScoringArtifactDigest: o.cfg.Scoring.ScoringArtifactDigest,
		ScoringPolicyRevision: o.cfg.Scoring.ScoringPolicyRevision, SecurityStatus: status, HoldRefs: holds,
	}
	claims := core.ReputationSnapshot{
		PactVersion: core.Version, Issuer: svc.ServiceID, Subject: q.AgentID, Audience: q.Audience, IssuedAt: now, NotBefore: now,
		Expiry: now + evalcase.SnapshotLifetime, TenantID: svc.TenantID, EnvironmentID: svc.EnvironmentID, HolderJKT: q.HolderJKT, Value: v,
	}
	return &Snapshot{Value: v, Manifest: man, Claims: claims}, ""
}

// holds returns the event_id of every active hold of the agent, in the
// order they were placed (Section 15.4): a qualified SECURITY report with
// result FAILURE whose signer is registered as a security authority places
// one; a later qualified REMEDIATION that names it in evidence_refs, beside
// a completed remediation record, clears it when its signer is one of the
// hold_clearance_authorities. Nothing else clears a hold; time does not,
// nor does a correction: a superseded SECURITY report keeps its hold, under
// its own event_id, and a correction places none.
func (o *Oracle) holds(verdicts map[*rec]Verdict, agent string) []string {
	holds := []string{}
	for _, x := range o.recs {
		r := x.r
		if verdicts[x].Qualification != evalcase.Qualified {
			continue
		}
		task, _ := o.native.Task(r.TaskID)
		if task.AgentID != agent {
			continue
		}
		switch r.EventKind {
		case core.EventSecurity:
			if r.Result == core.OutcomeFailure && x.role == string(core.ReporterSecurityAuthority) && !slices.Contains(holds, r.EventID) {
				holds = append(holds, r.EventID)
			}
		case core.EventRemediation:
			if slices.Contains(o.cfg.HoldClearanceAuthorities, r.Issuer) && o.cites(r, "remediation", "completed") {
				holds = slices.DeleteFunc(holds, func(id string) bool { return slices.Contains(r.EvidenceRefs, id) })
			}
		}
	}
	return holds
}
