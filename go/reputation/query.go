package reputation

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"unicode/utf16"

	"hop.top/pact-go/core"
	"hop.top/pact-go/core/digest"
	"hop.top/pact-go/core/jcs"
)

// ProvenanceManifest is the manifest of draft Section 15.2 whose
// object_digest a snapshot's value carries as provenance_digest. It is not
// a wire object; the service produces it to an authorized auditor.
type ProvenanceManifest struct {
	QualifiedEventIDs     [][2]string `json:"qualified_event_ids"`
	SupersededEventIDs    [][2]string `json:"superseded_event_ids"`
	QualificationPolicyID string      `json:"qualification_policy_id"`
	ScoringPolicyRevision string      `json:"scoring_policy_revision"`
	EvidenceCutoff        int64       `json:"evidence_cutoff"`
}

// Digest returns the object_digest of the manifest (draft Sections 7.4 and
// 15.2). The manifest is not a wire object, so the size limits of Section
// 20.1 do not bound it: each member value and each listed pair is
// canonicalized on its own (RFC 8785) and the members are joined in the
// order RFC 8785 sorts their names, which is the canonical form of the
// whole object at any size.
func (m ProvenanceManifest) Digest() (core.Digest, error) {
	var buf bytes.Buffer
	value := func(v any) error {
		b, err := json.Marshal(v)
		if err != nil {
			return err
		}
		c, err := jcs.Canonicalize(b)
		if err != nil {
			return err
		}
		buf.Write(c)
		return nil
	}
	list := func(ids [][2]string) error {
		buf.WriteByte('[')
		for i, id := range ids {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := value(id); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
		return nil
	}
	// RFC 8785 member order: evidence_cutoff, qualification_policy_id,
	// qualified_event_ids, scoring_policy_revision, superseded_event_ids.
	steps := []struct {
		name string
		put  func() error
	}{
		{"evidence_cutoff", func() error { return value(m.EvidenceCutoff) }},
		{"qualification_policy_id", func() error { return value(m.QualificationPolicyID) }},
		{"qualified_event_ids", func() error { return list(m.QualifiedEventIDs) }},
		{"scoring_policy_revision", func() error { return value(m.ScoringPolicyRevision) }},
		{"superseded_event_ids", func() error { return list(m.SupersededEventIDs) }},
	}
	buf.WriteByte('{')
	for i, st := range steps {
		if i > 0 {
			buf.WriteByte(',')
		}
		buf.WriteString(`"` + st.name + `":`)
		if err := st.put(); err != nil {
			return "", fmt.Errorf("reputation: provenance manifest %s: %w", st.name, err)
		}
	}
	buf.WriteByte('}')
	return digest.BytesDigest(buf.Bytes()), nil
}

// Snapshot is the answer to a reputation query: the compact
// pact-reputation+jwt, its decoded claims and the provenance manifest of
// its value.
type Snapshot struct {
	Compact    string
	Claims     core.ReputationSnapshot
	Provenance ProvenanceManifest
}

// Dimensions are the mandatory dimensions of Section 15.1.
var Dimensions = []core.Dimension{core.DimensionReliability, core.DimensionTaskQuality, core.DimensionPolicyAdherence}

// unitWeight returns the weight units a qualified report, classified under
// kind, adds before decay and the per-group cap (Sections 14.5, 14.6 rules
// 8 to 12, 15.3); a retracting correction, UNKNOWN, adds none.
func unitWeight(r core.OutcomeReport, kind core.EventKind) float64 {
	if !weighed(kind, r.ReporterRole) || r.Dimension == core.DimensionNone {
		return 0
	}
	switch r.Result {
	case core.OutcomeSuccess:
		if r.ReporterRole == core.ReporterAgent {
			return 0
		}
		return 1
	case core.OutcomeFailure:
		if r.Attribution.CausalAssessment == core.CausalAgent {
			return 1
		}
	}
	return 0
}

// Query answers a reputation query at the service time now (draft Sections
// 13.2, 15.1 to 15.4). A query for another tenant or environment, or whose
// context names another agent than the one it asks for, is
// CONTEXT_MISMATCH.
//
// The snapshot counts the qualified reports no qualified correction
// supersedes whose task is the queried agent's under the queried holder key
// and whose context is the queried one: the baseline moves no evidence
// between contexts (Section 15.1) and none to a holder key the task did not
// bind (Sections 6.4, 15.4). Successes of one independence group add at
// most one unit per dimension, their decayed sum capped at one; each
// failure adds its decayed weight (Section 15.3). Admission and
// authorization decisions, holds and remediations add nothing. The
// security status is HOLD while a hold of the agent is active, in every
// context and under every holder key, however old it is.
func (s *Service) Query(q core.ReputationQuery, now int64) (*Snapshot, *core.Problem) {
	if q.AgentID == "" || q.Audience == "" || q.HolderJKT == "" {
		return nil, s.problem(CodeInvalidMessage)
	}
	if q.Context.TenantID != s.cfg.TenantID || q.Context.EnvironmentID != s.cfg.EnvironmentID || q.Context.AgentID != q.AgentID {
		return nil, s.problem(CodeContextMismatch)
	}
	s.mu.Lock()
	reports, err := s.d.Store.All()
	s.mu.Unlock()
	if err != nil {
		return nil, s.problem(CodeDependencyUnavailable)
	}
	v := newView(s, reports)
	verdicts, superseded := v.classify()
	man := ProvenanceManifest{QualifiedEventIDs: [][2]string{}, SupersededEventIDs: [][2]string{},
		QualificationPolicyID: s.cfg.DataPolicy.QualificationPolicyID, ScoringPolicyRevision: s.cfg.ScoringPolicyRevision, EvidenceCutoff: now}
	type dim struct {
		order   []string
		success map[string]float64
		beta    float64
		stats   core.DimensionStats
	}
	dims := map[core.Dimension]*dim{}
	for _, d := range Dimensions {
		dims[d] = &dim{success: map[string]float64{}, beta: 1}
	}
	for i, st := range reports {
		r := st.Report
		task, ok := v.tasks.Task(r.TaskID)
		if !ok || task.AgentID != q.AgentID || task.HolderJKT != q.HolderJKT || !sameContext(r.Context, q.Context) {
			continue
		}
		id := [2]string{r.Issuer, r.JTI}
		if superseded[i] {
			man.SupersededEventIDs = append(man.SupersededEventIDs, id)
			continue
		}
		w := unitWeight(r, v.kinds[i])
		d := dims[r.Dimension]
		if verdicts[i].Qualification != Qualified || w == 0 || d == nil {
			continue
		}
		man.QualifiedEventIDs = append(man.QualifiedEventIDs, id)
		g := task.IndependenceGroup
		if !slices.Contains(d.order, g) {
			d.order = append(d.order, g)
		}
		d.stats.QualifiedEvents++
		if d.stats.NewestEventAt == nil || r.ObservedAt > *d.stats.NewestEventAt {
			at := r.ObservedAt
			d.stats.NewestEventAt = &at
		}
		decayed := float64(w * Decay(now, r.ObservedAt))
		if r.Result == core.OutcomeSuccess {
			d.success[g] += decayed
		} else {
			d.beta += decayed
		}
	}
	sortIDs(man.QualifiedEventIDs)
	sortIDs(man.SupersededEventIDs)
	for _, d := range dims {
		alpha := 1.0
		for _, g := range d.order {
			alpha += min(d.success[g], 1)
		}
		d.stats.ScoreBPS, d.stats.ConfidenceBPS = FromAlphaBeta(alpha, d.beta)
		d.stats.IndependentTasks = int64(len(d.order))
	}
	holds := v.holds(verdicts, q.AgentID)
	status := core.SecurityClear
	if len(holds) > 0 {
		status = core.SecurityHold
	}
	pd, err := man.Digest()
	if err != nil {
		return nil, s.problem(CodeDependencyUnavailable)
	}
	jti, err := s.randomID()
	if err != nil {
		return nil, s.problem(CodeDependencyUnavailable)
	}
	claims := core.ReputationSnapshot{
		PactVersion: core.Version, Issuer: s.cfg.ServiceID, Subject: q.AgentID, Audience: q.Audience, JTI: jti,
		IssuedAt: now, NotBefore: now, Expiry: now + s.cfg.SnapshotLifetime, TenantID: s.cfg.TenantID, EnvironmentID: s.cfg.EnvironmentID,
		HolderJKT: q.HolderJKT,
		Value: core.ReputationValue{
			Context: q.Context,
			Dimensions: core.ReputationDimensions{
				Reliability: dims[core.DimensionReliability].stats, TaskQuality: dims[core.DimensionTaskQuality].stats,
				PolicyAdherence: dims[core.DimensionPolicyAdherence].stats,
			},
			EvidenceCutoff: now, ProvenanceDigest: pd, ScoringArtifactDigest: s.cfg.ScoringArtifactDigest,
			ScoringPolicyRevision: s.cfg.ScoringPolicyRevision, SecurityStatus: status, HoldRefs: holds,
		},
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return nil, s.problem(CodeDependencyUnavailable)
	}
	compact, err := s.d.Signer.SignSnapshot(payload)
	if err != nil {
		return nil, s.problem(CodeDependencyUnavailable)
	}
	return &Snapshot{Compact: compact, Claims: claims, Provenance: man}, nil
}

func sameContext(a, b core.ReputationContext) bool {
	return a.TenantID == b.TenantID && a.EnvironmentID == b.EnvironmentID && a.AgentID == b.AgentID && a.PurposeID == b.PurposeID &&
		a.ActionClass == b.ActionClass && a.ResourceClass == b.ResourceClass && a.RuntimeClass == b.RuntimeClass
}

// sortIDs sorts [iss, jti] pairs by iss, then jti, comparing UTF-16 code
// units as RFC 8785 does (Section 15.2).
func sortIDs(ids [][2]string) {
	u := func(s string) []uint16 { return utf16.Encode([]rune(s)) }
	slices.SortFunc(ids, func(a, b [2]string) int {
		if c := slices.Compare(u(a[0]), u(b[0])); c != 0 {
			return c
		}
		return slices.Compare(u(a[1]), u(b[1]))
	})
}

// holds returns the event_id of each active hold of the agent, in the order
// placed (Section 15.4): a qualified SECURITY report with result FAILURE
// from a signer registered as security authority places one; a later
// qualified REMEDIATION from one of the hold clearance authorities that
// names it in evidence_refs, beside a completed remediation record, clears
// it. Nothing else clears a hold, and time does not.
//
// A correction never places or clears a hold: a superseded SECURITY report
// keeps its hold under its own event_id (Section 15.4).
func (v *view) holds(verdicts []Verdict, agent string) []string {
	holds := []string{}
	for i, st := range v.reports {
		r := st.Report
		if verdicts[i].Qualification != Qualified {
			continue
		}
		if task, ok := v.tasks.Task(r.TaskID); !ok || task.AgentID != agent {
			continue
		}
		switch r.EventKind {
		case core.EventSecurity:
			if r.Result == core.OutcomeFailure && r.ReporterRole == core.ReporterSecurityAuthority && !slices.Contains(holds, r.EventID) {
				holds = append(holds, r.EventID)
			}
		case core.EventRemediation:
			if slices.Contains(v.cfg.HoldClearanceAuthorities, r.Issuer) && v.cites(r, RecordRemediation, "completed") {
				holds = slices.DeleteFunc(holds, func(id string) bool { return slices.Contains(r.EvidenceRefs, id) })
			}
		}
	}
	return holds
}

// Classifications returns the qualification of every stored report by
// event_id, for an authorized auditor (Section 14.3); a duplicate, which
// casts no vote, is not listed.
func (s *Service) Classifications() (map[string]Verdict, error) {
	s.mu.Lock()
	reports, err := s.d.Store.All()
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	verdicts, _ := newView(s, reports).classify()
	out := map[string]Verdict{}
	for i, st := range reports {
		if !st.Duplicate {
			out[st.Report.EventID] = verdicts[i]
		}
	}
	return out, nil
}

// Holds returns the active holds of the agent (Section 15.4).
func (s *Service) Holds(agent string) ([]string, error) {
	s.mu.Lock()
	reports, err := s.d.Store.All()
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	v := newView(s, reports)
	verdicts, _ := v.classify()
	return v.holds(verdicts, agent), nil
}
