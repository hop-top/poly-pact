package runner

import (
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"hop.top/pact-go/core"
	"hop.top/pact-go/core/jcs"
	"hop.top/pact-go/core/jws"
	"hop.top/pact-go/core/strictjson"
	score "hop.top/pact-go/reputation"
	"hop.top/pact-go/runner/evalcase"
	"hop.top/pact-go/runner/manifest"
	"hop.top/pact-go/runner/reputation"
)

// SkipQualification is the reason of the qualification sub-check of an
// outcomes entry whose command prints no classifications.
const SkipQualification = "qualification: the command prints no classifications; the draft defines no endpoint that discloses a qualification, so the classifications.json sub-check is not run (spec/v1.0/fixtures/README.md, Outcomes output)"

// outputLimits bound the decoding of what an outcomes command prints and of
// its provenance manifests, which are not wire objects: the 256 KiB decode
// limit of draft Section 20.1 does not apply to them, and a manifest grows
// with the reports a snapshot lists. A snapshot itself is a wire object and
// keeps the default limits.
var outputLimits = strictjson.Limits{MaxBytes: 64 << 20}

// checkOutcomes runs the outcomes command on the case directory and judges
// the outcomes result object it prints (spec/v1.0/fixtures/README.md, section
// Outcomes output) against the case: the answer to each ingestion, the
// signed snapshot and provenance manifest of each query, and, when the
// command prints them, the qualifications. Every difference is a detail.
// The exit status of the command is informational.
func checkOutcomes(root string, e manifest.Entry, tmpl string, r Result) Result {
	dir, err := filepath.Abs(filepath.Join(root, filepath.FromSlash(e.Path)))
	if err != nil {
		return r.with(StatusFail, err.Error())
	}
	c, err := evalcase.ReadOutcomes(root, e.ID)
	if err != nil {
		return r.with(StatusFail, err.Error())
	}
	keys, err := reputationKeys(root, c.Config.ReputationService.Key)
	if err != nil {
		return r.with(StatusFail, err.Error())
	}
	scratch, err := os.MkdirTemp("", "pactc-outcomes-")
	if err != nil {
		return r.with(StatusFail, "cannot make the scratch state: "+err.Error())
	}
	defer func() { _ = os.RemoveAll(scratch) }()
	res := runCmd(BuildArgv(tmpl, map[string]string{"dir": dir, "state": filepath.Join(scratch, "state")}))
	if res.Err != nil {
		return r.with(StatusFail, "cannot run the outcomes command: "+res.summary())
	}
	text := strings.TrimSpace(string(res.Stdout))
	if text == "" {
		return r.with(StatusFail, "no outcomes result on stdout", res.summary())
	}
	problems, skipped := judgeOutcomes(c, keys, []byte(text))
	r.Skipped = skipped
	if len(problems) > 0 {
		return r.with(StatusFail, append(problems, res.summary())...)
	}
	return r.with(StatusPass)
}

// reputationKeys loads the public JWK file snapshots verify under.
func reputationKeys(root, key string) (jws.StaticResolver, error) {
	b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(key)))
	if err != nil {
		return jws.StaticResolver{}, fmt.Errorf("reputation_service.key: %w", err)
	}
	jwk, err := jws.ParseJWK(b)
	if err != nil {
		return jws.StaticResolver{}, fmt.Errorf("%s: %w", key, err)
	}
	ks, err := jws.NewKeySet(jwk)
	if err != nil {
		return jws.StaticResolver{}, fmt.Errorf("%s: %w", key, err)
	}
	return jws.StaticResolver{KeySets: map[jws.Role]*jws.KeySet{jws.RoleReputationService: ks}}, nil
}

// judgeOutcomes judges the outcomes result object text against the case and
// returns the problems and the sub-checks it did not run.
func judgeOutcomes(c *evalcase.OutcomesCase, keys jws.StaticResolver, text []byte) (problems, skipped []string) {
	var members map[string]json.RawMessage
	var out struct {
		Steps           []json.RawMessage  `json:"steps"`
		Classifications map[string]*string `json:"classifications"`
	}
	if err := strictjson.Unmarshal(text, outputLimits, &members); err != nil {
		return []string{"stdout is not the outcomes result object (spec/v1.0/fixtures/README.md, Outcomes output): " + err.Error()}, nil
	}
	if err := strictjson.Unmarshal(text, outputLimits, &out); err != nil {
		return []string{"stdout is not the outcomes result object (spec/v1.0/fixtures/README.md, Outcomes output): " + err.Error()}, nil
	}
	if _, ok := members["steps"]; !ok || len(out.Steps) != len(c.Steps) {
		return []string{fmt.Sprintf("steps has %d entries, want one per step of steps.json: %d", len(out.Steps), len(c.Steps))}, nil
	}
	acks := map[int]evalcase.ExpectedAck{}
	for _, a := range c.Acks {
		acks[a.Step] = a
	}
	snaps := map[int]evalcase.ExpectedSnapshot{}
	for _, s := range c.Snapshots {
		snaps[s.Step] = s
	}
	refused := map[string]bool{}
	// acknowledged holds, by (iss, jti), the signed report and the
	// Acknowledgment of its first acknowledged submission.
	type firstAck struct {
		compact string
		ack     json.RawMessage
	}
	acknowledged := map[string]firstAck{}
	ingested := map[[2]string]core.OutcomeReport{}
	for i, s := range c.Steps {
		if s.Ingest != "" {
			where := fmt.Sprintf("step %d (ingest %s)", i, s.Ingest)
			status, code, ack, ps := parseAnswer(where, out.Steps[i])
			problems = append(problems, ps...)
			if len(ps) > 0 {
				continue
			}
			rep := c.Reports[s.Ingest]
			key := rep.Issuer + "\x00" + rep.JTI
			if a, ok := acks[i]; ok {
				problems = append(problems, ackDiff(where, a, status, code)...)
			}
			// An identical authenticated retry returns the original
			// acknowledgment and creates no evidence (draft 7.5): the first
			// Acknowledgment again, or one with status DUPLICATE.
			if prev, ok := acknowledged[key]; ok && prev.compact == c.Signed[s.Ingest] && status != core.AckDuplicate && !sameJSON(ack, prev.ack) {
				problems = append(problems, fmt.Sprintf("%s: answered %s, but the same signed report was acknowledged before: an identical retry of an (iss, jti) gets the original acknowledgment or DUPLICATE (draft Section 7.5)", where, answerName(status, code)))
			}
			if status == "" {
				refused[s.Ingest] = true
				continue
			}
			if _, ok := acknowledged[key]; !ok {
				acknowledged[key] = firstAck{compact: c.Signed[s.Ingest], ack: ack}
			}
			ingested[[2]string{rep.Issuer, rep.JTI}] = rep
			continue
		}
		where := fmt.Sprintf("step %d (query)", i)
		problems = append(problems, judgeSnapshot(where, c, s, snaps[i], keys, out.Steps[i], ingested)...)
	}
	if out.Classifications == nil {
		return problems, []string{SkipQualification}
	}
	return append(problems, judgeClassifications(c, out.Classifications, refused)...), nil
}

func answerName(status core.AckStatus, code string) string {
	if status != "" {
		return string(status)
	}
	return "with a Problem " + code
}

// parseAnswer reads the entry of an ingest step: {"ack": Acknowledgment} or
// {"problem": Problem}, each in its Appendix A.3 and Section 13.4 form. It
// returns the status of an acknowledgment and the object as printed, or
// the code of a Problem.
func parseAnswer(where string, raw json.RawMessage) (core.AckStatus, string, json.RawMessage, []string) {
	var m map[string]json.RawMessage
	if err := strictjson.Unmarshal(raw, strictjson.Limits{}, &m); err != nil {
		return "", "", nil, []string{where + ": not an object: " + err.Error()}
	}
	ack, hasAck := m["ack"]
	prob, hasProb := m["problem"]
	if len(m) != 1 || hasAck == hasProb {
		return "", "", nil, []string{where + `: an ingest step's entry is {"ack": <Acknowledgment>} or {"problem": <Problem>}`}
	}
	if hasAck {
		var a core.Acknowledgment
		if err := strictjson.Unmarshal(ack, strictjson.Limits{}, &a); err != nil {
			return "", "", nil, []string{where + ": ack is not an Acknowledgment (draft Appendix A.3): " + err.Error()}
		}
		if a.RequestID == "" || a.ArtifactID == "" || !a.Status.Valid() || a.ReceivedAt < 0 {
			return "", "", nil, []string{where + ": ack needs a request_id, an artifact_id, a status ACCEPTED or DUPLICATE and a received_at (draft Appendix A.3)"}
		}
		return a.Status, "", ack, nil
	}
	var p core.Problem
	if err := strictjson.Unmarshal(prob, strictjson.Limits{}, &p); err != nil {
		return "", "", nil, []string{where + ": problem is not an RFC 9457 Problem (draft Section 13.4): " + err.Error()}
	}
	if p.Type == "" || p.Title == "" || p.RequestID == "" || p.Code == "" || p.Status < 400 || p.Status > 599 {
		return "", "", nil, []string{where + ": problem needs a type, a title, a request_id, a code and an HTTP error status (draft Section 13.4)"}
	}
	return "", p.Code, nil, nil
}

func ackDiff(where string, a evalcase.ExpectedAck, status core.AckStatus, code string) []string {
	switch {
	case a.Status != nil && status != *a.Status:
		return []string{fmt.Sprintf("%s: answered %s, want the acknowledgment %s (acks.json)", where, answerName(status, code), *a.Status)}
	case a.TransportCode != nil && code != *a.TransportCode:
		return []string{fmt.Sprintf("%s: answered %s, want a Problem %s (acks.json)", where, answerName(status, code), *a.TransportCode)}
	}
	return nil
}

// manifestOut is the printed ProvenanceManifest (draft Section 15.2).
type manifestOut struct {
	QualifiedEventIDs     *[][2]string `json:"qualified_event_ids"`
	SupersededEventIDs    *[][2]string `json:"superseded_event_ids"`
	QualificationPolicyID *string      `json:"qualification_policy_id"`
	ScoringPolicyRevision *string      `json:"scoring_policy_revision"`
	EvidenceCutoff        *int64       `json:"evidence_cutoff"`
}

// judgeSnapshot judges the entry of a query step: the signed snapshot, its
// binding to the query and the service (draft Sections 15.2, A.2), the
// expected snapshot.json entry, and the printed provenance manifest.
func judgeSnapshot(where string, c *evalcase.OutcomesCase, s evalcase.OutcomeStep, want evalcase.ExpectedSnapshot, keys jws.StaticResolver,
	raw json.RawMessage, ingested map[[2]string]core.OutcomeReport) []string {
	var entry struct {
		Snapshot   *string         `json:"snapshot"`
		Provenance json.RawMessage `json:"provenance"`
	}
	if err := strictjson.Unmarshal(raw, outputLimits, &entry); err != nil || entry.Snapshot == nil || len(entry.Provenance) == 0 {
		return []string{where + `: a query step's entry is {"snapshot": "<compact pact-reputation+jwt>", "provenance": <ProvenanceManifest>}`}
	}
	parsed, err := jws.Verifier{Keys: keys, Typ: jws.TypReputation}.Verify(*entry.Snapshot)
	if err != nil {
		return []string{fmt.Sprintf("%s: the snapshot does not verify as a %s under %s: %v", where, jws.TypReputation, c.Config.ReputationService.Key, err)}
	}
	var snap core.ReputationSnapshot
	if err := strictjson.Unmarshal(parsed.Payload, strictjson.Limits{}, &snap); err != nil {
		return []string{where + ": the snapshot payload is not a ReputationSnapshot (draft Appendix A.3): " + err.Error()}
	}
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(parsed.Payload, &payload); err != nil {
		return []string{where + ": " + err.Error()}
	}
	ps := bindingProblems(c, s, want, snap)
	for _, p := range reputation.MatchValue(want.Value, payload["value"]) {
		ps = append(ps, "snapshot "+p)
	}
	for _, k := range slices.Sorted(maps.Keys(want.Claims)) {
		if !sameJSON(payload[k], want.Claims[k]) {
			ps = append(ps, fmt.Sprintf("snapshot claim %s is %s, want %s", k, orAbsent(payload[k]), want.Claims[k]))
		}
	}
	ps = append(ps, provenanceProblems(c, want, snap, entry.Provenance, ingested)...)
	for i := range ps {
		ps[i] = where + ": " + ps[i]
	}
	return ps
}

func orAbsent(b json.RawMessage) string {
	if b == nil {
		return "absent"
	}
	return string(b)
}

func sameJSON(a, b json.RawMessage) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	ca, err1 := jcs.Canonicalize(a)
	cb, err2 := jcs.Canonicalize(b)
	return err1 == nil && err2 == nil && string(ca) == string(cb)
}

// bindingProblems applies the rules every snapshot follows, whatever the
// expected file names: issued by the service for the query's subject,
// audience, holder key and context, in the service's realm (Sections 15.1,
// 15.2, A.2); valid from the query's time for at most 300 seconds and not
// after exp_max; an evidence cutoff no later than its issuance; the
// configured scoring pins; and a security status that says HOLD exactly
// when hold_refs names an active hold (Section 15.4).
func bindingProblems(c *evalcase.OutcomesCase, s evalcase.OutcomeStep, want evalcase.ExpectedSnapshot, snap core.ReputationSnapshot) []string {
	var ps []string
	add := func(format string, args ...any) { ps = append(ps, fmt.Sprintf(format, args...)) }
	svc, q, v := c.Config.ReputationService, s.Query, snap.Value
	skew := c.Config.ClockSkewSeconds
	if snap.PactVersion != core.Version {
		add("pact_version %q, want %q", snap.PactVersion, core.Version)
	}
	if snap.Issuer != svc.ServiceID || snap.TenantID != svc.TenantID || snap.EnvironmentID != svc.EnvironmentID {
		add("iss %s, tenant_id %s, environment_id %s; want the reputation service's %s, %s, %s (draft Section 15.2)",
			snap.Issuer, snap.TenantID, snap.EnvironmentID, svc.ServiceID, svc.TenantID, svc.EnvironmentID)
	}
	if snap.Subject != q.AgentID || snap.Audience != q.Audience || snap.HolderJKT != q.HolderJKT {
		add("sub %s, aud %s, holder_jkt %s; want the query's %s, %s, %s (draft Sections 15.2, A.2)",
			snap.Subject, snap.Audience, snap.HolderJKT, q.AgentID, q.Audience, q.HolderJKT)
	}
	if !sameContextJSON(v.Context, q.Context) {
		add("value.context is not the queried context (draft Sections 15.1, A.2)")
	}
	if !validJTI(snap.JTI) {
		add("jti %q is not 22 to 128 base64url characters (draft Appendix A.2)", snap.JTI)
	}
	switch {
	case snap.IssuedAt > s.Now+skew || snap.NotBefore > s.Now+skew:
		add("iat %d, nbf %d after the query's time %d plus the clock skew (draft Section 7.5)", snap.IssuedAt, snap.NotBefore, s.Now)
	case snap.Expiry <= s.Now || snap.Expiry <= snap.IssuedAt || snap.Expiry-snap.IssuedAt > evalcase.SnapshotLifetime:
		add("exp %d: a snapshot is valid at the query's time %d, after iat %d, for at most %d seconds (draft Section 15.2)",
			snap.Expiry, s.Now, snap.IssuedAt, evalcase.SnapshotLifetime)
	case snap.Expiry > want.ExpMax:
		add("exp %d after exp_max %d", snap.Expiry, want.ExpMax)
	}
	if v.EvidenceCutoff > snap.IssuedAt || v.EvidenceCutoff > s.Now+skew {
		add("evidence_cutoff %d after the snapshot's issuance %d or the query's time (draft Appendix A.2)", v.EvidenceCutoff, snap.IssuedAt)
	}
	if v.ScoringArtifactDigest != c.Config.Scoring.ScoringArtifactDigest || v.ScoringPolicyRevision != c.Config.Scoring.ScoringPolicyRevision {
		add("scoring pins %s, %s; want the configured %s, %s (draft Section 15.2)", v.ScoringArtifactDigest, v.ScoringPolicyRevision,
			c.Config.Scoring.ScoringArtifactDigest, c.Config.Scoring.ScoringPolicyRevision)
	}
	if !v.SecurityStatus.Valid() || v.HoldRefs == nil || (v.SecurityStatus == core.SecurityHold) != (len(v.HoldRefs) > 0) {
		add("security_status %q with hold_refs %v: HOLD exactly while hold_refs names an active hold (draft Section 15.4)", v.SecurityStatus, v.HoldRefs)
	}
	for _, d := range reputation.Dimensions {
		st := dimension(v, d)
		if st.ScoreBPS < 0 || st.ScoreBPS > 10000 || st.ConfidenceBPS < 0 || st.ConfidenceBPS > 10000 || st.IndependentTasks < 0 || st.QualifiedEvents < 0 {
			add("%s: score_bps and confidence_bps are in 0..10000 and the counts not negative (draft Section 15.2)", d)
		}
	}
	return ps
}

func dimension(v core.ReputationValue, d core.Dimension) core.DimensionStats {
	switch d {
	case core.DimensionTaskQuality:
		return v.Dimensions.TaskQuality
	case core.DimensionPolicyAdherence:
		return v.Dimensions.PolicyAdherence
	}
	return v.Dimensions.Reliability
}

func sameContextJSON(a, b core.ReputationContext) bool {
	ab, err1 := json.Marshal(a)
	bb, err2 := json.Marshal(b)
	return err1 == nil && err2 == nil && sameJSON(ab, bb)
}

func validJTI(s string) bool {
	if len(s) < 22 || len(s) > 128 {
		return false
	}
	return !strings.ContainsFunc(s, func(r rune) bool {
		return (r < 'A' || r > 'Z') && (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' && r != '_'
	})
}

// provenanceProblems judges the printed ProvenanceManifest: its five
// members, its lists equal to the expected ones and sorted, the reports it
// lists ingested before the query, each dimension's qualified_events the
// number of listed reports of that dimension, its policy, revision and
// cutoff those of the service and the value, and the value's
// provenance_digest its object_digest, at any size (draft Sections 7.4,
// 15.2, A.2).
func provenanceProblems(c *evalcase.OutcomesCase, want evalcase.ExpectedSnapshot, snap core.ReputationSnapshot, raw json.RawMessage,
	ingested map[[2]string]core.OutcomeReport) []string {
	var m manifestOut
	if err := strictjson.Unmarshal(raw, outputLimits, &m); err != nil {
		return []string{"provenance is not a ProvenanceManifest (draft Section 15.2): " + err.Error()}
	}
	if m.QualifiedEventIDs == nil || m.SupersededEventIDs == nil || m.QualificationPolicyID == nil || m.ScoringPolicyRevision == nil || m.EvidenceCutoff == nil {
		return []string{"provenance needs qualified_event_ids, superseded_event_ids, qualification_policy_id, scoring_policy_revision and evidence_cutoff (draft Section 15.2)"}
	}
	var ps []string
	v := snap.Value
	for _, l := range []struct {
		name      string
		got, want [][2]string
	}{{"qualified_event_ids", *m.QualifiedEventIDs, want.Provenance.QualifiedEventIDs}, {"superseded_event_ids", *m.SupersededEventIDs, want.Provenance.SupersededEventIDs}} {
		if !slices.Equal(l.got, l.want) {
			ps = append(ps, fmt.Sprintf("provenance %s %v, want %v", l.name, l.got, l.want))
		}
		sorted := slices.Clone(l.got)
		reputation.SortPairs(sorted)
		if !slices.Equal(sorted, l.got) || len(slices.Compact(sorted)) != len(l.got) {
			ps = append(ps, fmt.Sprintf("provenance %s is not sorted by iss and jti, each pair once (draft Section 15.2)", l.name))
		}
		for _, p := range l.got {
			if _, ok := ingested[p]; !ok {
				ps = append(ps, fmt.Sprintf("provenance %s names %v, which no earlier step ingested", l.name, p))
			}
		}
	}
	counts := map[core.Dimension]int64{}
	for _, p := range *m.QualifiedEventIDs {
		if r, ok := ingested[p]; ok {
			counts[r.Dimension]++
		}
	}
	for _, d := range reputation.Dimensions {
		if got := dimension(v, d).QualifiedEvents; got != counts[d] {
			ps = append(ps, fmt.Sprintf("%s qualified_events %d, but the provenance lists %d reports of that dimension (draft Section 15.2)", d, got, counts[d]))
		}
	}
	if *m.QualificationPolicyID != c.Config.DataPolicy.QualificationPolicyID {
		ps = append(ps, fmt.Sprintf("provenance qualification_policy_id %s, want the data policy's %s", *m.QualificationPolicyID, c.Config.DataPolicy.QualificationPolicyID))
	}
	if *m.ScoringPolicyRevision != v.ScoringPolicyRevision || *m.EvidenceCutoff != v.EvidenceCutoff {
		ps = append(ps, "provenance scoring_policy_revision and evidence_cutoff are the value's (draft Appendix A.2)")
	}
	d, err := score.ProvenanceManifest{QualifiedEventIDs: *m.QualifiedEventIDs, SupersededEventIDs: *m.SupersededEventIDs,
		QualificationPolicyID: *m.QualificationPolicyID, ScoringPolicyRevision: *m.ScoringPolicyRevision, EvidenceCutoff: *m.EvidenceCutoff}.Digest()
	if err != nil || d != v.ProvenanceDigest {
		ps = append(ps, fmt.Sprintf("value.provenance_digest %s is not the object_digest of the printed manifest, %s (draft Sections 7.4, 15.2)", v.ProvenanceDigest, d))
	}
	return ps
}

// judgeClassifications compares the printed qualifications with
// classifications.json. A report whose expected qualification is null is
// not judged. A report the command refused has the qualification null; the
// receiver refuses an invalid report at ingestion (outcomes/mapping
// README), so null also meets an expected UNQUALIFIED of reason
// invalid-report when the step was refused.
func judgeClassifications(c *evalcase.OutcomesCase, got map[string]*string, refused map[string]bool) []string {
	var ps []string
	for _, id := range slices.Sorted(maps.Keys(got)) {
		if _, ok := c.Reports[id]; !ok {
			ps = append(ps, fmt.Sprintf("classifications names %s, which is no report of the case", id))
		}
		if q := got[id]; q != nil && *q != evalcase.Qualified && *q != evalcase.Unqualified && *q != evalcase.Disputed {
			ps = append(ps, fmt.Sprintf("classifications[%s] %q is not QUALIFIED, UNQUALIFIED, DISPUTED or null (draft Section 14.3)", id, *q))
		}
	}
	if c.Classifications == nil {
		return ps
	}
	for _, e := range c.Classifications.Events {
		if e.Qualification == nil {
			continue
		}
		q, ok := got[e.EventID]
		switch {
		case !ok:
			ps = append(ps, fmt.Sprintf("classifications has no %s, want %s", e.EventID, *e.Qualification))
		case q == nil && refused[e.EventID] && *e.Qualification == evalcase.Unqualified && e.Reason == reputation.ReasonInvalidReport:
		case q == nil:
			ps = append(ps, fmt.Sprintf("classifications[%s] is null, want %s (%s)", e.EventID, *e.Qualification, e.Reason))
		case *q != *e.Qualification:
			ps = append(ps, fmt.Sprintf("classifications[%s] is %s, want %s (%s)", e.EventID, *q, *e.Qualification, e.Reason))
		}
	}
	return ps
}
