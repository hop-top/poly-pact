package reputation

import (
	"errors"
	"slices"
	"strings"
	"unicode/utf16"

	"hop.top/pact-go/core"
	"hop.top/pact-go/core/digest"
	"hop.top/pact-go/runner/evalcase"
	"hop.top/pact-go/runner/learning"
)

// The transport error codes of draft Section 13.4 a reputation service
// answers an ingestion or a query with.
const (
	CodeInvalidMessage  = learning.CodeInvalidMessage
	CodeInvalidProof    = learning.CodeInvalidProof
	CodeContextMismatch = learning.CodeContextMismatch
	CodeExpired         = learning.CodeExpired
	CodeIDConflict      = learning.CodeIDConflict
)

// The reasons of a classification: the tokens of spec/v1.0/fixtures/README.md,
// section classifications.json, and refused, which the table does not
// name.
const (
	ReasonMapped                = "mapped"
	ReasonInvalidReport         = "invalid-report"
	ReasonNoExecutorRecord      = "no-executor-record"
	ReasonNoCompletionRecord    = "no-completion-record"
	ReasonExecutorClassMismatch = "executor-class-mismatch"
	ReasonReporterNotAuthorized = "reporter-not-authorized"
	ReasonTaskUnreconciled      = "task-unreconciled"
	ReasonDuplicate             = "duplicate"
	ReasonSelfPraise            = "self-praise"
	ReasonAffiliatedEvaluator   = "affiliated-evaluator"
	ReasonReciprocalEndorsement = "reciprocal-endorsement"
	ReasonCausalZeroWeight      = "causal-zero-weight"
	ReasonCorrection            = "correction"
	ReasonCorrectionMismatch    = "correction-mismatch"
	// ReasonRecordMismatch: an AUTHORIZATION report whose result is not the
	// state of the authorization record it cites, a SECURITY report on
	// policy_adherence that cites no violation record of its task and
	// operation, or one on none that cites no confirmed incident record of
	// its task and operation (Sections 14.2 and 14.5).
	ReasonRecordMismatch = "record-mismatch"
	// ReasonNoAssessmentRecord: a QUALITY report, or a FEEDBACK report from
	// an evaluator or the task owner, that cites no completed assessment of
	// the task (Sections 14.2 and 14.5: tied to an observed task).
	ReasonNoAssessmentRecord = "no-assessment-record"
	// ReasonRefused: a report refused for another reason than an A.2 rule,
	// with the Section 13.4 code in Verdict.Code.
	ReasonRefused = "refused"
)

// Verdict is the classification of a report (draft Section 14.3).
// Qualification is QUALIFIED, UNQUALIFIED or DISPUTED, or empty for a
// duplicate, which casts no vote and is not classified. A refused report
// has Refused set and the code of its refusal; one refused for breaking an
// A.2 rule is UNQUALIFIED invalid-report, the classification the fixtures
// give it.
type Verdict struct {
	Qualification string
	Reason        string
	Refused       bool
	Code          string
}

// Answer is the answer to one ingestion: an acknowledgment status, or the
// code of a refusal.
type Answer struct {
	Ack  core.AckStatus
	Code string
}

// Manifest is the ProvenanceManifest of draft Section 15.2.
type Manifest struct {
	QualifiedEventIDs     [][2]string `json:"qualified_event_ids"`
	SupersededEventIDs    [][2]string `json:"superseded_event_ids"`
	QualificationPolicyID string      `json:"qualification_policy_id"`
	ScoringPolicyRevision string      `json:"scoring_policy_revision"`
	EvidenceCutoff        int64       `json:"evidence_cutoff"`
}

// Snapshot is the content of the snapshot that answers a query: its value,
// with provenance_digest the object_digest of Manifest, and the payload
// claims that bind it. Signing it is the caller's.
type Snapshot struct {
	Value    core.ReputationValue
	Manifest Manifest
	Claims   core.ReputationSnapshot
}

type rec struct {
	r core.OutcomeReport
	// role is the reporter_role when a trust record of the signer registers
	// it, and empty otherwise (Appendix A.2).
	role string
	// duplicate: the report repeats the deduplication tuple of an earlier
	// registered report (Section 14.6 rule 4).
	duplicate bool
}

// Oracle is the reference reputation service of draft Sections 14 and 15:
// it ingests verified outcome reports, classifies them under
// pact-qualification-v1 and pact-reporter-independence-v1 (Section 14.6),
// and answers reputation queries with beta-decay-v1 values, provenance and
// security status. It holds no clock and does no I/O: the caller passes the
// service time and verifies signatures first. Classification is recomputed
// from every report received, so a later report can change an earlier
// report's qualification, as rule 7 requires.
type Oracle struct {
	cfg     evalcase.OutcomesConfig
	native  evalcase.OutcomesNative
	recs    []*rec
	seen    map[string]core.Digest
	byEvent map[string]*rec
	tuples  map[string]bool
	refused map[string]Verdict
}

// NewOracle returns an oracle with no report.
func NewOracle(cfg evalcase.OutcomesConfig, native evalcase.OutcomesNative) *Oracle {
	return &Oracle{cfg: cfg, native: native, seen: map[string]core.Digest{}, byEvent: map[string]*rec{},
		tuples: map[string]bool{}, refused: map[string]Verdict{}}
}

// Role returns the reporter_role claimed when a trust record of iss
// registers it, and "" otherwise.
func (o *Oracle) Role(iss string, claimed core.ReporterRole) string {
	for _, t := range o.cfg.Trust {
		if t.Iss == iss && t.ReporterRole != nil && *t.ReporterRole == string(claimed) {
			return string(claimed)
		}
	}
	return ""
}

// kindDimensions are the dimensions Section 14.5 gives each event_kind
// (Appendix A.2): reliability is observed only by an execution report,
// task_quality and policy_adherence only by an assessment, a SECURITY
// report, or a remediation of none. A CORRECTION, absent here, carries the
// dimension of the events it supersedes.
var kindDimensions = map[core.EventKind][]core.Dimension{
	core.EventAdmission:     {core.DimensionNone},
	core.EventAuthorization: {core.DimensionNone},
	core.EventExecution:     {core.DimensionReliability, core.DimensionNone},
	core.EventQuality:       {core.DimensionTaskQuality, core.DimensionPolicyAdherence},
	core.EventFeedback:      {core.DimensionTaskQuality, core.DimensionPolicyAdherence},
	core.EventSecurity:      {core.DimensionPolicyAdherence, core.DimensionNone},
	core.EventRemediation:   {core.DimensionNone},
}

// ValidReport applies the OutcomeReport schema of Appendix A.3 and the
// rules of Appendix A.2 that make a report invalid: CORRECTION and
// supersedes, dimension none for ADMISSION, AUTHORIZATION and for UNKNOWN
// other than a CORRECTION, which carries the dimension of the events it
// supersedes, and the dimensions of each event_kind.
func ValidReport(r core.OutcomeReport) error {
	if err := learning.ValidateReport(r); err != nil {
		return err
	}
	switch dims, ok := kindDimensions[r.EventKind]; {
	case (r.EventKind == core.EventAdmission || r.EventKind == core.EventAuthorization) && r.Dimension != core.DimensionNone:
		return errors.New("ADMISSION and AUTHORIZATION events use dimension none (Appendix A.2)")
	case r.Result == core.OutcomeUnknown && r.Dimension != core.DimensionNone && r.EventKind != core.EventCorrection:
		return errors.New("a report with result UNKNOWN other than a CORRECTION uses dimension none (Appendix A.2)")
	case ok && !slices.Contains(dims, r.Dimension):
		return errors.New("the dimension is not one Section 14.5 gives the event_kind (Appendix A.2)")
	}
	return nil
}

func (o *Oracle) refuse(r *core.OutcomeReport, v Verdict) Answer {
	if r != nil && r.EventID != "" {
		if _, ok := o.byEvent[r.EventID]; !ok {
			o.refused[r.EventID] = v
		}
	}
	return Answer{Code: v.Code}
}

// Refuse records that a report could not be accepted before it was decoded
// or verified, such as one whose signature does not verify. event is its
// event_id when known.
func (o *Oracle) Refuse(event, code string) Answer {
	if event == "" {
		return Answer{Code: code}
	}
	return o.refuse(&core.OutcomeReport{EventID: event}, Verdict{Qualification: "", Reason: ReasonRefused, Refused: true, Code: code})
}

// Ingest applies a report whose signature the caller has verified, at the
// service time now (Sections 7.5, 13.2, 14.3): a report that breaks
// Appendix A.2 or A.3 is INVALID_MESSAGE, as is one valid for more than 300
// seconds, issued in the future, or observed outside the ingestion window;
// an elapsed exp is EXPIRED; another audience, tenant or environment is
// CONTEXT_MISMATCH. An identical retry of an (iss, jti) is DUPLICATE and
// another payload under it ID_CONFLICT, as is an event_id another report
// already carries. A report that repeats the deduplication tuple of an
// earlier registered report is acknowledged DUPLICATE and casts no vote.
func (o *Oracle) Ingest(r core.OutcomeReport, now int64) Answer {
	if err := ValidReport(r); err != nil {
		return o.refuse(&r, Verdict{Qualification: evalcase.Unqualified, Reason: ReasonInvalidReport, Refused: true, Code: CodeInvalidMessage})
	}
	svc, skew := o.cfg.ReputationService, o.cfg.ClockSkewSeconds
	code := ""
	switch {
	case r.Expiry-r.IssuedAt > evalcase.SnapshotLifetime, r.IssuedAt > now+skew, r.NotBefore > now+skew:
		code = CodeInvalidMessage
	case now >= r.Expiry:
		code = CodeExpired
	case r.Audience != svc.ServiceID, r.TenantID != svc.TenantID, r.EnvironmentID != svc.EnvironmentID:
		code = CodeContextMismatch
	case r.ObservedAt > now+skew, now-r.ObservedAt > o.cfg.DataPolicy.IngestionWindowSeconds:
		code = CodeInvalidMessage
	}
	if code != "" {
		return o.refuse(&r, Verdict{Reason: ReasonRefused, Refused: true, Code: code})
	}
	pd, err := digest.ObjectDigest(r)
	if err != nil {
		return o.refuse(&r, Verdict{Reason: ReasonRefused, Refused: true, Code: CodeInvalidMessage})
	}
	key := r.Issuer + "\x00" + r.JTI
	if prev, ok := o.seen[key]; ok {
		if prev == pd {
			return Answer{Ack: core.AckDuplicate}
		}
		return Answer{Code: CodeIDConflict}
	}
	if _, ok := o.byEvent[r.EventID]; ok {
		return Answer{Code: CodeIDConflict}
	}
	o.seen[key] = pd
	x := &rec{r: r, role: o.Role(r.Issuer, r.ReporterRole)}
	o.recs = append(o.recs, x)
	o.byEvent[r.EventID] = x
	if x.role == "" {
		// It casts no vote, so it takes no tuple a later registered report
		// could repeat.
		return Answer{Ack: core.AckAccepted}
	}
	tuple := strings.Join([]string{r.TaskID, r.OperationID, string(r.EventKind), string(r.Dimension), r.Issuer}, "\x00")
	if o.tuples[tuple] {
		x.duplicate = true
		return Answer{Ack: core.AckDuplicate}
	}
	o.tuples[tuple] = true
	return Answer{Ack: core.AckAccepted}
}

// Verdicts returns the classification of every report received so far, by
// event_id: the refused ones included, the duplicates with an empty
// qualification and reason duplicate.
func (o *Oracle) Verdicts() map[string]Verdict {
	out := map[string]Verdict{}
	for id, v := range o.refused {
		out[id] = v
	}
	cls := o.classify().verdicts
	for _, x := range o.recs {
		out[x.r.EventID] = cls[x]
	}
	return out
}

func sameContext(a, b core.ReputationContext) bool {
	return a.TenantID == b.TenantID && a.EnvironmentID == b.EnvironmentID && a.AgentID == b.AgentID && a.PurposeID == b.PurposeID &&
		a.ActionClass == b.ActionClass && a.ResourceClass == b.ResourceClass && a.RuntimeClass == b.RuntimeClass
}

// lessUTF16 orders strings by UTF-16 code units, as RFC 8785 orders
// property names (Section 15.2).
func lessUTF16(a, b string) int {
	ua, ub := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	return slices.Compare(ua, ub)
}

// SortPairs sorts [iss, jti] pairs by iss, then jti, by UTF-16 code units.
func SortPairs(p [][2]string) {
	slices.SortFunc(p, func(a, b [2]string) int {
		if c := lessUTF16(a[0], b[0]); c != 0 {
			return c
		}
		return lessUTF16(a[1], b[1])
	})
}
