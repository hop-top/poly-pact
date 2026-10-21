package reputation

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"slices"
	"sync"

	"hop.top/pact-go/core"
	"hop.top/pact-go/core/digest"
	"hop.top/pact-go/core/jws"
	"hop.top/pact-go/core/strictjson"
)

// The Section 13.4 codes the service answers with.
const (
	CodeInvalidMessage        = "INVALID_MESSAGE"
	CodeInvalidProof          = "INVALID_PROOF"
	CodeContextMismatch       = "CONTEXT_MISMATCH"
	CodeExpired               = "EXPIRED"
	CodeIDConflict            = "ID_CONFLICT"
	CodeDependencyUnavailable = "DEPENDENCY_UNAVAILABLE"
)

var problemStatus = map[string]int64{
	CodeInvalidMessage: 400, CodeInvalidProof: 401, CodeContextMismatch: 403, CodeExpired: 410, CodeIDConflict: 409, CodeDependencyUnavailable: 503,
}

// Deps are the collaborators of a Service. Rand defaults to crypto/rand.
type Deps struct {
	Registry Registry
	Tasks    Tasks
	Records  Records
	Store    Store
	Signer   Signer
	Rand     io.Reader
}

// Service is the reputation service of draft Sections 14 and 15: it
// ingests signed outcome reports, classifies them under the baseline
// qualification and reporter independence policies, keeps security holds,
// and answers reputation queries with signed snapshots. It holds no clock:
// every call takes the service time. It is safe for concurrent use.
type Service struct {
	cfg Config
	d   Deps
	mu  sync.Mutex
}

// New returns a Service, or an error when the configuration or a
// collaborator is missing or is not what this package implements.
func New(cfg Config, d Deps) (*Service, error) {
	if cfg.SnapshotLifetime == 0 {
		cfg.SnapshotLifetime = MaxSnapshotLifetime
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if d.Registry == nil || d.Tasks == nil || d.Records == nil || d.Store == nil || d.Signer == nil {
		return nil, errors.New("reputation: Registry, Tasks, Records, Store and Signer are required")
	}
	if d.Rand == nil {
		d.Rand = rand.Reader
	}
	return &Service{cfg: cfg, d: d}, nil
}

// randomID returns 128 random bits, base64url (Appendix A.2).
func (s *Service) randomID() (string, error) {
	b := make([]byte, 16)
	if _, err := io.ReadFull(s.d.Rand, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (s *Service) problem(code string) *core.Problem {
	id, err := s.randomID()
	if err != nil {
		id = "unavailable"
	}
	return &core.Problem{Type: "about:blank", Title: code, Status: problemStatus[code], Code: code, RequestID: id}
}

// signatureReasons are the verification failures that mean the signer
// could not be authenticated.
var signatureReasons = []jws.Reason{jws.ErrSignatureInvalid, jws.ErrKidUnknown, jws.ErrKeyUnavailable}

// Ingest receives a signed OutcomeReport at the service time now (draft
// Sections 7.5, 13.2, 13.4, 14.3, Appendix A.2): it verifies the signature
// under the signer's registered keys (INVALID_PROOF, or INVALID_MESSAGE for
// a malformed JWS or another typ), decodes the payload strictly and checks
// it against the OutcomeReport schema and the A.2 rules (INVALID_MESSAGE),
// its validity and times (INVALID_MESSAGE, EXPIRED) and its audience and
// realm (CONTEXT_MISMATCH). An identical retry of an (iss, jti) is
// DUPLICATE and changes nothing, another payload under it is ID_CONFLICT,
// as is a used event_id; a report that repeats the deduplication tuple of
// an earlier registered report is acknowledged DUPLICATE and casts no vote.
// A report whose signer is not registered for its reporter_role is
// acknowledged and classified UNQUALIFIED.
func (s *Service) Ingest(compact string, now int64) (*core.Acknowledgment, *core.Problem) {
	parsed, err := jws.Verifier{Keys: s.d.Registry, Typ: jws.TypOutcome}.Verify(compact)
	if err != nil {
		if slices.Contains(signatureReasons, jws.ReasonOf(err)) {
			return nil, s.problem(CodeInvalidProof)
		}
		return nil, s.problem(CodeInvalidMessage)
	}
	var r core.OutcomeReport
	if err := strictjson.Unmarshal(parsed.Payload, strictjson.Limits{}, &r); err != nil {
		return nil, s.problem(CodeInvalidMessage)
	}
	if err := ValidateReport(r); err != nil {
		return nil, s.problem(CodeInvalidMessage)
	}
	if code := s.envelope(r, now); code != "" {
		return nil, s.problem(code)
	}
	pd, err := digest.ObjectDigest(r)
	if err != nil {
		return nil, s.problem(CodeInvalidMessage)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.d.Store
	prev, ok, err := st.ByKey(r.Issuer, r.JTI)
	if err != nil {
		return nil, s.problem(CodeDependencyUnavailable)
	}
	if ok {
		if prev.PayloadDigest != pd {
			return nil, s.problem(CodeIDConflict)
		}
		return s.ack(r, core.AckDuplicate, now)
	}
	rec := Stored{Report: r, PayloadDigest: pd, ReceivedAt: now, Registered: s.d.Registry.Registered(r.Issuer, r.ReporterRole)}
	if rec.Registered {
		taken, err := st.TupleTaken(TupleOf(r))
		if err != nil {
			return nil, s.problem(CodeDependencyUnavailable)
		}
		rec.Duplicate = taken
	}
	if err := st.Append(rec, rec.Registered && !rec.Duplicate); err != nil {
		if errors.Is(err, ErrConflict) {
			return nil, s.problem(CodeIDConflict)
		}
		return nil, s.problem(CodeDependencyUnavailable)
	}
	if rec.Duplicate {
		return s.ack(r, core.AckDuplicate, now)
	}
	return s.ack(r, core.AckAccepted, now)
}

func (s *Service) ack(r core.OutcomeReport, status core.AckStatus, now int64) (*core.Acknowledgment, *core.Problem) {
	id, err := s.randomID()
	if err != nil {
		return nil, s.problem(CodeDependencyUnavailable)
	}
	return &core.Acknowledgment{RequestID: id, Status: status, ArtifactID: r.EventID, ReceivedAt: now}, nil
}

// envelope applies the time and context rules of Sections 7.5 and 13.4 and
// the ingestion window of Section 14.3, and returns the code of the first
// broken, or "".
func (s *Service) envelope(r core.OutcomeReport, now int64) string {
	skew := s.cfg.ClockSkewSeconds
	switch {
	case r.IssuedAt > now+skew || r.NotBefore > now+skew || r.Expiry-r.IssuedAt > MaxSnapshotLifetime:
		return CodeInvalidMessage
	case now >= r.Expiry:
		return CodeExpired
	case r.Audience != s.cfg.ServiceID || r.TenantID != s.cfg.TenantID || r.EnvironmentID != s.cfg.EnvironmentID:
		return CodeContextMismatch
	case r.ObservedAt > now+skew || now-r.ObservedAt > s.cfg.DataPolicy.IngestionWindowSeconds:
		return CodeInvalidMessage
	}
	return ""
}

// ValidateReport applies the OutcomeReport schema of Appendix A.3 that
// strict decoding does not enforce, and the rules of Appendix A.2 that make
// a report invalid.
func ValidateReport(r core.OutcomeReport) error {
	switch {
	case r.PactVersion != core.Version:
		return fmt.Errorf("pact_version %q", r.PactVersion)
	case !validJTI(r.JTI):
		return errors.New("jti is not 22 to 128 base64url characters")
	case r.IssuedAt < 0 || r.NotBefore < 0 || r.Expiry < 0 || r.ObservedAt < 0 || r.IssuedAt >= r.Expiry || r.NotBefore >= r.Expiry:
		return errors.New("iat and nbf are before exp, and no time is negative")
	case !bounded(r.Issuer, r.Subject, r.Audience, r.TenantID, r.EventID, r.EnvironmentID, r.TaskID, r.OperationID,
		r.Context.TenantID, r.Context.EnvironmentID, r.Context.AgentID, r.Context.PurposeID, r.Context.ActionClass,
		r.Context.ResourceClass, r.Context.RuntimeClass, r.Attribution.NativeTaskRef, r.Attribution.IndependenceGroup):
		return errors.New("a required string is empty or longer than 1024 characters")
	case !r.ReporterRole.Valid() || !r.EventKind.Valid() || !r.Result.Valid() || !r.Dimension.Valid() || !r.Severity.Valid() ||
		!r.Attribution.CausalAssessment.Valid():
		return errors.New("an enumerated member has no defined value")
	case r.EvidenceRefs == nil || r.Supersedes == nil || !uniqueBounded(r.EvidenceRefs) || !uniqueBounded(r.Supersedes):
		return errors.New("evidence_refs and supersedes are arrays of at most 64 distinct strings")
	case len(r.Details) > 4096:
		return errors.New("details is longer than 4096 characters")
	case (r.EventKind == core.EventCorrection) != (len(r.Supersedes) > 0):
		return errors.New("a CORRECTION, and only a CORRECTION, has a nonempty supersedes")
	case (r.EventKind == core.EventAdmission || r.EventKind == core.EventAuthorization) && r.Dimension != core.DimensionNone:
		return errors.New("ADMISSION and AUTHORIZATION events use dimension none")
	case r.Result == core.OutcomeUnknown && r.Dimension != core.DimensionNone && r.EventKind != core.EventCorrection:
		// A correction carries the dimension of the events it supersedes
		// (Section 14.6 rule 10).
		return errors.New("a report with result UNKNOWN, other than a CORRECTION, uses dimension none")
	case !dimensionOfKind(r.EventKind, r.Dimension):
		return fmt.Errorf("dimension %s is not one of %s", r.Dimension, r.EventKind)
	}
	return nil
}

// dimensionOfKind reports whether Section 14.5 gives the event_kind the
// dimension (Appendix A.2): an execution report observes reliability, an
// assessment or feedback task_quality or policy_adherence, a SECURITY
// report policy_adherence or none, a remediation none. A CORRECTION carries
// the dimension of the events it supersedes, which classification checks
// (Section 14.6 rule 10).
func dimensionOfKind(k core.EventKind, d core.Dimension) bool {
	switch k {
	case core.EventExecution:
		return d == core.DimensionReliability || d == core.DimensionNone
	case core.EventQuality, core.EventFeedback:
		return d == core.DimensionTaskQuality || d == core.DimensionPolicyAdherence
	case core.EventSecurity:
		return d == core.DimensionPolicyAdherence || d == core.DimensionNone
	case core.EventRemediation, core.EventAdmission, core.EventAuthorization:
		return d == core.DimensionNone
	}
	return true
}

func validJTI(s string) bool {
	if len(s) < 22 || len(s) > 128 {
		return false
	}
	for i := range len(s) {
		c := s[i]
		if (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '_' {
			return false
		}
	}
	return true
}

func bounded(ss ...string) bool {
	return !slices.ContainsFunc(ss, func(s string) bool { return s == "" || len(s) > 1024 })
}

func uniqueBounded(ss []string) bool {
	if len(ss) > 64 || !bounded(ss...) {
		return false
	}
	c := slices.Clone(ss)
	slices.Sort(c)
	return len(slices.Compact(c)) == len(ss)
}
