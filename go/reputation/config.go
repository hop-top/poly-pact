package reputation

import (
	"errors"
	"fmt"
	"unicode/utf8"

	"hop.top/pact-go/core"
	"hop.top/pact-go/core/jws"
	"hop.top/pact-go/core/strictjson"
)

// The baseline policies this package implements (draft Section 14.6).
const (
	QualificationPolicyID        = "pact-qualification-v1"
	ReporterIndependencePolicyID = "pact-reporter-independence-v1"
)

// MaxSnapshotLifetime is the baseline bound on a snapshot's validity and
// the maximum validity of a signed report, in seconds (draft Sections 14.3
// and 15.2).
const MaxSnapshotLifetime int64 = 300

// MaxFailureWeight is the largest weight one failure may carry: a normal
// attributable failure weighs 1, and up to 5 under an explicitly approved
// severity rule (draft Section 15.3). It bounds a data policy's
// maximum_failure_weight (Appendix A.3).
const MaxFailureWeight int64 = 5

// CheckMaximumFailureWeight checks a data policy's maximum_failure_weight:
// 1 to MaxFailureWeight (draft Section 15.3, Appendix A.3).
func CheckMaximumFailureWeight(w int64) error {
	if w < 1 || w > MaxFailureWeight {
		return fmt.Errorf("maximum_failure_weight %d is outside 1..%d (draft Section 15.3)", w, MaxFailureWeight)
	}
	return nil
}

// The other bounds of a data policy, those of the DataPolicy schema of
// Appendix A.3.
const (
	// PositiveWeightCapPerTask is the only permitted
	// positive_weight_cap_per_task: at most one positive weight unit per
	// independent native task group and dimension (draft Section 15.3).
	PositiveWeightCapPerTask int64 = 1
	// MaxIngestionWindowSeconds bounds ingestion_window_seconds, which is
	// at least 1 (draft Section 14.3; Appendix A.3, the integer range of
	// every wire integer).
	MaxIngestionWindowSeconds int64 = strictjson.MaxSafeInteger
	// maxDataPolicyString is the maxLength of the identifier members, in
	// characters; maxDataPolicyExtensions the maxProperties of extensions.
	maxDataPolicyString     = 1024
	maxDataPolicyExtensions = 128
)

// CheckDataPolicy checks every bound of a data policy (Appendix A.3
// DataPolicy): ingestion_window_seconds 1 to MaxIngestionWindowSeconds
// (draft Section 14.3), positive_weight_cap_per_task exactly
// PositiveWeightCapPerTask and maximum_failure_weight 1 to MaxFailureWeight
// (draft Section 15.3), qualification_policy_id, task_attribution_source
// and reporter_independence_policy_id 1 to 1024 characters, and at most 128
// extensions. Every reader of a data policy applies it. The error names the
// first member out of bounds.
func CheckDataPolicy(d core.DataPolicy) error {
	if d.IngestionWindowSeconds < 1 || d.IngestionWindowSeconds > MaxIngestionWindowSeconds {
		return fmt.Errorf("ingestion_window_seconds %d is outside 1..%d (draft Section 14.3, Appendix A.3)", d.IngestionWindowSeconds, MaxIngestionWindowSeconds)
	}
	if d.PositiveWeightCapPerTask != PositiveWeightCapPerTask {
		return fmt.Errorf("positive_weight_cap_per_task %d is not %d (draft Section 15.3, Appendix A.3)", d.PositiveWeightCapPerTask, PositiveWeightCapPerTask)
	}
	if err := CheckMaximumFailureWeight(d.MaximumFailureWeight); err != nil {
		return err
	}
	for _, m := range []struct{ name, value string }{
		{"qualification_policy_id", d.QualificationPolicyID},
		{"task_attribution_source", d.TaskAttributionSource},
		{"reporter_independence_policy_id", d.ReporterIndependencePolicyID},
	} {
		if n := utf8.RuneCountInString(m.value); n < 1 || n > maxDataPolicyString {
			return fmt.Errorf("%s has %d characters, want 1 to %d (Appendix A.3)", m.name, n, maxDataPolicyString)
		}
	}
	if n := len(d.Extensions); n > maxDataPolicyExtensions {
		return fmt.Errorf("extensions has %d members, at most %d (Appendix A.3)", n, maxDataPolicyExtensions)
	}
	return nil
}

// Qualification is the classification of a report (draft Section 14.3).
type Qualification string

// Qualifications.
const (
	Qualified   Qualification = "QUALIFIED"
	Unqualified Qualification = "UNQUALIFIED"
	Disputed    Qualification = "DISPUTED"
)

// Task is an authoritative task record: the agent, its operator and
// principal, the independence group that task_attribution_source assigns
// (Section 14.6 rule 1) and the holder key the task's admission bound.
type Task struct {
	TaskID            string
	AgentID           string
	OperatorID        string
	PrincipalID       string
	IndependenceGroup string
	HolderJKT         core.Digest
}

// RecordKind is the kind of an immutable native record an evidence
// reference cites.
type RecordKind string

// Record kinds and the states this package reads.
const (
	RecordExecution     RecordKind = "execution"     // accepted, completed, failed
	RecordAuthorization RecordKind = "authorization" // allowed, denied
	RecordAssessment    RecordKind = "assessment"    // completed
	RecordIncident      RecordKind = "incident"      // confirmed
	RecordRemediation   RecordKind = "remediation"   // completed
	RecordViolation     RecordKind = "violation"     // recorded: a gateway's record of a violating request
)

// Executor is the executor identity a native record names (Section 17.5).
type Executor struct {
	Class       string
	PrincipalID string
}

// Record is an immutable native record. Executor is nil when the record
// does not identify one.
type Record struct {
	Kind        RecordKind
	State       string
	TaskID      string
	OperationID string
	Executor    *Executor
	ObservedAt  int64
}

// ExecutorClass is one entry of the installed execution-identity mapping
// (Section 17.5): the class of the executor of a task's operation, and,
// when ExecutorID is set, its identity.
type ExecutorClass struct {
	TaskID      string
	OperationID string
	Class       string
	ExecutorID  *string
}

// Affiliation pairs an evaluator with an operator it is affiliated with
// (Section 14.6 rule 6).
type Affiliation struct {
	EvaluatorIss string
	OperatorID   string
}

// EvaluatorAgent names the agent an evaluator operates and the operator
// that runs it (Section 14.6 rule 7).
type EvaluatorAgent struct {
	EvaluatorIss string
	AgentID      string
	OperatorID   string
}

// Config is the trusted configuration of a reputation service (draft
// Section 4.2).
type Config struct {
	// ServiceID is the audience of every report and the iss of every
	// snapshot; TenantID and EnvironmentID its realm.
	ServiceID     string
	TenantID      string
	EnvironmentID string
	// ClockSkewSeconds is the allowed clock skew (Section 7.5).
	ClockSkewSeconds int64
	// DataPolicy is the data policy of the learning policy (Appendix B.9).
	// Its qualification and reporter independence policies must be the
	// baselines this package implements.
	DataPolicy core.DataPolicy
	// ScoringArtifactDigest and ScoringPolicyRevision are the scorer the
	// snapshots pin (Section 15.2).
	ScoringArtifactDigest core.Digest
	ScoringPolicyRevision string
	// ExecutionVisible is false when the gateway profile declares absent
	// execution visibility (Section 14.5).
	ExecutionVisible bool
	ExecutorClasses  []ExecutorClass
	Affiliations     []Affiliation
	EvaluatorAgents  []EvaluatorAgent
	// HoldClearanceAuthorities are the issuers whose REMEDIATION may clear
	// a hold (Sections 15.4, 16.5).
	HoldClearanceAuthorities []string
	// SnapshotLifetime is the validity of a snapshot, at most and by
	// default MaxSnapshotLifetime.
	SnapshotLifetime int64
}

func (c Config) validate() error {
	switch {
	case c.ServiceID == "" || c.TenantID == "" || c.EnvironmentID == "":
		return errors.New("reputation: ServiceID, TenantID and EnvironmentID are required")
	case c.ClockSkewSeconds < 0:
		return errors.New("reputation: ClockSkewSeconds is negative")
	}
	if err := CheckDataPolicy(c.DataPolicy); err != nil {
		return fmt.Errorf("reputation: data_policy: %w", err)
	}
	switch {
	case c.DataPolicy.QualificationPolicyID != QualificationPolicyID:
		return fmt.Errorf("reputation: qualification policy %q is not %s, the policy this package implements", c.DataPolicy.QualificationPolicyID, QualificationPolicyID)
	case c.DataPolicy.ReporterIndependencePolicyID != ReporterIndependencePolicyID:
		return fmt.Errorf("reputation: reporter independence policy %q is not %s", c.DataPolicy.ReporterIndependencePolicyID, ReporterIndependencePolicyID)
	case c.ScoringArtifactDigest == "" || c.ScoringPolicyRevision == "":
		return errors.New("reputation: the scoring pins are required")
	case c.SnapshotLifetime < 0 || c.SnapshotLifetime > MaxSnapshotLifetime:
		return fmt.Errorf("reputation: SnapshotLifetime %d is not in 1..%d", c.SnapshotLifetime, MaxSnapshotLifetime)
	}
	return nil
}

// Registry is the trusted registration of reporters (Section 14.2,
// Appendix A.2): the keys of each signer, which a report's signature must
// verify under, and the reporter roles each is registered for.
type Registry interface {
	// TrustedKeys returns the keys of the request's iss for the reporter
	// role; jws.Verifier calls it.
	jws.KeyResolver
	// Registered reports whether iss is registered for role.
	Registered(iss string, role core.ReporterRole) bool
}

// Tasks resolves the authoritative task records (Section 14.6 rules 1 and
// 2).
type Tasks interface {
	Task(taskID string) (Task, bool)
}

// Records resolves native record references (Sections 14.2, 17.5).
type Records interface {
	Record(ref string) (Record, bool)
}

// Signer signs the payload of a snapshot as a compact JWS of typ
// pact-reputation+jwt.
type Signer interface {
	SignSnapshot(payload []byte) (string, error)
}
