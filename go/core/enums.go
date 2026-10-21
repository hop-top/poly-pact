package core

import "slices"

// Version is the only pact_version value of this draft.
const Version = "0.1"

// RuleSource says where a field rule's fact must come from.
type RuleSource string

const (
	RuleSourceSelf     RuleSource = "self"
	RuleSourceEvidence RuleSource = "evidence"
	RuleSourceNative   RuleSource = "native"
)

var ruleSourceValues = []RuleSource{RuleSourceSelf, RuleSourceEvidence, RuleSourceNative}

// Valid reports whether s is a defined value.
func (s RuleSource) Valid() bool { return slices.Contains(ruleSourceValues, s) }

// Comparison is how a field rule compares the presented value.
type Comparison string

const (
	ComparisonEqual  Comparison = "equal"
	ComparisonSubset Comparison = "subset"
)

var comparisonValues = []Comparison{ComparisonEqual, ComparisonSubset}

// Valid reports whether c is a defined value.
func (c Comparison) Valid() bool { return slices.Contains(comparisonValues, c) }

// Mode is the enforcement mode of a contract, attestation or gateway.
type Mode string

const (
	ModeEnforced Mode = "enforced"
	ModeObserve  Mode = "observe"
)

var modeValues = []Mode{ModeEnforced, ModeObserve}

// Valid reports whether m is a defined value.
func (m Mode) Valid() bool { return slices.Contains(modeValues, m) }

// EvidenceKind is the kind of an evidence artifact.
type EvidenceKind string

const (
	EvidenceKindIdentity   EvidenceKind = "identity"
	EvidenceKindMembership EvidenceKind = "membership"
	EvidenceKindDelegation EvidenceKind = "delegation"
	EvidenceKindRuntime    EvidenceKind = "runtime"
	EvidenceKindCapability EvidenceKind = "capability"
	EvidenceKindApproval   EvidenceKind = "approval"
)

var evidenceKindValues = []EvidenceKind{
	EvidenceKindIdentity, EvidenceKindMembership, EvidenceKindDelegation,
	EvidenceKindRuntime, EvidenceKindCapability, EvidenceKindApproval,
}

// Valid reports whether k is a defined value.
func (k EvidenceKind) Valid() bool { return slices.Contains(evidenceKindValues, k) }

// CheckStatus is the result of one admission check.
type CheckStatus string

const (
	CheckPass          CheckStatus = "PASS"
	CheckFail          CheckStatus = "FAIL"
	CheckUnknown       CheckStatus = "UNKNOWN"
	CheckNotApplicable CheckStatus = "NOT_APPLICABLE"
)

var checkStatusValues = []CheckStatus{CheckPass, CheckFail, CheckUnknown, CheckNotApplicable}

// Valid reports whether s is a defined value.
func (s CheckStatus) Valid() bool { return slices.Contains(checkStatusValues, s) }

// Decision is the admission decision of an attestation.
type Decision string

const (
	DecisionAdmissible   Decision = "ADMISSIBLE"
	DecisionInadmissible Decision = "INADMISSIBLE"
	DecisionDeferred     Decision = "DEFERRED"
)

var decisionValues = []Decision{DecisionAdmissible, DecisionInadmissible, DecisionDeferred}

// Valid reports whether d is a defined value.
func (d Decision) Valid() bool { return slices.Contains(decisionValues, d) }

// TerminalReason is the terminal state recorded in an attestation.
type TerminalReason string

const (
	TerminalCompleted TerminalReason = "COMPLETED"
	TerminalCancelled TerminalReason = "CANCELLED"
	TerminalExpired   TerminalReason = "EXPIRED"
)

var terminalReasonValues = []TerminalReason{TerminalCompleted, TerminalCancelled, TerminalExpired}

// Valid reports whether r is a defined value.
func (r TerminalReason) Valid() bool { return slices.Contains(terminalReasonValues, r) }

// SecurityStatus is the security standing of a reputation value.
type SecurityStatus string

const (
	SecurityClear   SecurityStatus = "CLEAR"
	SecurityCaution SecurityStatus = "CAUTION"
	SecurityHold    SecurityStatus = "HOLD"
	SecurityUnknown SecurityStatus = "UNKNOWN"
)

var securityStatusValues = []SecurityStatus{SecurityClear, SecurityCaution, SecurityHold, SecurityUnknown}

// Valid reports whether s is a defined value.
func (s SecurityStatus) Valid() bool { return slices.Contains(securityStatusValues, s) }

// CausalAssessment says who caused an outcome.
type CausalAssessment string

const (
	CausalAgent       CausalAssessment = "AGENT"
	CausalEnvironment CausalAssessment = "ENVIRONMENT"
	CausalMixed       CausalAssessment = "MIXED"
	CausalUnknown     CausalAssessment = "UNKNOWN"
)

var causalAssessmentValues = []CausalAssessment{CausalAgent, CausalEnvironment, CausalMixed, CausalUnknown}

// Valid reports whether a is a defined value.
func (a CausalAssessment) Valid() bool { return slices.Contains(causalAssessmentValues, a) }

// ReporterRole is the role of the party that reports an outcome.
type ReporterRole string

const (
	ReporterGateway           ReporterRole = "gateway"
	ReporterExecutor          ReporterRole = "executor"
	ReporterEvaluator         ReporterRole = "evaluator"
	ReporterTaskOwner         ReporterRole = "task_owner"
	ReporterSecurityAuthority ReporterRole = "security_authority"
	ReporterAgent             ReporterRole = "agent"
)

var reporterRoleValues = []ReporterRole{
	ReporterGateway, ReporterExecutor, ReporterEvaluator,
	ReporterTaskOwner, ReporterSecurityAuthority, ReporterAgent,
}

// Valid reports whether r is a defined value.
func (r ReporterRole) Valid() bool { return slices.Contains(reporterRoleValues, r) }

// EventKind is the kind of an outcome event.
type EventKind string

const (
	EventAdmission     EventKind = "ADMISSION"
	EventAuthorization EventKind = "AUTHORIZATION"
	EventExecution     EventKind = "EXECUTION"
	EventQuality       EventKind = "QUALITY"
	EventSecurity      EventKind = "SECURITY"
	EventFeedback      EventKind = "FEEDBACK"
	EventCorrection    EventKind = "CORRECTION"
	EventRemediation   EventKind = "REMEDIATION"
)

var eventKindValues = []EventKind{
	EventAdmission, EventAuthorization, EventExecution, EventQuality,
	EventSecurity, EventFeedback, EventCorrection, EventRemediation,
}

// Valid reports whether k is a defined value.
func (k EventKind) Valid() bool { return slices.Contains(eventKindValues, k) }

// OutcomeResult is the result an outcome report states.
type OutcomeResult string

const (
	OutcomeSuccess       OutcomeResult = "SUCCESS"
	OutcomeFailure       OutcomeResult = "FAILURE"
	OutcomeUnknown       OutcomeResult = "UNKNOWN"
	OutcomeNotApplicable OutcomeResult = "NOT_APPLICABLE"
)

var outcomeResultValues = []OutcomeResult{OutcomeSuccess, OutcomeFailure, OutcomeUnknown, OutcomeNotApplicable}

// Valid reports whether r is a defined value.
func (r OutcomeResult) Valid() bool { return slices.Contains(outcomeResultValues, r) }

// Dimension is the reputation dimension an outcome counts toward.
type Dimension string

const (
	DimensionReliability     Dimension = "reliability"
	DimensionTaskQuality     Dimension = "task_quality"
	DimensionPolicyAdherence Dimension = "policy_adherence"
	DimensionNone            Dimension = "none"
)

var dimensionValues = []Dimension{DimensionReliability, DimensionTaskQuality, DimensionPolicyAdherence, DimensionNone}

// Valid reports whether d is a defined value.
func (d Dimension) Valid() bool { return slices.Contains(dimensionValues, d) }

// Severity is the severity of an outcome.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

var severityValues = []Severity{SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical}

// Valid reports whether s is a defined value.
func (s Severity) Valid() bool { return slices.Contains(severityValues, s) }

// BoundDirection says whether a metric bound is a lower or an upper limit.
type BoundDirection string

const (
	BoundLower BoundDirection = "lower"
	BoundUpper BoundDirection = "upper"
)

var boundDirectionValues = []BoundDirection{BoundLower, BoundUpper}

// Valid reports whether d is a defined value.
func (d BoundDirection) Valid() bool { return slices.Contains(boundDirectionValues, d) }

// LearningMode is the operating mode of a learning policy.
type LearningMode string

const (
	LearningObserve           LearningMode = "observe"
	LearningBoundedAutonomous LearningMode = "bounded_autonomous"
)

var learningModeValues = []LearningMode{LearningObserve, LearningBoundedAutonomous}

// Valid reports whether m is a defined value.
func (m LearningMode) Valid() bool { return slices.Contains(learningModeValues, m) }

// ArtifactType is the model type of a learning artifact.
type ArtifactType string

const (
	ArtifactBaseline            ArtifactType = "baseline"
	ArtifactScore               ArtifactType = "score"
	ArtifactRequirementSelector ArtifactType = "requirement_selector"
	ArtifactCalibrator          ArtifactType = "calibrator"
	ArtifactAssessment          ArtifactType = "assessment"
)

var artifactTypeValues = []ArtifactType{
	ArtifactBaseline, ArtifactScore, ArtifactRequirementSelector,
	ArtifactCalibrator, ArtifactAssessment,
}

// Valid reports whether a is a defined value.
func (a ArtifactType) Valid() bool { return slices.Contains(artifactTypeValues, a) }

// Transition is the lifecycle transition a learning event requests.
type Transition string

const (
	TransitionEvaluated  Transition = "EVALUATED"
	TransitionShadow     Transition = "SHADOW"
	TransitionActive     Transition = "ACTIVE"
	TransitionFrozen     Transition = "FROZEN"
	TransitionRolledBack Transition = "ROLLED_BACK"
	TransitionRetired    Transition = "RETIRED"
)

var transitionValues = []Transition{
	TransitionEvaluated, TransitionShadow, TransitionActive,
	TransitionFrozen, TransitionRolledBack, TransitionRetired,
}

// Valid reports whether tr is a defined value.
func (tr Transition) Valid() bool { return slices.Contains(transitionValues, tr) }

// LifecycleState is the state a learning artifact is expected to be in.
type LifecycleState string

const (
	StateCandidate  LifecycleState = "CANDIDATE"
	StateEvaluated  LifecycleState = "EVALUATED"
	StateShadow     LifecycleState = "SHADOW"
	StateActive     LifecycleState = "ACTIVE"
	StateFrozen     LifecycleState = "FROZEN"
	StateRolledBack LifecycleState = "ROLLED_BACK"
	StateRetired    LifecycleState = "RETIRED"
)

var lifecycleStateValues = []LifecycleState{
	StateCandidate, StateEvaluated, StateShadow, StateActive,
	StateFrozen, StateRolledBack, StateRetired,
}

// Valid reports whether s is a defined value.
func (s LifecycleState) Valid() bool { return slices.Contains(lifecycleStateValues, s) }

// AckStatus is the status of an Acknowledgment.
type AckStatus string

const (
	AckAccepted  AckStatus = "ACCEPTED"
	AckDuplicate AckStatus = "DUPLICATE"
)

var ackStatusValues = []AckStatus{AckAccepted, AckDuplicate}

// Valid reports whether s is a defined value.
func (s AckStatus) Valid() bool { return slices.Contains(ackStatusValues, s) }

// JWSAlgorithm is a JWS algorithm a gateway accepts.
type JWSAlgorithm string

const (
	AlgES256   JWSAlgorithm = "ES256"
	AlgEd25519 JWSAlgorithm = "Ed25519"
)

var jwsAlgorithmValues = []JWSAlgorithm{AlgES256, AlgEd25519}

// Valid reports whether a is a defined value.
func (a JWSAlgorithm) Valid() bool { return slices.Contains(jwsAlgorithmValues, a) }

// PresentationTransport is a way to carry a presentation to a gateway.
type PresentationTransport string

const (
	TransportHeader          PresentationTransport = "header"
	TransportGatewayEvaluate PresentationTransport = "gateway-evaluate"
	TransportAdapterEnvelope PresentationTransport = "adapter-envelope"
)

var presentationTransportValues = []PresentationTransport{
	TransportHeader, TransportGatewayEvaluate, TransportAdapterEnvelope,
}

// Valid reports whether t is a defined value.
func (t PresentationTransport) Valid() bool { return slices.Contains(presentationTransportValues, t) }
