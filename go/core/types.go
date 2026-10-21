package core

import "encoding/json"

// Object is an open JSON object: the "attributes" and "extensions" members,
// where the schema allows any member. Values stay raw so that decoding and
// encoding do not alter them.
type Object map[string]json.RawMessage

// The signed artifacts (RequirementContract, Evidence, Presentation,
// AdmissionAttestation, ReputationSnapshot, OutcomeReport, LearningPolicy,
// LearningArtifact, LearningEvent) share the claims pact_version, iss, sub,
// aud, jti, iat, nbf, exp and tenant_id. PactVersion must equal Version. The
// artifact types are plain structs without an embedded claims type, so each
// struct mirrors its schema entry one to one.

// AgentProfile is an agent's enrolled profile.
type AgentProfile struct {
	ProfileID  string `json:"profile_id"`
	Revision   int64  `json:"revision"`
	AgentID    string `json:"agent_id"`
	OperatorID string `json:"operator_id"`
	TenantID   string `json:"tenant_id"`
	HolderJKT  Digest `json:"holder_jkt"`
	CreatedAt  int64  `json:"created_at"`
	ExpiresAt  int64  `json:"expires_at"`
	Attributes Object `json:"attributes"`
	Extensions Object `json:"extensions,omitzero"`
}

// Intent is the declared intent of an operation.
type Intent struct {
	IntentID    string `json:"intent_id"`
	PurposeID   string `json:"purpose_id"`
	Description string `json:"description"`
	TaskID      string `json:"task_id"`
	Extensions  Object `json:"extensions,omitzero"`
}

// OperationContext is the operation a gateway derives from a real request.
type OperationContext struct {
	OperationID   string            `json:"operation_id"`
	EnvironmentID string            `json:"environment_id"`
	PrincipalID   string            `json:"principal_id"`
	Action        string            `json:"action"`
	Resources     []string          `json:"resources"`
	Method        string            `json:"method"`
	TargetURI     string            `json:"target_uri"`
	BodyDigest    Digest            `json:"body_digest"`
	Headers       map[string]string `json:"headers"`
	Extensions    Object            `json:"extensions,omitzero"`
}

// FieldRule is one requirement a contract places on a profile field.
// Schema is a restricted JSON Schema object or boolean.
type FieldRule struct {
	RuleID              string          `json:"rule_id"`
	Path                string          `json:"path"`
	Schema              json.RawMessage `json:"schema"`
	Source              RuleSource      `json:"source"`
	Comparison          Comparison      `json:"comparison"`
	AllowedIssuers      []string        `json:"allowed_issuers"`
	NativePath          *string         `json:"native_path"`
	MaxAgeSeconds       int64           `json:"max_age_seconds"`
	StatusMaxAgeSeconds int64           `json:"status_max_age_seconds"`
	Extensions          Object          `json:"extensions,omitzero"`
}

// RequirementContract is the effective requirement contract (typ
// pact-requirements+jwt).
type RequirementContract struct {
	PactVersion            string      `json:"pact_version"`
	Issuer                 string      `json:"iss"`
	Subject                string      `json:"sub"`
	Audience               string      `json:"aud"`
	JTI                    string      `json:"jti"`
	IssuedAt               int64       `json:"iat"`
	NotBefore              int64       `json:"nbf"`
	Expiry                 int64       `json:"exp"`
	TenantID               string      `json:"tenant_id"`
	ContractID             string      `json:"contract_id"`
	EnvironmentID          string      `json:"environment_id"`
	HolderJKT              Digest      `json:"holder_jkt"`
	OperationDigest        Digest      `json:"operation_digest"`
	IntentDigest           Digest      `json:"intent_digest"`
	BaseRevision           string      `json:"base_revision"`
	SelectedSet            string      `json:"selected_set"`
	FieldRules             []FieldRule `json:"field_rules"`
	ContextChecks          []string    `json:"context_checks"`
	LearningPolicyDigest   Digest      `json:"learning_policy_digest"`
	LearningArtifactDigest Digest      `json:"learning_artifact_digest"`
	Nonce                  string      `json:"nonce"`
	Mode                   Mode        `json:"mode"`
	Extensions             Object      `json:"extensions,omitzero"`
}

// Claim is one claim of an evidence artifact. Value is any JSON value.
type Claim struct {
	Path  string          `json:"path"`
	Value json.RawMessage `json:"value"`
}

// Evidence is an evidence artifact (typ pact-evidence+jwt).
type Evidence struct {
	PactVersion   string       `json:"pact_version"`
	Issuer        string       `json:"iss"`
	Subject       string       `json:"sub"`
	Audience      string       `json:"aud"`
	JTI           string       `json:"jti"`
	IssuedAt      int64        `json:"iat"`
	NotBefore     int64        `json:"nbf"`
	Expiry        int64        `json:"exp"`
	TenantID      string       `json:"tenant_id"`
	EnvironmentID string       `json:"environment_id"`
	HolderJKT     Digest       `json:"holder_jkt"`
	Kind          EvidenceKind `json:"kind"`
	Claims        []Claim      `json:"claims"`
	StatusRef     string       `json:"status_ref"`
	Extensions    Object       `json:"extensions,omitzero"`
}

// Presentation is an agent presentation (typ pact-presentation+jwt). Contract,
// Evidence and Reputation hold compact JWS strings.
type Presentation struct {
	PactVersion string           `json:"pact_version"`
	Issuer      string           `json:"iss"`
	Subject     string           `json:"sub"`
	Audience    string           `json:"aud"`
	JTI         string           `json:"jti"`
	IssuedAt    int64            `json:"iat"`
	NotBefore   int64            `json:"nbf"`
	Expiry      int64            `json:"exp"`
	TenantID    string           `json:"tenant_id"`
	Contract    string           `json:"contract"`
	Profile     AgentProfile     `json:"profile"`
	Intent      Intent           `json:"intent"`
	Operation   OperationContext `json:"operation"`
	Evidence    []string         `json:"evidence"`
	Reputation  *string          `json:"reputation"`
	Nonce       string           `json:"nonce"`
	Extensions  Object           `json:"extensions,omitzero"`
}

// CheckResult is the outcome of one admission check.
type CheckResult struct {
	CheckID          string      `json:"check_id"`
	Result           CheckStatus `json:"result"`
	ReasonCode       string      `json:"reason_code"`
	CheckedAt        int64       `json:"checked_at"`
	SourceObservedAt *int64      `json:"source_observed_at"`
	StatusCheckedAt  *int64      `json:"status_checked_at"`
	EvidenceIDs      []string    `json:"evidence_ids"`
	SourceID         string      `json:"source_id"`
	SourceRef        *string     `json:"source_ref"`
	Extensions       Object      `json:"extensions,omitzero"`
}

// AdmissionAttestation is the signed admission receipt (typ
// pact-admission+jwt).
type AdmissionAttestation struct {
	PactVersion            string         `json:"pact_version"`
	Issuer                 string         `json:"iss"`
	Subject                string         `json:"sub"`
	Audience               string         `json:"aud"`
	JTI                    string         `json:"jti"`
	IssuedAt               int64          `json:"iat"`
	NotBefore              int64          `json:"nbf"`
	Expiry                 int64          `json:"exp"`
	TenantID               string         `json:"tenant_id"`
	PresentationID         string         `json:"presentation_id"`
	OperationID            string         `json:"operation_id"`
	PrincipalID            string         `json:"principal_id"`
	EnvironmentID          string         `json:"environment_id"`
	HolderJKT              Digest         `json:"holder_jkt"`
	ProfileDigest          Digest         `json:"profile_digest"`
	IntentDigest           Digest         `json:"intent_digest"`
	OperationDigest        Digest         `json:"operation_digest"`
	RequirementsDigest     Digest         `json:"requirements_digest"`
	LearningPolicyDigest   Digest         `json:"learning_policy_digest"`
	LearningArtifactDigest Digest         `json:"learning_artifact_digest"`
	Decision               Decision       `json:"decision"`
	TerminalReason         TerminalReason `json:"terminal_reason"`
	Mode                   Mode           `json:"mode"`
	Checks                 []CheckResult  `json:"checks"`
	Extensions             Object         `json:"extensions,omitzero"`
}

// ReputationContext is the context a reputation value or an outcome applies to.
type ReputationContext struct {
	TenantID      string `json:"tenant_id"`
	EnvironmentID string `json:"environment_id"`
	AgentID       string `json:"agent_id"`
	PurposeID     string `json:"purpose_id"`
	ActionClass   string `json:"action_class"`
	ResourceClass string `json:"resource_class"`
	RuntimeClass  string `json:"runtime_class"`
	Extensions    Object `json:"extensions,omitzero"`
}

// DimensionStats holds the statistics of one reputation dimension. Scores and
// confidences are in basis points.
type DimensionStats struct {
	ScoreBPS         int64  `json:"score_bps"`
	ConfidenceBPS    int64  `json:"confidence_bps"`
	IndependentTasks int64  `json:"independent_tasks"`
	QualifiedEvents  int64  `json:"qualified_events"`
	NewestEventAt    *int64 `json:"newest_event_at"`
	Extensions       Object `json:"extensions,omitzero"`
}

// ReputationDimensions is the "dimensions" object of a ReputationValue: the
// three dimensions the protocol defines, all required.
type ReputationDimensions struct {
	Reliability     DimensionStats `json:"reliability"`
	TaskQuality     DimensionStats `json:"task_quality"`
	PolicyAdherence DimensionStats `json:"policy_adherence"`
}

// ReputationValue is the contextual reputation carried by a snapshot.
type ReputationValue struct {
	Context               ReputationContext    `json:"context"`
	Dimensions            ReputationDimensions `json:"dimensions"`
	EvidenceCutoff        int64                `json:"evidence_cutoff"`
	ProvenanceDigest      Digest               `json:"provenance_digest"`
	ScoringArtifactDigest Digest               `json:"scoring_artifact_digest"`
	ScoringPolicyRevision string               `json:"scoring_policy_revision"`
	SecurityStatus        SecurityStatus       `json:"security_status"`
	HoldRefs              []string             `json:"hold_refs"`
	Extensions            Object               `json:"extensions,omitzero"`
}

// ReputationSnapshot is a signed reputation snapshot (typ
// pact-reputation+jwt).
type ReputationSnapshot struct {
	PactVersion   string          `json:"pact_version"`
	Issuer        string          `json:"iss"`
	Subject       string          `json:"sub"`
	Audience      string          `json:"aud"`
	JTI           string          `json:"jti"`
	IssuedAt      int64           `json:"iat"`
	NotBefore     int64           `json:"nbf"`
	Expiry        int64           `json:"exp"`
	TenantID      string          `json:"tenant_id"`
	EnvironmentID string          `json:"environment_id"`
	HolderJKT     Digest          `json:"holder_jkt"`
	Value         ReputationValue `json:"value"`
	Extensions    Object          `json:"extensions,omitzero"`
}

// Attribution ties an outcome to a native task and to a cause.
type Attribution struct {
	NativeTaskRef     string           `json:"native_task_ref"`
	IndependenceGroup string           `json:"independence_group"`
	CausalAssessment  CausalAssessment `json:"causal_assessment"`
	AssessmentRef     *string          `json:"assessment_ref"`
	Extensions        Object           `json:"extensions,omitzero"`
}

// OutcomeReport is a signed execution outcome (typ pact-outcome+jwt).
type OutcomeReport struct {
	PactVersion        string            `json:"pact_version"`
	Issuer             string            `json:"iss"`
	Subject            string            `json:"sub"`
	Audience           string            `json:"aud"`
	JTI                string            `json:"jti"`
	IssuedAt           int64             `json:"iat"`
	NotBefore          int64             `json:"nbf"`
	Expiry             int64             `json:"exp"`
	TenantID           string            `json:"tenant_id"`
	EventID            string            `json:"event_id"`
	EnvironmentID      string            `json:"environment_id"`
	TaskID             string            `json:"task_id"`
	OperationID        string            `json:"operation_id"`
	AdmissionReceiptID *string           `json:"admission_receipt_id"`
	ObservedAt         int64             `json:"observed_at"`
	ReporterRole       ReporterRole      `json:"reporter_role"`
	Context            ReputationContext `json:"context"`
	EventKind          EventKind         `json:"event_kind"`
	Result             OutcomeResult     `json:"result"`
	Dimension          Dimension         `json:"dimension"`
	Severity           Severity          `json:"severity"`
	EvidenceRefs       []string          `json:"evidence_refs"`
	Attribution        Attribution       `json:"attribution"`
	Supersedes         []string          `json:"supersedes"`
	Details            string            `json:"details"`
	Extensions         Object            `json:"extensions,omitzero"`
}

// AdaptiveControl names one control a learning policy lets artifacts adjust.
// ValueSchema is a JSON Schema object or boolean.
type AdaptiveControl struct {
	ControlID       string          `json:"control_id"`
	ValueSchema     json.RawMessage `json:"value_schema"`
	AllowRelaxation bool            `json:"allow_relaxation"`
	Extensions      Object          `json:"extensions,omitzero"`
}

// DataPolicy is the data-qualification part of a learning policy.
type DataPolicy struct {
	QualificationPolicyID        string `json:"qualification_policy_id"`
	IngestionWindowSeconds       int64  `json:"ingestion_window_seconds"`
	PositiveWeightCapPerTask     int64  `json:"positive_weight_cap_per_task"`
	MaximumFailureWeight         int64  `json:"maximum_failure_weight"`
	TaskAttributionSource        string `json:"task_attribution_source"`
	ReporterIndependencePolicyID string `json:"reporter_independence_policy_id"`
	Extensions                   Object `json:"extensions,omitzero"`
}

// MetricBound is a lower or upper bound on an evaluation metric.
type MetricBound struct {
	Direction BoundDirection `json:"direction"`
	Value     float64        `json:"value"`
}

// EvaluationPolicy is the candidate-evaluation part of a learning policy.
type EvaluationPolicy struct {
	MinimumIndependentTasks   int64                  `json:"minimum_independent_tasks"`
	MinimumObservationSeconds int64                  `json:"minimum_observation_seconds"`
	MinimumShadowSeconds      int64                  `json:"minimum_shadow_seconds"`
	HoldoutPolicyID           string                 `json:"holdout_policy_id"`
	ImmutableTestSuiteDigests []Digest               `json:"immutable_test_suite_digests"`
	MetricBounds              map[string]MetricBound `json:"metric_bounds"`
	MaximumRolloutPercent     int64                  `json:"maximum_rollout_percent"`
	RequiredEvaluatorIDs      []string               `json:"required_evaluator_ids"`
	RollbackConditionIDs      []string               `json:"rollback_condition_ids"`
	Extensions                Object                 `json:"extensions,omitzero"`
}

// LearningPolicy is a signed learning policy (typ pact-learning-policy+jwt).
type LearningPolicy struct {
	PactVersion                string            `json:"pact_version"`
	Issuer                     string            `json:"iss"`
	Subject                    string            `json:"sub"`
	Audience                   string            `json:"aud"`
	JTI                        string            `json:"jti"`
	IssuedAt                   int64             `json:"iat"`
	NotBefore                  int64             `json:"nbf"`
	Expiry                     int64             `json:"exp"`
	TenantID                   string            `json:"tenant_id"`
	PolicyID                   string            `json:"policy_id"`
	EnvironmentID              string            `json:"environment_id"`
	Mode                       LearningMode      `json:"mode"`
	ControllerIDs              []string          `json:"controller_ids"`
	BaseRevision               string            `json:"base_revision"`
	ConservativeSet            string            `json:"conservative_set"`
	AllowedRequirementSets     []string          `json:"allowed_requirement_sets"`
	AdaptiveFields             []AdaptiveControl `json:"adaptive_fields"`
	PermittedArtifactTypes     []ArtifactType    `json:"permitted_artifact_types"`
	PermittedImplementationIDs []string          `json:"permitted_implementation_ids"`
	DataPolicy                 DataPolicy        `json:"data_policy"`
	EvaluationPolicy           EvaluationPolicy  `json:"evaluation_policy"`
	HoldClearanceAuthorities   []string          `json:"hold_clearance_authorities"`
	Extensions                 Object            `json:"extensions,omitzero"`
}

// LearningArtifact is a learning artifact manifest (typ
// pact-learning-artifact+jwt).
type LearningArtifact struct {
	PactVersion                 string              `json:"pact_version"`
	Issuer                      string              `json:"iss"`
	Subject                     string              `json:"sub"`
	Audience                    string              `json:"aud"`
	JTI                         string              `json:"jti"`
	IssuedAt                    int64               `json:"iat"`
	NotBefore                   int64               `json:"nbf"`
	Expiry                      int64               `json:"exp"`
	TenantID                    string              `json:"tenant_id"`
	ArtifactID                  string              `json:"artifact_id"`
	Version                     string              `json:"version"`
	ModelType                   ArtifactType        `json:"model_type"`
	ImplementationID            string              `json:"implementation_id"`
	ContentDigest               Digest              `json:"content_digest"`
	SourceDataManifestDigest    Digest              `json:"source_data_manifest_digest"`
	FeatureSchemaDigest         Digest              `json:"feature_schema_digest"`
	TrainingConfigurationDigest Digest              `json:"training_configuration_digest"`
	EvaluationReportDigest      Digest              `json:"evaluation_report_digest"`
	IntendedContexts            []ReputationContext `json:"intended_contexts"`
	BaseRevision                string              `json:"base_revision"`
	ParentArtifactDigest        *Digest             `json:"parent_artifact_digest"`
	OutputControls              []string            `json:"output_controls"`
	ArtifactStoreRef            string              `json:"artifact_store_ref"`
	Extensions                  Object              `json:"extensions,omitzero"`
}

// LearningEvent is a learning lifecycle event (typ pact-learning-event+jwt).
type LearningEvent struct {
	PactVersion            string              `json:"pact_version"`
	Issuer                 string              `json:"iss"`
	Subject                string              `json:"sub"`
	Audience               string              `json:"aud"`
	JTI                    string              `json:"jti"`
	IssuedAt               int64               `json:"iat"`
	NotBefore              int64               `json:"nbf"`
	Expiry                 int64               `json:"exp"`
	TenantID               string              `json:"tenant_id"`
	EventID                string              `json:"event_id"`
	EnvironmentID          string              `json:"environment_id"`
	ArtifactDigest         Digest              `json:"artifact_digest"`
	PreviousArtifactDigest *Digest             `json:"previous_artifact_digest"`
	PolicyDigest           Digest              `json:"policy_digest"`
	Transition             Transition          `json:"transition"`
	ExpectedState          LifecycleState      `json:"expected_state"`
	ExpectedActiveDigest   *Digest             `json:"expected_active_digest"`
	ActivateArtifactDigest *Digest             `json:"activate_artifact_digest"`
	EffectiveAt            int64               `json:"effective_at"`
	ScopeContexts          []ReputationContext `json:"scope_contexts"`
	EvaluationRefs         []string            `json:"evaluation_refs"`
	ReasonCodes            []string            `json:"reason_codes"`
	Extensions             Object              `json:"extensions,omitzero"`
}

// ContractRequest asks a gateway for a requirement contract.
type ContractRequest struct {
	AgentID    string           `json:"agent_id"`
	HolderJKT  Digest           `json:"holder_jkt"`
	Intent     Intent           `json:"intent"`
	Operation  OperationContext `json:"operation"`
	Extensions Object           `json:"extensions,omitzero"`
}

// EvaluationRequest asks a gateway to evaluate a presentation against the
// operation that is about to run. Presentation is a compact JWS.
type EvaluationRequest struct {
	Presentation    string           `json:"presentation"`
	ActualOperation OperationContext `json:"actual_operation"`
	Extensions      Object           `json:"extensions,omitzero"`
}

// ReputationQuery asks for a reputation snapshot.
type ReputationQuery struct {
	AgentID    string            `json:"agent_id"`
	HolderJKT  Digest            `json:"holder_jkt"`
	Context    ReputationContext `json:"context"`
	Audience   string            `json:"audience"`
	Extensions Object            `json:"extensions,omitzero"`
}

// ReceiptQuery asks for an admission receipt.
type ReceiptQuery struct {
	ReceiptID  string `json:"receipt_id"`
	Extensions Object `json:"extensions,omitzero"`
}

// Acknowledgment answers a submitted outcome or learning event.
type Acknowledgment struct {
	RequestID  string    `json:"request_id"`
	Status     AckStatus `json:"status"`
	ArtifactID string    `json:"artifact_id"`
	ReceivedAt int64     `json:"received_at"`
	Extensions Object    `json:"extensions,omitzero"`
}

// NativeAdapter describes one native protocol adapter of a gateway.
type NativeAdapter struct {
	Protocol        string `json:"protocol"`
	Version         string `json:"version"`
	MappingRevision string `json:"mapping_revision"`
	Extensions      Object `json:"extensions,omitzero"`
}

// GatewayEndpoints is the "endpoints" object of GatewayMetadata: the seven
// protocol endpoints, all required.
type GatewayEndpoints struct {
	Requirements      string `json:"requirements"`
	Evaluate          string `json:"evaluate"`
	Outcomes          string `json:"outcomes"`
	ReputationQuery   string `json:"reputation_query"`
	LearningArtifacts string `json:"learning_artifacts"`
	LearningEvents    string `json:"learning_events"`
	ReceiptsQuery     string `json:"receipts_query"`
}

// GatewayMetadata is the document served at /.well-known/pact-configuration.
// Limits maps a limit key (max_json_depth, ...) to its advertised value.
// Endpoints and JWKSURI are required unless Extensions holds
// pact-transport-profile-v1 (draft 13.3.1, Appendix A.2); they are zero when
// omitted.
type GatewayMetadata struct {
	GatewayID               string                  `json:"gateway_id"`
	EnvironmentID           string                  `json:"environment_id"`
	WireVersions            []string                `json:"wire_versions"`
	JWSAlgorithms           []JWSAlgorithm          `json:"jws_algorithms"`
	Endpoints               GatewayEndpoints        `json:"endpoints,omitzero"`
	JWKSURI                 string                  `json:"jwks_uri,omitzero"`
	OperationMappingVersion string                  `json:"operation_mapping_version"`
	ExtensionsSupported     []string                `json:"extensions_supported"`
	Modes                   []Mode                  `json:"modes"`
	PresentationTransports  []PresentationTransport `json:"presentation_transports"`
	Limits                  map[string]int64        `json:"limits"`
	ProtectedHeaderNames    []string                `json:"protected_header_names"`
	HeaderNormalizationID   string                  `json:"header_normalization_id"`
	Adapters                []NativeAdapter         `json:"adapters"`
	Extensions              Object                  `json:"extensions,omitzero"`
}

// Problem is the error body of the transport (RFC 9457 shape).
type Problem struct {
	Type       string `json:"type"`
	Title      string `json:"title"`
	Status     int64  `json:"status"`
	Code       string `json:"code"`
	RequestID  string `json:"request_id"`
	Extensions Object `json:"extensions,omitzero"`
}
