package evalcase

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"hop.top/pact-go/core"
	"hop.top/pact-go/core/jws"
)

// Config is config.json of an evaluation case: the trusted configuration
// of the gateway (spec/v1.0/fixtures/README.md, sections config.json and
// config.json additions). Absent optional members are zero.
type Config struct {
	Mode             core.Mode       `json:"mode"`
	Now              int64           `json:"now"`
	ClockSkewSeconds int64           `json:"clock_skew_seconds"`
	Gateway          Gateway         `json:"gateway"`
	Trust            []TrustRecord   `json:"trust"`
	Validator        Validator       `json:"validator"`
	NativeMappings   []NativeMapping `json:"native_mappings"`
	InstalledChecks  []string        `json:"installed_checks"`
	ActivePolicy     ActivePolicy    `json:"active_policy"`
	// Limits are the limits of draft Section 20.1 by their metadata keys.
	Limits          map[string]int64 `json:"limits"`
	ExecutorClasses []ExecutorClass  `json:"executor_classes"`
	CheckFreshness  map[string]int64 `json:"check_freshness"`
	// Selection is nil when the contract's set is the conservative set.
	Selection *Selection `json:"selection"`
	// Purposes is the installed purpose mapping (draft 10.1): purpose id to
	// the actions it covers; nil when config.json does not name it. See
	// InstalledPurposes.
	Purposes map[string][]string `json:"purposes"`
	// ReputationContext is the installed reputation-context mapping (draft
	// 15.1); nil when config.json does not name it or names null. See
	// ReputationContextMapping.
	ReputationContext *ReputationContext `json:"reputation_context"`
}

// ReputationContext is config.json's reputation_context: the resource class
// of each resource prefix and the gateway's runtime class. The action class
// is the operation's action, the purpose the intent's, the agent the bound
// agent and the realm the gateway's.
type ReputationContext struct {
	ResourceClasses []ResourceClass `json:"resource_classes"`
	RuntimeClass    string          `json:"runtime_class"`
}

// ResourceClass is the resource_class of the resources whose URI starts
// with Prefix.
type ResourceClass struct {
	Prefix string `json:"prefix"`
	Class  string `json:"class"`
}

// InstalledPurposes returns the installed purpose mapping: purposes, or the
// Appendix B mapping (B.2, B.3) when config.json does not name it.
func (c Config) InstalledPurposes() map[string][]string {
	if c.Purposes == nil {
		return map[string][]string{"https://policies.example/purposes/invoice-summary/v1": {"invoice.read"}}
	}
	return c.Purposes
}

// ReputationContextMapping returns the installed reputation-context mapping:
// reputation_context, or the Appendix B mapping (B.6) when config.json does
// not name it or names null.
func (c Config) ReputationContextMapping() ReputationContext {
	if c.ReputationContext == nil {
		return ReputationContext{
			ResourceClasses: []ResourceClass{{Prefix: "https://invoices.example/invoices/", Class: "department-finance-invoice"}},
			RuntimeClass:    "managed-v1",
		}
	}
	return *c.ReputationContext
}

// check checks a reputation_context: a resource_classes array whose
// entries name a prefix and a class, and a runtime class.
func (r *ReputationContext) check() error {
	switch {
	case r == nil:
		return nil
	case r.ResourceClasses == nil:
		return errors.New("reputation_context: no resource_classes")
	case r.RuntimeClass == "":
		return errors.New("reputation_context: no runtime_class")
	}
	for i, rc := range r.ResourceClasses {
		if rc.Prefix == "" || rc.Class == "" {
			return fmt.Errorf("reputation_context: resource_classes[%d] needs a prefix and a class", i)
		}
	}
	return nil
}

// Gateway is config.json's gateway.
type Gateway struct {
	GatewayID               string   `json:"gateway_id"`
	EnvironmentID           string   `json:"environment_id"`
	TenantID                string   `json:"tenant_id"`
	OperationMappingVersion string   `json:"operation_mapping_version"`
	ExtensionsSupported     []string `json:"extensions_supported"`
	// JWSAlgorithms is the GatewayMetadata.jws_algorithms the gateway
	// publishes (draft 13.1, A.3); nil when config.json does not name it.
	// See Algorithms.
	JWSAlgorithms []string `json:"jws_algorithms"`
}

// Algorithms returns the JOSE algorithms the gateway publishes: its
// jws_algorithms, or the baseline ES256 alone when config.json does not name
// them (draft 7.2). A receipt alg is accepted only when it is one of them.
func (g Gateway) Algorithms() jws.Algorithms {
	if g.JWSAlgorithms == nil {
		return jws.Algorithms{jws.AlgES256}
	}
	return jws.Algorithms(slices.Clone(g.JWSAlgorithms))
}

// checkAlgorithms checks jws_algorithms against the type of
// GatewayMetadata.jws_algorithms (draft A.3): when present, one or two
// distinct algorithms out of ES256 and Ed25519. EdDSA, none and HMAC
// algorithms are never accepted (draft 7.2).
func (g Gateway) checkAlgorithms() error {
	if g.JWSAlgorithms == nil {
		return nil
	}
	if len(g.JWSAlgorithms) == 0 {
		return errors.New("gateway.jws_algorithms is empty; leave it out for the baseline [\"ES256\"]")
	}
	for i, alg := range g.JWSAlgorithms {
		if alg != jws.AlgES256 && alg != jws.AlgEd25519 {
			return fmt.Errorf("gateway.jws_algorithms[%d] %q is not ES256 or Ed25519 (draft 7.2, A.3)", i, alg)
		}
		if slices.Index(g.JWSAlgorithms, alg) != i {
			return fmt.Errorf("gateway.jws_algorithms[%d] %q repeats an algorithm", i, alg)
		}
	}
	return nil
}

// TrustRecord is one trust record: an issuer, the signer role it is trusted
// for, its public JWK files (paths under the fixture directory) and, for
// evidence issuers and reputation services, the claim paths it may assert.
// ReporterRole is set in the trust records of outcome cases.
type TrustRecord struct {
	Iss          string   `json:"iss"`
	Role         jws.Role `json:"role"`
	Keys         []string `json:"keys"`
	ClaimPaths   []string `json:"claim_paths"`
	ReporterRole *string  `json:"reporter_role"`
}

// Validator is the validator that signs the admission attestation.
type Validator struct {
	Iss      string `json:"iss"`
	SourceID string `json:"source_id"`
	Key      string `json:"key"`
}

// NativeMapping names the native path that is authoritative for a profile
// path (draft Section 17.2). Source is the declared capability of the
// mapping's native source; nil when config.json declares none (absent or
// null): no declared bound.
type NativeMapping struct {
	Path       string        `json:"path"`
	NativePath string        `json:"native_path"`
	Source     *NativeSource `json:"source"`
}

// NativeSource is the declared capability of a native source, as the
// integration profile declares it (spec/v1.0/fixtures/README.md, config.json
// additions; freshness profile, section 4.2): the best max_age_seconds and
// status_max_age_seconds it can meet, whether it can check live, and its
// change feed (informative). Every member is required.
type NativeSource struct {
	// SourceID is the source_id of the native claims the source answers.
	SourceID                string
	BestMaxAgeSeconds       int64
	BestStatusMaxAgeSeconds int64
	LiveCheck               bool
	// ChangeFeed is none, poll_delta or push.
	ChangeFeed string
}

// maxSeconds is the largest limit with a wire form, 2^53-1 (draft 7.1).
const maxSeconds = 1<<53 - 1

// UnmarshalJSON reads a source object strictly: each member once and
// present, no other member, bounds from 0 to 2^53-1, a change feed of none,
// poll_delta or push, and, for a source with no live check, a status bound
// of at least 1 (freshness profile, section 4.2).
func (s *NativeSource) UnmarshalJSON(b []byte) error {
	var raw struct {
		SourceID                *string `json:"source_id"`
		BestMaxAgeSeconds       *int64  `json:"best_max_age_seconds"`
		BestStatusMaxAgeSeconds *int64  `json:"best_status_max_age_seconds"`
		LiveCheck               *bool   `json:"live_check"`
		ChangeFeed              *string `json:"change_feed"`
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&raw); err != nil {
		return fmt.Errorf("native_mappings source: %w", err)
	}
	switch {
	case raw.SourceID == nil || *raw.SourceID == "":
		return errors.New("native_mappings source: no source_id")
	case raw.BestMaxAgeSeconds == nil:
		return errors.New("native_mappings source: no best_max_age_seconds")
	case raw.BestStatusMaxAgeSeconds == nil:
		return errors.New("native_mappings source: no best_status_max_age_seconds")
	case raw.LiveCheck == nil:
		return errors.New("native_mappings source: no live_check")
	case raw.ChangeFeed == nil:
		return errors.New("native_mappings source: no change_feed")
	}
	for name, v := range map[string]int64{"best_max_age_seconds": *raw.BestMaxAgeSeconds, "best_status_max_age_seconds": *raw.BestStatusMaxAgeSeconds} {
		if v < 0 || v > maxSeconds {
			return fmt.Errorf("native_mappings source: %s %d is not from 0 to 2^53-1", name, v)
		}
	}
	if f := *raw.ChangeFeed; f != "none" && f != "poll_delta" && f != "push" {
		return fmt.Errorf("native_mappings source: change_feed %q is not none, poll_delta or push", f)
	}
	if !*raw.LiveCheck && *raw.BestStatusMaxAgeSeconds < 1 {
		return errors.New("native_mappings source: a source with no live check has a best_status_max_age_seconds of at least 1")
	}
	*s = NativeSource{
		SourceID:                *raw.SourceID,
		BestMaxAgeSeconds:       *raw.BestMaxAgeSeconds,
		BestStatusMaxAgeSeconds: *raw.BestStatusMaxAgeSeconds,
		LiveCheck:               *raw.LiveCheck,
		ChangeFeed:              *raw.ChangeFeed,
	}
	return nil
}

// checkSources checks that every native claim at the native path of a
// mapping that declares a source names that source's source_id.
func (c Config) checkSources(nc NativeContext) error {
	for i, m := range c.NativeMappings {
		if m.Source == nil {
			continue
		}
		for _, cl := range nc.NativeClaims {
			if cl.NativePath == m.NativePath && cl.SourceID != m.Source.SourceID {
				return fmt.Errorf("native_mappings[%d] source source_id %q, but the native claim at %s names %q", i, m.Source.SourceID, m.NativePath, cl.SourceID)
			}
		}
	}
	return nil
}

// ActivePolicy is the active requirement and learning versions.
type ActivePolicy struct {
	BaseRevision           string `json:"base_revision"`
	SelectedSet            string `json:"selected_set"`
	LearningPolicyDigest   string `json:"learning_policy_digest"`
	LearningArtifactDigest string `json:"learning_artifact_digest"`
	// ScoringPolicyRevisions are the scoring-policy revisions the gateway
	// accepts in a snapshot (draft A.2); nil when config.json does not name
	// them. See AcceptedScoringRevisions.
	ScoringPolicyRevisions []string `json:"scoring_policy_revisions"`
}

// AcceptedScoringRevisions returns scoring_policy_revisions, or the
// Appendix B revision (B.6) when config.json does not name them.
func (a ActivePolicy) AcceptedScoringRevisions() []string {
	if a.ScoringPolicyRevisions == nil {
		return []string{"finance-scoring-1"}
	}
	return a.ScoringPolicyRevisions
}

// ExecutorClass is one entry of the installed execution-identity mapping.
// ExecutorID is nil when only the class is compared.
type ExecutorClass struct {
	PrincipalID string  `json:"principal_id"`
	TaskID      string  `json:"task_id"`
	OperationID string  `json:"operation_id"`
	Class       string  `json:"class"`
	ExecutorID  *string `json:"executor_id"`
}

// Selection is the requirement-set selection the gateway performed.
type Selection struct {
	Selector Selector `json:"selector"`
	// CurrentSnapshot is the path of a decoded snapshot, nil when the
	// gateway's current input is the presented snapshot.
	CurrentSnapshot *string         `json:"current_snapshot"`
	Record          SelectionRecord `json:"record"`
}

// Selector is the selector a contract pins.
type Selector struct {
	ImplementationID       string                      `json:"implementation_id"`
	LearningArtifactDigest string                      `json:"learning_artifact_digest"`
	Order                  []string                    `json:"order"`
	Sets                   map[string][]core.FieldRule `json:"sets"`
	Thresholds             map[string]Threshold        `json:"thresholds"`
	// Checks are the authorized context_checks of each set; a set that is
	// not a key has the contract's own (spec/v1.0/fixtures/README.md,
	// selection.selector).
	Checks map[string][]string `json:"checks"`
}

// Threshold is what a snapshot must meet for a set.
type Threshold struct {
	Dimensions     map[string]Minimums `json:"dimensions"`
	SecurityStatus string              `json:"security_status"`
}

// Minimums are the minimums of one reputation dimension.
type Minimums struct {
	ScoreBps         int64 `json:"score_bps"`
	ConfidenceBps    int64 `json:"confidence_bps"`
	IndependentTasks int64 `json:"independent_tasks"`
}

// SelectionRecord is the selection record.
type SelectionRecord struct {
	RecordRef              string   `json:"record_ref"`
	LearningPolicyDigest   string   `json:"learning_policy_digest"`
	LearningArtifactDigest string   `json:"learning_artifact_digest"`
	SnapshotJTI            *string  `json:"snapshot_jti"`
	HoldRefs               []string `json:"hold_refs"`
	BaseRevision           string   `json:"base_revision"`
}

// NativeContext is native_context.json: what the native environment
// establishes (spec/v1.0/fixtures/README.md, sections native_context.json and
// native_context.json additions). A nil member is null in the file.
type NativeContext struct {
	Authenticated  *Authenticated            `json:"authenticated"`
	NativeClaims   []NativeClaim             `json:"native_claims"`
	Approval       *Approval                 `json:"approval"`
	Delegation     *Delegation               `json:"delegation"`
	Executor       *Executor                 `json:"executor"`
	EvidenceStatus map[string]EvidenceStatus `json:"evidence_status"`
	SecurityHolds  []string                  `json:"security_holds"`
	Authorize      bool                      `json:"authorize"`
}

// Authenticated is the result of authenticate_native and
// resolve_agent_binding for the presented agent (spec/v1.0/fixtures/README.md,
// native_context.json). AgentID, OperatorID and HolderJKT are nil exactly
// when BindingStatus is BindingUnknown: the agent has no record on the
// authenticated workload in the realm (identity mapping IM-11).
type Authenticated struct {
	PrincipalID string       `json:"principal_id"`
	AgentID     *string      `json:"agent_id"`
	OperatorID  *string      `json:"operator_id"`
	TenantID    string       `json:"tenant_id"`
	HolderJKT   *core.Digest `json:"holder_jkt"`
	// BindingStatus is the binding status of resolve_agent_binding (draft
	// 17.1) in lower case: active, revoked, compromised or unknown.
	BindingStatus   string `json:"binding_status"`
	AuthenticatedAt int64  `json:"authenticated_at"`
	// EnrolledElsewhere is the report of draft 17.1 that the realm holds a
	// record of the presented agent ID for another workload. It is true only
	// with BindingUnknown.
	EnrolledElsewhere bool `json:"enrolled_elsewhere"`
	// BindingError is nil, or UNSUPPORTED_REQUIREMENT when the workload holds
	// more than one enrollment in force under a profile without shared
	// workloads (identity mapping IM-19); BindingStatus is then
	// BindingUnknown.
	BindingError *string `json:"binding_error"`
}

// The binding statuses of native_context.json's authenticated member.
const (
	BindingActive      = "active"
	BindingRevoked     = "revoked"
	BindingCompromised = "compromised"
	BindingUnknown     = "unknown"
)

// check applies the rules of the authenticated member that the decoder does
// not: the status set, the null members of an unknown binding, and the
// members that only an unknown binding may carry.
func (a *Authenticated) check() error {
	if a == nil {
		return nil
	}
	switch a.BindingStatus {
	case BindingActive, BindingRevoked, BindingCompromised, BindingUnknown:
	default:
		return fmt.Errorf("authenticated.binding_status %q is not active, revoked, compromised or unknown", a.BindingStatus)
	}
	unknown := a.BindingStatus == BindingUnknown
	for _, m := range []struct {
		name string
		set  bool
		val  string
	}{
		{"agent_id", a.AgentID != nil, deref(a.AgentID)},
		{"operator_id", a.OperatorID != nil, deref(a.OperatorID)},
		{"holder_jkt", a.HolderJKT != nil, string(deref(a.HolderJKT))},
	} {
		switch {
		case unknown && m.set:
			return fmt.Errorf("authenticated.%s is set, but binding_status unknown has no agent, operator or key (null)", m.name)
		case !unknown && (!m.set || m.val == ""):
			return fmt.Errorf("authenticated.%s is null or empty, but binding_status %s names a binding", m.name, a.BindingStatus)
		}
	}
	if a.EnrolledElsewhere && !unknown {
		return fmt.Errorf("authenticated.enrolled_elsewhere is true with binding_status %s; it reports only for unknown", a.BindingStatus)
	}
	if e := a.BindingError; e != nil {
		if *e != "UNSUPPORTED_REQUIREMENT" {
			return fmt.Errorf("authenticated.binding_error %q is not UNSUPPORTED_REQUIREMENT or null", *e)
		}
		if !unknown {
			return fmt.Errorf("authenticated.binding_error is set with binding_status %s; it comes with unknown", a.BindingStatus)
		}
	}
	return nil
}

// deref returns *p, or the zero value when p is nil.
func deref[T any](p *T) T {
	var zero T
	if p == nil {
		return zero
	}
	return *p
}

// NativeClaim is what read_native_claim returns for a native path.
type NativeClaim struct {
	NativePath      string          `json:"native_path"`
	Value           json.RawMessage `json:"value"`
	ObservedAt      int64           `json:"observed_at"`
	StatusCheckedAt int64           `json:"status_checked_at"`
	SourceID        string          `json:"source_id"`
}

// Approval is the native approval state. The members of format v2 are nil
// when absent or null: the approval then matches.
type Approval struct {
	Ref               string             `json:"ref"`
	State             string             `json:"state"`
	AgentID           string             `json:"agent_id"`
	PrincipalID       string             `json:"principal_id"`
	PurposeID         string             `json:"purpose_id"`
	TaskID            string             `json:"task_id"`
	StatusCheckedAt   *int64             `json:"status_checked_at"`
	ApproverID        *string            `json:"approver_id"`
	ApproverAuthority *ApproverAuthority `json:"approver_authority"`
	Amount            *Amount            `json:"amount"`
	Resources         []string           `json:"resources"`
}

// ApproverAuthority is what the native environment establishes about the
// approver's authority.
type ApproverAuthority struct {
	RequiredRole  string   `json:"required_role"`
	ApproverRoles []string `json:"approver_roles"`
}

// Amount is the amount an approval covers and the amount requested, as
// decimal strings.
type Amount struct {
	Approved  string `json:"approved"`
	Requested string `json:"requested"`
	Currency  string `json:"currency"`
}

// Delegation is the native delegation state.
type Delegation struct {
	AuthorityRef string `json:"authority_ref"`
	PrincipalID  string `json:"principal_id"`
	TaskID       string `json:"task_id"`
	State        string `json:"state"`
	ObservedAt   int64  `json:"observed_at"`
}

// Executor is the executor identity (draft Section 17.5).
type Executor struct {
	Class       string `json:"class"`
	PrincipalID string `json:"principal_id"`
}

// EvidenceStatus is the status of an evidence status reference.
type EvidenceStatus struct {
	Status    string `json:"status"`
	CheckedAt int64  `json:"checked_at"`
}

// Submission is one presentation the harness submits (README section
// exchange.json), with the defaults applied.
type Submission struct {
	Signed             string
	JTI                string
	Replica            string
	Concurrent         bool
	EvictReplayRecords bool
	ActualOperation    string
	// Transport is the transport profile the presentation arrives over, as
	// the gateway established it: https or stdio-ipc (draft 13.3.1, 17.1).
	Transport  string
	Evaluation Evaluation
}

// Evaluation is the timing of an evaluation. StartedAt defaults to the
// config's now; a nil time is null.
type Evaluation struct {
	StartedAt     int64
	NativeReadsAt *int64
	CancelledAt   *int64
}

// Availability is what does not answer during the case. ReplayStore is
// "available", "unavailable" or "full".
type Availability struct {
	Sources     []string
	ReplayStore string
	// EnrollmentSource is available or unavailable: the enrollment source
	// behind resolve_agent_binding (draft 17.1).
	EnrollmentSource string
}

// HandoffAttempt is a sidecar handoff of an issued attestation, with the
// defaults applied: Presentation is a submission's jti.
type HandoffAttempt struct {
	Presentation    string
	ActualOperation string
	At              int64
}

// Decision is an expected decision.json: one response at the top level, or,
// in format v2, one per submission under Responses, then one entry per
// handoff attempt (README sections decision.json and decision.json
// additions).
type Decision struct {
	TransportCode        *string         `json:"transport_code"`
	Decision             *core.Decision  `json:"decision"`
	Checks               []ExpectedCheck `json:"checks"`
	Receipt              *Receipt        `json:"receipt"`
	Executed             *bool           `json:"executed"`
	AbsentChecks         []string        `json:"absent_checks"`
	RejectedBeforeCrypto *bool           `json:"rejected_before_crypto"`
	Reason               *string         `json:"reason"`
	Responses            []Response      `json:"responses"`
	Handoff              []Handoff       `json:"handoff"`
	// Subject is the RFC 6901 pointer to the response the manifest outcome
	// summarizes; nil means "".
	Subject *string `json:"subject"`
}

// Response is one expected response: a transport rejection, when
// TransportCode is set, or a receipt.
type Response struct {
	TransportCode        *string         `json:"transport_code"`
	Decision             *core.Decision  `json:"decision"`
	Checks               []ExpectedCheck `json:"checks"`
	Receipt              *Receipt        `json:"receipt"`
	Executed             *bool           `json:"executed"`
	AbsentChecks         []string        `json:"absent_checks"`
	RejectedBeforeCrypto *bool           `json:"rejected_before_crypto"`
	Reason               *string         `json:"reason"`
}

// ExpectedCheck is a check result the receipt must carry.
type ExpectedCheck struct {
	CheckID            string   `json:"check_id"`
	Result             string   `json:"result"`
	ReasonCode         string   `json:"reason_code"`
	EvidenceIDsInclude []string `json:"evidence_ids_include"`
	SourceRef          *string  `json:"source_ref"`
}

// Receipt is what the expected receipt must be: its typ, the public JWK
// file of its signer, the payload members it must carry with exactly these
// values, and the latest permitted exp.
type Receipt struct {
	Typ    string                     `json:"typ"`
	Signer string                     `json:"signer"`
	Claims map[string]json.RawMessage `json:"claims"`
	ExpMax int64                      `json:"exp_max"`
}

// Handoff is the expected result of a handoff attempt: TransportCode is nil
// when the gateway accepts the attestation.
type Handoff struct {
	TransportCode *string `json:"transport_code"`
}

// ExpectedResponses returns the expected responses in submission order: the
// top level as one response, or Responses.
func (d Decision) ExpectedResponses() []Response {
	if d.Responses != nil {
		return d.Responses
	}
	return []Response{{
		TransportCode: d.TransportCode, Decision: d.Decision, Checks: d.Checks, Receipt: d.Receipt,
		Executed: d.Executed, AbsentChecks: d.AbsentChecks,
		RejectedBeforeCrypto: d.RejectedBeforeCrypto, Reason: d.Reason,
	}}
}
