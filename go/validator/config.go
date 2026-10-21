package validator

import (
	"context"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/contract"
	"hop.top/pact-go/core"
	"hop.top/pact-go/core/jws"
)

// The check identifiers of the mandatory protocol checks of draft 9.3,
// 11.3 and 12.1, in the order a receipt lists them (the table of draft
// 12.1), and of the two baseline installed checks the validator evaluates
// itself (draft 9.4, 17.5). A receipt then lists the field rules by rule_id
// and the contract's context_checks, each in contract order.
const (
	CheckNativeAuthentication   = "native-authentication"
	CheckAgentHolderBinding     = "agent-holder-binding"
	CheckContractValidity       = "contract-validity"
	CheckNonce                  = "nonce"
	CheckOperationBinding       = "operation-binding"
	CheckIntentBinding          = "intent-binding"
	CheckProfileValidity        = "profile-validity"
	CheckEvidenceValidity       = "evidence-validity"
	CheckReputationContext      = "reputation-context"
	CheckSecurityHold           = "security-hold"
	CheckActivePolicy           = "active-policy"
	CheckReceiptStore           = "receipt-store"
	CheckNativePrincipalBinding = "native-principal-binding-v1"
	CheckSelectionConsistency   = contract.SelectionConsistencyCheck
)

// Config is the trusted configuration of the validator (draft 4.2): whom it
// serves, whom it trusts for which artifact, and the limits it enforces.
type Config struct {
	// Audience is the gateway the validator evaluates for: the aud of the
	// contracts, presentations and evidence it accepts and of the
	// attestations it issues.
	Audience string
	// Realm is the gateway's tenant and environment.
	Realm adapter.Realm
	// Issuer is the iss of the attestations, the validator's trust record.
	Issuer string
	// SourceID names the validator as the source of the checks it performs
	// on inputs it already holds (draft A.2: a local check's source_id
	// identifies the installed authoritative adapter).
	SourceID string
	// Publishers maps the iss of each requirement publisher to its keys.
	Publishers map[string]*jws.KeySet
	// Issuers are the evidence issuers and ReputationServices the reputation
	// services, each with the claim paths it may assert (draft 8.3, A.2).
	Issuers            []Issuer
	ReputationServices []Issuer
	// Algorithms are the negotiated JWS algorithms; nil is ES256 alone.
	Algorithms jws.Algorithms
	// Skew is the allowed clock skew, 0 to 5 s (draft 7.5).
	Skew time.Duration
	// Limits are the limits of draft 20.1; the zero value is the baseline.
	Limits core.Limits
	// EvaluationTime bounds one evaluation, at most 30 s; zero is 30 s
	// (draft 12.2, 20.1).
	EvaluationTime time.Duration
	// NativeMappings are the approved mappings of profile paths to native
	// paths (draft 17.2).
	NativeMappings []NativeMapping
	// InstalledChecks are the context checks the gateway installed (draft
	// 9.3). A contract check that is not listed is UNKNOWN.
	InstalledChecks []string
	// SupportedExtensions are the contract extensions the gateway supports
	// (draft 7.1, 21).
	SupportedExtensions []string
}

// Issuer is a trust record: an issuer, its keys, and the profile paths it is
// authorized to assert, exactly (draft 8.3: claim-scoped authority).
type Issuer struct {
	ID         string
	Keys       *jws.KeySet
	ClaimPaths []string
}

// NativeMapping maps a profile path to the native path that is
// authoritative for it (draft 17.2). Source, when set, is the declared
// capability of the native source.
type NativeMapping struct {
	Path       string
	NativePath string
	Source     *SourceCapability
}

// SourceCapability is what a native source can establish (draft 17.2, 18):
// the tightest ages it can meet and whether it can be asked for its current
// state at evaluation time.
type SourceCapability struct {
	SourceID                string
	BestMaxAgeSeconds       int64
	BestStatusMaxAgeSeconds int64
	LiveCheck               bool
}

// Request is one evaluation request (draft 13.2, evaluate): the signed
// presentation, the actual operation the gateway mapped from the request
// (map_operation), and the principal that authenticate_native established
// for it (draft 17.1).
type Request struct {
	Presentation string
	Operation    core.OperationContext
	Principal    adapter.Principal
	// Transport is the transport profile the presentation arrived over,
	// which the gateway established from the channel as part of
	// authenticate_native, never from the message (draft 13.3.1, 17.1):
	// contract.TransportHTTPS or contract.TransportStdioIPC. Under an
	// enforced-mode contract, a transport other than the one the contract
	// names, or none, is rejected with CONTEXT_MISMATCH before an
	// authenticated evaluation (the downgrade rule); in observe mode the
	// presentation is evaluated and its receipt records the observation.
	Transport string
}

// Result is a sealed evaluation: the compact attestation and its payload.
type Result struct {
	Receipt     string
	Attestation core.AdmissionAttestation
}

// Native is what the validator calls of the native adapter (draft 17.1):
// the binding resolver and the two native reads of draft 12.1.
type Native interface {
	adapter.BindingResolver
	adapter.ClaimReader
	adapter.ContextChecker
}

// ReceiptStore keeps sealed receipts durably (draft 12.2). Put returns only
// once the receipt is durable; a store that cannot record it returns an
// error, and the evaluation is then never positive.
type ReceiptStore interface {
	Put(ctx context.Context, r Result) error
	// Get returns the receipt whose jti is jti.
	Get(ctx context.Context, jti string) (Result, error)
	// ByContract returns the receipts of the evaluations of the contract
	// whose requirements_digest is d.
	ByContract(ctx context.Context, d core.Digest) ([]Result, error)
}

// HoldStore reports the security holds in force for an agent (draft 15.4,
// 18). An error means the store cannot answer.
type HoldStore interface {
	Holds(ctx context.Context, realm adapter.Realm, agentID string) ([]string, error)
}

// StatusChecker checks the status of an evidence artifact through its
// issuer's configured adapter (draft 8.3). An error means the status cannot
// be established; unknown status is never validity.
type StatusChecker interface {
	EvidenceStatus(ctx context.Context, issuer, statusRef string) (EvidenceStatus, error)
}

// EvidenceStatus is the status of one evidence artifact.
type EvidenceStatus struct {
	Revoked   bool
	CheckedAt time.Time
	SourceID  string
}

// PolicyRegistry is the active policy registry (draft 9.4, 18).
type PolicyRegistry interface {
	// Active returns the active policy of the gateway.
	Active(ctx context.Context) (ActivePolicy, error)
	// Selection returns the gateway's selection record of the contract and
	// the selector the contract pins.
	Selection(ctx context.Context, c contract.Contract) (Selection, error)
}

// ActivePolicy is the active base revision and learning versions, the
// policy's conservative set, and the scoring-policy revisions the gateway
// accepts in a reputation snapshot (draft 15.2, A.2).
type ActivePolicy struct {
	Policy                 contract.Policy
	ConservativeSet        string
	ScoringPolicyRevisions []string
}

// Selection is what step 9 of draft 11.3 needs of the gateway's selection:
// the reference of its selection record (the source_ref of the
// reputation-context and selection-consistency-v1 results, draft A.2), the
// selector the contract pins, nil when none is installed, and the gateway's
// own current trusted selection input, nil when it is the presented
// snapshot.
type Selection struct {
	RecordRef string
	Selector  Selector
	Current   *core.ReputationValue
}

// Selector is an installed requirement-set selector (draft 9.4, 16.5).
type Selector interface {
	// Order lists the permitted sets, strictest first.
	Order() []string
	// Select yields the set for the inputs; it is deterministic.
	Select(in SelectionInput) (string, error)
	// Rules returns the authorized field rules of a set.
	Rules(set string) ([]core.FieldRule, bool)
	// Checks returns the authorized context_checks of a set, in order
	// (draft 11.3 step 3).
	Checks(set string) ([]string, bool)
}

// SelectionInput is what a selector re-derives a set from: a reputation
// value, nil for none, and the holds in force.
type SelectionInput struct {
	Snapshot *core.ReputationValue
	Holds    []string
}

// ContextMapper is the administrator-approved mapping of an operation to its
// reputation context (draft 15.1, A.2).
type ContextMapper interface {
	ReputationContext(ctx context.Context, in adapter.CheckInput) (core.ReputationContext, error)
}

// Signer signs an attestation payload as a compact JWS of typ
// pact-admission+jwt under the validator's key.
type Signer interface {
	SignAttestation(payload []byte) (string, error)
}
