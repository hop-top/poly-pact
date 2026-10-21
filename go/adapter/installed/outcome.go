package installed

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/core"
	"hop.top/pact-go/core/jws"
)

// outcomeValidity is the validity of a signed outcome report, the baseline
// maximum of draft 14.3.
const outcomeValidity = 300 * time.Second

// Reporting is the signer of outcome reports.
type Reporting struct {
	Issuer   string
	Audience string
	// KID names Key in the gateway's published key set.
	KID string
	// Key is the gateway's P-256 signing key.
	Key *ecdsa.PrivateKey
}

// Validate refuses a signer without an issuer, an audience, a kid or a key.
func (rp *Reporting) Validate() error {
	if rp != nil && (rp.Issuer == "" || rp.Audience == "" || rp.KID == "" || rp.Key == nil) {
		return errors.New("reporting needs an issuer, an audience, a kid and a key")
	}
	return nil
}

// Record signs the observation as an outcome report (draft 14.1) of a gateway
// of realm, at the instant now.
//
// The gateway reports what it observes: admission decisions and native
// authorization results. Unless executionVisible says the gateway observes
// execution, an EXECUTION observation gives NoVisibility with the reason
// noVisibility, never an assumed success. Other event kinds are
// [adapter.ErrUnsupportedRequirement], as is a nil rp. Free text and evidence
// references are cleaned of credential material first ([Redact]).
func Record(rp *Reporting, realm adapter.Realm, executionVisible bool, noVisibility string, o adapter.Observation, now time.Time) (adapter.Recorded, error) {
	if rp == nil {
		return nil, fmt.Errorf("no reporting key is configured: %w", adapter.ErrUnsupportedRequirement)
	}
	if o.EventID == "" {
		return nil, fmt.Errorf("the observation has no event id: %w", adapter.ErrInvalidMessage)
	}
	if o.Context.TenantID != realm.TenantID || o.Context.EnvironmentID != realm.EnvironmentID {
		return nil, fmt.Errorf("the observation belongs to another realm: %w", adapter.ErrContextMismatch)
	}
	var role core.ReporterRole
	switch o.EventKind {
	case core.EventAdmission, core.EventAuthorization:
		role = core.ReporterGateway
	case core.EventExecution:
		if !executionVisible {
			return adapter.NoVisibility{Reason: noVisibility}, nil
		}
		role = core.ReporterExecutor
	default:
		return nil, fmt.Errorf("the gateway does not report %s events: %w", o.EventKind, adapter.ErrUnsupportedRequirement)
	}
	refs := make([]string, len(o.EvidenceRefs))
	for i, ref := range o.EvidenceRefs {
		refs[i] = Redact(ref)
	}
	supersedes := o.Supersedes
	if supersedes == nil {
		supersedes = []string{}
	}
	sum := sha256.Sum256([]byte(rp.Issuer + "\x00" + o.EventID))
	rep := core.OutcomeReport{
		PactVersion:        core.Version,
		Issuer:             rp.Issuer,
		Subject:            o.Context.AgentID,
		Audience:           rp.Audience,
		JTI:                base64.RawURLEncoding.EncodeToString(sum[:])[:22],
		IssuedAt:           now.Unix(),
		NotBefore:          now.Unix(),
		Expiry:             now.Add(outcomeValidity).Unix(),
		TenantID:           o.Context.TenantID,
		EventID:            o.EventID,
		EnvironmentID:      o.Context.EnvironmentID,
		TaskID:             o.TaskID,
		OperationID:        o.OperationID,
		AdmissionReceiptID: o.AdmissionReceiptID,
		ObservedAt:         o.ObservedAt.Unix(),
		ReporterRole:       role,
		Context:            o.Context,
		EventKind:          o.EventKind,
		Result:             o.Result,
		Dimension:          o.Dimension,
		Severity:           o.Severity,
		EvidenceRefs:       refs,
		Attribution:        o.Attribution,
		Supersedes:         supersedes,
		Details:            Redact(o.Details),
	}
	payload, err := json.Marshal(rep)
	if err != nil {
		return nil, fmt.Errorf("outcome report: %w", err)
	}
	compact, err := jws.Sign(jws.Header{Typ: jws.TypOutcome, Kid: rp.KID}, payload, rp.Key)
	if err != nil {
		return nil, fmt.Errorf("signing: %w", adapter.ErrDependencyUnavailable)
	}
	return adapter.Signed{JWS: compact}, nil
}

// The shapes of credential material that draft 19 keeps out of outcome
// reports.
var (
	headerLine = regexp.MustCompile(`(?i)\b(authorization|proxy-authorization|cookie|set-cookie|pact-presentation|pact-admission)\s*:[^\r\n]*`)
	authValue  = regexp.MustCompile(`(?i)\b(bearer|basic)(\s+|%20|\+)[A-Za-z0-9._~+/=%-]+`)
	jwsLike    = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*`)
	assignment = regexp.MustCompile(`(?i)\b(access_token|refresh_token|id_token|api_?key|password|passwd|pwd|secret|session(?:_?id)?|sid|token|auth|authorization)=[^\s&;"']+`)
)

const redacted = "[redacted]"

// Redact removes credential material from free text and references:
// credential header lines, Basic and Bearer values, compact JWS, and
// name=value pairs with a credential name (draft 19).
func Redact(s string) string {
	s = headerLine.ReplaceAllString(s, "${1}: "+redacted)
	s = authValue.ReplaceAllString(s, "${1} "+redacted)
	s = jwsLike.ReplaceAllString(s, redacted)
	return assignment.ReplaceAllString(s, "${1}="+redacted)
}
