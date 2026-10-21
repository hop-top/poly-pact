package memory

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strings"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/core"
)

// outcomeValidity is the validity of a signed outcome report: the baseline
// maximum of draft 14.3.
const outcomeValidity = 300 * time.Second

// RecordOutcome records the observation as an outcome report signed with ES256.
//
// What the adapter cannot see it does not claim. An EXECUTION observation with
// no execution visibility returns NoVisibility whatever result the observation
// carries, and never an assumed success (draft 14.1). The adapter signs only
// the events it observes itself: admission and authorization decisions as the
// gateway and, with visibility, executions as the executor. Free text and
// evidence references are cleaned of credential material first (draft 19).
func (a *Adapter) RecordOutcome(ctx context.Context, o adapter.Observation) (adapter.Recorded, error) {
	if err := a.live(ctx, "record outcome"); err != nil {
		return nil, err
	}
	if a.key == nil {
		return nil, fmt.Errorf("memory: no reporting key is configured: %w", adapter.ErrUnsupportedRequirement)
	}
	if o.EventID == "" {
		return nil, errors.New("memory: the observation has no event id")
	}
	if o.Context.TenantID != a.st.Gateway.TenantID || o.Context.EnvironmentID != a.st.Gateway.EnvironmentID {
		return nil, fmt.Errorf("memory: the observation belongs to another realm: %w", adapter.ErrContextMismatch)
	}
	var role core.ReporterRole
	switch o.EventKind {
	case core.EventAdmission, core.EventAuthorization:
		role = core.ReporterGateway
	case core.EventExecution:
		if a.st.Visibility != "execution" {
			return adapter.NoVisibility{Reason: "the adapter does not observe the execution of operations; execution is reported by the system that runs them"}, nil
		}
		role = core.ReporterExecutor
	default:
		return nil, fmt.Errorf("memory: the adapter does not report %s events: %w", o.EventKind, adapter.ErrUnsupportedRequirement)
	}

	now := a.clk.Now()
	refs := make([]string, len(o.EvidenceRefs))
	for i, ref := range o.EvidenceRefs {
		refs[i] = a.redact(ref)
	}
	supersedes := o.Supersedes
	if supersedes == nil {
		supersedes = []string{}
	}
	rep := core.OutcomeReport{
		PactVersion:        core.Version,
		Issuer:             a.st.Reporting.Issuer,
		Subject:            o.Context.AgentID,
		Audience:           a.st.Reporting.Audience,
		JTI:                a.jti(o.EventID),
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
		Details:            a.redact(o.Details),
	}
	jws, err := a.sign(rep)
	if err != nil {
		return nil, fmt.Errorf("memory: signing: %w", adapter.ErrDependencyUnavailable)
	}
	return adapter.Signed{JWS: jws}, nil
}

// jti is stable per event, so a retry of the same observation carries the same
// identifier and the receiver deduplicates it (draft 7.5).
func (a *Adapter) jti(eventID string) string {
	sum := sha256.Sum256([]byte(a.st.Reporting.Issuer + "\x00" + eventID))
	return base64.RawURLEncoding.EncodeToString(sum[:])[:22]
}

// sign returns the compact JWS of rep: header typ pact-outcome+jwt, alg ES256.
func (a *Adapter) sign(rep core.OutcomeReport) (string, error) {
	hdr, err := json.Marshal(map[string]string{
		"alg": "ES256",
		"kid": a.st.Reporting.KID,
		"typ": "pact-outcome+jwt",
	})
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(rep)
	if err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding
	input := enc.EncodeToString(hdr) + "." + enc.EncodeToString(payload)
	sum := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, a.key, sum[:])
	if err != nil {
		return "", err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return input + "." + enc.EncodeToString(sig), nil
}

// VerifyOutcome verifies the ES256 signature of a compact JWS this adapter
// signed.
func (a *Adapter) VerifyOutcome(jws string) error {
	if a.key == nil {
		return errors.New("memory: no reporting key is configured")
	}
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		return errors.New("memory: not a compact JWS")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) != 64 {
		return errors.New("memory: malformed signature")
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	r, s := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(&a.key.PublicKey, sum[:], r, s) {
		return errors.New("memory: the signature does not verify")
	}
	return nil
}

// The shapes of credential material that draft 19 keeps out of receipts,
// outcome reports and logs.
var (
	headerLine = regexp.MustCompile(`(?i)\b(authorization|proxy-authorization|cookie|set-cookie|pact-presentation|pact-admission)\s*:[^\r\n]*`)
	authValue  = regexp.MustCompile(`(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]+`)
	jwsLike    = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*`)
	assignment = regexp.MustCompile(`(?i)\b(access_token|refresh_token|id_token|api_?key|password|passwd|secret|session(?:_?id)?|sid|token)=[^\s&;"']+`)
)

const redacted = "[redacted]"

// redact removes credential material from free text and references: every
// secret the adapter holds, header lines that carry credentials, bearer and
// basic values, compact JWS strings, and name=value pairs with a credential
// name.
func (a *Adapter) redact(s string) string {
	for _, id := range a.st.Identities {
		if id.Secret != "" {
			s = strings.ReplaceAll(s, id.Secret, redacted)
		}
	}
	s = headerLine.ReplaceAllString(s, "${1}: "+redacted)
	s = authValue.ReplaceAllString(s, "${1} "+redacted)
	s = jwsLike.ReplaceAllString(s, redacted)
	return assignment.ReplaceAllString(s, "${1}="+redacted)
}
