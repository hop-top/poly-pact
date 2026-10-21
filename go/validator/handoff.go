package validator

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/core"
	"hop.top/pact-go/core/clock"
	"hop.top/pact-go/core/digest"
	"hop.top/pact-go/core/jws"
	"hop.top/pact-go/core/strictjson"
)

// AttestationStore marks positive attestations consumed, atomically and
// once (draft 11.5). Gateway replicas share one store.
type AttestationStore interface {
	// Consume marks jti consumed and keeps the mark at least until until.
	// A jti consumed before is an error that carries the code REPLAY; a
	// store that cannot answer returns an error that wraps
	// adapter.ErrDependencyUnavailable.
	Consume(ctx context.Context, jti string, until time.Time) error
}

// Handoff is the gateway side of a sidecar deployment (draft 4.4, 11.5): it
// accepts an attestation of a trusted validator for exactly the operation
// it was issued for, once.
type Handoff struct {
	// Validators maps the iss of each trusted validator to its keys.
	Validators map[string]*jws.KeySet
	// Audience and Realm are the gateway's.
	Audience string
	Realm    adapter.Realm
	// Algorithms are the negotiated JWS algorithms; nil is ES256 alone.
	Algorithms jws.Algorithms
	// Skew is the allowed clock skew, 0 to 5 s.
	Skew time.Duration
	// Consumed marks accepted attestations; Holds, when set, is checked
	// at handoff (draft 11.5: current local security holds).
	Consumed AttestationStore
	Holds    HoldStore
}

// Accept verifies the attestation compact for the actual operation op of the
// authenticated principal at the instant now (draft 11.5): the validator's
// signature, audience, realm, principal, operation digest, decision and
// expiry, then marks it consumed. The error carries the draft 13.4 code of
// the rejection: INVALID_MESSAGE or INVALID_PROOF for the JWS,
// CONTEXT_MISMATCH for another gateway, principal, operation or a decision
// other than ADMISSIBLE, EXPIRED, SECURITY_HOLD, or REPLAY for an
// attestation already accepted.
func (h *Handoff) Accept(ctx context.Context, compact string, op core.OperationContext, p adapter.Principal, now time.Time) (core.AdmissionAttestation, error) {
	var att core.AdmissionAttestation
	if h.Consumed == nil {
		return att, errors.New("validator: Handoff needs a Consumed store")
	}
	parsed, err := jws.Verifier{Keys: issuerKeys(h.Validators), Typ: jws.TypAdmission, Algorithms: h.Algorithms}.Verify(compact)
	if err != nil {
		if isProofFailure(err) {
			return att, reject(adapter.CodeInvalidProof, "attestation signature: "+err.Error())
		}
		return att, reject(adapter.CodeInvalidMessage, "attestation: "+err.Error())
	}
	if err := strictjson.Unmarshal(parsed.Payload, strictjson.Limits{}, &att); err != nil {
		return att, reject(adapter.CodeInvalidMessage, "attestation payload: "+err.Error())
	}
	opDigest, err := digest.ObjectDigest(op)
	if err != nil {
		return att, reject(adapter.CodeInvalidMessage, "operation: "+err.Error())
	}
	switch {
	case att.Audience != h.Audience || att.TenantID != h.Realm.TenantID || att.EnvironmentID != h.Realm.EnvironmentID:
		return att, reject(adapter.CodeContextMismatch, "attestation is for another gateway or realm")
	case att.PrincipalID != p.ID || op.PrincipalID != p.ID:
		return att, reject(adapter.CodeContextMismatch, "attestation is for another principal")
	case att.OperationDigest != opDigest || att.OperationID != op.OperationID:
		return att, reject(adapter.CodeContextMismatch, "attestation is for another operation")
	case att.Decision != core.DecisionAdmissible || att.Mode != core.ModeEnforced:
		return att, reject(adapter.CodeContextMismatch, "attestation is not an enforced positive admission")
	}
	if err := clock.CheckWindow(att.IssuedAt, att.NotBefore, att.Expiry, now, h.Skew); err != nil {
		if errors.Is(err, clock.ErrExpired) {
			return att, reject(codeExpired, "attestation expired")
		}
		return att, reject(adapter.CodeInvalidMessage, "attestation: "+err.Error())
	}
	if h.Holds != nil {
		holds, err := h.Holds.Holds(ctx, h.Realm, att.Subject)
		if err != nil {
			return att, reject(adapter.CodeDependencyUnavailable, "hold store: "+err.Error())
		}
		if len(holds) > 0 {
			return att, reject(codeSecurityHold, "a security hold is in force")
		}
	}
	if err := h.Consumed.Consume(ctx, att.JTI, time.Unix(att.Expiry, 0)); err != nil {
		if code, ok := adapter.CodeOf(err); ok && code == codeReplay {
			return att, reject(codeReplay, "attestation already accepted")
		}
		return att, reject(adapter.CodeDependencyUnavailable, "attestation store: "+err.Error())
	}
	return att, nil
}

// MemoryAttestations is an AttestationStore in the memory of one process,
// safe for concurrent use.
type MemoryAttestations struct {
	mu       sync.Mutex
	consumed map[string]time.Time
}

// NewMemoryAttestations returns an empty store.
func NewMemoryAttestations() *MemoryAttestations {
	return &MemoryAttestations{consumed: map[string]time.Time{}}
}

// Consume implements AttestationStore.
func (m *MemoryAttestations) Consume(_ context.Context, jti string, until time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.consumed[jti]; ok {
		return reject(codeReplay, fmt.Sprintf("attestation %q already consumed", jti))
	}
	m.consumed[jti] = until
	return nil
}
