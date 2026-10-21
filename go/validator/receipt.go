package validator

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sync"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/core"
	"hop.top/pact-go/core/jws"
)

// receiptLifetime is the longest receipt validity of draft 12.1 and 20.1.
const receiptLifetime = 60 * time.Second

// seal is draft 11.3 step 10 and the terminal transition of draft 12.2: the
// final checks of a positive result, the decision, the durable record and
// the signed attestation. A receipt that cannot be recorded is never
// positive (draft 12.2, 18).
func (e *evaluation) seal(ctx, run context.Context) (Result, error) {
	e.over(run)
	checks := e.ordered()
	decision := Decide(checks, e.terminal())
	if decision == core.DecisionAdmissible {
		e.finalChecks(ctx)
		e.over(run)
		checks = e.ordered()
		decision = Decide(checks, e.terminal())
	}
	at := e.v.Clock.Now()
	if e.ended != "" {
		at = e.endedAt
	}
	res, err := e.sign(checks, decision, at)
	if err != nil {
		return Result{}, err
	}
	if perr := e.v.Receipts.Put(ctx, res); perr != nil {
		if decision == core.DecisionAdmissible {
			e.set(CheckReceiptStore, unknown(reasonUnavailable))
			checks = e.ordered()
			decision = core.DecisionDeferred
			if res, err = e.sign(checks, decision, at); err != nil {
				return Result{}, err
			}
			_ = e.v.Receipts.Put(ctx, res)
		}
		e.fireSeal(decision)
		return res, fmt.Errorf("validator: receipt not recorded: %w: %w", adapter.ErrDependencyUnavailable, perr)
	}
	e.fireSeal(decision)
	return res, nil
}

func (e *evaluation) terminal() core.TerminalReason {
	if e.ended != "" {
		return e.ended
	}
	return core.TerminalCompleted
}

func (e *evaluation) fireSeal(d core.Decision) {
	// The machine is this evaluation's own and has not been sealed, so the
	// transition exists; an error here would be a defect, not an input.
	_, _ = e.m.fire(sealEvent(d, e.terminal()))
}

// finalChecks is the final check of draft 11.3 step 10 before a positive
// result: the contract is still active, and no security hold or binding
// revocation became effective during the evaluation.
func (e *evaluation) finalChecks(ctx context.Context) {
	if active, err := e.v.Policies.Active(ctx); err != nil {
		e.set(CheckActivePolicy, unknown(reasonUnavailable))
	} else if e.c.CheckActive(active.Policy) != nil {
		e.set(CheckActivePolicy, fail(reasonRequirementsChanged))
	}
	if holds, err := e.v.Holds.Holds(ctx, e.v.Config.Realm, e.p.Subject); err != nil {
		e.set(CheckSecurityHold, unknown(reasonUnavailable))
	} else if len(holds) > 0 {
		o := fail(reasonSecurityHold)
		o.evidence = holds
		e.set(CheckSecurityHold, o)
	}
	pr := e.req.Principal
	b, err := e.v.Native.ResolveAgentBinding(ctx, pr.Realm, pr.Workload, adapter.AgentID(e.p.Subject))
	switch {
	case err != nil:
		e.set(CheckAgentHolderBinding, unknown(reasonUnavailable))
	case b.Status == adapter.BindingCompromised:
		e.set(CheckAgentHolderBinding, fail(reasonSecurityHold))
	case b.Status != adapter.BindingActive || b.HolderJKT != e.jkt || b.AgentID != e.p.Subject:
		e.set(CheckAgentHolderBinding, fail(reasonInvalidProof))
	}
}

// ordered returns the check results in receipt order: the protocol checks,
// the field rules and the contract's context checks, each exactly once. A
// rule or check that was not performed is UNKNOWN with NOT_EVALUATED, never
// PASS (draft 12.1).
func (e *evaluation) ordered() []core.CheckResult {
	ids := []string{
		CheckNativeAuthentication, CheckAgentHolderBinding, CheckContractValidity, CheckNonce,
		CheckOperationBinding, CheckIntentBinding, CheckProfileValidity, CheckEvidenceValidity,
		CheckReputationContext, CheckSecurityHold, CheckActivePolicy, CheckReceiptStore,
	}
	out := make([]core.CheckResult, 0, len(ids)+len(e.c.Claims.FieldRules)+len(e.c.Claims.ContextChecks))
	for _, id := range ids {
		if c, ok := e.checks[id]; ok {
			out = append(out, c)
		}
	}
	required := make([]string, 0, len(e.c.Claims.FieldRules)+len(e.c.Claims.ContextChecks))
	for _, r := range e.c.Claims.FieldRules {
		required = append(required, r.RuleID)
	}
	required = append(required, e.c.Claims.ContextChecks...)
	for _, id := range required {
		c, ok := e.checks[id]
		if !ok {
			e.set(id, notEvaluated())
			c = e.checks[id]
			c.CheckedAt = e.sealUnix()
			e.checks[id] = c
		}
		out = append(out, c)
	}
	return out
}

func (e *evaluation) sealUnix() int64 {
	if e.ended != "" {
		return e.endedAt.Unix()
	}
	return e.v.Clock.Now().Unix()
}

// sign builds and signs the attestation (draft 12.1).
func (e *evaluation) sign(checks []core.CheckResult, d core.Decision, at time.Time) (Result, error) {
	jti, err := randomID()
	if err != nil {
		return Result{}, fmt.Errorf("validator: jti: %w: %w", adapter.ErrDependencyUnavailable, err)
	}
	iat := at.Unix()
	exp := iat + int64(receiptLifetime/time.Second)
	if d == core.DecisionAdmissible {
		for _, x := range append([]int64{e.p.Expiry, e.c.Claims.Expiry, e.p.Profile.ExpiresAt}, e.expiries...) {
			exp = min(exp, x)
		}
	}
	pol := e.c.Claims
	att := core.AdmissionAttestation{
		PactVersion: core.Version, Issuer: e.v.Config.Issuer, Subject: e.p.Subject, Audience: e.v.Config.Audience,
		JTI: jti, IssuedAt: iat, NotBefore: iat, Expiry: exp, TenantID: e.v.Config.Realm.TenantID,
		PresentationID: e.p.JTI, OperationID: e.req.Operation.OperationID, PrincipalID: e.req.Operation.PrincipalID,
		EnvironmentID: e.v.Config.Realm.EnvironmentID, HolderJKT: e.jkt,
		ProfileDigest: objectDigest(e.profileRaw), IntentDigest: objectDigest(e.intentRaw),
		OperationDigest: e.actualDigest(), RequirementsDigest: e.c.Digest,
		LearningPolicyDigest: pol.LearningPolicyDigest, LearningArtifactDigest: pol.LearningArtifactDigest,
		Decision: d, TerminalReason: e.terminal(), Mode: pol.Mode, Checks: slices.Clone(checks),
		Extensions: e.extensions(),
	}
	payload, err := json.Marshal(att)
	if err != nil {
		return Result{}, err
	}
	compact, err := e.v.Signer.SignAttestation(payload)
	if err != nil {
		return Result{}, fmt.Errorf("validator: signer: %w: %w", adapter.ErrDependencyUnavailable, err)
	}
	return Result{Receipt: compact, Attestation: att}, nil
}

// extensions are the contract's supported extensions, which the attestation
// carries too (draft 21).
func (e *evaluation) extensions() core.Object {
	var out core.Object
	for name, v := range e.c.Claims.Extensions {
		if slices.Contains(e.v.Config.SupportedExtensions, name) {
			if out == nil {
				out = core.Object{}
			}
			out[name] = v
		}
	}
	return out
}

func randomID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// ES256Signer signs attestations with a P-256 key (draft 7.2).
type ES256Signer struct {
	Kid string
	Key *ecdsa.PrivateKey
}

// SignAttestation implements Signer.
func (s ES256Signer) SignAttestation(payload []byte) (string, error) {
	return jws.Sign(jws.Header{Typ: jws.TypAdmission, Kid: s.Kid}, payload, s.Key)
}

// Ed25519Signer signs attestations with an Ed25519 key, for a gateway that
// negotiated Ed25519 (draft 7.2, RFC 9864).
type Ed25519Signer struct {
	Kid string
	Key ed25519.PrivateKey
}

// SignAttestation implements Signer.
func (s Ed25519Signer) SignAttestation(payload []byte) (string, error) {
	return jws.SignEd25519(jws.Header{Typ: jws.TypAdmission, Kid: s.Kid}, payload, s.Key)
}

// ErrNotFound is the error of a receipt a store does not hold.
var ErrNotFound = errors.New("validator: receipt not found")

// MemoryReceipts is a ReceiptStore in the memory of one process, safe for
// concurrent use. A sealed receipt is stored once and never replaced.
type MemoryReceipts struct {
	mu      sync.Mutex
	byJTI   map[string]Result
	byDigst map[core.Digest][]string
}

// NewMemoryReceipts returns an empty store.
func NewMemoryReceipts() *MemoryReceipts {
	return &MemoryReceipts{byJTI: map[string]Result{}, byDigst: map[core.Digest][]string{}}
}

// Put implements ReceiptStore. A second receipt with the jti of a stored one
// is refused.
func (m *MemoryReceipts) Put(_ context.Context, r Result) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	jti := r.Attestation.JTI
	if _, dup := m.byJTI[jti]; dup || jti == "" {
		return fmt.Errorf("validator: receipt %q already recorded or without jti", jti)
	}
	m.byJTI[jti] = r
	d := r.Attestation.RequirementsDigest
	m.byDigst[d] = append(m.byDigst[d], jti)
	return nil
}

// Get implements ReceiptStore.
func (m *MemoryReceipts) Get(_ context.Context, jti string) (Result, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.byJTI[jti]
	if !ok {
		return Result{}, ErrNotFound
	}
	return r, nil
}

// ByContract implements ReceiptStore.
func (m *MemoryReceipts) ByContract(_ context.Context, d core.Digest) ([]Result, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Result, 0, len(m.byDigst[d]))
	for _, jti := range m.byDigst[d] {
		out = append(out, m.byJTI[jti])
	}
	return out, nil
}

// All returns every stored receipt, by jti.
func (m *MemoryReceipts) All() map[string]Result {
	m.mu.Lock()
	defer m.mu.Unlock()
	return maps.Clone(m.byJTI)
}
