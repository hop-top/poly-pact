package validator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/contract"
	"hop.top/pact-go/core"
	"hop.top/pact-go/core/clock"
	"hop.top/pact-go/core/digest"
	"hop.top/pact-go/core/jws"
	"hop.top/pact-go/core/strictjson"
)

// maxEvaluation is the longest evaluation of draft 12.2 and 20.1.
const maxEvaluation = 30 * time.Second

// Validator evaluates presentations (draft 11.3) and seals each authenticated
// evaluation in a signed receipt (draft 12). Every store is an interface the
// gateway implements; a store that cannot answer defers, never admits
// (draft 18). It is safe for concurrent use when its stores are: replicas of
// a gateway share one ReplayStore and one ReceiptStore.
type Validator struct {
	Config Config
	// Native is the gateway's native adapter (draft 17.1).
	Native Native
	// Replay consumes contract nonces atomically (draft 7.5).
	Replay contract.ReplayStore
	// Receipts records sealed receipts durably (draft 12.2).
	Receipts ReceiptStore
	// Holds reports security holds, Policies the active policy and
	// selection, Status the status of evidence (draft 18).
	Holds    HoldStore
	Policies PolicyRegistry
	Status   StatusChecker
	// Contexts is the installed reputation context mapping; without it a
	// presented snapshot's context cannot be checked, so the
	// reputation-context check is UNKNOWN.
	Contexts ContextMapper
	// Signer signs the attestations; Clock is the only source of time.
	Signer Signer
	Clock  clock.Clock
}

// evaluation is the state of one Evaluate call.
type evaluation struct {
	v       *Validator
	req     Request
	m       *machine
	start   time.Time
	ended   core.TerminalReason // "" while the evaluation runs
	endedAt time.Time

	p          core.Presentation
	profileRaw json.RawMessage
	intentRaw  json.RawMessage
	opRaw      json.RawMessage
	profile    any
	jkt        core.Digest
	c          contract.Contract
	deadline   time.Time

	binding      adapter.AgentBinding
	bindingKnown bool // false when the enrollment source could not answer

	nonce  outcome
	checks map[string]core.CheckResult

	claims       []authClaim
	failedPaths  map[string]string
	pendingPaths map[string]string
	evidenceIDs  []string
	expiries     []int64
	snapshot     *core.ReputationSnapshot
	snapshotJTI  string

	active    ActivePolicy
	activeErr error
	sel       Selection
	selErr    error
	holds     []string
	holdsErr  error
	holdsAt   time.Time // the time of the evaluation's security-hold check
}

// Evaluate evaluates one presentation for the actual operation of req, at
// the instant the Clock gives, and returns the sealed receipt.
//
// A request rejected before an authenticated evaluation (draft 12.2) gets no
// receipt: the error then carries the draft 13.4 code that adapter.CodeOf
// reads and ProblemOf turns into a transport error. An authenticated
// evaluation always ends in a receipt, ADMISSIBLE only when every required
// check passed; when the receipt cannot be recorded durably, the result is a
// DEFERRED receipt and the error wraps adapter.ErrDependencyUnavailable.
// Cancelling ctx is the requestor's cancellation through native session
// control (draft 12.2): the evaluation seals as CANCELLED.
func (v *Validator) Evaluate(ctx context.Context, req Request) (Result, error) {
	if err := v.ready(); err != nil {
		return Result{}, err
	}
	e := &evaluation{
		v: v, req: req, m: newMachine(), start: v.Clock.Now(),
		checks: map[string]core.CheckResult{}, failedPaths: map[string]string{}, pendingPaths: map[string]string{},
	}
	if err := e.admit(ctx); err != nil {
		return Result{}, err
	}
	if _, err := e.m.fire(EventPresented); err != nil {
		return Result{}, err
	}
	run, cancel := context.WithDeadline(ctx, time.Now().Add(e.deadline.Sub(e.start)))
	defer cancel()
	e.run(run)
	return e.seal(context.WithoutCancel(ctx), run)
}

// ready reports a configuration the validator cannot work with.
func (v *Validator) ready() error {
	switch {
	case v.Native == nil, v.Replay == nil, v.Receipts == nil, v.Holds == nil, v.Policies == nil,
		v.Status == nil, v.Signer == nil, v.Clock == nil:
		return errors.New("validator: Native, Replay, Receipts, Holds, Policies, Status, Signer and Clock are required")
	case v.Config.Audience == "", v.Config.Issuer == "", v.Config.SourceID == "",
		v.Config.Realm.TenantID == "", v.Config.Realm.EnvironmentID == "":
		return errors.New("validator: Config needs Audience, Issuer, SourceID and Realm")
	case v.Config.Skew < 0 || v.Config.Skew > clock.BaselineSkew:
		return fmt.Errorf("validator: skew %v outside 0 to %v", v.Config.Skew, clock.BaselineSkew)
	case v.Config.EvaluationTime < 0 || v.Config.EvaluationTime > maxEvaluation:
		return fmt.Errorf("validator: evaluation time %v outside 0 to %v", v.Config.EvaluationTime, maxEvaluation)
	}
	return v.limits().Check()
}

func (v *Validator) limits() core.Limits {
	if v.Config.Limits == (core.Limits{}) {
		return core.Defaults()
	}
	return v.Config.Limits
}

// admit runs what comes before an authenticated evaluation (draft 11.3
// steps 1 to 4, 12.2): native authentication, the presentation's form and
// signature, the agent binding, the contract's signature and validity window,
// the transport the contract names (draft 13.3.1), the presentation's time
// bounds and the nonce. A failure is a transport
// rejection.
func (e *evaluation) admit(ctx context.Context) error {
	cfg, lim := e.v.Config, e.v.limits()
	if e.req.Principal.ID == "" {
		return reject(adapter.CodeInvalidProof, "no native authentication")
	}
	var refused error
	keys := holderKeys(func(r jws.KeyRequest) (core.Digest, error) {
		jkt, err := e.prepare(ctx, r.Payload)
		refused = err
		return jkt, err
	})
	parsed, err := jws.Verifier{
		Keys: keys, Typ: jws.TypPresentation, Algorithms: cfg.Algorithms,
		Limits: lim.PresentationJSON(),
	}.Verify(e.req.Presentation)
	switch {
	case refused != nil:
		return refused
	case err != nil && isProofFailure(err):
		return reject(adapter.CodeInvalidProof, "presentation signature: "+err.Error())
	case err != nil:
		return reject(adapter.CodeInvalidMessage, "presentation: "+err.Error())
	}
	if parsed.Header.JWK == nil {
		return reject(adapter.CodeInvalidMessage, "presentation carries no jwk")
	}
	if e.jkt, err = jws.Thumbprint(*parsed.Header.JWK); err != nil {
		return reject(adapter.CodeInvalidMessage, "presentation jwk: "+err.Error())
	}
	if e.jkt != e.p.Profile.HolderJKT || e.jkt != e.c.Claims.HolderJKT {
		return reject(adapter.CodeInvalidProof, "presentation key is not the profile and contract holder_jkt")
	}
	if named := e.c.Transport(); e.c.Claims.Mode == core.ModeEnforced && e.req.Transport != named {
		return reject(adapter.CodeContextMismatch, fmt.Sprintf("presentation arrived over transport %q; the contract names %q", e.req.Transport, named))
	}
	if err := clock.CheckPresentation(e.p.IssuedAt, e.p.NotBefore, e.p.Expiry, e.start, cfg.Skew); err != nil {
		if errors.Is(err, clock.ErrExpired) || errors.Is(err, clock.ErrTooOld) {
			return reject(codeExpired, "presentation: "+err.Error())
		}
		return reject(adapter.CodeInvalidMessage, "presentation: "+err.Error())
	}
	if err := lim.ValidateOperation(&e.req.Operation); err != nil {
		return reject(adapter.CodeInvalidMessage, "actual operation: "+err.Error())
	}
	if e.req.Operation.PrincipalID != e.req.Principal.ID {
		return reject(adapter.CodeInvalidMessage, "actual operation names another principal than the authenticated one")
	}
	e.deadline = e.start.Add(e.evaluationTime())
	for _, exp := range []int64{e.c.Claims.Expiry, e.p.Expiry} {
		if t := time.Unix(exp, 0); t.Before(e.deadline) {
			e.deadline = t
		}
	}
	return e.consumeNonce(ctx)
}

func (e *evaluation) evaluationTime() time.Duration {
	if e.v.Config.EvaluationTime == 0 {
		return maxEvaluation
	}
	return e.v.Config.EvaluationTime
}

// prepare decodes the presentation payload, verifies the embedded contract
// and resolves the agent binding, and returns the holder_jkt the
// presentation key must have. It runs inside the JWS verification, after
// the structural checks and before the signature check; nothing in the
// payload is trusted until that check passes.
func (e *evaluation) prepare(ctx context.Context, payload []byte) (core.Digest, error) {
	cfg, lim := e.v.Config, e.v.limits()
	if err := strictjson.Unmarshal(payload, lim.PresentationJSON(), &e.p); err != nil {
		return "", reject(adapter.CodeInvalidMessage, "presentation payload: "+err.Error())
	}
	var raw map[string]json.RawMessage
	if err := strictjson.Unmarshal(payload, lim.PresentationJSON(), &raw); err != nil {
		return "", reject(adapter.CodeInvalidMessage, "presentation payload: "+err.Error())
	}
	e.profileRaw, e.intentRaw, e.opRaw = raw["profile"], raw["intent"], raw["operation"]
	if err := lim.ValidatePresentation(&e.p, len(payload)); err != nil {
		return "", reject(adapter.CodeInvalidMessage, err.Error())
	}
	if err := lim.ValidateProfileSize(len(e.profileRaw)); err != nil {
		return "", reject(adapter.CodeInvalidMessage, err.Error())
	}
	if e.p.PactVersion != core.Version || e.p.Issuer != e.p.Subject {
		return "", reject(adapter.CodeInvalidMessage, "presentation pact_version or iss and sub")
	}
	profile, err := decodeJSON(e.profileRaw)
	if err != nil {
		return "", reject(adapter.CodeInvalidMessage, "profile: "+err.Error())
	}
	e.profile = profile
	c, err := contract.Verifier{Publishers: cfg.Publishers, Algorithms: cfg.Algorithms, Skew: cfg.Skew}.Verify(e.p.Contract, e.start)
	if err != nil {
		code, _ := adapter.CodeOf(err)
		return "", reject(code, err.Error())
	}
	if err := lim.ValidateContract(&c.Claims); err != nil {
		return "", reject(adapter.CodeInvalidMessage, "contract: "+err.Error())
	}
	e.c = c
	return e.resolveBinding(ctx)
}

// resolveBinding resolves the binding of the agent the presentation names to
// the authenticated workload (draft 6.1, 11.3 step 2, 17.1).
func (e *evaluation) resolveBinding(ctx context.Context) (core.Digest, error) {
	pr := e.req.Principal
	b, err := e.v.Native.ResolveAgentBinding(ctx, pr.Realm, pr.Workload, adapter.AgentID(e.p.Subject))
	if err != nil {
		code, _ := adapter.CodeOf(err)
		switch code {
		case adapter.CodeUnsupportedRequirement:
			return "", reject(code, "agent binding: "+err.Error())
		case adapter.CodeInvalidProof, adapter.CodeContextMismatch:
			return "", reject(code, "agent binding: "+err.Error())
		}
		// The enrollment source cannot answer: the evaluation proceeds and
		// defers (draft 18); the key must still be the one the publisher
		// bound into the contract.
		return e.c.Claims.HolderJKT, nil
	}
	switch b.Status {
	case adapter.BindingUnknown:
		if b.EnrolledElsewhere {
			return "", reject(adapter.CodeContextMismatch, "agent is enrolled for another workload")
		}
		return "", reject(adapter.CodeInvalidProof, "agent has no enrollment on the authenticated workload")
	case adapter.BindingActive, adapter.BindingCompromised:
		if b.AgentID != e.p.Subject {
			return "", reject(adapter.CodeInvalidProof, "binding names another agent")
		}
	default:
		return "", reject(adapter.CodeInvalidProof, "agent binding is "+string(b.Status))
	}
	e.binding, e.bindingKnown = b, true
	return b.HolderJKT, nil
}

// consumeNonce is step 4 of draft 11.3: the nonce of the presentation is its
// contract's, consumed atomically, once.
func (e *evaluation) consumeNonce(ctx context.Context) error {
	if e.p.Nonce != e.c.Claims.Nonce {
		e.nonce = fail(reasonContextMismatch)
		return nil
	}
	until := clock.ReplayRetention(e.p.Expiry, e.p.IssuedAt, e.v.Config.Skew)
	if t := time.Unix(e.c.Claims.Expiry, 0); t.After(until) {
		until = t
	}
	err := e.v.Replay.Consume(ctx, e.c.NonceRecord(), e.start, until)
	switch {
	case err == nil:
		e.nonce = pass()
	case errors.Is(err, contract.ErrReplay):
		if e.sealedStale(ctx) {
			return reject(codeRequirementsChanged, "contract was sealed stale; obtain a new contract")
		}
		return reject(codeReplay, "nonce already consumed")
	case errors.Is(err, contract.ErrContextMismatch):
		e.nonce = fail(reasonContextMismatch)
	default:
		e.nonce = unknown(reasonUnavailable)
	}
	e.nonce.observed, e.nonce.status = nil, nil
	return nil
}

// sealedStale reports whether an evaluation of the contract sealed with a
// result that makes the contract stale: on reuse of such a contract the
// transport error is REQUIREMENTS_CHANGED (draft 11.3 step 9, 12.2).
func (e *evaluation) sealedStale(ctx context.Context) bool {
	rs, err := e.v.Receipts.ByContract(ctx, e.c.Digest)
	if err != nil {
		return false
	}
	for _, r := range rs {
		for _, c := range r.Attestation.Checks {
			if c.Result == core.CheckFail && staleContract(c.ReasonCode) {
				return true
			}
		}
	}
	return false
}

// holderKeys is the key resolver of a presentation: the expected holder_jkt
// comes from the agent binding, which the callback resolves.
type holderKeys func(jws.KeyRequest) (core.Digest, error)

func (h holderKeys) TrustedKeys(jws.KeyRequest) (*jws.KeySet, error) {
	return nil, errors.New("a presentation is holder-signed")
}

func (h holderKeys) HolderJKT(r jws.KeyRequest) (core.Digest, error) { return h(r) }

// issuerKeys resolves the key set of the trust record that the payload's
// iss names; the payload is not authenticated yet (jws.KeyRequest).
type issuerKeys map[string]*jws.KeySet

func (k issuerKeys) TrustedKeys(r jws.KeyRequest) (*jws.KeySet, error) {
	var claims struct {
		Iss string `json:"iss"`
	}
	if err := json.Unmarshal(r.Payload, &claims); err != nil {
		return nil, nil
	}
	return k[claims.Iss], nil
}

func (issuerKeys) HolderJKT(jws.KeyRequest) (core.Digest, error) {
	return "", errors.New("not a holder-signed artifact")
}

func trustKeys(issuers []Issuer) issuerKeys {
	k := issuerKeys{}
	for _, i := range issuers {
		k[i.ID] = i.Keys
	}
	return k
}

// isProofFailure reports the JWS failures that mean the signer could not be
// authenticated; every other failure is a malformed message.
func isProofFailure(err error) bool {
	switch jws.ReasonOf(err) {
	case jws.ErrSignatureInvalid, jws.ErrKidUnknown, jws.ErrKeyUnavailable, jws.ErrHolderJKTMismatch:
		return true
	}
	return false
}

// objectDigest is the object_digest of received JSON (draft 7.4).
func objectDigest(raw json.RawMessage) core.Digest {
	d, err := digest.ObjectDigest(raw)
	if err != nil {
		return ""
	}
	return d
}
