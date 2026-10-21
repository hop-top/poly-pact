package validator_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/contract"
	"hop.top/pact-go/core"
	"hop.top/pact-go/core/digest"
	"hop.top/pact-go/core/jws"
	"hop.top/pact-go/validator"
	"hop.top/pact-go/validator/conformance"
)

var fixtures = filepath.Join("..", "..", "spec", "v1.0", "fixtures")

func prepare(t *testing.T, id string) *conformance.Fixture {
	t.Helper()
	f, err := conformance.Prepare(filepath.Join(fixtures, filepath.FromSlash(id)))
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func evaluate(t *testing.T, f *conformance.Fixture) validator.Result {
	t.Helper()
	res, err := f.Validator.Evaluate(context.Background(), f.Request)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	return res
}

func codeOf(t *testing.T, err error) adapter.Code {
	t.Helper()
	code, ok := adapter.CodeOf(err)
	if !ok {
		t.Fatalf("error %v carries no draft 13.4 code", err)
	}
	return code
}

func check(t *testing.T, res validator.Result, id string) core.CheckResult {
	t.Helper()
	for _, c := range res.Attestation.Checks {
		if c.CheckID == id {
			return c
		}
	}
	t.Fatalf("receipt has no check %q", id)
	return core.CheckResult{}
}

func wantCheck(t *testing.T, res validator.Result, id string, result core.CheckStatus, reason string) {
	t.Helper()
	if c := check(t, res, id); c.Result != result || c.ReasonCode != reason {
		t.Errorf("%s = %s %s, want %s %s", id, c.Result, c.ReasonCode, result, reason)
	}
}

// b7Checks are the check ids of the Appendix B.7 receipt, in its order.
var b7Checks = []string{
	"native-authentication", "agent-holder-binding", "contract-validity", "nonce", "operation-binding",
	"intent-binding", "profile-validity", "evidence-validity", "reputation-context", "security-hold",
	"active-policy", "principal", "roles", "supervisor-approval", "isolation", "reputation-status",
	"native-principal-binding-v1", "purpose-operation-v1", "native-delegation-v1", "security-hold-v1",
}

// TestValidAdmissible is the worked exchange of Appendix B: ADMISSIBLE with
// every check of B.7 PASS, in B.7 order, and the digests B.7 prints.
func TestValidAdmissible(t *testing.T) {
	f := prepare(t, "admission/valid")
	res := evaluate(t, f)
	a := res.Attestation
	if a.Decision != core.DecisionAdmissible || a.TerminalReason != core.TerminalCompleted {
		t.Fatalf("decision %s %s, want ADMISSIBLE COMPLETED: %+v", a.Decision, a.TerminalReason, a.Checks)
	}
	if len(a.Checks) != len(b7Checks) {
		t.Fatalf("%d checks, want the %d of B.7", len(a.Checks), len(b7Checks))
	}
	for i, c := range a.Checks {
		if c.CheckID != b7Checks[i] || c.Result != core.CheckPass || c.ReasonCode != "REQUIREMENT_SATISFIED" {
			t.Errorf("check %d = %s %s %s, want %s PASS", i, c.CheckID, c.Result, c.ReasonCode, b7Checks[i])
		}
		if c.SourceID == "" || c.EvidenceIDs == nil {
			t.Errorf("check %s has no source_id or a null evidence_ids", c.CheckID)
		}
	}
	for name, got := range map[string]core.Digest{
		"profile_digest": a.ProfileDigest, "intent_digest": a.IntentDigest, "operation_digest": a.OperationDigest,
	} {
		want := map[string]core.Digest{
			"profile_digest":   "b6pNI8i5pX5MtuxkaBw0M-4tmzdkGsHVS_Kyji7_uOU",
			"intent_digest":    "t79YgXU70gzKitcuPJ_fUp4V_bM5MGooinyuyL8cE5M",
			"operation_digest": "R5nfhv7g_o93VPHK6a2o56-MyyGy75GQwXxDM4M3cn0",
		}[name]
		if got != want {
			t.Errorf("%s = %s, want the B.7 value %s", name, got, want)
		}
	}
	signed, err := os.ReadFile(filepath.Join(fixtures, "admission", "valid", "signed", "contract.jws"))
	if err != nil {
		t.Fatal(err)
	}
	if d, _ := digest.ArtifactDigest(strings.TrimSpace(string(signed))); a.RequirementsDigest != d {
		t.Errorf("requirements_digest %s, want artifact_digest of the contract %s", a.RequirementsDigest, d)
	}
	if a.PresentationID != "v6wxT-_cB0Ua8Xkqgcuu2g" || a.PrincipalID != "https://identity.example/principals/alice" ||
		a.Audience != "https://gateway.example/finance" || a.Issuer != "https://trust.example/issuers/finance" {
		t.Errorf("claims %+v", a)
	}
	if a.IssuedAt != 1792080000 || a.Expiry > 1792080060 || a.Expiry <= a.IssuedAt {
		t.Errorf("iat %d exp %d: at most 60 s and no later than the contract (12.1)", a.IssuedAt, a.Expiry)
	}
	verifyReceipt(t, res.Receipt, "validator.jwk.json")
	stored, err := f.Validator.Receipts.Get(context.Background(), a.JTI)
	if err != nil || stored.Receipt != res.Receipt {
		t.Errorf("receipt not recorded: %v", err)
	}
}

func verifyReceipt(t *testing.T, compact, keyFile string) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(fixtures, "keys", keyFile))
	if err != nil {
		t.Fatal(err)
	}
	k, err := jws.ParseJWK(b)
	if err != nil {
		t.Fatal(err)
	}
	ks, err := jws.NewKeySet(k)
	if err != nil {
		t.Fatal(err)
	}
	keys := jws.StaticResolver{KeySets: map[jws.Role]*jws.KeySet{jws.RoleValidator: ks}}
	if _, err := (jws.Verifier{Keys: keys, Typ: jws.TypAdmission}).Verify(compact); err != nil {
		t.Errorf("receipt does not verify under the validator key: %v", err)
	}
}

// TestNonceConsumedOnce: a presentation is accepted for evaluation once; a
// second submission of the same nonce is REPLAY with no receipt (draft 7.5).
func TestNonceConsumedOnce(t *testing.T) {
	f := prepare(t, "admission/valid")
	evaluate(t, f)
	res, err := f.Validator.Evaluate(context.Background(), f.Request)
	if res.Receipt != "" || codeOf(t, err) != contract.CodeReplay {
		t.Fatalf("second submission: %v, receipt %q; want REPLAY and no receipt", err, res.Receipt)
	}
}

// TestReplicasConsumeOnce: the same nonce submitted concurrently to
// replicas that share the replay store is accepted at most once (draft 22.2).
func TestReplicasConsumeOnce(t *testing.T) {
	f := prepare(t, "admission/valid")
	const replicas = 8
	var mu sync.Mutex
	var wg sync.WaitGroup
	receipts, replays := 0, 0
	for range replicas {
		v := *f.Validator
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := v.Evaluate(context.Background(), f.Request)
			mu.Lock()
			defer mu.Unlock()
			if res.Receipt != "" {
				receipts++
			}
			if code, _ := adapter.CodeOf(err); code == contract.CodeReplay {
				replays++
			}
		}()
	}
	wg.Wait()
	if receipts != 1 || replays != replicas-1 {
		t.Fatalf("%d receipts and %d replays, want 1 and %d", receipts, replays, replicas-1)
	}
}

type failingReplay struct{ contract.ReplayStore }

func (failingReplay) Consume(context.Context, contract.NonceRecord, time.Time, time.Time) error {
	return contract.ErrDependencyUnavailable
}

// TestReplayStoreOutageDefers: an unavailable or full replay store defers,
// never fails open (draft 7.5, 18).
func TestReplayStoreOutageDefers(t *testing.T) {
	f := prepare(t, "admission/valid")
	f.Validator.Replay = failingReplay{f.Validator.Replay}
	res := evaluate(t, f)
	if res.Attestation.Decision != core.DecisionDeferred {
		t.Fatalf("decision %s, want DEFERRED", res.Attestation.Decision)
	}
	wantCheck(t, res, "nonce", core.CheckUnknown, "DEPENDENCY_UNAVAILABLE")
}

type failingReceipts struct{ validator.ReceiptStore }

func (failingReceipts) Put(context.Context, validator.Result) error { return errors.New("disk full") }

// TestReceiptStoreOutageNeverAdmits: a receipt that cannot be recorded
// durably is never a positive admission (draft 12.2, 18).
func TestReceiptStoreOutageNeverAdmits(t *testing.T) {
	f := prepare(t, "admission/valid")
	f.Validator.Receipts = failingReceipts{f.Validator.Receipts}
	res, err := f.Validator.Evaluate(context.Background(), f.Request)
	if codeOf(t, err) != adapter.CodeDependencyUnavailable {
		t.Errorf("error %v, want DEPENDENCY_UNAVAILABLE", err)
	}
	if res.Attestation.Decision == core.DecisionAdmissible || res.Receipt == "" {
		t.Fatalf("decision %s, receipt %q: an unrecorded receipt must be a DEFERRED one", res.Attestation.Decision, res.Receipt)
	}
	wantCheck(t, res, "receipt-store", core.CheckUnknown, "DEPENDENCY_UNAVAILABLE")
	verifyReceipt(t, res.Receipt, "validator.jwk.json")
}

type failingHolds struct{}

func (failingHolds) Holds(context.Context, adapter.Realm, string) ([]string, error) {
	return nil, adapter.ErrDependencyUnavailable
}

type failingPolicies struct{ validator.PolicyRegistry }

func (failingPolicies) Active(context.Context) (validator.ActivePolicy, error) {
	return validator.ActivePolicy{}, adapter.ErrDependencyUnavailable
}

type failingStatus struct{}

func (failingStatus) EvidenceStatus(context.Context, string, string) (validator.EvidenceStatus, error) {
	return validator.EvidenceStatus{}, adapter.ErrDependencyUnavailable
}

type failingClaims struct{ validator.Native }

func (failingClaims) ReadNativeClaim(context.Context, string, adapter.ClaimContext) (adapter.NativeClaim, error) {
	return adapter.NativeClaim{}, adapter.ErrDependencyUnavailable
}

type unknownCheck struct {
	validator.Native
	id string
}

func (u unknownCheck) CheckContext(ctx context.Context, id string, in adapter.CheckInput) adapter.CheckOutcome {
	if id == u.id {
		return adapter.CheckOutcome{Result: adapter.VerdictUnknown, ReasonCode: "DEPENDENCY_UNAVAILABLE"}
	}
	return u.Native.CheckContext(ctx, id, in)
}

// TestOutagesDefer: a hold store, policy registry, status source, native
// source or installed check that cannot answer makes its check UNKNOWN and
// the decision DEFERRED; an UNKNOWN never counts as a pass (draft 11.4, 18).
func TestOutagesDefer(t *testing.T) {
	cases := []struct {
		name  string
		apply func(v *validator.Validator)
		check string
	}{
		{"hold store", func(v *validator.Validator) { v.Holds = failingHolds{} }, "security-hold"},
		{"policy registry", func(v *validator.Validator) { v.Policies = failingPolicies{v.Policies} }, "active-policy"},
		{"evidence status", func(v *validator.Validator) { v.Status = failingStatus{} }, "evidence-validity"},
		{"native source", func(v *validator.Validator) { v.Native = failingClaims{v.Native} }, "roles"},
		{"installed check", func(v *validator.Validator) { v.Native = unknownCheck{v.Native, "purpose-operation-v1"} }, "purpose-operation-v1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := prepare(t, "admission/valid")
			c.apply(f.Validator)
			res := evaluate(t, f)
			if res.Attestation.Decision != core.DecisionDeferred {
				t.Fatalf("decision %s, want DEFERRED", res.Attestation.Decision)
			}
			if got := check(t, res, c.check); got.Result != core.CheckUnknown {
				t.Errorf("%s = %s %s, want UNKNOWN", c.check, got.Result, got.ReasonCode)
			}
		})
	}
}

// laterHolds reports no hold on its first answer and a hold afterwards: a
// hold that becomes effective during the evaluation.
type laterHolds struct {
	mu    sync.Mutex
	calls int
}

func (h *laterHolds) Holds(context.Context, adapter.Realm, string) ([]string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.calls++
	if h.calls == 1 {
		return nil, nil
	}
	return []string{"security-incident-event-0001"}, nil
}

// TestFinalCheckBeforePositive: a hold that became effective during the
// evaluation prevents positive admission (draft 11.3 step 10).
func TestFinalCheckBeforePositive(t *testing.T) {
	f := prepare(t, "admission/valid")
	f.Validator.Holds = &laterHolds{}
	res := evaluate(t, f)
	if res.Attestation.Decision == core.DecisionAdmissible {
		t.Fatal("a hold that became effective during the evaluation was admitted")
	}
	wantCheck(t, res, "security-hold", core.CheckFail, "SECURITY_HOLD")
}

// cancelling cancels the evaluation through ctx when the first native read
// is issued, as a requestor's native session control does (draft 12.2).
type cancelling struct {
	validator.Native
	cancel context.CancelFunc
}

func (c cancelling) ReadNativeClaim(ctx context.Context, p string, cc adapter.ClaimContext) (adapter.NativeClaim, error) {
	c.cancel()
	return c.Native.ReadNativeClaim(ctx, p, cc)
}

// TestCancelledEvaluation: a cancelled authenticated evaluation gets a
// DEFERRED receipt with terminal reason CANCELLED; every native read it did
// not complete is UNKNOWN NOT_EVALUATED, never PASS or NOT_APPLICABLE.
func TestCancelledEvaluation(t *testing.T) {
	f := prepare(t, "admission/valid")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.Validator.Native = cancelling{f.Validator.Native, cancel}
	res, err := f.Validator.Evaluate(ctx, f.Request)
	if err != nil {
		t.Fatal(err)
	}
	a := res.Attestation
	if a.Decision != core.DecisionDeferred || a.TerminalReason != core.TerminalCancelled {
		t.Fatalf("%s %s, want DEFERRED CANCELLED", a.Decision, a.TerminalReason)
	}
	for _, id := range []string{"principal", "roles", "supervisor-approval", "purpose-operation-v1", "native-delegation-v1", "security-hold-v1"} {
		wantCheck(t, res, id, core.CheckUnknown, "NOT_EVALUATED")
	}
	wantCheck(t, res, "native-principal-binding-v1", core.CheckPass, "REQUIREMENT_SATISFIED")
	if a.Expiry-a.IssuedAt != 60 {
		t.Errorf("a cancelled receipt is valid 60 s from issuance, not shortened: iat %d exp %d", a.IssuedAt, a.Expiry)
	}
}

// slowSource answers its native reads 40 s later: past the 30 s deadline.
type slowSource struct {
	validator.Native
	f *conformance.Fixture
}

func (s slowSource) ReadNativeClaim(ctx context.Context, p string, cc adapter.ClaimContext) (adapter.NativeClaim, error) {
	s.f.Clock.Advance(40 * time.Second)
	return s.Native.ReadNativeClaim(ctx, p, cc)
}

// TestDeadline: an evaluation still waiting on a native read at its
// deadline seals EXPIRED at the deadline, DEFERRED, and the late answer is
// not used (draft 12.1, 12.2).
func TestDeadline(t *testing.T) {
	f := prepare(t, "admission/valid")
	f.Validator.Native = slowSource{f.Validator.Native, f}
	res := evaluate(t, f)
	a := res.Attestation
	if a.Decision != core.DecisionDeferred || a.TerminalReason != core.TerminalExpired {
		t.Fatalf("%s %s, want DEFERRED EXPIRED", a.Decision, a.TerminalReason)
	}
	if a.IssuedAt != 1792080030 {
		t.Errorf("sealed at %d, want the deadline 1792080030", a.IssuedAt)
	}
	wantCheck(t, res, "principal", core.CheckUnknown, "NOT_EVALUATED")
}

// TestTransportRejections: what is refused before an authenticated
// evaluation gets the draft 13.4 code and no receipt (draft 12.2).
func TestTransportRejections(t *testing.T) {
	cases := []struct {
		name   string
		change func(f *conformance.Fixture)
		code   adapter.Code
	}{
		{"no native authentication", func(f *conformance.Fixture) { f.Request.Principal = adapter.Principal{} }, adapter.CodeInvalidProof},
		{"not a JWS", func(f *conformance.Fixture) { f.Request.Presentation = "not-a-jws" }, adapter.CodeInvalidMessage},
		{"signature edited", func(f *conformance.Fixture) {
			p := f.Request.Presentation
			last := p[len(p)-2]
			repl := byte('A')
			if last == 'A' {
				repl = 'B'
			}
			f.Request.Presentation = p[:len(p)-2] + string(repl) + p[len(p)-1:]
		}, adapter.CodeInvalidProof},
		{"presentation expired", func(f *conformance.Fixture) { f.Clock.Advance(61 * time.Second) }, contract.CodeExpired},
		{"actual operation of another principal", func(f *conformance.Fixture) {
			f.Request.Operation.PrincipalID = "https://identity.example/principals/bob"
		}, adapter.CodeInvalidMessage},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := prepare(t, "admission/valid")
			c.change(f)
			res, err := f.Validator.Evaluate(context.Background(), f.Request)
			if res.Receipt != "" || codeOf(t, err) != c.code {
				t.Fatalf("%v, receipt %q; want %s and no receipt", err, res.Receipt, c.code)
			}
			p, ok := validator.ProblemOf(err, "r1")
			if !ok || p.Code != string(c.code) || p.Status == 0 || p.RequestID != "r1" {
				t.Errorf("problem %+v", p)
			}
		})
	}
}

// TestHandoff: a positive attestation is accepted once, for its own
// operation only (draft 11.5).
func TestHandoff(t *testing.T) {
	f := prepare(t, "admission/valid")
	res := evaluate(t, f)
	b, err := os.ReadFile(filepath.Join(fixtures, "keys", "validator.jwk.json"))
	if err != nil {
		t.Fatal(err)
	}
	k, err := jws.ParseJWK(b)
	if err != nil {
		t.Fatal(err)
	}
	ks, err := jws.NewKeySet(k)
	if err != nil {
		t.Fatal(err)
	}
	cfg := f.Validator.Config
	h := validator.Handoff{
		Validators: map[string]*jws.KeySet{cfg.Issuer: ks}, Audience: cfg.Audience, Realm: cfg.Realm,
		Skew: cfg.Skew, Consumed: validator.NewMemoryAttestations(),
	}
	now := f.Clock.Now()
	other := f.Request.Operation
	other.OperationID, other.Action = "invoice-export-operation-0002", "invoice.export"
	if _, err := h.Accept(context.Background(), res.Receipt, other, f.Request.Principal, now); codeOf(t, err) != adapter.CodeContextMismatch {
		t.Errorf("another operation: %v, want CONTEXT_MISMATCH", err)
	}
	if _, err := h.Accept(context.Background(), res.Receipt, f.Request.Operation, f.Request.Principal, now); err != nil {
		t.Fatalf("own operation: %v", err)
	}
	if _, err := h.Accept(context.Background(), res.Receipt, f.Request.Operation, f.Request.Principal, now); codeOf(t, err) != contract.CodeReplay {
		t.Errorf("second handoff: %v, want REPLAY", err)
	}
	h.Consumed = validator.NewMemoryAttestations()
	if _, err := h.Accept(context.Background(), res.Receipt, f.Request.Operation, f.Request.Principal, now.Add(time.Minute)); codeOf(t, err) != contract.CodeExpired {
		t.Errorf("expired attestation: %v, want EXPIRED", err)
	}
}

// TestReceiptJSON: the payload is an AdmissionAttestation with no unknown
// member, as a strict consumer decodes it (draft 7.1).
func TestReceiptJSON(t *testing.T) {
	res := evaluate(t, prepare(t, "admission/valid"))
	payload := strings.Split(res.Receipt, ".")[1]
	raw, err := jwsPayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	var a core.AdmissionAttestation
	if err := dec.Decode(&a); err != nil {
		t.Fatal(err)
	}
}

func jwsPayload(segment string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(segment) }

// onceFailingHolds cannot answer its first query: the hold check of the
// evaluation is UNKNOWN, whatever the store answers later.
type onceFailingHolds struct {
	mu    sync.Mutex
	calls int
}

func (h *onceFailingHolds) Holds(context.Context, adapter.Realm, string) ([]string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.calls++
	if h.calls == 1 {
		return nil, adapter.ErrDependencyUnavailable
	}
	return nil, nil
}

// TestHoldOutageNotRescuedLater: a hold store that could not answer during
// the evaluation defers it, even when it answers by the final check.
func TestHoldOutageNotRescuedLater(t *testing.T) {
	f := prepare(t, "admission/valid")
	f.Validator.Holds = &onceFailingHolds{}
	res := evaluate(t, f)
	if res.Attestation.Decision != core.DecisionDeferred {
		t.Fatalf("decision %s, want DEFERRED", res.Attestation.Decision)
	}
	wantCheck(t, res, "security-hold", core.CheckUnknown, "DEPENDENCY_UNAVAILABLE")
}

// compromisedOnce reports the binding compromised at the start of the
// evaluation and active afterwards.
type compromisedOnce struct {
	validator.Native
	mu    sync.Mutex
	calls int
}

func (c *compromisedOnce) ResolveAgentBinding(ctx context.Context, r adapter.Realm, w adapter.Workload, a adapter.AgentID) (adapter.AgentBinding, error) {
	b, err := c.Native.ResolveAgentBinding(ctx, r, w, a)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	if c.calls == 1 && err == nil {
		b.Status = adapter.BindingCompromised
	}
	return b, err
}

// TestCompromisedBinding: a compromised identity is evaluated and held
// (draft 6.4, 13.4): agent-holder-binding FAIL SECURITY_HOLD, INADMISSIBLE.
func TestCompromisedBinding(t *testing.T) {
	f := prepare(t, "admission/valid")
	f.Validator.Native = &compromisedOnce{Native: f.Validator.Native}
	res := evaluate(t, f)
	if res.Attestation.Decision != core.DecisionInadmissible {
		t.Fatalf("decision %s, want INADMISSIBLE", res.Attestation.Decision)
	}
	wantCheck(t, res, "agent-holder-binding", core.CheckFail, "SECURITY_HOLD")
}
