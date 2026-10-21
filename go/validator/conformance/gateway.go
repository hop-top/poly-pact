package conformance

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/contract"
	"hop.top/pact-go/core"
	"hop.top/pact-go/core/clock"
	"hop.top/pact-go/core/jws"
	"hop.top/pact-go/core/strictjson"
	"hop.top/pact-go/runner/evalcase"
	"hop.top/pact-go/validator"
)

// workload is the authenticated workload of every case: native_context.json
// states the enrollment of the workload the request came from.
const workload adapter.Workload = "fixture:workload"

// gatewayState is what carries over between the exchanges of a sequence
// (spec/v1.0/fixtures/README.md, Multi-exchange cases): the replay store, the
// receipt store and the consumed attestations.
type gatewayState struct {
	replay   *replayStore
	receipts *validator.MemoryReceipts
	consumed *validator.MemoryAttestations
}

func newGatewayState() *gatewayState {
	return &gatewayState{replay: newReplayStore(), receipts: validator.NewMemoryReceipts(), consumed: validator.NewMemoryAttestations()}
}

// gateway is the gateway of one exchange.
type gateway struct {
	fixtures string
	x        *evalcase.Exchange
	gs       *gatewayState
	clk      *clock.Fake
	cfg      validator.Config
	signer   validator.Signer
	reg      *registry
	holds    holdStore
	status   statusChecker
	contexts contextMapper
	auth     evalcase.Authenticated
}

func buildGateway(fixtures string, x *evalcase.Exchange, keys map[string]privateKey, gs *gatewayState) (*gateway, error) {
	cfg := x.Config
	nc := x.NativeContext
	if nc.Authenticated == nil {
		return nil, fmt.Errorf("native_context.json has no authenticated principal")
	}
	g := &gateway{fixtures: fixtures, x: x, gs: gs, clk: clock.NewFake(time.Unix(cfg.Now, 0)), auth: *nc.Authenticated}
	var err error
	if g.cfg, err = validatorConfig(fixtures, cfg); err != nil {
		return nil, err
	}
	if g.signer, err = signerFor(keys, cfg.Validator.Key); err != nil {
		return nil, err
	}
	if g.reg, err = newRegistry(fixtures, x); err != nil {
		return nil, err
	}
	g.holds = holdStore(slices.Clone(nc.SecurityHolds))
	g.status = statusChecker{states: nc.EvidenceStatus, unavailable: x.Availability.Sources}
	g.contexts = contextMapper{realm: g.cfg.Realm, m: cfg.ReputationContextMapping()}
	g.gs.replay.setMode(x.Availability.ReplayStore)
	return g, nil
}

// principal is what authenticate_native established (native_context.json).
func (g *gateway) principal() adapter.Principal {
	return adapter.Principal{
		ID:              g.auth.PrincipalID,
		Realm:           adapter.Realm{TenantID: g.auth.TenantID, EnvironmentID: g.x.Config.Gateway.EnvironmentID},
		Workload:        workload,
		Mechanism:       "fixture",
		AuthenticatedAt: time.Unix(g.auth.AuthenticatedAt, 0),
	}
}

// prepareSubmission sets the clock to the submission's start, applies an
// eviction it asks for, and registers its contract's nonce as the gateway's
// publisher did when it issued the contract.
func (g *gateway) prepareSubmission(sub evalcase.Submission) {
	g.clk.Set(time.Unix(sub.Evaluation.StartedAt, 0))
	if sub.EvictReplayRecords {
		g.gs.replay.evict(g.clk.Now())
	}
	compact, err := readText(g.fixtures, g.x, sub.Signed)
	if err != nil {
		return
	}
	if c, ok := embeddedContract(compact); ok {
		g.gs.replay.register(c)
	}
}

// submit evaluates one submission and returns its result and response line.
func (g *gateway) submit(sub evalcase.Submission) (validator.Result, string, error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	v, req, err := g.validatorFor(sub, cancel)
	if err != nil {
		return validator.Result{}, line(validator.Result{}, err, sub.JTI), err
	}
	res, err := v.Evaluate(ctx, req)
	return res, line(res, err, sub.JTI), err
}

// validatorFor builds the validator replica and the evaluate request of a
// submission; cancel is the requestor's cancellation of its evaluation.
func (g *gateway) validatorFor(sub evalcase.Submission, cancel context.CancelFunc) (*validator.Validator, validator.Request, error) {
	compact, err := readText(g.fixtures, g.x, sub.Signed)
	if err != nil {
		return nil, validator.Request{}, err
	}
	op, err := g.operation(sub.ActualOperation)
	if err != nil {
		return nil, validator.Request{}, err
	}
	nat, err := g.nativeAdapter(op)
	if err != nil {
		return nil, validator.Request{}, err
	}
	v := &validator.Validator{
		Config: g.cfg, Native: &timedNative{inner: nat, clk: g.clk, eval: sub.Evaluation, cancel: cancel},
		Replay: g.gs.replay, Receipts: g.gs.receipts, Holds: g.holds, Policies: g.reg, Status: g.status,
		Contexts: g.contexts, Signer: g.signer, Clock: g.clk,
	}
	return v, validator.Request{Presentation: compact, Operation: op, Principal: g.principal(), Transport: sub.Transport}, nil
}

func (g *gateway) operation(rel string) (core.OperationContext, error) {
	var op core.OperationContext
	b, err := readCase(g.fixtures, g.x, rel)
	if err != nil {
		return op, err
	}
	err = strictjson.Unmarshal(b, strictjson.Limits{}, &op)
	return op, err
}

// handoff attempts the sidecar handoff of a submission's attestation
// (draft 11.5) and returns its response line.
func (g *gateway) handoff(h evalcase.HandoffAttempt, res validator.Result) string {
	if res.Receipt == "" {
		return line(validator.Result{}, errNoReceipt, h.Presentation)
	}
	op, err := g.operation(h.ActualOperation)
	if err != nil {
		return line(validator.Result{}, err, h.Presentation)
	}
	ks, err := keySet(g.fixtures, g.cfg.Algorithms, []string{g.x.Config.Validator.Key})
	if err != nil {
		return line(validator.Result{}, err, h.Presentation)
	}
	hf := validator.Handoff{
		Validators: map[string]*jws.KeySet{g.cfg.Issuer: ks}, Audience: g.cfg.Audience, Realm: g.cfg.Realm,
		Algorithms: g.cfg.Algorithms, Skew: g.cfg.Skew, Consumed: g.gs.consumed, Holds: g.holds,
	}
	if _, err := hf.Accept(context.Background(), res.Receipt, op, g.principal(), time.Unix(h.At, 0)); err != nil {
		return line(validator.Result{}, err, h.Presentation)
	}
	return `{"handoff":"accepted"}`
}

// embeddedContract reads the contract a presentation embeds, without
// verifying anything: the gateway's publisher issued it, and the validator
// verifies it.
func embeddedContract(presentation string) (contract.Contract, bool) {
	payload, ok := jwsPayload(presentation)
	if !ok {
		return contract.Contract{}, false
	}
	var p struct {
		Contract string `json:"contract"`
	}
	if json.Unmarshal(payload, &p) != nil {
		return contract.Contract{}, false
	}
	cp, ok := jwsPayload(p.Contract)
	if !ok {
		return contract.Contract{}, false
	}
	var c contract.Contract
	if json.Unmarshal(cp, &c.Claims) != nil {
		return contract.Contract{}, false
	}
	c.Compact = p.Contract
	d, err := artifactDigest(p.Contract)
	if err != nil {
		return contract.Contract{}, false
	}
	c.Digest = d
	return c, true
}
