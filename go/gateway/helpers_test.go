package gateway_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapters/memory"
	"hop.top/pact-go/contract"
	"hop.top/pact-go/core"
	"hop.top/pact-go/core/binding"
	"hop.top/pact-go/core/clock"
	"hop.top/pact-go/core/digest"
	"hop.top/pact-go/core/jws"
	"hop.top/pact-go/core/strictjson"
	"hop.top/pact-go/gateway"
	"hop.top/pact-go/holder"
	"hop.top/pact-go/validator"
)

// The gateway of these tests: one tenant and environment, a public origin, a
// requirement publisher and a validator of its own, and an agent enrolled on
// the workload of the principal alice.
const (
	origin     = "https://gateway.example"
	audience   = "https://gateway.example/api"
	tenant     = "acme"
	env        = "https://gateway.example/environments/prod"
	publisher  = "https://gateway.example/publisher"
	validatorI = "https://gateway.example/validator"
	agentID    = "https://identity.example/agents/invoice-assistant"
	operatorID = "https://identity.example/operators/acme"
	principal  = "https://identity.example/principals/alice"
	workload   = "workload:invoice-assistant"
	token      = "alice-token"
	mappingV1  = "map-1"
	mappingV2  = "map-2"
	baseRev    = "base-1"
	baseSet    = "base"
	// purposeCheck is the installed check of every contract, run through
	// the adapter's check_context (draft 17.1).
	purposeCheck = "purpose-operation-v1"
	start        = 1792080000
)

var realm = adapter.Realm{TenantID: tenant, EnvironmentID: env}

// routes are the route classes of the gateway, as ServeMux patterns.
var routes = map[string]gateway.Class{
	"GET /invoices/{id}":        gateway.ClassEnforce,
	"POST /invoices/{id}/notes": gateway.ClassEnforce,
	"GET /reports/{id}":         gateway.ClassEnforce,
	"GET /observed/{id}":        gateway.ClassObserve,
	"GET /health":               gateway.ClassOff,
}

// mapping is the installed operation mapping of the memory adapter under
// either version: the same routes, so that only the version differs.
func mapping(version string) memory.Mapping {
	return memory.Mapping{Version: version, Routes: []memory.Route{
		{Method: "GET", Path: "/invoices/{id}", Action: "invoice.read", Resource: "https://invoices.example/invoices/{id}"},
		{Method: "POST", Path: "/invoices/{id}/notes", Action: "invoice.annotate", Resource: "https://invoices.example/invoices/{id}"},
		{Method: "GET", Path: "/reports/{id}", Action: "report.read", Resource: "https://invoices.example/reports/{id}"},
		{Method: "GET", Path: "/observed/{id}", Action: "invoice.read", Resource: "https://invoices.example/invoices/{id}"},
		{Method: "GET", Path: "/health", Action: "health.read", Resource: "https://gateway.example/health"},
	}}
}

func newKey(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func keySet(t testing.TB, k *ecdsa.PrivateKey, kid string) *jws.KeySet {
	t.Helper()
	jwk, err := jws.PublicJWK(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	jwk.Kid = kid
	ks, err := jws.NewKeySet(jwk)
	if err != nil {
		t.Fatal(err)
	}
	return ks
}

// receipts is a receipt store that can be made to fail.
type receipts struct {
	*validator.MemoryReceipts
	down atomic.Bool
}

func (r *receipts) Put(ctx context.Context, res validator.Result) error {
	if r.down.Load() {
		return errors.New("receipt store unavailable")
	}
	return r.MemoryReceipts.Put(ctx, res)
}

// replay is a replay store that can be made to fail.
type replay struct {
	*contract.MemoryReplay
	down atomic.Bool
}

func (r *replay) Consume(ctx context.Context, rec contract.NonceRecord, now, until time.Time) error {
	if r.down.Load() {
		return errors.New("replay store unavailable")
	}
	return r.MemoryReplay.Consume(ctx, rec, now, until)
}

// records is a contract record store that can be made to fail and counts
// the contracts it recorded.
type records struct {
	*gateway.MemoryRecords
	down     atomic.Bool
	recorded atomic.Int64
}

func (r *records) Record(ctx context.Context, d core.Digest, rec gateway.ContractRecord, now, until time.Time) error {
	r.recorded.Add(1)
	return r.MemoryRecords.Record(ctx, d, rec, now, until)
}

func (r *records) Lookup(ctx context.Context, d core.Digest, now time.Time) (gateway.ContractRecord, error) {
	if r.down.Load() {
		return gateway.ContractRecord{}, errors.New("record store unavailable")
	}
	return r.MemoryRecords.Lookup(ctx, d, now)
}

// visit is what the wrapped handler saw of one request.
type visit struct {
	admission  gateway.Admission
	admitted   bool
	body       []byte
	requestURI string
	header     http.Header
}

// app is the protected application: it records what it saw.
type app struct {
	mu     sync.Mutex
	visits []visit
}

func (a *app) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	adm, ok := gateway.FromContext(r.Context())
	body, _ := io.ReadAll(r.Body)
	a.mu.Lock()
	a.visits = append(a.visits, visit{admission: adm, admitted: ok, body: body, requestURI: r.RequestURI, header: r.Header.Clone()})
	a.mu.Unlock()
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("native result"))
}

func (a *app) count() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.visits)
}

func (a *app) last(t *testing.T) visit {
	t.Helper()
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.visits) == 0 {
		t.Fatal("the application was never reached")
	}
	return a.visits[len(a.visits)-1]
}

// world is one gateway with its stores, the agent's holder and a server.
type world struct {
	t        *testing.T
	clk      *clock.Fake
	native   *memory.Adapter
	replay   *replay
	receipts *receipts
	records  *records
	holds    *gateway.MemoryHolds
	val      *validator.Validator
	pub      *contract.Publisher
	cfg      gateway.Config
	holder   *holder.Holder
	hkey     *ecdsa.PrivateKey
	jkt      core.Digest
	app      *app
	srv      *httptest.Server
}

type option func(*world)

// denyReports makes the native policy deny report.read to alice.
func withPolicy(rules ...memory.PolicyRule) option {
	return func(w *world) {
		st := w.native.State()
		st.Policy = rules
		a, err := memory.New(st, w.clk)
		if err != nil {
			w.t.Fatal(err)
		}
		w.native = a
	}
}

func allow(action string) memory.PolicyRule {
	return memory.PolicyRule{Realm: memory.Realm{TenantID: tenant, EnvironmentID: env}, Principal: principal, Action: action, Effect: "ALLOW"}
}

func deny(action string) memory.PolicyRule {
	return memory.PolicyRule{Realm: memory.Realm{TenantID: tenant, EnvironmentID: env}, Principal: principal, Action: action, Effect: "DENY", Reason: "private reason"}
}

func newWorld(t *testing.T, opts ...option) *world {
	t.Helper()
	w := &world{t: t, clk: clock.NewFake(time.Unix(start, 0)), app: &app{}, hkey: newKey(t)}
	hk, err := holder.NewMemoryKeyES256(w.hkey)
	if err != nil {
		t.Fatal(err)
	}
	jwk, err := hk.PublicJWK(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if w.jkt, err = jws.Thumbprint(jwk); err != nil {
		t.Fatal(err)
	}
	observed := int64(start - 600)
	r := memory.Realm{TenantID: tenant, EnvironmentID: env}
	st := memory.State{
		Model:    memory.Model,
		Gateway:  memory.Gateway{TenantID: tenant, EnvironmentID: env, Origin: origin, HeaderAllowlist: []string{"if-match"}},
		Mappings: []memory.Mapping{mapping(mappingV1), mapping(mappingV2)},
		Identities: []memory.Identity{
			{Ref: "alice", ID: principal, Realm: r, Workload: workload, Secret: token},
		},
		Enrollments: []memory.Enrollment{{
			Realm: r, Workload: workload, AgentID: agentID, OperatorID: operatorID, HolderJKT: string(w.jkt),
			Status: string(adapter.BindingActive), ObservedAt: &observed, StatusCheckedAt: &observed, SourceID: "enrollment",
		}},
		Checks: []memory.CheckRecord{{
			ID: purposeCheck, Result: string(adapter.VerdictPass), ReasonCode: "REQUIREMENT_SATISFIED", SourceID: "purpose-mapping",
			ObservedAt: &observed,
		}},
		Policy: []memory.PolicyRule{allow("invoice.read"), allow("invoice.annotate"), allow("report.read")},
	}
	if w.native, err = memory.New(st, w.clk); err != nil {
		t.Fatal(err)
	}
	for _, o := range opts {
		o(w)
	}
	pubKey, valKey := newKey(t), newKey(t)
	w.replay = &replay{MemoryReplay: contract.NewMemoryReplay(1024)}
	w.receipts = &receipts{MemoryReceipts: validator.NewMemoryReceipts()}
	w.records = &records{MemoryRecords: gateway.NewMemoryRecords(1024)}
	w.holds = gateway.NewMemoryHolds()
	pol := contract.Policy{
		BaseRevision:           baseRev,
		LearningPolicyDigest:   digest.BytesDigest([]byte("learning policy")),
		LearningArtifactDigest: digest.BytesDigest([]byte("learning artifact")),
	}
	w.val = &validator.Validator{
		Config: validator.Config{
			Audience: audience, Realm: realm, Issuer: validatorI, SourceID: "gateway-validator",
			Publishers:      map[string]*jws.KeySet{publisher: keySet(t, pubKey, "publisher-1")},
			InstalledChecks: []string{purposeCheck},
		},
		Native:   w.native,
		Replay:   w.replay,
		Receipts: w.receipts,
		Holds:    w.holds,
		Policies: gateway.StaticPolicy{ActivePolicy: validator.ActivePolicy{Policy: pol, ConservativeSet: baseSet}},
		Status:   gateway.NewMemoryStatus(),
		Signer:   validator.ES256Signer{Kid: "validator-1", Key: valKey},
		Clock:    w.clk,
	}
	w.pub = &contract.Publisher{
		Issuer: publisher, Audience: audience, Realm: realm,
		Signer: contract.ES256Signer{Kid: "publisher-1", Key: pubKey},
		Replay: w.replay.MemoryReplay,
	}
	w.cfg = gateway.Config{
		Adapter:   w.native,
		Validator: w.val,
		Publisher: w.pub,
		Requirements: gateway.RequirementsFunc(func(context.Context, adapter.Principal, core.ContractRequest) (contract.Requirements, error) {
			return contract.Requirements{Policy: pol, SelectedSet: baseSet, ConservativeSet: baseSet, ContextChecks: []string{purposeCheck}}, nil
		}),
		Records:        w.records,
		MappingVersion: mappingV1,
		Routes:         routes,
	}
	w.holder = &holder.Holder{
		AgentID: agentID, Keys: hk, Gateway: audience, Realm: realm,
		Publishers: map[string]*jws.KeySet{publisher: keySet(t, pubKey, "publisher-1")},
	}
	return w
}

// serve starts the server with the gateway of cfg in front of the
// application. The enforcement point marks each request as arrived, as the
// memory adapter requires.
func (w *world) serve(cfg gateway.Config) {
	w.t.Helper()
	mw, err := gateway.New(cfg)
	if err != nil {
		w.t.Fatalf("New: %v", err)
	}
	h := mw(w.app)
	w.srv = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(rw, memory.Arrive(r))
	}))
	w.t.Cleanup(w.srv.Close)
}

func (w *world) start() *world {
	w.serve(w.cfg)
	return w
}

// request is a request of the agent to the gateway, with alice's credential.
func (w *world) request(method, path string, body []byte) *http.Request {
	w.t.Helper()
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	r, err := http.NewRequest(method, w.srv.URL+path, rd)
	if err != nil {
		w.t.Fatal(err)
	}
	r.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	return r
}

// retarget points r at the current server.
func (w *world) retarget(r *http.Request) {
	r.URL.Host = strings.TrimPrefix(w.srv.URL, "http://")
	r.Host = r.URL.Host
}

func intent() core.Intent {
	return core.Intent{IntentID: "intent-1", PurposeID: "invoice-summary", Description: "Summarize an invoice", TaskID: "task-1"}
}

// proposal is the operation the agent proposes for r: the baseline HTTP
// mapping of the request as the agent writes it (holder.OperationFromRequest)
// with the action, resources and operation id of the gateway's installed
// mapping, which the agent knows. It checks that both bind the same bytes.
func (w *world) proposal(r *http.Request) core.OperationContext {
	w.t.Helper()
	body := []byte{}
	if r.Body != nil {
		var err error
		if body, err = io.ReadAll(r.Body); err != nil {
			w.t.Fatal(err)
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
	}
	server := r.Clone(context.Background())
	server.Body = io.NopCloser(bytes.NewReader(body))
	server.RequestURI = r.URL.RequestURI()
	server.Host = r.URL.Host
	mapped, err := w.native.MapOperation(context.Background(), server, adapter.Principal{ID: principal, Realm: realm}, mappingV1)
	if err != nil {
		w.t.Fatalf("gateway mapping: %v", err)
	}
	cfg := binding.Config{Origin: origin, HeaderAllowlist: []string{"if-match"}, HeaderNormalizationID: "memory-header-normalization-1", MappingVersion: mappingV1, MaxBody: 8 << 20}
	op, err := holder.OperationFromRequest(cfg, r, mapped.OperationID, env, principal, mapped.Action, mapped.Resources)
	if err != nil {
		w.t.Fatalf("OperationFromRequest: %v", err)
	}
	if a, b := mustJSON(w.t, op), mustJSON(w.t, mapped); a != b {
		w.t.Fatalf("holder and gateway bind different operations:\n%s\n%s", a, b)
	}
	return op
}

func mustJSON(t testing.TB, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// contractFor asks the requirements endpoint for a contract for op.
func (w *world) contractFor(op core.OperationContext) (*http.Response, string) {
	w.t.Helper()
	cr := core.ContractRequest{AgentID: agentID, HolderJKT: w.jkt, Intent: intent(), Operation: op}
	r := w.request(http.MethodPost, gateway.RequirementsPath, []byte(mustJSON(w.t, cr)))
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		w.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

// present runs the agent side for r: proposal, contract, verification and a
// signed presentation, which it attaches to r.
func (w *world) present(r *http.Request) holder.Presentation {
	w.t.Helper()
	op := w.proposal(r)
	resp, compact := w.contractFor(op)
	if resp.StatusCode != http.StatusOK {
		w.t.Fatalf("requirements: %d %s", resp.StatusCode, compact)
	}
	now := w.clk.Now()
	c, err := w.holder.VerifyContract(context.Background(), compact, intent(), op, now)
	if err != nil {
		w.t.Fatalf("VerifyContract: %v", err)
	}
	p, err := w.holder.Present(context.Background(), holder.Input{Contract: c.Compact, Intent: intent(), Operation: op, Profile: w.profile()}, now)
	if err != nil {
		w.t.Fatalf("Present: %v", err)
	}
	r.Header.Set(gateway.HeaderPresentation, p.Compact)
	return p
}

func (w *world) profile() core.AgentProfile {
	return core.AgentProfile{
		ProfileID: "profile-1", Revision: 1, AgentID: agentID, OperatorID: operatorID, TenantID: tenant,
		HolderJKT: w.jkt, CreatedAt: start - 60, ExpiresAt: start + 3600, Attributes: core.Object{},
	}
}

// send sends r, rewinding its body first so that a request can be sent twice.
func (w *world) send(r *http.Request) (*http.Response, []byte) {
	w.t.Helper()
	if r.GetBody != nil {
		b, err := r.GetBody()
		if err != nil {
			w.t.Fatal(err)
		}
		r.Body = b
	}
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		w.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp, b
}

// problem decodes an RFC 9457 problem response and checks its media type,
// code and status.
func problem(t *testing.T, resp *http.Response, body []byte, code string, status int) core.Problem {
	t.Helper()
	if resp.StatusCode != status {
		t.Fatalf("status %d, want %d: %s", resp.StatusCode, status, body)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/problem+json" {
		t.Fatalf("Content-Type %q, want application/problem+json", ct)
	}
	var p core.Problem
	if err := strictjson.Unmarshal(body, strictjson.Limits{}, &p); err != nil {
		t.Fatalf("problem: %v: %s", err, body)
	}
	if p.Code != code || p.Status != int64(status) || p.Type == "" || p.Title == "" || p.RequestID == "" {
		t.Fatalf("problem %+v, want code %s status %d", p, code, status)
	}
	return p
}

// receiptOf decodes the PACT-Admission receipt of a response.
func receiptOf(t *testing.T, resp *http.Response) core.AdmissionAttestation {
	t.Helper()
	compact := resp.Header.Get(gateway.HeaderAdmission)
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		t.Fatalf("PACT-Admission %q is not a compact JWS", compact)
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var a core.AdmissionAttestation
	if err := json.Unmarshal(b, &a); err != nil {
		t.Fatal(err)
	}
	return a
}
