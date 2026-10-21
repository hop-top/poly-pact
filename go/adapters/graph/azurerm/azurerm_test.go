package azurerm_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/task"
	"hop.top/pact-go/adapters/graph"
	"hop.top/pact-go/adapters/graph/azurerm"
	"hop.top/pact-go/core"
	"hop.top/pact-go/core/clock"
	"hop.top/pact-go/core/digest"
)

// The identifiers of the I14 restart.
const (
	tenant   = "8f3d2c1b-5a4e-4f6d-9b7a-1c2e3f4a5b6c"
	opsApp   = "3f1c9a2e-6b7d-4e8f-a0b1-c2d3e4f5a6b7"
	sub      = "0b5d7c1e-4f0a-4c39-9b8e-2f3d6c1a9e77"
	vm       = "/subscriptions/" + sub + "/resourceGroups/rg-incident/providers/Microsoft.Compute/virtualMachines/vm-web-07"
	opPath   = "/subscriptions/" + sub + "/providers/Microsoft.Compute/locations/westeurope/operations/7c1d"
	asyncOp  = azurerm.ARMOrigin + opPath + "?api-version=" + azurerm.APIVersion
	locOp    = azurerm.ARMOrigin + "/subscriptions/" + sub + "/providers/Microsoft.Compute/locations/westeurope/operations/7c1d?monitor=true&api-version=" + azurerm.APIVersion
	tokenA   = "inbound-token-a-of-maya"
	tokenB   = "arm-token-b-delegated"
	armScope = "https://management.azure.com/user_impersonation"
	taskRef  = task.Ref("native-task:incident-1177-vm-restart")
)

var (
	realm = adapter.Realm{TenantID: "northstar", EnvironmentID: "https://ops.northstar.example/environments/production"}
	maya  = adapter.Principal{ID: "oauth:entra:" + tenant + ":maya", Realm: realm, Workload: "client:incident-console", Mechanism: "bearer"}
	agent = adapter.AgentID("https://agents.northstar.example/incident-assistant")
	t0    = time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC)
)

// answer is one scripted answer of the fake ARM endpoint.
type answer struct {
	status  int
	headers map[string]string
	body    any
	// hang blocks the answer until the client gives up.
	hang bool
}

// arm is the fake Azure: the token endpoint of the tenant and Resource
// Manager, which count the requests they receive.
type arm struct {
	mu       sync.Mutex
	srv      *httptest.Server
	posts    int
	reads    []string
	tokens   []url.Values
	restart  answer
	status   []answer
	tokenErr bool
	auth     []string
	// seen is every request the fake received, as method and URL.
	seen []string
}

func newARM(t *testing.T) *arm {
	a := &arm{}
	a.srv = httptest.NewServer(http.HandlerFunc(a.serve))
	t.Cleanup(a.srv.Close)
	return a
}

func write(w http.ResponseWriter, an answer) {
	for k, v := range an.headers {
		w.Header().Set(k, v)
	}
	if an.body != nil {
		w.Header().Set("Content-Type", "application/json")
	}
	w.WriteHeader(an.status)
	if an.body != nil {
		_ = json.NewEncoder(w).Encode(an.body)
	}
}

func (a *arm) serve(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	a.seen = append(a.seen, r.Method+" "+r.Host+r.URL.Path)
	a.mu.Unlock()
	switch {
	case r.Host == "login.microsoftonline.com" && r.Method == http.MethodPost && r.URL.Path == "/"+tenant+"/oauth2/v2.0/token":
		_ = r.ParseForm()
		a.mu.Lock()
		a.tokens = append(a.tokens, r.PostForm)
		fail := a.tokenErr
		a.mu.Unlock()
		if fail {
			write(w, answer{status: 400, body: map[string]any{"error": "invalid_grant", "error_codes": []int{50013}}})
			return
		}
		write(w, answer{status: 200, body: map[string]any{"token_type": "Bearer", "access_token": tokenB, "expires_in": 3599, "scope": armScope}})
	case r.Host == "management.azure.com" && r.Method == http.MethodPost && r.URL.Path == vm+"/restart":
		a.mu.Lock()
		a.posts++
		a.auth = append(a.auth, r.Header.Get("Authorization"))
		an := a.restart
		a.mu.Unlock()
		if r.URL.RawQuery != "api-version="+azurerm.APIVersion {
			write(w, answer{status: 400})
			return
		}
		if an.hang {
			<-r.Context().Done()
			return
		}
		write(w, an)
	case r.Host == "management.azure.com" && r.Method == http.MethodGet && r.URL.Path == opPath:
		a.mu.Lock()
		a.reads = append(a.reads, r.URL.RawQuery)
		a.auth = append(a.auth, r.Header.Get("Authorization"))
		an := answer{status: 500}
		if len(a.status) > 0 {
			an = a.status[0]
			if len(a.status) > 1 {
				a.status = a.status[1:]
			}
		}
		a.mu.Unlock()
		write(w, an)
	default:
		write(w, answer{status: 404})
	}
}

func (a *arm) count() (posts, reads int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.posts, len(a.reads)
}

// client sends every request to the fake, keeping the Host of the URL.
func (a *arm) client() *http.Client {
	target, _ := url.Parse(a.srv.URL)
	return &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		r = r.Clone(r.Context())
		r.Host = r.URL.Host
		r.URL.Scheme, r.URL.Host = target.Scheme, target.Host
		return http.DefaultTransport.RoundTrip(r)
	})}
}

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// registry is the task registry: one active task with max_operations 1.
type registry struct{}

func (registry) Resolve(_ context.Context, _ adapter.Realm, p string, a adapter.AgentID, v string) ([]task.Ref, error) {
	if v == "incident-1177" && p == maya.ID && a == agent {
		return []task.Ref{taskRef}, nil
	}
	return nil, nil
}

func (registry) Lookup(_ context.Context, _ adapter.Realm, ref task.Ref) (task.Record, error) {
	if ref != taskRef {
		return task.Record{}, task.ErrNoRecord
	}
	return task.Record{Ref: ref, State: task.StateActive, Limits: task.Limits{
		MaxOperations: task.Bounded(1), MaxPages: task.Bounded(0), MaxBytes: task.Unbounded(), Deadline: t0.Add(time.Hour),
	}}, nil
}

// gate is the activation gate of the deployment.
type gate struct{ outcome adapter.CheckOutcome }

func (g *gate) CheckActivation(context.Context, azurerm.RestartInput) adapter.CheckOutcome {
	return g.outcome
}

var active = adapter.CheckOutcome{Result: adapter.VerdictPass, ReasonCode: "REQUIREMENT_SATISFIED"}

// reconciler is the deployment's native status source of an ambiguous
// restart, scripted.
type reconciler struct {
	mu     sync.Mutex
	script []task.Status
	reads  int
}

func (r *reconciler) ReadStatus(context.Context, task.Key, task.Operation) (task.Status, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reads++
	s := r.script[0]
	if len(r.script) > 1 {
		r.script = r.script[1:]
	}
	return s, nil
}

// fixture is one world: the fake, the clock, the ledger and the executor.
type fixture struct {
	arm    *arm
	clk    *clock.Fake
	ledger task.TaskLedger
	gate   *gate
	sleeps []time.Duration
	x      *azurerm.Executor
	seq    int
}

func newFixture(t *testing.T, edit func(*azurerm.Config)) *fixture {
	f := &fixture{arm: newARM(t), clk: clock.NewFake(t0), gate: &gate{outcome: active}}
	f.ledger = task.NewMemory(task.Config{Registry: registry{}, Clock: f.clk})
	acq, err := graph.NewOnBehalfOf(graph.AcquirerConfig{
		Tenant: tenant, ClientID: opsApp, Auth: graph.ClientAuth{Secret: "ops-client-secret"},
		Scope: azurerm.ScopeARMDefault, AcceptedScopes: []string{armScope}, HTTPClient: f.arm.client(), Clock: f.clk,
	})
	if err != nil {
		t.Fatal(err)
	}
	cfg := azurerm.Config{
		Acquirer: acq, Ledger: f.ledger, Activation: f.gate, Subscription: sub,
		MaxStatusReads: 5, MinInterval: 20 * time.Second, HTTPClient: f.arm.client(), Timeout: 200 * time.Millisecond, Clock: f.clk,
		Sleep: func(_ context.Context, d time.Duration) error {
			f.sleeps = append(f.sleeps, d)
			f.clk.Advance(d)
			return nil
		},
	}
	if edit != nil {
		edit(&cfg)
	}
	if f.x, err = azurerm.New(cfg); err != nil {
		t.Fatal(err)
	}
	return f
}

// input is the restart under a fresh contract: a new operation_id each time
// (MO-20), the same logical operation (MO-27).
func (f *fixture) input() azurerm.RestartInput {
	f.seq++
	target := "https://ops.northstar.example/vms/vm-web-07/restart"
	return azurerm.RestartInput{
		Request: task.Request{Principal: maya, AgentID: agent, TaskID: "incident-1177", Operation: core.OperationContext{
			OperationID: fmt.Sprintf("op-%03d", f.seq), EnvironmentID: realm.EnvironmentID, PrincipalID: maya.ID,
			Action: "compute.vm.restart", Resources: []string{vm}, Method: http.MethodPost, TargetURI: target,
			BodyDigest: digest.BytesDigest(nil), Headers: map[string]string{},
		}},
		Assertion: tokenA, VM: vm,
	}
}

func (f *fixture) key() task.Key { return task.Key{Realm: realm, Task: taskRef} }

func (f *fixture) state(t *testing.T, id string) task.OpState {
	t.Helper()
	e, err := f.ledger.Entry(context.Background(), f.key())
	if err != nil {
		t.Fatal(err)
	}
	for _, op := range e.Operations {
		if op.ID == id {
			return op.State
		}
	}
	t.Fatalf("no operation %s", id)
	return ""
}

func requireReport(t *testing.T, o *adapter.Observation, kind core.EventKind, result core.OutcomeResult, dim core.Dimension, what string) {
	t.Helper()
	if o == nil {
		t.Fatalf("%s: no report", what)
	}
	if o.EventKind != kind || o.Result != result || o.Dimension != dim || o.TaskID != string(taskRef) {
		t.Errorf("%s: report %s %s %s task %s, want %s %s %s task %s", what, o.EventKind, o.Result, o.Dimension, o.TaskID, kind, result, dim, taskRef)
	}
	if len(o.EvidenceRefs) == 0 || !strings.HasPrefix(o.EvidenceRefs[0], "azurerm-executor:delegated-user:"+opsApp+":") {
		t.Errorf("%s: evidence %v, want the executor record first (draft 14.2)", what, o.EvidenceRefs)
	}
}

var bg = context.Background()

// TestAcceptedThenSucceeded: 202 with Location and Retry-After is Accepted
// with an EXECUTION UNKNOWN none report; the tracker waits the Retry-After
// values and reads the handle until Succeeded; the restart asked again is
// answered from the record and sends nothing; the task stays Active.
func TestAcceptedThenSucceeded(t *testing.T) {
	f := newFixture(t, nil)
	f.arm.restart = answer{status: 202, headers: map[string]string{"Location": locOp, "Retry-After": "7"}}
	f.arm.status = []answer{
		{status: 202, headers: map[string]string{"Retry-After": "3"}},
		{status: 200, body: map[string]any{"status": "Succeeded", "name": "7c1d"}},
	}
	out, err := f.x.Restart(bg, f.input())
	if err != nil {
		t.Fatal(err)
	}
	if out.Settled.Operation.State != task.OpAccepted || out.Settled.Operation.Handle != locOp {
		t.Fatalf("202: %+v, want Accepted with the Location handle", out.Settled.Operation)
	}
	requireReport(t, out.Settled.Report, core.EventExecution, core.OutcomeUnknown, core.DimensionNone, "202")
	tr, err := f.x.Track(bg, tokenA, out.Key, out.Settled.Operation.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got := f.state(t, out.Settled.Operation.ID); got != task.OpSucceeded {
		t.Errorf("after Succeeded: %s", got)
	}
	requireReport(t, tr.Settled.Report, core.EventExecution, core.OutcomeSuccess, core.DimensionReliability, "completion")
	if !slices.Equal(f.sleeps, []time.Duration{7 * time.Second, 3 * time.Second}) {
		t.Errorf("waits %v, want the Retry-After values 7s and 3s", f.sleeps)
	}
	again, err := f.x.Restart(bg, f.input())
	if err != nil || again.Settled.Operation.ID != out.Settled.Operation.ID || again.Settled.Operation.State != task.OpSucceeded {
		t.Errorf("asked again: %+v %v, want the Succeeded record", again.Settled.Operation, err)
	}
	if posts, reads := f.arm.count(); posts != 1 || reads != 2 {
		t.Errorf("%d restarts and %d status reads, want 1 and 2", posts, reads)
	}
	e, _ := f.ledger.Entry(bg, f.key())
	if e.State != task.StateActive || e.Budget.Operations != 1 {
		t.Errorf("task %s with %d operations, want Active with 1 (MO-47)", e.State, e.Budget.Operations)
	}
	for _, a := range f.arm.auth {
		if a != "Bearer "+tokenB {
			t.Errorf("Authorization %q sent to Azure, want the delegated token B only", a)
		}
	}
}

// TestAcceptedThenFailed: a status Failed makes the record Failed with an
// EXECUTION FAILURE reliability report; a new restart is a new reservation
// and is budget-exhausted with max_operations 1 (I14 row 6b).
func TestAcceptedThenFailed(t *testing.T) {
	f := newFixture(t, nil)
	f.arm.restart = answer{status: 202, headers: map[string]string{"Location": locOp}}
	f.arm.status = []answer{{status: 200, body: map[string]any{"status": "Failed", "error": map[string]any{"code": "OperationPreempted", "message": "preempted"}}}}
	out, err := f.x.Restart(bg, f.input())
	if err != nil {
		t.Fatal(err)
	}
	tr, err := f.x.Track(bg, tokenA, out.Key, out.Settled.Operation.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got := f.state(t, out.Settled.Operation.ID); got != task.OpFailed {
		t.Errorf("after Failed: %s", got)
	}
	requireReport(t, tr.Settled.Report, core.EventExecution, core.OutcomeFailure, core.DimensionReliability, "failure")
	if !slices.Equal(f.sleeps, []time.Duration{20 * time.Second}) {
		t.Errorf("waits %v, want the minimum interval without a Retry-After", f.sleeps)
	}
	_, err = f.x.Restart(bg, f.input())
	var ref *task.Refusal
	if !errors.As(err, &ref) || ref.Label != task.LabelBudgetExhausted {
		t.Errorf("a new restart after Failed: %v, want budget-exhausted", err)
	}
	if posts, _ := f.arm.count(); posts != 1 {
		t.Errorf("%d restarts, want 1", posts)
	}
}

// TestCanceled: a status Canceled is terminal without success, on the
// cancelled-completion row of draft 14.5 (MO-44).
func TestCanceled(t *testing.T) {
	f := newFixture(t, nil)
	f.arm.restart = answer{status: 202, headers: map[string]string{"Location": locOp}}
	f.arm.status = []answer{{status: 200, body: map[string]any{"status": "Canceled"}}}
	out, _ := f.x.Restart(bg, f.input())
	tr, err := f.x.Track(bg, tokenA, out.Key, out.Settled.Operation.ID)
	if err != nil {
		t.Fatal(err)
	}
	requireReport(t, tr.Settled.Report, core.EventExecution, core.OutcomeFailure, core.DimensionReliability, "cancelled")
	if tr.Settled.Report.Details != "cancelled" || f.state(t, out.Settled.Operation.ID) != task.OpFailed {
		t.Errorf("cancelled: details %q state %s", tr.Settled.Report.Details, f.state(t, out.Settled.Operation.ID))
	}
}

// TestTimeoutThenReconcile: a restart whose POST times out is Unknown with
// an ambiguous timeout report; asked again under a fresh contract it is
// outcome-unknown and no second POST is sent; without a native status source
// it stays Unknown; an indeterminate reconciliation leaves it Unknown; an
// authoritative read of the effect makes it Succeeded. Throughout, Azure
// receives one POST (draft 10.3, MO-32, MO-33, MO-35, MO-38, MO-39).
func TestTimeoutThenReconcile(t *testing.T) {
	f := newFixture(t, nil)
	f.arm.restart = answer{hang: true}
	out, err := f.x.Restart(bg, f.input())
	if err != nil {
		t.Fatal(err)
	}
	id := out.Settled.Operation.ID
	if out.Settled.Operation.State != task.OpUnknown {
		t.Fatalf("timeout: %s, want Unknown", out.Settled.Operation.State)
	}
	requireReport(t, out.Settled.Report, core.EventExecution, core.OutcomeUnknown, core.DimensionNone, "timeout")
	f.arm.mu.Lock()
	f.arm.restart = answer{status: 202, headers: map[string]string{"Location": locOp}}
	f.arm.mu.Unlock()
	_, err = f.x.Restart(bg, f.input())
	var ref *task.Refusal
	if !errors.As(err, &ref) || ref.Label != task.LabelOutcomeUnknown {
		t.Errorf("asked again: %v, want outcome-unknown", err)
	}
	if _, err := f.x.Track(bg, tokenA, out.Key, id); !errors.Is(err, azurerm.ErrNoStatusSource) || f.state(t, id) != task.OpUnknown {
		t.Errorf("no native status source: %v, state %s; want ErrNoStatusSource and Unknown", err, f.state(t, id))
	}

	rec := &reconciler{script: []task.Status{{Effect: task.EffectIndeterminate}}}
	x2, err := azurerm.New(azurerm.Config{
		Acquirer: mustOBO(t, f), Ledger: f.ledger, Activation: f.gate, Subscription: sub, Reconcile: rec,
		MaxStatusReads: 2, MinInterval: time.Second, HTTPClient: f.arm.client(), Clock: f.clk,
		Sleep: func(context.Context, time.Duration) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := x2.Track(bg, tokenA, out.Key, id); err != nil || f.state(t, id) != task.OpUnknown || rec.reads != 2 {
		t.Errorf("indeterminate: %v, state %s, %d reads; want Unknown after 2 reads", err, f.state(t, id), rec.reads)
	}
	rec.script = []task.Status{{Effect: task.EffectApplied, Authoritative: true}}
	tr, err := x2.Track(bg, tokenA, out.Key, id)
	if err != nil || f.state(t, id) != task.OpSucceeded {
		t.Fatalf("reconciled: %v, state %s; want Succeeded", err, f.state(t, id))
	}
	requireReport(t, tr.Settled.Report, core.EventExecution, core.OutcomeSuccess, core.DimensionReliability, "reconciled")
	if posts, reads := f.arm.count(); posts != 1 || reads != 0 {
		t.Errorf("%d restarts and %d handle reads, want 1 and 0", posts, reads)
	}
}

func mustOBO(t *testing.T, f *fixture) graph.TokenAcquirer {
	acq, err := graph.NewOnBehalfOf(graph.AcquirerConfig{
		Tenant: tenant, ClientID: opsApp, Auth: graph.ClientAuth{Secret: "ops-client-secret"},
		Scope: azurerm.ScopeARMDefault, AcceptedScopes: []string{armScope}, HTTPClient: f.arm.client(), Clock: f.clk,
	})
	if err != nil {
		t.Fatal(err)
	}
	return acq
}

// TestAsyncOperationPreferred: with both headers the handle is the
// Azure-AsyncOperation URL (MO-42, [S2]).
func TestAsyncOperationPreferred(t *testing.T) {
	f := newFixture(t, nil)
	f.arm.restart = answer{status: 202, headers: map[string]string{"Location": locOp, "Azure-AsyncOperation": asyncOp}}
	f.arm.status = []answer{{status: 200, body: map[string]any{"status": "InProgress"}}, {status: 200, body: map[string]any{"status": "Succeeded"}}}
	out, err := f.x.Restart(bg, f.input())
	if err != nil || out.Settled.Operation.Handle != asyncOp {
		t.Fatalf("both headers: handle %q %v, want the Azure-AsyncOperation URL", out.Settled.Operation.Handle, err)
	}
	if _, err := f.x.Track(bg, tokenA, out.Key, out.Settled.Operation.ID); err != nil || f.state(t, out.Settled.Operation.ID) != task.OpSucceeded {
		t.Errorf("InProgress then Succeeded: %v %s", err, f.state(t, out.Settled.Operation.ID))
	}
	if f.arm.reads[0] != "api-version="+azurerm.APIVersion {
		t.Errorf("status read query %q, want that of the Azure-AsyncOperation URL", f.arm.reads[0])
	}
}

// TestLocationWithoutStatus: a 200 at the handle without a status member
// establishes nothing (probe P3): the record stays Accepted.
func TestLocationWithoutStatus(t *testing.T) {
	f := newFixture(t, func(c *azurerm.Config) { c.MaxStatusReads = 2 })
	f.arm.restart = answer{status: 202, headers: map[string]string{"Location": locOp}}
	f.arm.status = []answer{{status: 200}}
	out, _ := f.x.Restart(bg, f.input())
	tr, err := f.x.Track(bg, tokenA, out.Key, out.Settled.Operation.ID)
	if err != nil || f.state(t, out.Settled.Operation.ID) != task.OpAccepted || tr.Settled.Report != nil {
		t.Errorf("200 without status: %v, state %s, report %v; want Accepted and no completion", err, f.state(t, out.Settled.Operation.ID), tr.Settled.Report)
	}
}

// TestTrackingForbidden: a status read the principal may not make leaves the
// record Accepted with DEPENDENCY_UNAVAILABLE; no success is inferred
// (MO-46, I14 row 6d).
func TestTrackingForbidden(t *testing.T) {
	f := newFixture(t, nil)
	f.arm.restart = answer{status: 202, headers: map[string]string{"Location": locOp}}
	f.arm.status = []answer{{status: 403, body: map[string]any{"error": map[string]any{"code": "AuthorizationFailed"}}}}
	out, _ := f.x.Restart(bg, f.input())
	tr, err := f.x.Track(bg, tokenA, out.Key, out.Settled.Operation.ID)
	if !errors.Is(err, adapter.ErrDependencyUnavailable) || f.state(t, out.Settled.Operation.ID) != task.OpAccepted {
		t.Errorf("403 at the handle: %v, state %s; want DEPENDENCY_UNAVAILABLE and Accepted", err, f.state(t, out.Settled.Operation.ID))
	}
	if tr.Settled.Report != nil && tr.Settled.Report.Result == core.OutcomeSuccess {
		t.Error("a success was inferred")
	}
}

// TestHandleOtherOrigin: a handle outside the configured prefixes is not
// followed (MO-43).
func TestHandleOtherOrigin(t *testing.T) {
	f := newFixture(t, nil)
	f.arm.restart = answer{status: 202, headers: map[string]string{"Location": "https://management.azure.com.example" + opPath}}
	out, _ := f.x.Restart(bg, f.input())
	if _, err := f.x.Track(bg, tokenA, out.Key, out.Settled.Operation.ID); err == nil {
		t.Error("a foreign handle was followed")
	}
	if _, reads := f.arm.count(); reads != 0 || f.state(t, out.Settled.Operation.ID) != task.OpAccepted {
		t.Errorf("%d reads, state %s", reads, f.state(t, out.Settled.Operation.ID))
	}
	for _, r := range f.arm.seen {
		if strings.HasPrefix(r, "GET ") {
			t.Errorf("the executor sent %s", r)
		}
	}
}

// TestActivationPending: an activation that is not PASS reserves nothing,
// requests no token and sends nothing (MO-10, I14 row 1).
func TestActivationPending(t *testing.T) {
	f := newFixture(t, nil)
	f.gate.outcome = adapter.CheckOutcome{Result: adapter.VerdictUnknown, ReasonCode: "APPROVAL_PENDING"}
	_, err := f.x.Restart(bg, f.input())
	var ae *azurerm.ActivationError
	if !errors.As(err, &ae) || ae.Outcome.ReasonCode != "APPROVAL_PENDING" || !errors.Is(err, adapter.ErrDependencyUnavailable) {
		t.Errorf("pending: %v, want an ActivationError APPROVAL_PENDING that is DEPENDENCY_UNAVAILABLE", err)
	}
	f.gate.outcome = adapter.CheckOutcome{Result: adapter.VerdictFail, ReasonCode: "APPROVAL_SCOPE_MISMATCH"}
	if _, err := f.x.Restart(bg, f.input()); !errors.As(err, &ae) || errors.Is(err, adapter.ErrDependencyUnavailable) {
		t.Errorf("scope mismatch: %v, want an ActivationError that is not DEPENDENCY_UNAVAILABLE", err)
	}
	if _, err := f.ledger.Entry(bg, f.key()); !errors.Is(err, task.ErrNoEntry) {
		t.Errorf("entry after a pending activation: %v", err)
	}
	if posts, _ := f.arm.count(); posts != 0 || len(f.arm.tokens) != 0 {
		t.Errorf("%d restarts, %d token requests; want none", posts, len(f.arm.tokens))
	}
}

// TestOBORequest: the token is obtained on behalf of the user with the
// scope of Resource Manager; token A is never sent to Azure Resource
// Manager.
func TestOBORequest(t *testing.T) {
	f := newFixture(t, nil)
	f.arm.restart = answer{status: 200}
	out, err := f.x.Restart(bg, f.input())
	if err != nil || out.Settled.Operation.State != task.OpSucceeded {
		t.Fatalf("200: %v %s, want Succeeded", err, out.Settled.Operation.State)
	}
	if len(f.arm.tokens) != 1 {
		t.Fatalf("%d token requests", len(f.arm.tokens))
	}
	tr := f.arm.tokens[0]
	if tr.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" || tr.Get("requested_token_use") != "on_behalf_of" ||
		tr.Get("scope") != azurerm.ScopeARMDefault || tr.Get("assertion") != tokenA {
		t.Errorf("token request %v, want the OBO request for %s", tr, azurerm.ScopeARMDefault)
	}
	for _, a := range f.arm.auth {
		if strings.Contains(a, tokenA) {
			t.Error("token A was sent to Azure Resource Manager")
		}
	}
}

// TestTokenFailureReleases: a failed token request sends nothing and
// releases the reservation (MO-22).
func TestTokenFailureReleases(t *testing.T) {
	f := newFixture(t, nil)
	f.arm.tokenErr = true
	if _, err := f.x.Restart(bg, f.input()); err == nil {
		t.Fatal("restarted without a token")
	}
	e, err := f.ledger.Entry(bg, f.key())
	if err != nil || e.Budget.Operations != 0 || e.Operations[0].State != task.OpReleased {
		t.Errorf("entry %+v %v, want the reservation released", e, err)
	}
	if posts, _ := f.arm.count(); posts != 0 {
		t.Errorf("%d restarts", posts)
	}
}

// TestOtherVM: a resource ID that is not a virtual machine of the
// subscription is INVALID_MESSAGE and reserves nothing.
func TestOtherVM(t *testing.T) {
	f := newFixture(t, nil)
	for _, id := range []string{
		strings.Replace(vm, sub, "11111111-2222-4333-8444-555555555555", 1),
		vm + "/extensions/x",
		strings.Replace(vm, "virtualMachines", "virtualMachineScaleSets", 1),
		strings.Replace(vm, "vm-web-07", "vm%2Fweb", 1),
		strings.Replace(vm, "vm-web-07", "..", 1),
		strings.Replace(vm, "vm-web-07", ".", 1),
		strings.Replace(vm, "rg-incident", "..", 1),
	} {
		in := f.input()
		in.VM = id
		if _, err := f.x.Restart(bg, in); !errors.Is(err, adapter.ErrInvalidMessage) {
			t.Errorf("%s: %v, want INVALID_MESSAGE", id, err)
		}
	}
	if _, err := f.ledger.Entry(bg, f.key()); !errors.Is(err, task.ErrNoEntry) {
		t.Errorf("entry: %v", err)
	}
}

// TestNew: the configuration the executor requires.
func TestNew(t *testing.T) {
	f := newFixture(t, nil)
	base := azurerm.Config{
		Acquirer: mustOBO(t, f), Ledger: f.ledger, Activation: f.gate, Subscription: sub,
		MaxStatusReads: 1, MinInterval: time.Second, Clock: f.clk,
	}
	for name, edit := range map[string]func(*azurerm.Config){
		"no ledger":       func(c *azurerm.Config) { c.Ledger = nil },
		"no gate":         func(c *azurerm.Config) { c.Activation = nil },
		"upper-case sub":  func(c *azurerm.Config) { c.Subscription = strings.ToUpper(sub) },
		"read route":      func(c *azurerm.Config) { c.Route = task.Route{ID: "r", Class: task.ClassRead} },
		"no reads":        func(c *azurerm.Config) { c.MaxStatusReads = 0 },
		"http prefix":     func(c *azurerm.Config) { c.HandlePrefixes = []string{"http://management.azure.com/"} },
		"no acquirer":     func(c *azurerm.Config) { c.Acquirer = nil },
		"no clock":        func(c *azurerm.Config) { c.Clock = nil },
		"no min interval": func(c *azurerm.Config) { c.MinInterval = 0 },
	} {
		c := base
		edit(&c)
		if _, err := azurerm.New(c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := azurerm.New(base); err != nil {
		t.Errorf("base: %v", err)
	}
}
