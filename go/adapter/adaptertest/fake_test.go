package adaptertest

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/core"
)

// fake is an adapter whose behavior each test scripts. A function that is not
// set returns the zero value, which the suite treats as a wrong answer.
type fake struct {
	auth   func(context.Context, *http.Request) (adapter.Principal, error)
	bind   func(context.Context, adapter.Realm, adapter.Workload, adapter.AgentID) (adapter.AgentBinding, error)
	mapOp  func(context.Context, *http.Request, adapter.Principal, string) (core.OperationContext, error)
	claim  func(context.Context, string, adapter.ClaimContext) (adapter.NativeClaim, error)
	check  func(context.Context, string, adapter.CheckInput) adapter.CheckOutcome
	authz  func(context.Context, adapter.Principal, core.OperationContext) (adapter.Decision, error)
	record func(context.Context, adapter.Observation) (adapter.Recorded, error)
}

func (f *fake) Describe() adapter.Descriptor { return adapter.Descriptor{Protocol: "fake"} }

func (f *fake) AuthenticateNative(ctx context.Context, r *http.Request) (adapter.Principal, error) {
	if f.auth == nil {
		return adapter.Principal{}, nil
	}
	return f.auth(ctx, r)
}

func (f *fake) ResolveAgentBinding(ctx context.Context, realm adapter.Realm, w adapter.Workload, a adapter.AgentID) (adapter.AgentBinding, error) {
	if f.bind == nil {
		return adapter.AgentBinding{}, nil
	}
	return f.bind(ctx, realm, w, a)
}

func (f *fake) MapOperation(ctx context.Context, r *http.Request, p adapter.Principal, v string) (core.OperationContext, error) {
	if f.mapOp == nil {
		return core.OperationContext{}, nil
	}
	return f.mapOp(ctx, r, p, v)
}

func (f *fake) ReadNativeClaim(ctx context.Context, path string, c adapter.ClaimContext) (adapter.NativeClaim, error) {
	if f.claim == nil {
		return adapter.NativeClaim{}, nil
	}
	return f.claim(ctx, path, c)
}

func (f *fake) CheckContext(ctx context.Context, id string, in adapter.CheckInput) adapter.CheckOutcome {
	if f.check == nil {
		return adapter.CheckOutcome{}
	}
	return f.check(ctx, id, in)
}

func (f *fake) AuthorizeNative(ctx context.Context, p adapter.Principal, op core.OperationContext) (adapter.Decision, error) {
	if f.authz == nil {
		return adapter.Decision{}, nil
	}
	return f.authz(ctx, p, op)
}

func (f *fake) RecordOutcome(ctx context.Context, o adapter.Observation) (adapter.Recorded, error) {
	if f.record == nil {
		return nil, nil
	}
	return f.record(ctx, o)
}

// factoryFor returns a Factory that hands out f with an Arrive hook that
// marks nothing and a Credential hook that sets a bearer token.
func factoryFor(f *fake) Factory {
	return func(testing.TB, Env) (Subject, error) {
		return Subject{
			Adapter: f,
			Arrive:  func(r *http.Request) *http.Request { return r },
			Credential: func(r *http.Request, ref string) error {
				r.Header.Set("Authorization", "Bearer tok-"+ref)
				return nil
			},
		}, nil
	}
}

// the current time of a case that states none.
var now = time.Unix(defaultNow, 0)

// runFake runs one case against f and returns the failures.
func runFake(t *testing.T, f *fake, c *Case) []string {
	t.Helper()
	if c.NativeState == nil {
		c.NativeState = []byte(`{}`)
	}
	if c.ID == "" {
		c.ID = "T-01"
	}
	return runCase(t, factoryFor(f), c)
}

// wantClean fails the test when the case produced any failure.
func wantClean(t *testing.T, fails []string) {
	t.Helper()
	if len(fails) > 0 {
		t.Errorf("unexpected failures: %q", fails)
	}
}

// wantFails fails the test unless some failure contains each substring, and
// unless there is a failure at all.
func wantFails(t *testing.T, fails []string, subs ...string) {
	t.Helper()
	if len(fails) == 0 {
		t.Errorf("the case passed, want failures containing %q", subs)
		return
	}
	for _, s := range subs {
		found := false
		for _, f := range fails {
			if strings.Contains(f, s) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("no failure contains %q; failures: %q", s, fails)
		}
	}
}

// row is one row of a table of scripted behaviors: the fake, the case, and
// the failures expected (none for a pass).
type row struct {
	name  string
	fake  *fake
	c     *Case
	fails []string
}

// runRows runs each row and compares its failures with the expectation.
func runRows(t *testing.T, rows []row) {
	t.Helper()
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			got := runFake(t, r.fake, r.c)
			if len(r.fails) == 0 {
				wantClean(t, got)
				return
			}
			wantFails(t, got, r.fails...)
		})
	}
}

var (
	acme   = adapter.Realm{TenantID: "acme", EnvironmentID: "https://gateway.example/environments/finance"}
	acmeJS = RealmJSON{TenantID: "acme", EnvironmentID: "https://gateway.example/environments/finance"}
)

// goodPrincipal is an authenticated principal that satisfies every invariant.
func goodPrincipal() adapter.Principal {
	return adapter.Principal{
		ID: "https://idp.example/alice", Realm: acme, Workload: "w-1", Mechanism: "bearer",
		AuthenticatedAt: now,
	}
}

// goodOp is an operation context that satisfies every invariant.
func goodOp() core.OperationContext {
	return core.OperationContext{
		OperationID: "op-1", EnvironmentID: acme.EnvironmentID,
		PrincipalID: "https://idp.example/alice", Action: "invoice.read",
		Resources: []string{"https://invoices.example/invoices/1"}, Method: "GET",
		TargetURI:  "https://gateway.example/invoices/1",
		BodyDigest: "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU",
		Headers:    map[string]string{},
	}
}
