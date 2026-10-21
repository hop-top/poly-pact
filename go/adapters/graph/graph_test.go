package graph_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/adaptertest"
	"hop.top/pact-go/adapter/enroll"
	"hop.top/pact-go/adapters/oauth"
	"hop.top/pact-go/core"
	"hop.top/pact-go/core/clock"
)

// The adapter under test: conformanceFactory realizes the graph/1 cases and
// the common cases, unitBroker the unit tier.
var (
	conformanceFactory adaptertest.Factory = stubFactory
	unitBroker         brokerFactory       = stubBrokerFactory
)

// brokerFactory builds the broker of a unit world.
type brokerFactory func(t testing.TB, w *unitWorld) (broker, error)

// TestConformance runs the conformance suite, the common cases and the Graph
// cases of spec/v1.0/fixtures/adapters/graph. No common case is replaced. The
// profile claims no shared workloads, so the dedicated cases run.
func TestConformance(t *testing.T) {
	adaptertest.Run(t, conformanceFactory, adaptertest.Options{Adapter: "graph"})
}

// TestStubFailsTheGraphCases runs the Graph cases against the fallback stub:
// every case but those of stubPasses must fail, so that each case can catch
// the obvious wiring.
func TestStubFailsTheGraphCases(t *testing.T) {
	results, err := adaptertest.Evaluate(t, stubFactory, adaptertest.Options{Adapter: "graph"})
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, r := range results {
		if !strings.HasPrefix(r.ID, "GRAPH-") {
			continue
		}
		seen++
		switch {
		case stubPasses[r.ID] && !r.Passed():
			t.Errorf("%s: the stub was expected to pass it: %v", r.ID, r.Failures)
		case !stubPasses[r.ID] && r.Passed():
			t.Errorf("%s: the stub passes it; the case cannot catch the stub", r.ID)
		}
	}
	if seen == 0 {
		t.Fatal("no Graph case loaded")
	}
}

// TestFixtureStates strict-parses the native state of every Graph case.
func TestFixtureStates(t *testing.T) {
	fsys, err := fixtures()
	if err != nil {
		t.Fatal(err)
	}
	cases, err := adaptertest.Load(fsys, "graph")
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, c := range cases {
		if !strings.HasPrefix(c.ID, "GRAPH-") {
			continue
		}
		seen++
		if _, err := parseState(c.NativeState); err != nil {
			t.Errorf("%s: %v", c.ID, err)
		}
	}
	if seen == 0 {
		t.Fatal("no Graph case loaded")
	}
}

// unitCase is one case of the unit tier: it builds its world, runs the broker
// and returns its failures.
type unitCase struct {
	id  string
	run func(t testing.TB, mk brokerFactory) []string
}

// TestUnit runs the unit tier against the broker of the package.
func TestUnit(t *testing.T) {
	for _, c := range unitCases {
		t.Run(c.id, func(t *testing.T) {
			for _, f := range c.run(t, unitBroker) {
				t.Error(f)
			}
		})
	}
}

// stubUnitPasses are the unit cases the fallback stub passes: with a settled
// preflight, the app-only request of the registered mailbox is the request a
// correct executor sends too.
var stubUnitPasses = map[string]bool{
	"GRAPH-11.app-only-path": true,
}

// TestStubFailsTheUnitCases is the mutation rule of the profile: an executor
// that falls back to the client credentials grant after a failed OBO
// exchange fails GRAPH-04, GRAPH-05 and GRAPH-06, and every other unit case
// but those of stubUnitPasses.
func TestStubFailsTheUnitCases(t *testing.T) {
	failed := map[string]bool{}
	for _, c := range unitCases {
		fails := c.run(t, stubBrokerFactory)
		switch {
		case stubUnitPasses[c.id] && len(fails) > 0:
			t.Errorf("%s: the stub was expected to pass it: %v", c.id, fails)
		case !stubUnitPasses[c.id] && len(fails) == 0:
			t.Errorf("%s: the stub passes it", c.id)
		}
		if len(fails) > 0 {
			failed[strings.SplitN(c.id, ".", 2)[0]] = true
		}
	}
	for _, g := range []string{"GRAPH-04", "GRAPH-05", "GRAPH-06"} {
		if !failed[g] {
			t.Errorf("no %s case fails against the fallback stub", g)
		}
	}
}

// failures collects the failures of a unit case.
type failures []string

func (f *failures) add(format string, args ...any) { *f = append(*f, fmt.Sprintf(format, args...)) }

// newUnitWorld is a world of one form: the fake cloud, the clock at uNow, the
// reference bindings, and in form D the OAuth front door of the gateway.
func newUnitWorld(t testing.TB, form string) *unitWorld {
	hooks := &adaptertest.Hooks{}
	w := &unitWorld{form: form, hooks: hooks, cloud: newCloud(t, hooks), clk: clock.NewFake(time.Unix(uNow, 0)), registry: unitBindings(form)}
	if form == formDelegated {
		fd, err := oauth.New(oauth.Config{
			Realm: uRealm,
			Entries: []oauth.Entry{{
				ID: "entra-northwind", Form: oauth.FormEntraV2, Issuer: uIssuer, Tenant: uTID,
				Audiences: []string{uGatewayApp}, Clients: []string{uClientApp},
			}},
			Routes:      []oauth.Route{{Method: http.MethodGet, Path: "/mail/messages", Entry: "entra-northwind", Scope: "Mail.Read"}},
			HTTPClient:  w.cloud.client,
			Origin:      uOrigin,
			Registry:    noEnrollments{},
			Permissions: noPolicy{},
			Clock:       w.clk,
		})
		if err != nil {
			t.Fatal(err)
		}
		w.frontDoor = fd
	}
	return w
}

// build makes the broker of w, failing the case when it cannot.
func build(t testing.TB, mk brokerFactory, w *unitWorld, f *failures) broker {
	b, err := mk(t, w)
	if err != nil {
		f.add("broker: %v", err)
		return nil
	}
	return b
}

// noEnrollments is an enrollment registry with no record.
type noEnrollments struct{}

func (noEnrollments) Lookup(context.Context, adapter.Realm, adapter.Workload, adapter.AgentID) (adapter.AgentBinding, error) {
	return adapter.AgentBinding{Status: adapter.BindingUnknown}, nil
}

func (noEnrollments) Rotate(context.Context, enroll.Actor, string, core.Digest) error {
	return errors.New("read-only")
}

func (noEnrollments) MarkCompromised(context.Context, enroll.Actor, string) error {
	return errors.New("read-only")
}

// noPolicy denies every operation.
type noPolicy struct{}

func (noPolicy) Decide(context.Context, adapter.Principal, core.OperationContext) (adapter.Decision, error) {
	return adapter.Decision{Effect: adapter.EffectDeny, SourceID: "gateway-policy"}, nil
}
