package abac_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/adaptertest"
	"hop.top/pact-go/adapters/abac"
	"hop.top/pact-go/core"
	"hop.top/pact-go/core/clock"
)

// loadCase returns the ABAC case with the id.
func loadCase(t *testing.T, id string) adaptertest.Case {
	t.Helper()
	fsys, err := fixtures()
	if err != nil {
		t.Fatal(err)
	}
	cases, err := adaptertest.Load(fsys, "abac")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("no case %s", id)
	return adaptertest.Case{}
}

// checkID is the identifier of the installed ABAC check of the cases.
const checkID = "abac-policy-check-1"

// fixture is the adapter over the world of a case, with its clock and hooks.
type fixture struct {
	a     *abac.Adapter
	w     *world
	clk   *clock.Fake
	hooks *adaptertest.Hooks
	p     adapter.Principal
	op    core.OperationContext
}

// queries is the number of requests that reached the PDP.
func (f *fixture) queries() int {
	n := 0
	for _, h := range f.hooks.Fired() {
		if h == hookPDP {
			n++
		}
	}
	return n
}

// newFixture builds the adapter over the case's state; edit, when set,
// changes the state document first.
func newFixture(t *testing.T, id string, edit func(st map[string]any)) *fixture {
	t.Helper()
	c := loadCase(t, id)
	var st map[string]any
	if err := json.Unmarshal(c.NativeState, &st); err != nil {
		t.Fatal(err)
	}
	if edit != nil {
		edit(st)
	}
	if _, ok := st["entry"]; !ok {
		// The cases of the other functions state no entry; the unit tests of
		// the check install the one the check cases state.
		st["entry"] = map[string]any{"check_id": checkID, "policy_version": i11Version}
	}
	raw, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	clk := clock.NewFake(time.Unix(1792080000, 0))
	hooks := &adaptertest.Hooks{}
	w, err := loadWorld(t, raw, hooks)
	if err != nil {
		t.Fatal(err)
	}
	a, _, err := worldAdapter(w, clk)
	if err != nil {
		t.Fatal(err)
	}
	k := c.Call
	f := &fixture{a: a, w: w, clk: clk, hooks: hooks}
	if k.Principal != nil {
		f.p = adapter.Principal{
			ID:        k.Principal.ID,
			Realm:     adapter.Realm{TenantID: k.Principal.Realm.TenantID, EnvironmentID: k.Principal.Realm.EnvironmentID},
			Workload:  adapter.Workload(k.Principal.Workload),
			Mechanism: adapter.Mechanism(k.Principal.Mechanism), AuthenticatedAt: clk.Now(), Attributes: k.Principal.Attributes,
		}
	}
	if k.Operation != nil {
		f.op = *k.Operation
	}
	return f
}

// noExpectInput drops the pinned input, whose time is the case's now.
func noExpectInput(st map[string]any) {
	delete(st["pdp"].(map[string]any), "expect_input")
}

func TestDescribe(t *testing.T) {
	f := newFixture(t, "ABAC-02.control", nil)
	d := f.a.Describe()
	if d.Protocol != "opa-data-api" || d.Version != "v1" || d.MappingRevision != "pact-abac-1" {
		t.Errorf("Describe() = %+v", d)
	}
}

// TestCheck is the third column of ABAC-8 and ABAC-14: the ABAC check reports
// whether a well-formed, version-pinned, attributable decision with installed
// obligations was produced, never the decision itself.
func TestCheck(t *testing.T) {
	tests := []struct {
		id   string
		want adapter.Verdict
		code string
	}{
		{"ABAC-02.control", adapter.VerdictPass, "REQUIREMENT_SATISFIED"},
		{"ABAC-19.native-deny", adapter.VerdictPass, "REQUIREMENT_SATISFIED"},
		{"ABAC-17.deny-with-obligations", adapter.VerdictPass, "REQUIREMENT_SATISFIED"},
		{"ABAC-05.clearance-observed", adapter.VerdictFail, "STALE_EVIDENCE"},
		{"ABAC-06.clock-ahead", adapter.VerdictFail, "CLOCK_AHEAD"},
		{"ABAC-06.restamped", adapter.VerdictFail, "RESTAMPED"},
		{"ABAC-07.catalog", adapter.VerdictUnknown, "DEPENDENCY_UNAVAILABLE"},
		{"ABAC-08.no-classification", adapter.VerdictUnknown, "UNSUPPORTED_REQUIREMENT"},
		{"ABAC-11.no-result", adapter.VerdictUnknown, "DEPENDENCY_UNAVAILABLE"},
		{"ABAC-12.bare-boolean", adapter.VerdictUnknown, "UNSUPPORTED_REQUIREMENT"},
		{"ABAC-12.extra-member", adapter.VerdictUnknown, "UNSUPPORTED_REQUIREMENT"},
		{"ABAC-12.not-json", adapter.VerdictUnknown, "UNSUPPORTED_REQUIREMENT"},
		{"ABAC-13.absent", adapter.VerdictFail, "REQUIREMENTS_CHANGED"},
		{"ABAC-13.empty", adapter.VerdictFail, "REQUIREMENTS_CHANGED"},
		{"ABAC-14.other-version", adapter.VerdictFail, "REQUIREMENTS_CHANGED"},
		{"ABAC-15.status-500", adapter.VerdictUnknown, "DEPENDENCY_UNAVAILABLE"},
		{"ABAC-16.no-decision-id", adapter.VerdictUnknown, "DEPENDENCY_UNAVAILABLE"},
		{"ABAC-28.unknown-type", adapter.VerdictUnknown, "UNSUPPORTED_REQUIREMENT"},
	}
	for _, tc := range tests {
		t.Run(tc.id, func(t *testing.T) {
			f := newFixture(t, tc.id, nil)
			out := f.a.CheckContext(context.Background(), checkID, adapter.CheckInput{Principal: f.p, Operation: f.op})
			if out.Result != tc.want || out.ReasonCode != tc.code {
				t.Errorf("Check = %s %s, want %s %s", out.Result, out.ReasonCode, tc.want, tc.code)
			}
			if out.SourceID != "pdp-northstar" {
				t.Errorf("source %q", out.SourceID)
			}
			if out.ObservedAt.After(f.clk.Now()) {
				t.Errorf("observed at %v, after now", out.ObservedAt)
			}
		})
	}
}

func TestCheckWithoutEntryIsUnknown(t *testing.T) {
	f := newFixture(t, "ABAC-02.control", nil)
	a, err := abac.New(abac.Config{
		Realm: f.p.Realm, Origin: "https://gateway.northstar.example",
		Authenticator: stubAuth{}, Bindings: stubAuth{}, Subjects: worldFacts{f.w}, Resources: worldFacts{f.w}, Devices: worldFacts{f.w},
		Environment: abac.Gateway{SourceID: "gateway", Clock: f.clk},
		PDP:         abac.PDP{SourceID: "pdp", URL: f.w.pdp.URL, DecisionPath: "pact/abac/decision", Client: f.w.pdp.Client},
		Clock:       f.clk,
	})
	if err != nil {
		t.Fatal(err)
	}
	if out := a.CheckContext(context.Background(), checkID, adapter.CheckInput{Principal: f.p, Operation: f.op}); out.Result != adapter.VerdictUnknown || out.ReasonCode != "UNSUPPORTED_REQUIREMENT" {
		t.Errorf("Check = %+v", out)
	}
	if got := a.CheckContext(context.Background(), checkID, adapter.CheckInput{Principal: f.p, Operation: f.op}); got.Result != adapter.VerdictUnknown || got.ReasonCode != "UNSUPPORTED_REQUIREMENT" {
		t.Errorf("CheckContext of the ABAC check id = %+v; no entry is installed", got)
	}
}

// stubAuth is an inherited authentication that the unit tests never call.
type stubAuth struct{}

func (stubAuth) AuthenticateNative(context.Context, *http.Request) (adapter.Principal, error) {
	return adapter.Principal{}, errors.New("not used")
}

func (stubAuth) ResolveAgentBinding(context.Context, adapter.Realm, adapter.Workload, adapter.AgentID) (adapter.AgentBinding, error) {
	return adapter.AgentBinding{Status: adapter.BindingUnknown}, nil
}

// TestGate is the gateway's use of a decision (profile section 17, ABAC-28).
func TestGate(t *testing.T) {
	e := abac.Entry{CheckID: "c", PinnedVersion: "abac-2026-10-01"}
	allow := adapter.Decision{Effect: adapter.EffectAllow, PolicyRevision: "abac-2026-10-01",
		Obligations: []adapter.Obligation{{ID: "filter_fields"}, {ID: "watermark"}}}
	if err := abac.Gate(allow, e); err != nil {
		t.Errorf("pinned allow with installed obligations: %v", err)
	}
	other := allow
	other.PolicyRevision = "abac-2026-11-01"
	err := abac.Gate(other, e)
	if !errors.Is(err, abac.ErrRequirementsChanged) {
		t.Errorf("another version: %v", err)
	}
	if code, _ := adapter.CodeOf(err); code != "REQUIREMENTS_CHANGED" {
		t.Errorf("code %q", code)
	}
	empty := allow
	empty.PolicyRevision = ""
	if err := abac.Gate(empty, e); !errors.Is(err, abac.ErrRequirementsChanged) {
		t.Errorf("no version: %v", err)
	}
	unknown := allow
	unknown.Obligations = []adapter.Obligation{{ID: "filter_fields"}, {ID: "encrypt_at_rest"}}
	if err := abac.Gate(unknown, e); !errors.Is(err, abac.ErrObligationUnsupported) || !errors.Is(err, adapter.ErrUnsupportedRequirement) {
		t.Errorf("unknown type: %v", err)
	}
	narrow := e
	narrow.Obligations = []string{"filter_fields"}
	if err := abac.Gate(allow, narrow); !errors.Is(err, abac.ErrObligationUnsupported) {
		t.Errorf("type outside a narrower set: %v", err)
	}
	for _, eff := range []adapter.Effect{adapter.EffectDeny, adapter.EffectUnknown, ""} {
		d := allow
		d.Effect = eff
		if err := abac.Gate(d, e); !errors.Is(err, abac.ErrNotPermitted) {
			t.Errorf("effect %q: %v", eff, err)
		}
	}
}

// TestNoDecisionCache is ABAC-20: each call is a new query.
func TestNoDecisionCache(t *testing.T) {
	f := newFixture(t, "ABAC-02.control", nil)
	for i := 1; i <= 2; i++ {
		d, err := f.a.AuthorizeNative(context.Background(), f.p, f.op)
		if err != nil || !d.Permits() {
			t.Fatalf("call %d: %+v, %v", i, d, err)
		}
		if f.queries() != i {
			t.Errorf("after call %d the PDP saw %d queries", i, f.queries())
		}
	}
}

// recorder is a PDP that records the requests it gets and answers an allow.
type recorder struct {
	n      atomic.Int32
	header http.Header
	target string
	status int
}

func (r *recorder) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	r.n.Add(1)
	r.header, r.target = req.Header.Clone(), req.Method+" "+req.URL.RequestURI()
	if r.status != 0 {
		rw.Header().Set("Location", "/v1/data/pact/abac/decision?strict-builtin-errors=true")
		rw.WriteHeader(r.status)
		return
	}
	_, _ = rw.Write([]byte(`{"decision_id":"d-1","result":{"allow":true,"obligations":[],"policy_version":"abac-2026-10-01"}}`))
}

// recorderAdapter is the adapter of a case with the PDP replaced.
func recorderAdapter(t *testing.T, rec *recorder, token string) (*abac.Adapter, *fixture) {
	t.Helper()
	f := newFixture(t, "ABAC-02.control", noExpectInput)
	srv := httptest.NewTLSServer(rec)
	t.Cleanup(srv.Close)
	a, err := abac.New(abac.Config{
		Realm: f.p.Realm, Origin: "https://gateway.northstar.example",
		Authenticator: stubAuth{}, Bindings: stubAuth{}, Subjects: worldFacts{f.w}, Resources: worldFacts{f.w}, Devices: worldFacts{f.w},
		Environment: abac.Gateway{SourceID: "gateway", Zones: []abac.Zone{{Prefix: netip.MustParsePrefix("10.20.0.0/16"), Name: "corporate"}}, Clock: f.clk},
		PDP:         abac.PDP{SourceID: "pdp", URL: srv.URL, DecisionPath: "pact/abac/decision", Client: srv.Client(), Token: token},
		Clock:       f.clk,
	})
	if err != nil {
		t.Fatal(err)
	}
	return a, f
}

// TestRequest is ABAC-13 and ABAC-22: the adapter sends only POST to the
// decision path with strict-builtin-errors, its bearer token when it has one,
// and never follows a redirect.
func TestRequest(t *testing.T) {
	rec := &recorder{}
	a, f := recorderAdapter(t, rec, "pdp-client-token-5f2c9a")
	d, err := a.AuthorizeNative(context.Background(), f.p, f.op)
	if err != nil || !d.Permits() || d.SourceRef != "d-1" {
		t.Fatalf("AuthorizeNative = %+v, %v", d, err)
	}
	if rec.target != "POST /v1/data/pact/abac/decision?strict-builtin-errors=true" {
		t.Errorf("request %q", rec.target)
	}
	if got := rec.header.Get("Authorization"); got != "Bearer pdp-client-token-5f2c9a" {
		t.Errorf("Authorization %q", got)
	}
	if got := rec.header.Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type %q", got)
	}

	redirect := &recorder{status: http.StatusTemporaryRedirect}
	a, f = recorderAdapter(t, redirect, "pdp-client-token-5f2c9a")
	_, err = a.AuthorizeNative(context.Background(), f.p, f.op)
	if !errors.Is(err, adapter.ErrDependencyUnavailable) || redirect.n.Load() != 1 {
		t.Errorf("redirect: %v after %d requests; want DEPENDENCY_UNAVAILABLE after one", err, redirect.n.Load())
	}
	if strings.Contains(err.Error(), "pdp-client-token") {
		t.Errorf("the error carries the token: %v", err)
	}
}

func TestNewRefusesConfiguration(t *testing.T) {
	f := newFixture(t, "ABAC-02.control", nil)
	base := func() abac.Config {
		return abac.Config{
			Realm: f.p.Realm, Origin: "https://gateway.northstar.example",
			Authenticator: stubAuth{}, Bindings: stubAuth{}, Subjects: worldFacts{f.w}, Resources: worldFacts{f.w}, Devices: worldFacts{f.w},
			Environment: abac.Gateway{SourceID: "gateway", Clock: f.clk},
			PDP:         abac.PDP{SourceID: "pdp", URL: "https://pdp.northstar.example:8181", DecisionPath: "pact/abac/decision"},
			Clock:       f.clk,
		}
	}
	if _, err := abac.New(base()); err != nil {
		t.Fatalf("base configuration: %v", err)
	}
	looser := abac.ProfileLimits()
	looser[abac.PathDeviceCompliant] = abac.Limit{MaxAgeSeconds: 600, StatusMaxAgeSeconds: 30}
	tighter := abac.ProfileLimits()
	tighter[abac.PathDeviceCompliant] = abac.Limit{MaxAgeSeconds: 120, StatusMaxAgeSeconds: 10}
	if c := base(); func() error { c.Limits = tighter; _, err := abac.New(c); return err }() != nil {
		t.Error("a tighter limit is refused")
	}
	tests := map[string]func(*abac.Config){
		"http PDP":              func(c *abac.Config) { c.PDP.URL = "http://pdp.northstar.example:8181" },
		"PDP URL with path":     func(c *abac.Config) { c.PDP.URL = "https://pdp.northstar.example/v1/data" },
		"PDP URL with userinfo": func(c *abac.Config) { c.PDP.URL = "https://u:p@pdp.northstar.example" },
		"no PDP source":         func(c *abac.Config) { c.PDP.SourceID = "" },
		"decision path dot":     func(c *abac.Config) { c.PDP.DecisionPath = "pact/../abac" },
		"decision path empty":   func(c *abac.Config) { c.PDP.DecisionPath = "" },
		"no clock":              func(c *abac.Config) { c.Clock = nil },
		"no authenticator":      func(c *abac.Config) { c.Authenticator = nil },
		"no device source":      func(c *abac.Config) { c.Devices = nil },
		"looser limit":          func(c *abac.Config) { c.Limits = looser },
		"missing limit":         func(c *abac.Config) { c.Limits = map[string]abac.Limit{} },
		"fact path as claim":    func(c *abac.Config) { c.Claims = map[string]abac.ClaimSource{abac.PathClearance: nil} },
		"entry without pin":     func(c *abac.Config) { c.Entry = &abac.Entry{CheckID: "c"} },
	}
	for name, edit := range tests {
		c := base()
		edit(&c)
		if _, err := abac.New(c); err == nil {
			t.Errorf("%s: New succeeded", name)
		}
	}
}

func TestGatewayEnvironment(t *testing.T) {
	clk := clock.NewFake(time.Unix(1792080000, 0))
	g := abac.Gateway{SourceID: "gw", Clock: clk, Zones: []abac.Zone{
		{Prefix: netip.MustParsePrefix("10.0.0.0/8"), Name: "internal"},
		{Prefix: netip.MustParsePrefix("10.20.0.0/16"), Name: "corporate"},
	}}
	ctx := context.Background()
	for addr, want := range map[string]string{"10.20.30.40": "corporate", "10.9.0.1": "internal", "::ffff:10.20.30.40": "corporate"} {
		c, err := g.NetworkZone(ctx, netip.MustParseAddr(addr))
		if err != nil || c.Value != want || !c.ObservedAt.Equal(clk.Now()) || !c.StatusCheckedAt.Equal(clk.Now()) || c.SourceID != "gw" {
			t.Errorf("%s: %+v, %v; want %s observed now", addr, c, err, want)
		}
	}
	if _, err := g.NetworkZone(ctx, netip.MustParseAddr("192.0.2.1")); !errors.Is(err, abac.ErrNoFact) {
		t.Errorf("unmapped address: %v", err)
	}
	if c, err := g.Time(ctx); err != nil || c.Value != int64(1792080000) {
		t.Errorf("Time = %+v, %v", c, err)
	}
}

func TestParsePointer(t *testing.T) {
	good := map[string][]string{
		"": {}, "/": {""}, "/a~1b": {"a/b"}, "/m~0n": {"m~n"}, "/foo/0": {"foo", "0"}, "/ ": {" "},
	}
	for s, want := range good {
		got, err := abac.ParsePointer(s)
		if err != nil || !slices.Equal(got, want) {
			t.Errorf("ParsePointer(%q) = %q, %v; want %q", s, got, err, want)
		}
	}
	for _, s := range []string{"a", "/a~", "/a~2", "/items/-", "#/a"} {
		if _, err := abac.ParsePointer(s); err == nil {
			t.Errorf("ParsePointer(%q) succeeded", s)
		}
	}
}
