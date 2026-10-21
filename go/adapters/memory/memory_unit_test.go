package memory_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapters/memory"
	"hop.top/pact-go/core"
	"hop.top/pact-go/core/binding"
	"hop.top/pact-go/core/clock"
)

var (
	t0  = time.Unix(1792080000, 0)
	env = "https://gateway.example/environments/finance"
)

// newAdapter builds the adapter over a state with one identity, one mapping,
// one approved claim path and one installed check. Its workloads are
// dedicated, the default.
func newAdapter(t *testing.T, mutate ...func(*memory.State)) (*memory.Adapter, *clock.Fake) {
	t.Helper()
	return newAdapterWith(t, nil, mutate...)
}

// newSharedAdapter is newAdapter with workloads that several agents may share.
func newSharedAdapter(t *testing.T, mutate ...func(*memory.State)) (*memory.Adapter, *clock.Fake) {
	t.Helper()
	return newAdapterWith(t, []memory.Option{memory.WithSharedWorkloads()}, mutate...)
}

func newAdapterWith(t *testing.T, opts []memory.Option, mutate ...func(*memory.State)) (*memory.Adapter, *clock.Fake) {
	t.Helper()
	realm := memory.Realm{TenantID: "acme", EnvironmentID: env}
	st := memory.State{
		Model: memory.Model,
		Gateway: memory.Gateway{
			TenantID: "acme", EnvironmentID: env, Origin: "https://gateway.example",
			HeaderAllowlist: []string{"x-request-kind"},
		},
		Mappings: []memory.Mapping{{Version: "map-1", Routes: []memory.Route{
			{Method: "GET", Path: "/invoices/{id}", Action: "invoice.read", Resource: "https://invoices.example/invoices/{id}"},
		}}},
		Identities: []memory.Identity{
			{Ref: "alice", ID: "https://idp.example/alice", Realm: realm, Workload: "w-alice", Secret: "tok-alice-secret-1"},
			{Ref: "bob", ID: "https://idp.example/bob", Realm: realm, Workload: "w-bob", Secret: "tok-bob-secret-2"},
		},
		ApprovedPaths: []string{"/roles"},
		Claims: []memory.ClaimRecord{{Realm: realm, Principal: "https://idp.example/alice", Path: "/roles",
			Value: json.RawMessage(`["approver"]`), SourceID: "directory"}},
		Checks: []memory.CheckRecord{{ID: "approval-v1", Result: "PASS", ReasonCode: "REQUIREMENT_SATISFIED", SourceID: "approvals"}},
		Reporting: &memory.Reporting{Issuer: "https://gateway.example/reporters/finance",
			Audience: "https://reputation.example/", KID: "k1"},
		Visibility: "execution",
	}
	for _, m := range mutate {
		m(&st)
	}
	clk := clock.NewFake(t0)
	a, err := memory.New(st, clk, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return a, clk
}

func alice() adapter.Principal {
	return adapter.Principal{
		ID: "https://idp.example/alice", Workload: "w-alice", Mechanism: "bearer",
		Realm: adapter.Realm{TenantID: "acme", EnvironmentID: env},
	}
}

func get(t *testing.T, target string) *http.Request {
	t.Helper()
	return received(t, "GET", target, nil)
}

// received returns the request a server takes off the wire for an
// absolute-form request-target: RequestURI is the target, octet for octet.
func received(t *testing.T, method, target string, body io.Reader) *http.Request {
	t.Helper()
	r, err := http.NewRequest(method, target, body)
	if err != nil {
		t.Fatal(err)
	}
	r.RequestURI = target
	return r
}

func TestNewValidatesTheState(t *testing.T) {
	good := func(st *memory.State) {}
	tests := []struct {
		name   string
		mutate func(*memory.State)
		want   string
	}{
		{"valid", good, ""},
		{"wrong model", func(st *memory.State) { st.Model = "common/2" }, "model"},
		{"no tenant", func(st *memory.State) { st.Gateway.TenantID = "" }, "tenant_id"},
		{"http origin", func(st *memory.State) { st.Gateway.Origin = "http://gateway.example" }, "https origin"},
		{"origin with a path", func(st *memory.State) { st.Gateway.Origin = "https://gateway.example/api" }, "bare origin"},
		{"origin with userinfo", func(st *memory.State) { st.Gateway.Origin = "https://u:p@gateway.example" }, "bare origin"},
		// The baseline mapping's own configuration checks apply too.
		{"origin with a trailing slash", func(st *memory.State) { st.Gateway.Origin = "https://gateway.example/" }, "invalid configuration"},
		{"presentation header on the allowlist", func(st *memory.State) { st.Gateway.HeaderAllowlist = []string{"pact-trace"} }, "invalid configuration"},
		{"allowlist entry is not a token", func(st *memory.State) { st.Gateway.HeaderAllowlist = []string{"x kind"} }, "invalid configuration"},
		{"mapping version too long", func(st *memory.State) { st.Mappings[0].Version = strings.Repeat("v", 1025) }, "invalid configuration"},
		{"credential header on the allowlist", func(st *memory.State) { st.Gateway.HeaderAllowlist = []string{"authorization"} }, "never belong"},
		{"hop-by-hop header on the allowlist", func(st *memory.State) { st.Gateway.HeaderAllowlist = []string{"connection"} }, "never belong"},
		{"uppercase allowlist entry", func(st *memory.State) { st.Gateway.HeaderAllowlist = []string{"X-Kind"} }, "lowercase"},
		{"mapping without a version", func(st *memory.State) { st.Mappings[0].Version = "" }, "no version"},
		{"incomplete route", func(st *memory.State) { st.Mappings[0].Routes[0].Action = "" }, "incomplete route"},
		{"identity without a secret", func(st *memory.State) { st.Identities[0].Secret = "" }, "needs a ref"},
		{"duplicate identity ref", func(st *memory.State) { st.Identities[1].Ref = "alice" }, "used twice"},
		{"bad enrollment status", func(st *memory.State) {
			st.Enrollments = []memory.Enrollment{{Workload: "w", Status: "SUSPENDED", AgentID: "https://a.example/a", SourceID: "s"}}
		}, "status"},
		{"enrollment without a source", func(st *memory.State) {
			st.Enrollments = []memory.Enrollment{{Workload: "w", Status: "ACTIVE", AgentID: "https://a.example/a"}}
		}, "source_id"},
		{"enrollment agent is not a URI", func(st *memory.State) {
			st.Enrollments = []memory.Enrollment{{Workload: "w", Status: "ACTIVE", AgentID: "agent", SourceID: "s"}}
		}, "absolute URI"},
		{"enrollment holder key is not a thumbprint", func(st *memory.State) {
			st.Enrollments = []memory.Enrollment{{Workload: "w", Status: "ACTIVE", AgentID: "https://a.example/a", SourceID: "s", HolderJKT: "x"}}
		}, "digest"},
		{"claim outside the approved paths", func(st *memory.State) { st.Claims[0].Path = "/other" }, "approved path"},
		{"claim without a value", func(st *memory.State) { st.Claims[0].Value = nil }, "no value"},
		{"claim without a source", func(st *memory.State) { st.Claims[0].SourceID = "" }, "source_id"},
		{"check with a bad result", func(st *memory.State) { st.Checks[0].Result = "OK" }, "needs an id"},
		{"policy with a bad effect", func(st *memory.State) {
			st.Policy = []memory.PolicyRule{{Principal: "p", Action: "a", Effect: "PERMIT"}}
		}, "needs a principal"},
		{"bad visibility", func(st *memory.State) { st.Visibility = "partial" }, "visibility"},
		{"reporting without a key id", func(st *memory.State) { st.Reporting.KID = "" }, "reporting"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a, _ := newAdapter(t)
			st := a.State()
			// Copy the slices that the mutation edits, so cases stay independent.
			st.Mappings = append([]memory.Mapping(nil), st.Mappings...)
			st.Mappings[0].Routes = append([]memory.Route(nil), st.Mappings[0].Routes...)
			st.Identities = append([]memory.Identity(nil), st.Identities...)
			st.Claims = append([]memory.ClaimRecord(nil), st.Claims...)
			st.Checks = append([]memory.CheckRecord(nil), st.Checks...)
			rep := *st.Reporting
			st.Reporting = &rep
			tc.mutate(&st)
			_, err := memory.New(st, clock.NewFake(t0))
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.want)
			}
		})
	}

	t.Run("no clock", func(t *testing.T) {
		a, _ := newAdapter(t)
		if _, err := memory.New(a.State(), nil); err == nil {
			t.Error("New accepted a nil clock")
		}
	})
}

func TestParseStateIsStrict(t *testing.T) {
	const base = `{"model":"common/1","gateway":{"tenant_id":"t","environment_id":"e","origin":"https://g.example"}`
	for name, doc := range map[string]string{
		"unknown member":    base + `,"surprise":1}`,
		"duplicate member":  base + `,"visibility":"none","visibility":"none"}`,
		"unknown in nested": strings.Replace(base, `"origin"`, `"extra":1,"origin"`, 1) + `}`,
		"not an object":     `[]`,
	} {
		if _, err := memory.ParseState([]byte(doc)); err == nil {
			t.Errorf("%s: ParseState accepted %s", name, doc)
		}
	}
	if _, err := memory.ParseState([]byte(base + `}`)); err != nil {
		t.Errorf("minimal state: %v", err)
	}
	if _, err := memory.FromJSON([]byte(base+`}`), clock.NewFake(t0)); err != nil {
		t.Errorf("FromJSON: %v", err)
	}
	if _, err := memory.FromJSON([]byte(`{`), clock.NewFake(t0)); err == nil {
		t.Error("FromJSON accepted broken JSON")
	}
}

func TestNormalizeOrigin(t *testing.T) {
	for in, want := range map[string]string{
		"https://gateway.example":      "https://gateway.example",
		"HTTPS://Gateway.Example:443":  "https://gateway.example",
		"https://gateway.example:8443": "https://gateway.example:8443",
		"https://gateway.example/":     "https://gateway.example",
		"https://[::1]:443":            "https://[::1]",
		"https://[2001:db8::1]:8443":   "https://[2001:db8::1]:8443",
	} {
		got, err := memory.NormalizeOrigin(in)
		if err != nil || got != want {
			t.Errorf("NormalizeOrigin(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "gateway.example", "http://gateway.example", "https://", "https://g.example/x", "https://g.example?x=1", "https://g.example#f", "mailto:a@b.example"} {
		if got, err := memory.NormalizeOrigin(in); err == nil {
			t.Errorf("NormalizeOrigin(%q) = %q, want an error", in, got)
		}
	}
}

func TestAuthenticate(t *testing.T) {
	a, _ := newAdapter(t)
	req := func(authz string, arrive bool) *http.Request {
		r := get(t, "https://gateway.example/invoices/1")
		if authz != "" {
			r.Header.Set("Authorization", authz)
		}
		if arrive {
			r = memory.Arrive(r)
		}
		return r
	}
	denial := func(err error) adapter.DenialReason {
		var d *adapter.NativeDenial
		if !errors.As(err, &d) {
			t.Fatalf("err = %v, want a *NativeDenial", err)
		}
		return d.Reason
	}

	p, err := a.AuthenticateNative(context.Background(), req("Bearer tok-alice-secret-1", true))
	if err != nil || p.ID != "https://idp.example/alice" || p.Workload != "w-alice" || p.Mechanism != "bearer" || !p.AuthenticatedAt.Equal(t0) {
		t.Fatalf("principal = %+v, %v", p, err)
	}
	if p, err = a.AuthenticateNative(context.Background(), req("bearer tok-bob-secret-2", true)); err != nil || p.ID != "https://idp.example/bob" {
		t.Errorf("a lowercase scheme: %+v, %v", p, err)
	}
	for name, tc := range map[string]struct {
		r      *http.Request
		reason adapter.DenialReason
	}{
		"no header":          {req("", true), adapter.DenialNoCredential},
		"no header, direct":  {req("", false), adapter.DenialNoCredential},
		"unknown token":      {req("Bearer tok-nobody", true), adapter.DenialCredentialRejected},
		"basic scheme":       {req("Basic dXNlcjpwdw==", true), adapter.DenialCredentialRejected},
		"empty token":        {req("Bearer ", true), adapter.DenialCredentialRejected},
		"direct, valid":      {req("Bearer tok-alice-secret-1", false), adapter.DenialCredentialRejected},
		"token prefix only":  {req("Bearer tok-alice", true), adapter.DenialCredentialRejected},
		"token plus suffix":  {req("Bearer tok-alice-secret-1x", true), adapter.DenialCredentialRejected},
		"token in lowercase": {req("Bearer TOK-ALICE-SECRET-1", true), adapter.DenialCredentialRejected},
	} {
		_, err := a.AuthenticateNative(context.Background(), tc.r)
		if err == nil {
			t.Errorf("%s: authenticated", name)
			continue
		}
		if got := denial(err); got != tc.reason {
			t.Errorf("%s: reason %s, want %s", name, got, tc.reason)
		}
		if !errors.Is(err, adapter.ErrInvalidProof) {
			t.Errorf("%s: not an ErrInvalidProof", name)
		}
	}

	t.Run("a header cannot carry the mark", func(t *testing.T) {
		r := req("Bearer tok-alice-secret-1", false)
		r.Header.Set("X-Arrived", "true")
		r.Header.Set("Arrived", "true")
		if _, err := a.AuthenticateNative(context.Background(), r); err == nil {
			t.Error("authenticated a request that was marked by a header")
		}
		if memory.Arrived(r) {
			t.Error("Arrived is true for an unmarked request")
		}
		if !memory.Arrived(memory.Arrive(r)) {
			t.Error("Arrived is false for a marked request")
		}
	})

	t.Run("attributes are copied", func(t *testing.T) {
		a, _ := newAdapter(t, func(st *memory.State) {
			st.Identities[0].Attributes = map[string]any{"groups": []any{"finance"}}
		})
		p, err := a.AuthenticateNative(context.Background(), req("Bearer tok-alice-secret-1", true))
		if err != nil {
			t.Fatal(err)
		}
		p.Attributes["groups"] = "changed"
		p2, _ := a.AuthenticateNative(context.Background(), req("Bearer tok-alice-secret-1", true))
		if g, _ := p2.Attributes["groups"].([]any); len(g) != 1 {
			t.Errorf("attributes of the store changed through a returned principal: %v", p2.Attributes)
		}
	})

	t.Run("cancelled context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := a.AuthenticateNative(ctx, req("Bearer tok-alice-secret-1", true))
		if !errors.Is(err, adapter.ErrDependencyUnavailable) {
			t.Errorf("err = %v, want a dependency error", err)
		}
	})
}

func TestCredentialHook(t *testing.T) {
	a, _ := newAdapter(t)
	r := get(t, "https://gateway.example/")
	if err := a.Credential(r, "bob"); err != nil || r.Header.Get("Authorization") != "Bearer tok-bob-secret-2" {
		t.Errorf("Credential: %v, %q", err, r.Header.Get("Authorization"))
	}
	r.Header.Set("Authorization", "Bearer explicit")
	if err := a.Credential(r, "alice"); err != nil || r.Header.Get("Authorization") != "Bearer explicit" {
		t.Errorf("an explicit header was replaced: %q", r.Header.Get("Authorization"))
	}
	if err := a.Credential(r, "nobody"); err == nil {
		t.Error("an unknown ref was accepted")
	}
}

func TestResolveAgentBinding(t *testing.T) {
	realm := memory.Realm{TenantID: "acme", EnvironmentID: env}
	other := memory.Realm{TenantID: "globex", EnvironmentID: env}
	const jkt = "xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M"
	enroll := func(w, status string, r memory.Realm, observed, checked *int64) memory.Enrollment {
		return memory.Enrollment{Realm: r, Workload: w, AgentID: "https://identity.example/agents/" + w, OperatorID: "https://identity.example/operators/o",
			HolderJKT: jkt, Status: status, ObservedAt: observed, StatusCheckedAt: checked, SourceID: "registry", SourceRef: "ref-" + w}
	}
	past, future, edge, pastSkew := t0.Unix()-60, t0.Unix()+3600, t0.Unix()+5, t0.Unix()+6
	a, _ := newAdapter(t, func(st *memory.State) {
		st.Enrollments = []memory.Enrollment{
			enroll("active", "ACTIVE", realm, &past, &past),
			enroll("checked-edge", "ACTIVE", realm, &past, &edge),
			enroll("checked-past", "ACTIVE", realm, &past, &pastSkew),
			enroll("revoked", "REVOKED", realm, nil, nil),
			enroll("compromised", "COMPROMISED", realm, nil, nil),
			enroll("unknown", "UNKNOWN", realm, nil, nil),
			enroll("future", "ACTIVE", realm, &future, nil),
			enroll("globex-only", "ACTIVE", other, nil, nil),
		}
	})
	ar := adapter.Realm{TenantID: "acme", EnvironmentID: env}
	// resolve names the agent enrolled for w, so that only the realm and the
	// workload decide; TestResolveAgentBindingSelectsTheAgent varies the agent.
	resolve := func(realm adapter.Realm, w string) (adapter.AgentBinding, error) {
		return a.ResolveAgentBinding(context.Background(), realm, adapter.Workload(w), adapter.AgentID("https://identity.example/agents/"+w))
	}

	b, err := resolve(ar, "active")
	if err != nil || b.Status != adapter.BindingActive || b.AgentID != "https://identity.example/agents/active" ||
		b.HolderJKT != jkt || b.SourceID != "registry" || b.SourceRef != "ref-active" ||
		!b.ObservedAt.Equal(time.Unix(past, 0)) || !b.StatusCheckedAt.Equal(time.Unix(past, 0)) {
		t.Errorf("active: %+v, %v", b, err)
	}
	// Identity mapping IM-11: a revoked or compromised binding is returned
	// as its status, with the agent, operator and holder key, and no error.
	for w, status := range map[string]adapter.BindingStatus{"revoked": adapter.BindingRevoked, "compromised": adapter.BindingCompromised} {
		b, err := resolve(ar, w)
		want := adapter.AgentBinding{AgentID: "https://identity.example/agents/" + w, OperatorID: "https://identity.example/operators/o",
			HolderJKT: jkt, Status: status, SourceID: "registry", SourceRef: "ref-" + w}
		if err != nil || b != want {
			t.Errorf("%s: %+v, %v; want %+v and no error", w, b, err, want)
		}
	}
	for _, w := range []string{"unknown", "no-such-workload", "globex-only"} {
		b, err := resolve(ar, w)
		if err != nil || b.Status != adapter.BindingUnknown || b.AgentID != "" || b.HolderJKT != "" {
			t.Errorf("%s: %+v, %v; want UNKNOWN with nothing in it", w, b, err)
		}
	}
	if b, err := resolve(adapter.Realm{TenantID: "globex", EnvironmentID: env}, "globex-only"); err != nil || b.Status != adapter.BindingActive {
		t.Errorf("globex-only in its own realm: %+v, %v", b, err)
	}
	if b, err := resolve(ar, "future"); !errors.Is(err, adapter.ErrDependencyUnavailable) || b.AgentID != "" {
		t.Errorf("future observation: %+v, %v", b, err)
	}
	// Draft A.2: no status-check time may be later than now plus the skew.
	if b, err := resolve(ar, "checked-edge"); err != nil || b.Status != adapter.BindingActive || !b.StatusCheckedAt.Equal(time.Unix(edge, 0)) {
		t.Errorf("status checked at now+skew: %+v, %v", b, err)
	}
	if b, err := resolve(ar, "checked-past"); !errors.Is(err, adapter.ErrDependencyUnavailable) || b.AgentID != "" {
		t.Errorf("status checked past now+skew: %+v, %v", b, err)
	}
}

// TestResolveAgentBindingSelectsTheAgent: the agent ID the request names
// selects among the records of the authenticated workload in the realm, and
// only there (draft 17.1). An agent with no record on the workload, an agent
// enrolled only on another workload of the realm or only in another realm, a
// near-miss spelling of the agent ID and no agent ID at all answer UNKNOWN; a
// workload alone never names an agent.
func TestResolveAgentBindingSelectsTheAgent(t *testing.T) {
	realm := memory.Realm{TenantID: "acme", EnvironmentID: env}
	other := memory.Realm{TenantID: "globex", EnvironmentID: env}
	const (
		ka = "xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M"
		kb = "lHkry8t631MLf-lKvuVhoHKwGhJta35vQQ3PCjI0bVU"
		kd = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
		ag = "https://identity.example/agents/"
	)
	rec := func(r memory.Realm, w, agent, jkt string) memory.Enrollment {
		return memory.Enrollment{Realm: r, Workload: w, AgentID: ag + agent, OperatorID: "https://identity.example/operators/o",
			HolderJKT: jkt, Status: "ACTIVE", SourceID: "registry", SourceRef: "ref-" + agent}
	}
	a, _ := newSharedAdapter(t, func(st *memory.State) {
		st.Enrollments = []memory.Enrollment{
			rec(realm, "shared", "a", ka),
			rec(realm, "shared", "b", kb),
			rec(realm, "dedicated", "d", kd),
			rec(other, "shared", "g", kd),
		}
	})
	ar := adapter.Realm{TenantID: "acme", EnvironmentID: env}
	for _, tc := range []struct {
		w, agent string
		jkt      core.Digest // "" for UNKNOWN
	}{
		{"shared", ag + "a", ka},
		{"shared", ag + "b", kb},
		{"dedicated", ag + "d", kd},
		{"shared", ag + "c", ""},
		{"shared", ag + "d", ""},
		{"dedicated", ag + "a", ""},
		{"shared", ag + "g", ""},
		{"shared", ag + "A", ""},
		{"shared", ag + "a/", ""},
		{"shared", "", ""},
		{"dedicated", "", ""},
	} {
		b, err := a.ResolveAgentBinding(context.Background(), ar, adapter.Workload(tc.w), adapter.AgentID(tc.agent))
		if err != nil {
			t.Errorf("(%s, %q): %v", tc.w, tc.agent, err)
			continue
		}
		if tc.jkt == "" {
			if b.Status != adapter.BindingUnknown || b.AgentID != "" || b.HolderJKT != "" {
				t.Errorf("(%s, %q) = %+v, want UNKNOWN with nothing in it", tc.w, tc.agent, b)
			}
			continue
		}
		if b.Status != adapter.BindingActive || b.AgentID != tc.agent || b.HolderJKT != tc.jkt {
			t.Errorf("(%s, %q) = %+v, want ACTIVE agent %q with key %q", tc.w, tc.agent, b, tc.agent, tc.jkt)
		}
	}
}

// TestResolveAgentBindingEnrolledElsewhere: an UNKNOWN answer reports whether
// the agent ID is enrolled for another workload of the realm, in any status
// (draft 17.1). A binding on the authenticated workload never carries the
// report, and an enrollment in another realm, on any workload, never sets it.
// A record of the agent on another workload whose source cannot answer leaves
// the report unknown, so the call is DEPENDENCY_UNAVAILABLE.
func TestResolveAgentBindingEnrolledElsewhere(t *testing.T) {
	realm := memory.Realm{TenantID: "acme", EnvironmentID: env}
	otherTenant := memory.Realm{TenantID: "globex", EnvironmentID: env}
	otherEnv := memory.Realm{TenantID: "acme", EnvironmentID: env + "-staging"}
	const (
		ka = "xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M"
		kb = "lHkry8t631MLf-lKvuVhoHKwGhJta35vQQ3PCjI0bVU"
		kd = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
		ag = "https://identity.example/agents/"
	)
	rec := func(r memory.Realm, w, agent, jkt, status, source string) memory.Enrollment {
		return memory.Enrollment{Realm: r, Workload: w, AgentID: ag + agent, OperatorID: "https://identity.example/operators/o",
			HolderJKT: jkt, Status: status, SourceID: source, SourceRef: "ref-" + agent}
	}
	a, _ := newSharedAdapter(t, func(st *memory.State) {
		st.Enrollments = []memory.Enrollment{
			rec(realm, "shared", "a", ka, "ACTIVE", "registry"),
			rec(realm, "shared", "b", kb, "ACTIVE", "registry"),
			rec(realm, "dedicated", "d", kd, "ACTIVE", "registry"),
			rec(realm, "retired", "r", ka, "REVOKED", "registry"),
			rec(realm, "quarantine", "q", kb, "COMPROMISED", "registry"),
			rec(realm, "dedicated", "both", kd, "ACTIVE", "registry"),
			rec(realm, "shared", "both", ka, "REVOKED", "registry"),
			rec(otherTenant, "shared", "g", kd, "ACTIVE", "registry"),
			rec(otherEnv, "elsewhere", "x", kd, "ACTIVE", "registry"),
			rec(realm, "far", "down", kd, "ACTIVE", "registry-down"),
		}
		st.UnavailableSources = []string{"registry-down"}
	})
	ar := adapter.Realm{TenantID: "acme", EnvironmentID: env}
	for _, tc := range []struct {
		w, agent  string
		status    adapter.BindingStatus
		elsewhere bool
	}{
		{"shared", "a", adapter.BindingActive, false},
		{"shared", "both", adapter.BindingRevoked, false},
		{"dedicated", "both", adapter.BindingActive, false},
		{"shared", "d", adapter.BindingUnknown, true},
		{"dedicated", "a", adapter.BindingUnknown, true},
		{"shared", "r", adapter.BindingUnknown, true},
		{"shared", "q", adapter.BindingUnknown, true},
		{"shared", "c", adapter.BindingUnknown, false},
		{"shared", "g", adapter.BindingUnknown, false},
		{"shared", "x", adapter.BindingUnknown, false},
		{"elsewhere", "x", adapter.BindingUnknown, false},
		{"shared", "", adapter.BindingUnknown, false},
	} {
		agent := ""
		if tc.agent != "" {
			agent = ag + tc.agent
		}
		b, err := a.ResolveAgentBinding(context.Background(), ar, adapter.Workload(tc.w), adapter.AgentID(agent))
		if err != nil || b.Status != tc.status || b.EnrolledElsewhere != tc.elsewhere {
			t.Errorf("(%s, %q) = status %s, enrolled elsewhere %t, %v; want %s, %t", tc.w, agent, b.Status, b.EnrolledElsewhere, err, tc.status, tc.elsewhere)
		}
	}
	if b, err := a.ResolveAgentBinding(context.Background(), ar, "shared", ag+"down"); !errors.Is(err, adapter.ErrDependencyUnavailable) || b != (adapter.AgentBinding{}) {
		t.Errorf("record elsewhere in a source that cannot answer: %+v, %v; want DEPENDENCY_UNAVAILABLE and no binding", b, err)
	}
	if b, err := a.ResolveAgentBinding(context.Background(), ar, "far", ag+"a"); err != nil || b.Status != adapter.BindingUnknown || !b.EnrolledElsewhere {
		t.Errorf("unavailable source of another agent: %+v, %v; want UNKNOWN, enrolled elsewhere", b, err)
	}
}

func TestMapOperationRules(t *testing.T) {
	a, _ := newAdapter(t)
	ctx := context.Background()
	p := alice()

	t.Run("mapping version", func(t *testing.T) {
		_, err := a.MapOperation(ctx, get(t, "https://gateway.example/invoices/1"), p, "map-9")
		if !errors.Is(err, adapter.ErrUnsupportedRequirement) {
			t.Errorf("err = %v, want UNSUPPORTED_REQUIREMENT", err)
		}
	})

	t.Run("no route", func(t *testing.T) {
		for _, target := range []string{
			"https://gateway.example/invoices", "https://gateway.example/invoices/1/approve",
			"https://gateway.example/other/1", "https://gateway.example/invoices/a%20b",
		} {
			_, err := a.MapOperation(ctx, get(t, target), p, "map-1")
			if !errors.Is(err, adapter.ErrUnsupportedRequirement) {
				t.Errorf("%s: err = %v, want UNSUPPORTED_REQUIREMENT", target, err)
			}
		}
		r := received(t, "DELETE", "https://gateway.example/invoices/1", nil)
		if _, err := a.MapOperation(ctx, r, p, "map-1"); !errors.Is(err, adapter.ErrUnsupportedRequirement) {
			t.Errorf("DELETE: err = %v", err)
		}
	})

	t.Run("realm and credential", func(t *testing.T) {
		other := p
		other.Realm.TenantID = "globex"
		if _, err := a.MapOperation(ctx, get(t, "https://gateway.example/invoices/1"), other, "map-1"); !errors.Is(err, adapter.ErrContextMismatch) {
			t.Errorf("other realm: %v", err)
		}
		if _, err := a.MapOperation(ctx, get(t, "https://gateway.example/invoices/1"), adapter.Principal{Realm: p.Realm}, "map-1"); !errors.Is(err, adapter.ErrContextMismatch) {
			t.Errorf("no principal id: %v", err)
		}
		r := get(t, "https://gateway.example/invoices/1")
		r.Header.Set("Authorization", "Bearer tok-bob-secret-2")
		if _, err := a.MapOperation(ctx, r, p, "map-1"); !errors.Is(err, adapter.ErrContextMismatch) {
			t.Errorf("bob's token with alice as principal: %v", err)
		}
		r.Header.Set("Authorization", "Bearer tok-alice-secret-1")
		if _, err := a.MapOperation(ctx, r, p, "map-1"); err != nil {
			t.Errorf("alice's token with alice as principal: %v", err)
		}
		r.Header.Set("Authorization", "Bearer tok-unknown-to-the-store")
		if _, err := a.MapOperation(ctx, r, p, "map-1"); err != nil {
			t.Errorf("an unknown token says nothing about the sender: %v", err)
		}
	})

	// Every request the baseline mapping refuses is an INVALID_MESSAGE (draft
	// 10.2, 13.4): the sentinel, its code, and nothing else, with no operation
	// context. Where the baseline mapping names the rule, the error carries it.
	wantInvalid := func(t *testing.T, name string, r *http.Request, rule binding.Rule) {
		t.Helper()
		op, err := a.MapOperation(ctx, r, p, "map-1")
		if err == nil {
			t.Errorf("%s: mapped to %s %s", name, op.Method, op.TargetURI)
			return
		}
		if !errors.Is(err, adapter.ErrInvalidMessage) {
			t.Errorf("%s: err = %v, want ErrInvalidMessage", name, err)
		}
		if c, ok := adapter.CodeOf(err); !ok || c != "INVALID_MESSAGE" {
			t.Errorf("%s: code = %q, %v; want INVALID_MESSAGE", name, c, ok)
		}
		if errors.Is(err, adapter.ErrDependencyUnavailable) || errors.Is(err, adapter.ErrUnsupportedRequirement) {
			t.Errorf("%s: a refused request is not an unavailable dependency or an unsupported mapping: %v", name, err)
		}
		if rule != "" {
			var re *binding.RequestError
			if !errors.As(err, &re) || re.Rule != rule {
				t.Errorf("%s: err = %v, want the baseline mapping rule %q", name, err, rule)
			}
		}
		if op.TargetURI != "" || op.OperationID != "" {
			t.Errorf("%s: returned an operation context with the error", name)
		}
	}

	t.Run("rejected forms", func(t *testing.T) {
		withHeader := func(k, v string) *http.Request {
			r := get(t, "https://gateway.example/invoices/1")
			r.Header.Set(k, v)
			return r
		}
		withTarget := func(rt string) *http.Request {
			r := get(t, "https://gateway.example/invoices/1")
			r.RequestURI = rt
			return r
		}
		withMethod := func(m string) *http.Request {
			r := get(t, "https://gateway.example/invoices/1")
			r.Method = m
			return r
		}
		chunkedGzip := get(t, "https://gateway.example/invoices/1")
		chunkedGzip.TransferEncoding = []string{"gzip", "chunked"}
		client := get(t, "https://gateway.example/invoices/1")
		client.RequestURI = ""
		for _, tc := range []struct {
			name string
			r    *http.Request
			rule binding.Rule
		}{
			{"fragment", get(t, "https://gateway.example/invoices/1#f"), binding.RuleFragment},
			{"request-target fragment", withTarget("/invoices/1#f"), binding.RuleFragment},
			{"userinfo", get(t, "https://u:p@gateway.example/invoices/1"), binding.RuleUserinfo},
			{"content encoding", withHeader("Content-Encoding", "gzip"), binding.RuleContentEncoding},
			{"identity encoding", withHeader("Content-Encoding", "identity"), binding.RuleContentEncoding},
			{"blank content encoding", withHeader("Content-Encoding", " "), binding.RuleContentEncoding},
			{"transfer coding other than chunked", chunkedGzip, binding.RuleTransferCoding},
			{"method with a digit", withMethod("GET1"), binding.RuleMethod},
			{"method with a hyphen", withMethod("M-SEARCH"), binding.RuleMethod},
			{"no request-target", client, binding.RuleTargetForm},
			{"asterisk-form", withTarget("*"), binding.RuleTargetForm},
			{"authority-form", withTarget("gateway.example:443"), binding.RuleTargetForm},
			{"absolute-form without a path", withTarget("https://gateway.example?x=1"), binding.RuleTargetForm},
			{"non-ASCII host", withTarget("https://gatéway.example/invoices/1"), binding.RuleNonASCIIHost},
			{"space in the query", withTarget("/invoices/1?q=a b"), binding.RuleInvalidCharacter},
			{"raw non-ASCII in the path", withTarget("/invoices/é"), binding.RuleInvalidCharacter},
			{"malformed escape", withTarget("/invoices/1?q=%zz"), binding.RuleMalformedEscape},
			{"target too long", withTarget("/invoices/1?q=" + strings.Repeat("x", 1024)), binding.RuleTargetTooLong},
			{"control octet in a covered header", withHeader("X-Request-Kind", "a\x01b"), binding.RuleHeaderValue},
			{"covered header not UTF-8", withHeader("X-Request-Kind", "a\xffb"), binding.RuleHeaderValue},
			{"covered header too long", withHeader("X-Request-Kind", strings.Repeat("k", 8193)), binding.RuleHeaderTooLong},
			{"nil URL", &http.Request{}, ""},
		} {
			wantInvalid(t, tc.name, tc.r, tc.rule)
		}
		collision := get(t, "https://gateway.example/invoices/1")
		collision.Header["X-Request-Kind"] = []string{"a"}
		collision.Header["x-request-kind"] = []string{"b"}
		wantInvalid(t, "covered header under two keys", collision, binding.RuleHeaderKeyCollision)
		_, err := a.MapOperation(ctx, nil, p, "map-1")
		if !errors.Is(err, adapter.ErrInvalidMessage) {
			t.Errorf("nil request: %v", err)
		}
	})

	// Draft 10.2: an encoding is ambiguous when RFC 3986 syntax-based
	// normalization would change it, or when it hides structure. It is rejected,
	// never normalized.
	t.Run("ambiguous encodings", func(t *testing.T) {
		for _, tc := range []struct {
			name, target string
			rule         binding.Rule
		}{
			{"encoded unreserved tilde", "https://gateway.example/invoices/INV%7E1", binding.RuleEncodedUnreserved},
			{"encoded unreserved letter", "https://gateway.example/invoices/%41", binding.RuleEncodedUnreserved},
			{"encoded dot segment", "https://gateway.example/invoices/%2E%2E/1", binding.RuleEncodedUnreserved},
			{"encoded unreserved in the query", "https://gateway.example/invoices/1?r=%7E", binding.RuleEncodedUnreserved},
			{"lowercase hex in the query", "https://gateway.example/invoices/1?a=%2f", binding.RuleLowercaseHex},
			{"lowercase hex in the path", "https://gateway.example/invoices/%c3%a9", binding.RuleLowercaseHex},
			{"encoded slash", "https://gateway.example/invoices/a%2Fb", binding.RuleEncodedSlash},
			{"encoded slash lowercase", "https://gateway.example/invoices/a%2fb", binding.RuleLowercaseHex},
			{"overlong slash", "https://gateway.example/invoices/1%C0%AF", binding.RuleInvalidUTF8},
			{"stray octet in the query", "https://gateway.example/invoices/1?q=%FF", binding.RuleInvalidUTF8},
			{"surrogate", "https://gateway.example/invoices/%ED%A0%80", binding.RuleInvalidUTF8},
			{"dot segment", "https://gateway.example/invoices/../admin", binding.RuleDotSegment},
		} {
			wantInvalid(t, tc.name, get(t, tc.target), tc.rule)
		}
	})

	// Other escapes are not ambiguous: they are bound as sent, and the mapping
	// decides whether a route takes them.
	t.Run("other escapes reach the mapping", func(t *testing.T) {
		for _, target := range []string{
			"https://gateway.example/invoices/a%5Cb", "https://gateway.example/invoices/a%00b",
			"https://gateway.example/invoices/a%25b",
		} {
			_, err := a.MapOperation(ctx, get(t, target), p, "map-1")
			if !errors.Is(err, adapter.ErrUnsupportedRequirement) || errors.Is(err, adapter.ErrInvalidMessage) {
				t.Errorf("%s: err = %v, want UNSUPPORTED_REQUIREMENT from the mapping", target, err)
			}
		}
	})

	t.Run("target uri", func(t *testing.T) {
		for target, want := range map[string]string{
			"https://internal.local:8443/invoices/1":                   "https://gateway.example/invoices/1",
			"https://internal.local/invoices/1?":                       "https://gateway.example/invoices/1?",
			"https://internal.local/invoices/1?b=2&a=%2F&a=1":          "https://gateway.example/invoices/1?b=2&a=%2F&a=1",
			"https://internal.local/invoices/1?q=%C3%A9+%20&q=&z":      "https://gateway.example/invoices/1?q=%C3%A9+%20&q=&z",
			"https://internal.local/invoices/INV~1?q=a+b%20c&r=~":      "https://gateway.example/invoices/INV~1?q=a+b%20c&r=~",
			"http://Other.Example:8080/invoices/1?x=%3D%26&x=%2F%3F/?": "https://gateway.example/invoices/1?x=%3D%26&x=%2F%3F/?",
		} {
			op, err := a.MapOperation(ctx, get(t, target), p, "map-1")
			if err != nil || op.TargetURI != want {
				t.Errorf("%s: %q, %v; want %q", target, op.TargetURI, err, want)
			}
		}
		// An origin-form request-target is the path and query as sent; the URL
		// a server parses from it plays no part.
		r := get(t, "https://internal.local/invoices/INV~1?z=%2F&a=1")
		r.RequestURI = "/invoices/INV~1?z=%2F&a=1"
		r.URL.RawQuery = "a=1&z=%2F"
		if op, err := a.MapOperation(ctx, r, p, "map-1"); err != nil || op.TargetURI != "https://gateway.example/invoices/INV~1?z=%2F&a=1" {
			t.Errorf("origin-form request target: %q, %v", op.TargetURI, err)
		}
		// The method is uppercased; the route is matched on the bound path.
		r = get(t, "https://gateway.example/invoices/7")
		r.Method = "get"
		if op, err := a.MapOperation(ctx, r, p, "map-1"); err != nil || op.Method != "GET" || op.Action != "invoice.read" ||
			len(op.Resources) != 1 || op.Resources[0] != "https://invoices.example/invoices/7" {
			t.Errorf("lowercase method: %+v, %v", op, err)
		}
	})

	t.Run("operation id and environment", func(t *testing.T) {
		id := func(target string, pr adapter.Principal) string {
			op, err := a.MapOperation(ctx, get(t, target), pr, "map-1")
			if err != nil {
				t.Fatal(err)
			}
			if op.EnvironmentID != env {
				t.Errorf("environment_id = %q, want %q", op.EnvironmentID, env)
			}
			return op.OperationID
		}
		u := "https://gateway.example/invoices/1"
		bob := alice()
		bob.ID = "https://idp.example/bob"
		first, second := id(u, p), id(u, p)
		if first == "" || first != second {
			t.Errorf("the same request has the operation ids %q and %q", first, second)
		}
		if first == id(u+"?x=1", p) || first == id(u, bob) {
			t.Error("operation ids are not specific to the request and the principal")
		}
	})

	t.Run("headers", func(t *testing.T) {
		post := func(body string, hdr map[string]string) core.OperationContext {
			a, _ := newAdapter(t, func(st *memory.State) {
				st.Mappings[0].Routes = append(st.Mappings[0].Routes, memory.Route{Method: "POST", Path: "/invoices/{id}", Action: "invoice.write", Resource: "https://invoices.example/invoices/{id}"})
			})
			r := received(t, "POST", "https://gateway.example/invoices/1", strings.NewReader(body))
			for k, v := range hdr {
				r.Header.Add(k, v)
			}
			op, err := a.MapOperation(ctx, r, p, "map-1")
			if err != nil {
				t.Fatal(err)
			}
			return op
		}
		op := post("x", map[string]string{"Content-Type": "text/plain", "X-Request-Kind": "  bulk\t", "Authorization": "Bearer t"})
		if len(op.Headers) != 2 || op.Headers["content-type"] != "text/plain" || op.Headers["x-request-kind"] != "bulk" {
			t.Errorf("headers = %v", op.Headers)
		}
		// Content-type is covered when there is a body, and only then.
		op = post("", map[string]string{"Content-Type": "text/plain"})
		if op.Headers == nil || len(op.Headers) != 0 {
			t.Errorf("headers without a body = %v", op.Headers)
		}
		// A header the request names in Connection is hop-by-hop for it
		// (RFC 9110 7.6.1), so it is not covered even when allowlisted.
		op = post("", map[string]string{"X-Request-Kind": "bulk", "Connection": "x-request-kind"})
		if len(op.Headers) != 0 {
			t.Errorf("headers with x-request-kind named in Connection = %v", op.Headers)
		}
		// Repeated headers are joined.
		r := get(t, "https://gateway.example/invoices/1")
		r.Header.Add("X-Request-Kind", "a")
		r.Header.Add("X-Request-Kind", "b")
		if op, _ := a.MapOperation(ctx, r, p, "map-1"); op.Headers["x-request-kind"] != "a, b" {
			t.Errorf("repeated header = %q", op.Headers["x-request-kind"])
		}
	})

	t.Run("body", func(t *testing.T) {
		body := []byte("exact bytes \x00\xff\r\n")
		a, _ := newAdapter(t, func(st *memory.State) {
			st.Mappings[0].Routes = append(st.Mappings[0].Routes, memory.Route{Method: "PUT", Path: "/invoices/{id}", Action: "invoice.write", Resource: "https://invoices.example/invoices/{id}"})
		})
		r := received(t, "PUT", "https://gateway.example/invoices/1", bytes.NewReader(body))
		op, err := a.MapOperation(ctx, r, p, "map-1")
		if err != nil {
			t.Fatal(err)
		}
		if op.BodyDigest != "M24hzpYZfgDraiT_FZmtqZmmKetxRFnz_tSjno0bnXQ" {
			t.Errorf("body_digest = %q", op.BodyDigest)
		}
		again, _ := io.ReadAll(r.Body)
		if !bytes.Equal(again, body) {
			t.Errorf("body after the call = %q", again)
		}
		if r.GetBody == nil {
			t.Fatal("GetBody was not restored")
		}
		rc, _ := r.GetBody()
		if third, _ := io.ReadAll(rc); !bytes.Equal(third, body) {
			t.Errorf("GetBody = %q", third)
		}
		// A second mapping of the same request gives the same digest.
		r.Body, _ = r.GetBody()
		op2, err := a.MapOperation(ctx, r, p, "map-1")
		if err != nil || op2.BodyDigest != op.BodyDigest {
			t.Errorf("second call: %v, %q vs %q", err, op2.BodyDigest, op.BodyDigest)
		}
	})

	t.Run("body too large", func(t *testing.T) {
		a, _ := newAdapter(t, func(st *memory.State) {
			st.Mappings[0].Routes = append(st.Mappings[0].Routes, memory.Route{Method: "PUT", Path: "/invoices/{id}", Action: "invoice.write", Resource: "https://invoices.example/invoices/{id}"})
		})
		const size = 9 << 20
		r := received(t, "PUT", "https://gateway.example/invoices/1", io.LimitReader(zeros{}, size))
		_, err := a.MapOperation(ctx, r, p, "map-1")
		var re *binding.RequestError
		if !errors.Is(err, adapter.ErrInvalidMessage) || !errors.As(err, &re) || re.Rule != binding.RuleBodyTooLarge {
			t.Errorf("err = %v, want INVALID_MESSAGE under the body-too-large rule", err)
		}
		// The request keeps its whole body for the native error path.
		if n, _ := io.Copy(io.Discard, r.Body); n != size {
			t.Errorf("the body has %d bytes after the call, want %d", n, size)
		}
	})

	t.Run("unreadable body", func(t *testing.T) {
		a, _ := newAdapter(t, func(st *memory.State) {
			st.Mappings[0].Routes = append(st.Mappings[0].Routes, memory.Route{Method: "PUT", Path: "/invoices/{id}", Action: "invoice.write", Resource: "https://invoices.example/invoices/{id}"})
		})
		r := received(t, "PUT", "https://gateway.example/invoices/1", io.NopCloser(failing{}))
		_, err := a.MapOperation(ctx, r, p, "map-1")
		if !errors.Is(err, adapter.ErrDependencyUnavailable) || errors.Is(err, adapter.ErrInvalidMessage) {
			t.Errorf("err = %v, want DEPENDENCY_UNAVAILABLE", err)
		}
		if !errors.Is(err, binding.ErrBodyRead) {
			t.Errorf("err = %v, want it to wrap the binding's body read error", err)
		}
	})
}

type zeros struct{}

func (zeros) Read(b []byte) (int, error) { return len(b), nil }

type failing struct{}

func (failing) Read([]byte) (int, error) { return 0, errors.New("connection reset") }

func TestReadNativeClaim(t *testing.T) {
	realm := memory.Realm{TenantID: "acme", EnvironmentID: env}
	past, future := t0.Unix()-120, t0.Unix()+3600
	a, _ := newAdapter(t, func(st *memory.State) {
		st.ApprovedPaths = []string{"/roles", "/null", "/future", "/checked", "/edge", "/checked-edge", "/checked-past", "/number"}
		rec := func(path, value string, o, c *int64) memory.ClaimRecord {
			return memory.ClaimRecord{Realm: realm, Principal: "https://idp.example/alice", Path: path,
				Value: json.RawMessage(value), ObservedAt: o, StatusCheckedAt: c, SourceID: "dir", SourceRef: "r-" + path}
		}
		edge, pastSkew := t0.Unix()+5, t0.Unix()+6
		st.Claims = []memory.ClaimRecord{
			rec("/roles", `["approver","viewer"]`, &past, &past),
			rec("/null", `null`, nil, nil),
			rec("/future", `["x"]`, &future, nil),
			rec("/checked", `["x"]`, &past, &future),
			rec("/edge", `["x"]`, &edge, nil),
			rec("/checked-edge", `["x"]`, &past, &edge),
			rec("/checked-past", `["x"]`, &past, &pastSkew),
			rec("/number", `12345678901234567890`, nil, nil),
		}
	})
	read := func(path string, p adapter.Principal) (adapter.NativeClaim, error) {
		return a.ReadNativeClaim(context.Background(), path, adapter.ClaimContext{Principal: p})
	}

	c, err := read("/roles", alice())
	if err != nil || c.SourceID != "dir" || c.SourceRef != "r-/roles" || !c.ObservedAt.Equal(time.Unix(past, 0)) || !c.StatusCheckedAt.Equal(time.Unix(past, 0)) {
		t.Fatalf("claim = %+v, %v", c, err)
	}
	if v, ok := c.Value.([]any); !ok || len(v) != 2 || v[0] != "approver" {
		t.Errorf("value = %#v", c.Value)
	}
	if c, err := read("/null", alice()); err != nil || c.Value != nil || !c.ObservedAt.IsZero() || !c.StatusCheckedAt.IsZero() {
		t.Errorf("null claim = %+v, %v; want a nil value and no times", c, err)
	}
	if c, err := read("/edge", alice()); err != nil || !c.ObservedAt.Equal(t0.Add(5*time.Second)) {
		t.Errorf("observation at now+skew: %+v, %v", c, err)
	}
	// Draft A.2: no status-check time may be later than now plus the skew.
	if c, err := read("/checked-edge", alice()); err != nil || !c.StatusCheckedAt.Equal(t0.Add(5*time.Second)) {
		t.Errorf("status check at now+skew: %+v, %v", c, err)
	}
	for _, path := range []string{"/future", "/checked", "/checked-past"} {
		if _, err := read(path, alice()); !errors.Is(err, adapter.ErrDependencyUnavailable) {
			t.Errorf("%s: err = %v, want DEPENDENCY_UNAVAILABLE", path, err)
		}
	}
	if _, err := read("/not-approved", alice()); !errors.Is(err, adapter.ErrUnsupportedRequirement) {
		t.Errorf("unapproved path: %v", err)
	}
	if _, err := read("", alice()); !errors.Is(err, adapter.ErrUnsupportedRequirement) {
		t.Errorf("empty path: %v", err)
	}
	for name, p := range map[string]adapter.Principal{
		"another principal": {ID: "https://idp.example/bob", Realm: alice().Realm},
		"another tenant":    {ID: alice().ID, Realm: adapter.Realm{TenantID: "globex", EnvironmentID: env}},
		"another env":       {ID: alice().ID, Realm: adapter.Realm{TenantID: "acme", EnvironmentID: "other"}},
	} {
		if c, err := read("/roles", p); err == nil {
			t.Errorf("%s: read %+v", name, c)
		} else if errors.Is(err, adapter.ErrDependencyUnavailable) || errors.Is(err, adapter.ErrUnsupportedRequirement) {
			t.Errorf("%s: a missing value is not %v", name, err)
		}
	}
}

func TestReadNativeClaimFollowsTheClock(t *testing.T) {
	a, clk := newAdapter(t, func(st *memory.State) {
		ahead := t0.Unix() + 600
		st.Claims[0].ObservedAt = &ahead
	})
	if _, err := a.ReadNativeClaim(context.Background(), "/roles", adapter.ClaimContext{Principal: alice()}); err == nil {
		t.Fatal("a claim observed ten minutes ahead was passed on")
	}
	clk.Advance(10 * time.Minute)
	c, err := a.ReadNativeClaim(context.Background(), "/roles", adapter.ClaimContext{Principal: alice()})
	if err != nil || !c.ObservedAt.Equal(t0.Add(10*time.Minute)) {
		t.Errorf("after the clock passed the observation: %+v, %v", c, err)
	}
}

// TestReadNativeClaimScope: a record that names a resource is read only for an
// operation that lists the resource, and a record that names a task only for an
// intent that carries the task (draft 17.1: "approved native path and
// context"). A record that names neither is read in any context.
func TestReadNativeClaimScope(t *testing.T) {
	realm := memory.Realm{TenantID: "acme", EnvironmentID: env}
	const (
		doc1 = "https://docs.example/d/1"
		doc2 = "https://docs.example/d/2"
	)
	a, _ := newAdapter(t, func(st *memory.State) {
		st.ApprovedPaths = []string{"/roles", "/classification", "/grant", "/both"}
		rec := func(path, value, resource, task string) memory.ClaimRecord {
			return memory.ClaimRecord{Realm: realm, Principal: "https://idp.example/alice", Path: path,
				Value: json.RawMessage(value), SourceID: "src", Resource: resource, TaskID: task}
		}
		st.Claims = []memory.ClaimRecord{
			rec("/roles", `["approver"]`, "", ""),
			rec("/classification", `"restricted"`, doc1, ""),
			rec("/classification", `"internal"`, doc2, ""),
			rec("/grant", `"grant-a"`, "", "task-a"),
			rec("/grant", `"grant-b"`, "", "task-b"),
			rec("/both", `"doc1-task-a"`, doc1, "task-a"),
		}
	})
	ops := func(resources ...string) core.OperationContext {
		return core.OperationContext{PrincipalID: alice().ID, Resources: resources}
	}
	task := func(id string) core.Intent { return core.Intent{TaskID: id} }
	read := func(path string, in core.Intent, op core.OperationContext) (any, error) {
		c, err := a.ReadNativeClaim(context.Background(), path, adapter.ClaimContext{Principal: alice(), Intent: in, Operation: op})
		return c.Value, err
	}
	tests := []struct {
		name string
		path string
		in   core.Intent
		op   core.OperationContext
		want any // nil: no value
	}{
		{"unscoped, no context", "/roles", core.Intent{}, core.OperationContext{}, []any{"approver"}},
		{"unscoped, any context", "/roles", task("task-a"), ops(doc1), []any{"approver"}},
		{"the first resource", "/classification", core.Intent{}, ops(doc1), "restricted"},
		{"the second resource", "/classification", core.Intent{}, ops(doc2), "internal"},
		{"a resource among several", "/classification", core.Intent{}, ops("https://docs.example/d/9", doc2), "internal"},
		{"a resource the operation does not list", "/classification", core.Intent{}, ops("https://docs.example/d/9"), nil},
		{"a resource fact with no operation", "/classification", core.Intent{}, core.OperationContext{}, nil},
		{"a resource fact is not read from the intent", "/classification", core.Intent{TaskID: doc1}, core.OperationContext{}, nil},
		{"the first task", "/grant", task("task-a"), core.OperationContext{}, "grant-a"},
		{"the second task", "/grant", task("task-b"), ops(doc1), "grant-b"},
		{"another task", "/grant", task("task-c"), core.OperationContext{}, nil},
		{"a task fact with no intent", "/grant", core.Intent{}, core.OperationContext{}, nil},
		{"a task fact is not read from the resources", "/grant", core.Intent{}, ops("task-a"), nil},
		{"a task is matched exactly", "/grant", task("TASK-A"), core.OperationContext{}, nil},
		{"both scopes", "/both", task("task-a"), ops(doc1), "doc1-task-a"},
		{"both scopes, task missing", "/both", core.Intent{}, ops(doc1), nil},
		{"both scopes, resource missing", "/both", task("task-a"), core.OperationContext{}, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := read(tc.path, tc.in, tc.op)
			if tc.want == nil {
				if err == nil {
					t.Fatalf("read %#v, want no value", got)
				}
				if errors.Is(err, adapter.ErrDependencyUnavailable) || errors.Is(err, adapter.ErrUnsupportedRequirement) {
					t.Errorf("a value out of scope is missing, not %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			gj, _ := json.Marshal(got)
			wj, _ := json.Marshal(tc.want)
			if string(gj) != string(wj) {
				t.Errorf("value = %s, want %s", gj, wj)
			}
		})
	}

	t.Run("the realm still applies", func(t *testing.T) {
		other := alice()
		other.Realm.TenantID = "globex"
		if c, err := a.ReadNativeClaim(context.Background(), "/classification",
			adapter.ClaimContext{Principal: other, Operation: ops(doc1)}); err == nil {
			t.Errorf("read %+v for a same-spelled principal of another realm", c)
		}
	})
}

func TestCheckContext(t *testing.T) {
	future := t0.Unix() + 3600
	a, _ := newAdapter(t, func(st *memory.State) {
		st.Checks = append(st.Checks,
			memory.CheckRecord{ID: "failing-v1", Result: "FAIL", ReasonCode: "APPROVAL_REJECTED", SourceID: "approvals", SourceRef: "a-1"},
			memory.CheckRecord{ID: "pending-v1", Result: "UNKNOWN", ReasonCode: "APPROVAL_PENDING", SourceID: "approvals"},
			memory.CheckRecord{ID: "future-v1", Result: "PASS", ReasonCode: "REQUIREMENT_SATISFIED", SourceID: "approvals", ObservedAt: &future})
	})
	run := func(id string) adapter.CheckOutcome {
		return a.CheckContext(context.Background(), id, adapter.CheckInput{})
	}
	for id, want := range map[string]adapter.Verdict{
		"approval-v1": adapter.VerdictPass, "failing-v1": adapter.VerdictFail, "pending-v1": adapter.VerdictUnknown,
		"": adapter.VerdictUnknown, "approval": adapter.VerdictUnknown, "approval-v10": adapter.VerdictUnknown,
		"APPROVAL-V1": adapter.VerdictUnknown, " approval-v1": adapter.VerdictUnknown, "approval-v1 ": adapter.VerdictUnknown,
	} {
		if got := run(id); got.Result != want || got.ReasonCode == "" {
			t.Errorf("%q: %+v, want %s with a reason", id, got, want)
		}
	}
	if got := run("nothing"); got.ReasonCode != "UNSUPPORTED_REQUIREMENT" || got.SourceID != "" {
		t.Errorf("unknown id: %+v", got)
	}
	if got := run("failing-v1"); got.ReasonCode != "APPROVAL_REJECTED" || got.SourceRef != "a-1" {
		t.Errorf("failing check: %+v", got)
	}
	if got := run("future-v1"); got.Result != adapter.VerdictUnknown || got.ReasonCode != "DEPENDENCY_UNAVAILABLE" {
		t.Errorf("a check observed in the future must not pass: %+v", got)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := a.CheckContext(ctx, "approval-v1", adapter.CheckInput{}); got.Result != adapter.VerdictUnknown {
		t.Errorf("cancelled context: %+v", got)
	}
}

// TestCheckContextScope: a check whose record names a principal or an agent
// applies only in a call from that principal and that agent's binding; an
// installed check that no record applies to is FAIL with
// APPROVAL_SCOPE_MISMATCH, never PASS (draft 17.1, 17.3.1).
func TestCheckContextScope(t *testing.T) {
	const (
		alice  = "https://idp.example/alice"
		bob    = "https://idp.example/bob"
		agentA = "https://agents.example/a"
		agentB = "https://agents.example/b"
	)
	pass := memory.CheckRecord{ID: "scoped-v1", Principal: alice, AgentID: agentA, Result: "PASS", ReasonCode: "REQUIREMENT_SATISFIED", SourceID: "approvals", SourceRef: "appr-1"}
	a, _ := newAdapter(t, func(st *memory.State) {
		st.Checks = append(st.Checks,
			pass,
			memory.CheckRecord{ID: "principal-only-v1", Principal: alice, Result: "PASS", ReasonCode: "REQUIREMENT_SATISFIED", SourceID: "approvals"},
			memory.CheckRecord{ID: "agent-only-v1", AgentID: agentA, Result: "PASS", ReasonCode: "REQUIREMENT_SATISFIED", SourceID: "approvals"},
			memory.CheckRecord{ID: "two-v1", Principal: bob, Result: "FAIL", ReasonCode: "APPROVAL_REJECTED", SourceID: "approvals"},
			memory.CheckRecord{ID: "two-v1", Principal: alice, Result: "PASS", ReasonCode: "REQUIREMENT_SATISFIED", SourceID: "approvals"})
	})
	in := func(principal, agent string) adapter.CheckInput {
		return adapter.CheckInput{Principal: adapter.Principal{ID: principal}, Binding: adapter.AgentBinding{AgentID: agent, Status: adapter.BindingActive}}
	}
	for _, tc := range []struct {
		name, id string
		in       adapter.CheckInput
		want     adapter.Verdict
		code     string
	}{
		{"both match", "scoped-v1", in(alice, agentA), adapter.VerdictPass, "REQUIREMENT_SATISFIED"},
		{"other agent", "scoped-v1", in(alice, agentB), adapter.VerdictFail, memory.CodeApprovalScopeMismatch},
		{"other principal", "scoped-v1", in(bob, agentA), adapter.VerdictFail, memory.CodeApprovalScopeMismatch},
		{"no binding", "scoped-v1", in(alice, ""), adapter.VerdictFail, memory.CodeApprovalScopeMismatch},
		{"no input at all", "scoped-v1", adapter.CheckInput{}, adapter.VerdictFail, memory.CodeApprovalScopeMismatch},
		{"principal only, match", "principal-only-v1", in(alice, ""), adapter.VerdictPass, "REQUIREMENT_SATISFIED"},
		{"principal only, other", "principal-only-v1", in(bob, agentA), adapter.VerdictFail, memory.CodeApprovalScopeMismatch},
		{"agent only, match", "agent-only-v1", in("", agentA), adapter.VerdictPass, "REQUIREMENT_SATISFIED"},
		{"agent only, none", "agent-only-v1", in(alice, ""), adapter.VerdictFail, memory.CodeApprovalScopeMismatch},
		{"the record that applies is used", "two-v1", in(alice, ""), adapter.VerdictPass, "REQUIREMENT_SATISFIED"},
		{"the other record that applies is used", "two-v1", in(bob, ""), adapter.VerdictFail, "APPROVAL_REJECTED"},
		{"no record applies to a third principal", "two-v1", in("https://idp.example/carol", ""), adapter.VerdictFail, memory.CodeApprovalScopeMismatch},
		{"not installed stays unknown", "absent-v1", in(alice, agentA), adapter.VerdictUnknown, "UNSUPPORTED_REQUIREMENT"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := a.CheckContext(context.Background(), tc.id, tc.in)
			if got.Result != tc.want || got.ReasonCode != tc.code {
				t.Errorf("%s %s, want %s %s", got.Result, got.ReasonCode, tc.want, tc.code)
			}
		})
	}
	t.Run("a mismatch names no record of the approval", func(t *testing.T) {
		got := a.CheckContext(context.Background(), "scoped-v1", in(alice, agentB))
		if got.SourceRef != "" {
			t.Errorf("source ref %q: the record is for another agent", got.SourceRef)
		}
	})
}

func TestAuthorizeNative(t *testing.T) {
	realm := memory.Realm{TenantID: "acme", EnvironmentID: env}
	const res = "https://invoices.example/invoices/1"
	rule := func(principal, action, resource, effect, reason string, obl ...memory.Obligation) memory.PolicyRule {
		return memory.PolicyRule{Realm: realm, Principal: principal, Action: action, Resource: resource, Effect: effect, Reason: reason, Obligations: obl}
	}
	a, _ := newAdapter(t, func(st *memory.State) {
		st.Policy = []memory.PolicyRule{
			rule("https://idp.example/alice", "invoice.read", res, "ALLOW", "r1", memory.Obligation{ID: "mask", Attributes: map[string]any{"f": "iban"}}),
			rule("https://idp.example/alice", "invoice.read", "", "ALLOW", "r2"),
			rule("https://idp.example/alice", "invoice.write", "", "ALLOW", "w1"),
			rule("https://idp.example/alice", "invoice.write", res, "DENY", "w2"),
			rule("https://idp.example/alice", "invoice.pay", "", "UNKNOWN", "p1"),
			rule("https://idp.example/alice", "invoice.pay", "", "ALLOW", "p2"),
			rule("https://idp.example/bob", "invoice.read", "", "DENY", "b1"),
		}
	})
	op := func(action string, resources ...string) core.OperationContext {
		return core.OperationContext{Action: action, Resources: resources}
	}
	decide := func(p adapter.Principal, o core.OperationContext) adapter.Decision {
		d, err := a.AuthorizeNative(context.Background(), p, o)
		if err != nil {
			t.Fatal(err)
		}
		return d
	}

	d := decide(alice(), op("invoice.read", res))
	if d.Effect != adapter.EffectAllow || d.Reason != "r1" || len(d.Obligations) != 1 || d.Obligations[0].ID != "mask" || d.Obligations[0].Attributes["f"] != "iban" {
		t.Errorf("read of the named resource: %+v", d)
	}
	if d := decide(alice(), op("invoice.read", "https://invoices.example/invoices/2")); d.Effect != adapter.EffectAllow || d.Reason != "r2" {
		t.Errorf("read of another resource: %+v", d)
	}
	if d := decide(alice(), op("invoice.write", res)); d.Effect != adapter.EffectDeny || d.Reason != "w2" {
		t.Errorf("a deny wins over an allow: %+v", d)
	}
	if d := decide(alice(), op("invoice.write", "https://invoices.example/invoices/2")); d.Effect != adapter.EffectAllow {
		t.Errorf("the deny names another resource: %+v", d)
	}
	if d := decide(alice(), op("invoice.pay")); d.Effect != adapter.EffectUnknown || d.Reason != "p1" {
		t.Errorf("an unknown wins over an allow: %+v", d)
	}
	for name, tc := range map[string]struct {
		p adapter.Principal
		o core.OperationContext
	}{
		"no rule for the action":    {alice(), op("invoice.delete", res)},
		"another principal":         {adapter.Principal{ID: "https://idp.example/carol", Realm: alice().Realm}, op("invoice.read", res)},
		"another realm":             {adapter.Principal{ID: alice().ID, Realm: adapter.Realm{TenantID: "globex", EnvironmentID: env}}, op("invoice.read", res)},
		"a denied principal":        {adapter.Principal{ID: "https://idp.example/bob", Realm: alice().Realm}, op("invoice.read", res)},
		"the empty principal":       {adapter.Principal{Realm: alice().Realm}, op("invoice.read", res)},
		"an operation with no data": {alice(), core.OperationContext{}},
	} {
		if d := decide(tc.p, tc.o); d.Permits() {
			t.Errorf("%s: %+v", name, d)
		}
	}
}

// TestAuthorizeNativeProvenance: a decision carries the source, the record,
// the time and the policy revision of the rule that decided, as the rule gives
// them, and names a source even when the rule names none or no rule applies.
// A decision time later than now plus the skew is not passed on.
func TestAuthorizeNativeProvenance(t *testing.T) {
	realm := memory.Realm{TenantID: "acme", EnvironmentID: env}
	decided, future, edge := t0.Unix()-2, t0.Unix()+3600, t0.Unix()+5
	a, clk := newAdapter(t, func(st *memory.State) {
		st.Policy = []memory.PolicyRule{
			{Realm: realm, Principal: "https://idp.example/alice", Action: "invoice.read", Effect: "ALLOW",
				SourceID: "pdp-1", SourceRef: "decision-8f0d", DecidedAt: &decided, PolicyRevision: "policy-2026-10-01"},
			{Realm: realm, Principal: "https://idp.example/alice", Action: "invoice.list", Effect: "DENY"},
			{Realm: realm, Principal: "https://idp.example/alice", Action: "invoice.pay", Effect: "ALLOW",
				SourceID: "pdp-1", DecidedAt: &future},
			{Realm: realm, Principal: "https://idp.example/alice", Action: "invoice.void", Effect: "DENY",
				SourceID: "pdp-1", DecidedAt: &future},
			{Realm: realm, Principal: "https://idp.example/alice", Action: "invoice.edge", Effect: "ALLOW",
				SourceID: "pdp-1", DecidedAt: &edge},
		}
	})
	decide := func(action string) (adapter.Decision, error) {
		return a.AuthorizeNative(context.Background(), alice(), core.OperationContext{Action: action})
	}

	d, err := decide("invoice.read")
	if err != nil {
		t.Fatal(err)
	}
	if d.Effect != adapter.EffectAllow || d.SourceID != "pdp-1" || d.SourceRef != "decision-8f0d" ||
		!d.DecidedAt.Equal(time.Unix(decided, 0)) || d.PolicyRevision != "policy-2026-10-01" {
		t.Errorf("decision = %+v, want the rule's provenance unchanged", d)
	}

	d, err = decide("invoice.list")
	if err != nil {
		t.Fatal(err)
	}
	if d.Effect != adapter.EffectDeny || d.SourceID != memory.PolicySourceID || d.SourceRef != "" || !d.DecidedAt.IsZero() || d.PolicyRevision != "" {
		t.Errorf("a rule without provenance: %+v, want the adapter's policy source and nothing else", d)
	}

	d, err = decide("invoice.delete")
	if err != nil {
		t.Fatal(err)
	}
	if d.Effect != adapter.EffectDeny || d.SourceID != memory.PolicySourceID || !d.DecidedAt.IsZero() {
		t.Errorf("no rule applies: %+v, want a deny from the adapter's policy source", d)
	}
	if memory.PolicySourceID == "" {
		t.Error("the adapter's policy source has no id")
	}

	for _, action := range []string{"invoice.pay", "invoice.void"} {
		if d, err := decide(action); !errors.Is(err, adapter.ErrDependencyUnavailable) {
			t.Errorf("%s decided an hour ahead: %+v, %v; want DEPENDENCY_UNAVAILABLE", action, d, err)
		}
	}
	if d, err := decide("invoice.edge"); err != nil || !d.DecidedAt.Equal(time.Unix(edge, 0)) {
		t.Errorf("decided at now plus the skew: %+v, %v", d, err)
	}
	clk.Advance(time.Hour)
	if d, err := decide("invoice.pay"); err != nil || !d.Permits() || !d.DecidedAt.Equal(time.Unix(future, 0)) {
		t.Errorf("after the clock passed the decision time: %+v, %v", d, err)
	}
}

func TestRecordOutcome(t *testing.T) {
	ctxt := core.ReputationContext{TenantID: "acme", EnvironmentID: env, AgentID: "https://identity.example/agents/a",
		PurposeID: "p", ActionClass: "a", ResourceClass: "r", RuntimeClass: "managed"}
	obs := func(kind core.EventKind) adapter.Observation {
		return adapter.Observation{
			EventID: "event-1", EventKind: kind, Context: ctxt, TaskID: "task-1", OperationID: "op-1",
			ObservedAt: t0.Add(-5 * time.Second), Result: core.OutcomeSuccess, Dimension: core.DimensionReliability,
			Severity: core.SeverityInfo, Attribution: core.Attribution{NativeTaskRef: "task-1", IndependenceGroup: "g", CausalAssessment: core.CausalUnknown},
		}
	}
	a, clk := newAdapter(t)
	rec := func(a *memory.Adapter, o adapter.Observation) (adapter.Recorded, error) {
		return a.RecordOutcome(context.Background(), o)
	}
	payload := func(r adapter.Recorded) core.OutcomeReport {
		t.Helper()
		s, ok := r.(adapter.Signed)
		if !ok {
			t.Fatalf("recorded %T, want Signed", r)
		}
		raw, err := base64.RawURLEncoding.DecodeString(strings.Split(s.JWS, ".")[1])
		if err != nil {
			t.Fatal(err)
		}
		var rep core.OutcomeReport
		if err := json.Unmarshal(raw, &rep); err != nil {
			t.Fatal(err)
		}
		return rep
	}

	t.Run("roles by kind", func(t *testing.T) {
		for kind, role := range map[core.EventKind]core.ReporterRole{
			core.EventAdmission: core.ReporterGateway, core.EventAuthorization: core.ReporterGateway, core.EventExecution: core.ReporterExecutor,
		} {
			r, err := rec(a, obs(kind))
			if err != nil {
				t.Fatalf("%s: %v", kind, err)
			}
			rep := payload(r)
			if rep.ReporterRole != role || rep.EventKind != kind {
				t.Errorf("%s: role %s", kind, rep.ReporterRole)
			}
			if err := a.VerifyOutcome(r.(adapter.Signed).JWS); err != nil {
				t.Errorf("%s: %v", kind, err)
			}
		}
	})

	t.Run("report fields", func(t *testing.T) {
		r, _ := rec(a, obs(core.EventExecution))
		rep := payload(r)
		if rep.IssuedAt != t0.Unix() || rep.NotBefore != t0.Unix() || rep.Expiry != t0.Unix()+300 || rep.ObservedAt != t0.Unix()-5 {
			t.Errorf("times: iat %d nbf %d exp %d observed %d", rep.IssuedAt, rep.NotBefore, rep.Expiry, rep.ObservedAt)
		}
		if rep.Issuer != "https://gateway.example/reporters/finance" || rep.Audience != "https://reputation.example/" || rep.Subject != ctxt.AgentID || rep.TenantID != "acme" {
			t.Errorf("claims: %+v", rep)
		}
		if rep.EvidenceRefs == nil || rep.Supersedes == nil || len(rep.JTI) != 22 {
			t.Errorf("evidence_refs %v supersedes %v jti %q", rep.EvidenceRefs, rep.Supersedes, rep.JTI)
		}
		clk.Advance(time.Hour)
		r2, _ := rec(a, obs(core.EventExecution))
		if payload(r2).IssuedAt != t0.Unix()+3600 {
			t.Error("iat does not follow the clock")
		}
		clk.Advance(-time.Hour)
	})

	t.Run("a retry carries the same jti", func(t *testing.T) {
		r1, _ := rec(a, obs(core.EventAdmission))
		r2, _ := rec(a, obs(core.EventAdmission))
		o := obs(core.EventAdmission)
		o.EventID = "event-2"
		r3, _ := rec(a, o)
		if payload(r1).JTI != payload(r2).JTI || payload(r1).JTI == payload(r3).JTI {
			t.Error("jti is not a function of the event id")
		}
	})

	t.Run("no execution visibility", func(t *testing.T) {
		blind, _ := newAdapter(t, func(st *memory.State) { st.Visibility = "none" })
		for _, vis := range []string{"none", ""} {
			a, _ := newAdapter(t, func(st *memory.State) { st.Visibility = vis })
			for _, result := range []core.OutcomeResult{core.OutcomeSuccess, core.OutcomeFailure, core.OutcomeUnknown} {
				o := obs(core.EventExecution)
				o.Result = result
				r, err := rec(a, o)
				nv, ok := r.(adapter.NoVisibility)
				if err != nil || !ok || nv.Validate() != nil {
					t.Errorf("visibility %q, result %s: %#v, %v", vis, result, r, err)
				}
			}
		}
		if r, err := rec(blind, obs(core.EventAdmission)); err != nil {
			t.Errorf("admission without execution visibility: %v", err)
		} else if _, ok := r.(adapter.Signed); !ok {
			t.Errorf("admission recorded as %T", r)
		}
	})

	t.Run("refusals", func(t *testing.T) {
		other := obs(core.EventAdmission)
		other.Context.TenantID = "globex"
		if _, err := rec(a, other); !errors.Is(err, adapter.ErrContextMismatch) {
			t.Errorf("another tenant: %v", err)
		}
		other.Context = ctxt
		other.Context.EnvironmentID = "other"
		if _, err := rec(a, other); !errors.Is(err, adapter.ErrContextMismatch) {
			t.Errorf("another environment: %v", err)
		}
		noID := obs(core.EventAdmission)
		noID.EventID = ""
		if _, err := rec(a, noID); err == nil {
			t.Error("an observation without an event id was recorded")
		}
		for _, kind := range []core.EventKind{core.EventQuality, core.EventSecurity, core.EventFeedback, core.EventCorrection, core.EventRemediation} {
			if _, err := rec(a, obs(kind)); !errors.Is(err, adapter.ErrUnsupportedRequirement) {
				t.Errorf("%s: err = %v, want UNSUPPORTED_REQUIREMENT", kind, err)
			}
		}
		unsigned, _ := newAdapter(t, func(st *memory.State) { st.Reporting = nil })
		if _, err := rec(unsigned, obs(core.EventAdmission)); !errors.Is(err, adapter.ErrUnsupportedRequirement) {
			t.Errorf("no reporting key: %v", err)
		}
		if err := unsigned.VerifyOutcome("a.b.c"); err == nil {
			t.Error("VerifyOutcome with no key did not fail")
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := a.RecordOutcome(ctx, obs(core.EventAdmission)); !errors.Is(err, adapter.ErrDependencyUnavailable) {
			t.Errorf("cancelled: %v", err)
		}
	})

	t.Run("credentials are removed", func(t *testing.T) {
		o := obs(core.EventExecution)
		o.Details = "rejected: Authorization: Bearer tok-alice-secret-1 and tok-bob-secret-2 inline\n" +
			"Cookie: session=abcdef123456; other=1\nset-cookie: sid=zzzzzzzz\nCookie: sc=cookievalue9999; plain=1\n" +
			"pact-presentation: eyJhbGciOiJFUzI1NiJ9.eyJhIjoxfQ.c2ln\nbasic dXNlcjpwYXNzd29yZA==\n" +
			"token eyJhbGciOiJFUzI1NiJ9.eyJhIjoxfQ.c2ln and password=hunter22 api_key=abcdef12"
		o.EvidenceRefs = []string{"native-record:1", "https://e.example/x?access_token=abc123456&keep=1", "tok-alice-secret-1"}
		r, err := rec(a, o)
		if err != nil {
			t.Fatal(err)
		}
		rep := payload(r)
		text := rep.Details + "\n" + strings.Join(rep.EvidenceRefs, "\n")
		for _, secret := range []string{"tok-alice-secret-1", "tok-bob-secret-2", "abcdef123456", "zzzzzzzz", "cookievalue9999", "eyJhbGci", "dXNlcjpwYXNzd29yZA", "hunter22", "abcdef12", "abc123456"} {
			if strings.Contains(text, secret) {
				t.Errorf("%q survived in %q", secret, text)
			}
		}
		if rep.EvidenceRefs[0] != "native-record:1" || !strings.Contains(rep.EvidenceRefs[1], "keep=1") {
			t.Errorf("a reference without a credential was changed: %v", rep.EvidenceRefs)
		}
		if !strings.Contains(rep.Details, "rejected:") {
			t.Errorf("the free text was dropped: %q", rep.Details)
		}
	})

	t.Run("signature", func(t *testing.T) {
		r, _ := rec(a, obs(core.EventAdmission))
		jws := r.(adapter.Signed).JWS
		parts := strings.Split(jws, ".")
		tamper := func(i int) string {
			p := append([]string(nil), parts...)
			raw, _ := base64.RawURLEncoding.DecodeString(p[i])
			raw[len(raw)/2] ^= 1
			p[i] = base64.RawURLEncoding.EncodeToString(raw)
			return strings.Join(p, ".")
		}
		if err := a.VerifyOutcome(jws); err != nil {
			t.Errorf("a signed report does not verify: %v", err)
		}
		for _, bad := range []string{tamper(0), tamper(1), tamper(2), "a.b", "a.b.c", parts[0] + "." + parts[1] + ".", strings.Join(parts[:2], ".") + "." + base64.RawURLEncoding.EncodeToString(make([]byte, 64))} {
			if err := a.VerifyOutcome(bad); err == nil {
				t.Errorf("VerifyOutcome accepted %.40q", bad)
			}
		}
		other, _ := newAdapter(t)
		if err := other.VerifyOutcome(jws); err == nil {
			t.Error("a report verifies under another adapter's key")
		}
		var hdr map[string]string
		raw, _ := base64.RawURLEncoding.DecodeString(parts[0])
		if err := json.Unmarshal(raw, &hdr); err != nil || hdr["alg"] != "ES256" || hdr["typ"] != "pact-outcome+jwt" || hdr["kid"] != "k1" || len(hdr) != 3 {
			t.Errorf("header = %v, %v", hdr, err)
		}
		if sig, _ := base64.RawURLEncoding.DecodeString(parts[2]); len(sig) != 64 {
			t.Errorf("signature has %d bytes, want the 64 of an ES256 R||S", len(sig))
		}
	})
}

func TestDescribe(t *testing.T) {
	a, _ := newAdapter(t)
	d := a.Describe()
	if d.Protocol == "" || d.Version == "" || d.MappingRevision == "" {
		t.Errorf("descriptor = %+v", d)
	}
	var _ adapter.Adapter = a
}

// TestConcurrentUse: after New the adapter only reads its state, so calls from
// several goroutines are safe. Run with -race.
func TestConcurrentUse(t *testing.T) {
	a, _ := newAdapter(t)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 50 {
				r := memory.Arrive(get(t, "https://gateway.example/invoices/1"))
				r.Header.Set("Authorization", "Bearer tok-alice-secret-1")
				p, err := a.AuthenticateNative(context.Background(), r)
				if err != nil {
					t.Error(err)
					return
				}
				if _, err := a.MapOperation(context.Background(), r, p, "map-1"); err != nil {
					t.Error(err)
					return
				}
				_, _ = a.ReadNativeClaim(context.Background(), "/roles", adapter.ClaimContext{Principal: p})
				a.CheckContext(context.Background(), "approval-v1", adapter.CheckInput{})
			}
		}()
	}
	wg.Wait()
}

// TestResolveAgentBindingSharedWorkload: on a workload that two agents share,
// each agent ID resolves to that agent's own record, whatever the status of the
// other agent's record and the order of the records (identity mapping IM-16,
// IM-18): a record of another agent is never the answer.
func TestResolveAgentBindingSharedWorkload(t *testing.T) {
	realm := memory.Realm{TenantID: "acme", EnvironmentID: env}
	const (
		shared = "k8s:prod-eu-1:system:serviceaccount:payments:agent-runner"
		ka     = "xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M"
		kb     = "lHkry8t631MLf-lKvuVhoHKwGhJta35vQQ3PCjI0bVU"
		agentA = "https://identity.example/agents/a"
		agentB = "https://identity.example/agents/b"
	)
	rec := func(agent, jkt, status string) memory.Enrollment {
		return memory.Enrollment{Realm: realm, Workload: shared, AgentID: agent,
			OperatorID: "https://identity.example/operators/o", HolderJKT: jkt, Status: status, SourceID: "registry"}
	}
	// own is the answer for an agent whose single record has status.
	own := func(status, agent, jkt string) func(adapter.AgentBinding, error) bool {
		return func(b adapter.AgentBinding, err error) bool {
			switch status {
			case "ACTIVE":
				return err == nil && b.Status == adapter.BindingActive && b.AgentID == agent && b.HolderJKT == core.Digest(jkt)
			case "UNKNOWN":
				return err == nil && b.Status == adapter.BindingUnknown && b.AgentID == "" && b.HolderJKT == ""
			}
			// REVOKED and COMPROMISED: the status with the agent's own
			// record (identity mapping IM-11).
			return err == nil && string(b.Status) == status && b.AgentID == agent && b.HolderJKT == core.Digest(jkt)
		}
	}
	statuses := []string{"ACTIVE", "REVOKED", "COMPROMISED", "UNKNOWN"}
	for _, sa := range statuses {
		for _, sb := range statuses {
			for _, order := range []string{"a first", "b first"} {
				t.Run(sa+" and "+sb+", "+order, func(t *testing.T) {
					rows := []memory.Enrollment{rec(agentA, ka, sa), rec(agentB, kb, sb)}
					if order == "b first" {
						rows[0], rows[1] = rows[1], rows[0]
					}
					a, _ := newSharedAdapter(t, func(st *memory.State) { st.Enrollments = rows })
					for _, tc := range []struct {
						agent, jkt, status string
					}{{agentA, ka, sa}, {agentB, kb, sb}} {
						b, err := a.ResolveAgentBinding(context.Background(), adapter.Realm{TenantID: "acme", EnvironmentID: env}, shared, adapter.AgentID(tc.agent))
						if !own(tc.status, tc.agent, tc.jkt)(b, err) {
							t.Errorf("%s: got %+v, %v; want the answer of its own %s record", tc.agent, b, err, tc.status)
						}
					}
				})
			}
		}
	}
}

// TestResolveAgentBindingSeveralRecordsOfTheAgent: when the source holds more
// than one record of the named agent on the workload, the rule of IM-18
// applies among those records only. A record that is not REVOKED is in force,
// a COMPROMISED one included; a single record in force is the answer, several
// are UNKNOWN; with none in force a single revoked record is the answer and
// several are UNKNOWN. Records of another agent on the same workload never
// take part, and the order of the records never matters.
func TestResolveAgentBindingSeveralRecordsOfTheAgent(t *testing.T) {
	realm := memory.Realm{TenantID: "acme", EnvironmentID: env}
	const (
		shared = "k8s:prod-eu-1:system:serviceaccount:payments:agent-runner"
		k1     = "xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M"
		k2     = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
		kb     = "lHkry8t631MLf-lKvuVhoHKwGhJta35vQQ3PCjI0bVU"
		agentA = "https://identity.example/agents/a"
		agentB = "https://identity.example/agents/b"
	)
	rec := func(agent, jkt, status string) memory.Enrollment {
		return memory.Enrollment{Realm: realm, Workload: shared, AgentID: agent,
			OperatorID: "https://identity.example/operators/o", HolderJKT: jkt, Status: status, SourceID: "registry"}
	}
	type want struct {
		status adapter.BindingStatus
		jkt    core.Digest
		err    error
	}
	unknown := want{status: adapter.BindingUnknown}
	// The single record in force is COMPROMISED: it is the answer, as its
	// status with its own key (identity mapping IM-11, IM-18).
	notInForce := want{status: adapter.BindingCompromised, jkt: k1}
	for _, tc := range []struct {
		name   string
		s1, s2 string
		want   want
	}{
		{"both active", "ACTIVE", "ACTIVE", unknown},
		{"one revoked", "ACTIVE", "REVOKED", want{status: adapter.BindingActive, jkt: k1}},
		{"one compromised", "ACTIVE", "COMPROMISED", unknown},
		{"one unknown", "ACTIVE", "UNKNOWN", unknown},
		{"both revoked", "REVOKED", "REVOKED", unknown},
		{"compromised and revoked", "COMPROMISED", "REVOKED", notInForce},
		{"both compromised", "COMPROMISED", "COMPROMISED", unknown},
	} {
		for _, order := range []string{"first", "second"} {
			t.Run(tc.name+", "+order+" first", func(t *testing.T) {
				// Agent B's ACTIVE record on the same workload sits between
				// agent A's two records; it is never part of A's answer.
				rows := []memory.Enrollment{rec(agentA, k1, tc.s1), rec(agentB, kb, "ACTIVE"), rec(agentA, k2, tc.s2)}
				if order == "second" {
					rows[0], rows[2] = rows[2], rows[0]
				}
				a, _ := newSharedAdapter(t, func(st *memory.State) { st.Enrollments = rows })
				b, err := a.ResolveAgentBinding(context.Background(), adapter.Realm{TenantID: "acme", EnvironmentID: env}, shared, agentA)
				if tc.want.err != nil {
					if !errors.Is(err, tc.want.err) || b != (adapter.AgentBinding{}) {
						t.Errorf("got %+v, %v; want %v and no binding", b, err, tc.want.err)
					}
					return
				}
				wantAgent := ""
				if tc.want.status != adapter.BindingUnknown {
					wantAgent = agentA
				}
				if err != nil || b.Status != tc.want.status || b.AgentID != wantAgent || b.HolderJKT != tc.want.jkt {
					t.Errorf("got %+v, %v; want status %s, agent %q, key %q", b, err, tc.want.status, wantAgent, tc.want.jkt)
				}
				if b2, err := a.ResolveAgentBinding(context.Background(), adapter.Realm{TenantID: "acme", EnvironmentID: env}, shared, agentB); err != nil || b2.HolderJKT != kb {
					t.Errorf("agent B: got %+v, %v; want its own ACTIVE record", b2, err)
				}
			})
		}
	}
}

// TestResolveAgentBindingDedicatedWorkload: by default a workload serves one
// agent, and a workload with more than one enrollment in force is a
// configuration error: whichever agent ID the request names, the answer is no
// binding and UNSUPPORTED_REQUIREMENT (draft 17.1, identity mapping IM-19).
// Only records in force count, as IM-18 defines them: a REVOKED record does
// not, a COMPROMISED one does, and so does every other status. Records of
// another workload or of another realm never count. With WithSharedWorkloads
// the same records select by the agent ID instead.
func TestResolveAgentBindingDedicatedWorkload(t *testing.T) {
	realm := memory.Realm{TenantID: "acme", EnvironmentID: env}
	other := memory.Realm{TenantID: "globex", EnvironmentID: env}
	const (
		w  = "k8s:prod-eu-1:system:serviceaccount:payments:agent-runner"
		ka = "xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M"
		kb = "lHkry8t631MLf-lKvuVhoHKwGhJta35vQQ3PCjI0bVU"
		kd = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
		ag = "https://identity.example/agents/"
	)
	rec := func(r memory.Realm, workload, agent, jkt, status, source string) memory.Enrollment {
		return memory.Enrollment{Realm: r, Workload: workload, AgentID: ag + agent, OperatorID: "https://identity.example/operators/o",
			HolderJKT: jkt, Status: status, SourceID: source, SourceRef: "ref-" + agent}
	}
	ar := adapter.Realm{TenantID: "acme", EnvironmentID: env}
	// configError is the answer for every agent ID on a workload in error.
	configError := func(t *testing.T, a *memory.Adapter) {
		t.Helper()
		for _, agent := range []string{ag + "a", ag + "b", ag + "c", ""} {
			b, err := a.ResolveAgentBinding(context.Background(), ar, w, adapter.AgentID(agent))
			if !errors.Is(err, adapter.ErrUnsupportedRequirement) || b != (adapter.AgentBinding{}) {
				t.Errorf("%q: %+v, %v; want UNSUPPORTED_REQUIREMENT and no binding", agent, b, err)
			}
			if code, ok := adapter.CodeOf(err); !ok || code != adapter.CodeUnsupportedRequirement {
				t.Errorf("%q: code %q, want %s", agent, code, adapter.CodeUnsupportedRequirement)
			}
		}
	}
	// selects is the answer of IM-18 for each agent ID: its own record's
	// status, or UNKNOWN.
	selects := func(t *testing.T, a *memory.Adapter, want map[string]adapter.BindingStatus) {
		t.Helper()
		for agent, status := range want {
			b, err := a.ResolveAgentBinding(context.Background(), ar, w, adapter.AgentID(ag+agent))
			wantAgent := ag + agent
			if status == adapter.BindingUnknown {
				wantAgent = ""
			}
			if err != nil || b.Status != status || b.AgentID != wantAgent {
				t.Errorf("%s: %+v, %v; want status %s for agent %q", agent, b, err, status, wantAgent)
			}
		}
	}
	for _, tc := range []struct {
		name    string
		rows    []memory.Enrollment
		inError bool
		want    map[string]adapter.BindingStatus
	}{
		{"two active", []memory.Enrollment{rec(realm, w, "a", ka, "ACTIVE", "r"), rec(realm, w, "b", kb, "ACTIVE", "r")}, true, nil},
		{"compromised and active", []memory.Enrollment{rec(realm, w, "a", ka, "COMPROMISED", "r"), rec(realm, w, "b", kb, "ACTIVE", "r")}, true, nil},
		{"two compromised", []memory.Enrollment{rec(realm, w, "a", ka, "COMPROMISED", "r"), rec(realm, w, "b", kb, "COMPROMISED", "r")}, true, nil},
		{"unknown status and active", []memory.Enrollment{rec(realm, w, "a", ka, "UNKNOWN", "r"), rec(realm, w, "b", kb, "ACTIVE", "r")}, true, nil},
		{"two active and a revoked", []memory.Enrollment{rec(realm, w, "d", kd, "REVOKED", "r"), rec(realm, w, "a", ka, "ACTIVE", "r"), rec(realm, w, "b", kb, "ACTIVE", "r")}, true, nil},
		{"revoked and active", []memory.Enrollment{rec(realm, w, "a", ka, "REVOKED", "r"), rec(realm, w, "b", kb, "ACTIVE", "r")}, false,
			map[string]adapter.BindingStatus{"a": adapter.BindingRevoked, "b": adapter.BindingActive, "c": adapter.BindingUnknown}},
		{"revoked and compromised", []memory.Enrollment{rec(realm, w, "a", ka, "REVOKED", "r"), rec(realm, w, "b", kb, "COMPROMISED", "r")}, false,
			map[string]adapter.BindingStatus{"a": adapter.BindingRevoked, "b": adapter.BindingCompromised}},
		{"two revoked", []memory.Enrollment{rec(realm, w, "a", ka, "REVOKED", "r"), rec(realm, w, "b", kb, "REVOKED", "r")}, false,
			map[string]adapter.BindingStatus{"a": adapter.BindingRevoked, "b": adapter.BindingRevoked}},
		{"another realm", []memory.Enrollment{rec(realm, w, "a", ka, "ACTIVE", "r"), rec(other, w, "b", kb, "ACTIVE", "r")}, false,
			map[string]adapter.BindingStatus{"a": adapter.BindingActive, "b": adapter.BindingUnknown}},
		{"another workload", []memory.Enrollment{rec(realm, w, "a", ka, "ACTIVE", "r"), rec(realm, w+"-2", "b", kb, "ACTIVE", "r")}, false,
			map[string]adapter.BindingStatus{"a": adapter.BindingActive, "b": adapter.BindingUnknown}},
	} {
		for _, order := range []string{"as listed", "reversed"} {
			t.Run(tc.name+", "+order, func(t *testing.T) {
				rows := slices.Clone(tc.rows)
				if order == "reversed" {
					slices.Reverse(rows)
				}
				a, _ := newAdapter(t, func(st *memory.State) { st.Enrollments = rows })
				if tc.inError {
					configError(t, a)
					return
				}
				selects(t, a, tc.want)
			})
		}
	}

	t.Run("a record of the workload that cannot be read", func(t *testing.T) {
		a, _ := newAdapter(t, func(st *memory.State) {
			st.Enrollments = []memory.Enrollment{rec(realm, w, "a", ka, "ACTIVE", "r"), rec(realm, w, "b", kb, "REVOKED", "down")}
			st.UnavailableSources = []string{"down"}
		})
		b, err := a.ResolveAgentBinding(context.Background(), ar, w, ag+"a")
		if !errors.Is(err, adapter.ErrDependencyUnavailable) || b != (adapter.AgentBinding{}) {
			t.Errorf("%+v, %v; want DEPENDENCY_UNAVAILABLE: whether the workload is in error cannot be established", b, err)
		}
	})

	t.Run("shared workloads select by the agent ID", func(t *testing.T) {
		a, _ := newSharedAdapter(t, func(st *memory.State) {
			st.Enrollments = []memory.Enrollment{rec(realm, w, "a", ka, "ACTIVE", "r"), rec(realm, w, "b", kb, "COMPROMISED", "r")}
		})
		selects(t, a, map[string]adapter.BindingStatus{"a": adapter.BindingActive, "b": adapter.BindingCompromised, "c": adapter.BindingUnknown})
	})
}
