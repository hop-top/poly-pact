package basic_test

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/enroll"
	"hop.top/pact-go/adapters/basic"
	"hop.top/pact-go/core"
	"hop.top/pact-go/core/clock"
)

var (
	testRealm = adapter.Realm{TenantID: "northstar", EnvironmentID: "https://gateway.northstar.example/environments/invoices"}
	testNow   = time.Unix(1792080000, 0)
	testID    = basic.PrincipalID("legacy-accounts", "20417")
)

// stubRegistry answers every lookup with b and err.
type stubRegistry struct {
	b   adapter.AgentBinding
	err error
}

func (s stubRegistry) Lookup(context.Context, adapter.Realm, adapter.Workload, adapter.AgentID) (adapter.AgentBinding, error) {
	return s.b, s.err
}
func (stubRegistry) Rotate(context.Context, enroll.Actor, string, core.Digest) error { return nil }
func (stubRegistry) MarkCompromised(context.Context, enroll.Actor, string) error     { return nil }

// stubLookup answers every permission question with d and err.
type stubLookup struct {
	d   adapter.Decision
	err error
}

func (s stubLookup) Decide(context.Context, adapter.Principal, core.OperationContext) (adapter.Decision, error) {
	return s.d, s.err
}

// oneAccount is an account database holding the account 20417 with the
// password "Tq7!harbor-lantern-42".
func oneAccount(t *testing.T) *fixtureStore {
	t.Helper()
	h, err := basic.HashPassword("Tq7!harbor-lantern-42", []byte("0123456789abcdef"), 16, 32)
	if err != nil {
		t.Fatal(err)
	}
	return &fixtureStore{
		source:   "legacy-accounts",
		accounts: []basic.Account{{Principal: testID, Workload: adapter.Workload(testID), Realm: testRealm, Password: h, Roles: []string{"AP_READER", "AP_READER", "AP_EXPORT"}}},
		userIDs:  []string{"invoice-assistant-ops"},
	}
}

func newAdapter(t *testing.T, edit func(*basic.Config)) *basic.Adapter {
	t.Helper()
	cfg := basic.Config{
		Realm:       testRealm,
		Origin:      "https://invoices.northstar.example",
		Accounts:    oneAccount(t),
		Decoy:       basic.PasswordHash{Iterations: 16, Salt: []byte("decoy"), Key: make([]byte, 32)},
		RoleMap:     map[string]string{"AP_READER": "invoice-reader"},
		Registry:    stubRegistry{b: adapter.AgentBinding{Status: adapter.BindingUnknown}},
		Permissions: stubLookup{d: adapter.Decision{Effect: adapter.EffectAllow, SourceID: "legacy-permissions"}},
		Clock:       clock.NewFake(testNow),
	}
	if edit != nil {
		edit(&cfg)
	}
	a, err := basic.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func codeIs(err error, want adapter.Code) bool {
	got, ok := adapter.CodeOf(err)
	return ok && got == want
}

// The PBKDF2-HMAC-SHA-256 key of "password" with the salt "salt", one
// iteration and 32 octets, computed independently with Python's
// hashlib.pbkdf2_hmac.
func TestPasswordHashMatches(t *testing.T) {
	key, _ := base64.RawURLEncoding.DecodeString("Eg-2z_z4syxD5yJSVsT4N6hlSMkszDVICAWYfLcL4Xs")
	h := basic.PasswordHash{Iterations: 1, Salt: []byte("salt"), Key: key}
	if !h.Matches("password") {
		t.Error("the hash does not match its password")
	}
	for _, wrong := range []string{"", "Password", "password "} {
		if h.Matches(wrong) {
			t.Errorf("the hash matches %q", wrong)
		}
	}
	if (basic.PasswordHash{}).Matches("") {
		t.Error("an empty hash matches")
	}
}

func TestNewRefusesIncompleteConfig(t *testing.T) {
	cases := map[string]func(*basic.Config){
		"no clock":          func(c *basic.Config) { c.Clock = nil },
		"no realm":          func(c *basic.Config) { c.Realm = adapter.Realm{} },
		"no accounts":       func(c *basic.Config) { c.Accounts = nil },
		"no registry":       func(c *basic.Config) { c.Registry = nil },
		"no permissions":    func(c *basic.Config) { c.Permissions = nil },
		"no decoy":          func(c *basic.Config) { c.Decoy = basic.PasswordHash{} },
		"bad origin":        func(c *basic.Config) { c.Origin = "http://invoices.northstar.example" },
		"credential header": func(c *basic.Config) { c.HeaderAllowlist = []string{"authorization"} },
		"account path source": func(c *basic.Config) {
			c.Claims = map[string]basic.ClaimSource{basic.PathPrincipalRoles: commonClaims{}}
		},
		"check without implementation": func(c *basic.Config) {
			c.Checks = map[string]basic.InstalledCheck{"x-v1": {}}
		},
		"reporting without key": func(c *basic.Config) {
			c.Reporting = &basic.Reporting{Issuer: "i", Audience: "a", KID: "k"}
		},
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := basic.Config{
				Realm: testRealm, Origin: "https://invoices.northstar.example", Accounts: oneAccount(t),
				Decoy:    basic.PasswordHash{Iterations: 1, Salt: []byte("s"), Key: []byte("k")},
				Registry: stubRegistry{}, Permissions: stubLookup{}, Clock: clock.NewFake(testNow),
			}
			edit(&cfg)
			if _, err := basic.New(cfg); err == nil {
				t.Error("New accepted the configuration")
			}
		})
	}
}

func TestDescribe(t *testing.T) {
	d := newAdapter(t, nil).Describe()
	if d.Protocol != "http-basic" || d.Version != "rfc7617" || d.MappingRevision != "pact-basic-1" {
		t.Errorf("Describe() = %+v, want http-basic, rfc7617, pact-basic-1 (profile section 1)", d)
	}
}

func request(header string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "https://invoices.northstar.example/invoices/INV-1041", nil)
	if header != "" {
		r.Header.Set("Authorization", header)
	}
	return r
}

func TestAuthenticateNative(t *testing.T) {
	a := newAdapter(t, nil)
	good := basicCredential("invoice-assistant-ops", "Tq7!harbor-lantern-42")
	p, err := a.AuthenticateNative(context.Background(), basic.Mark(request(good)))
	if err != nil || p.ID != testID || p.Workload != adapter.Workload(testID) || p.Mechanism != basic.Mechanism || !p.AuthenticatedAt.Equal(testNow) {
		t.Fatalf("valid credentials: %+v, %v", p, err)
	}
	// Two Authorization headers are ambiguous: neither is read.
	two := basic.Mark(request(good))
	two.Header.Add("Authorization", good)
	if _, err := a.AuthenticateNative(context.Background(), two); !errors.Is(err, adapter.ErrInvalidProof) {
		t.Errorf("two Authorization headers: %v, want a native denial", err)
	}
	// The scheme name is case-insensitive.
	lower := "basic " + strings.TrimPrefix(good, "Basic ")
	if _, err := a.AuthenticateNative(context.Background(), basic.Mark(request(lower))); err != nil {
		t.Errorf("lowercase scheme: %v", err)
	}
	// A database that cannot answer is a dependency failure, not a denial.
	down := newAdapter(t, func(c *basic.Config) { s := oneAccount(t); s.down = true; c.Accounts = s })
	if _, err := down.AuthenticateNative(context.Background(), basic.Mark(request(good))); !codeIs(err, adapter.CodeDependencyUnavailable) {
		t.Errorf("database down: %v, want DEPENDENCY_UNAVAILABLE", err)
	}
	// A cancelled context is not an answer.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := a.AuthenticateNative(ctx, basic.Mark(request(good))); !codeIs(err, adapter.CodeDependencyUnavailable) {
		t.Errorf("cancelled: %v, want DEPENDENCY_UNAVAILABLE", err)
	}
}

func TestEnforceMarksRequests(t *testing.T) {
	var marked bool
	h := basic.Enforce(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { marked = basic.Marked(r) }))
	h.ServeHTTP(httptest.NewRecorder(), request(""))
	if !marked {
		t.Error("Enforce did not mark the request")
	}
	r := request("")
	r.Header.Set("X-Gateway-Authenticated", "true")
	if basic.Marked(r) {
		t.Error("a request is marked without passing the filter")
	}
}

// TestPipelineNeedsPresentation is BASIC-04: in the enforced request path of
// profile section 3, built from the adapter's functions, a request with valid
// Basic credentials and no presentation does not reach the backend; the same
// request with a presentation the validator accepts does. The adapter's
// functions never run the backend themselves.
func TestPipelineNeedsPresentation(t *testing.T) {
	a := newAdapter(t, nil)
	reached := 0
	backend := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached++ })
	validate := func(presentation string) error {
		if presentation == "" {
			return adapter.ErrInvalidProof
		}
		return nil
	}
	gateway := basic.Enforce(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, err := a.AuthenticateNative(r.Context(), r)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		op, err := a.MapOperation(r.Context(), r, p, basic.MappingRevision)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if err := validate(r.Header.Get("PACT-Presentation")); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		d, err := a.AuthorizeNative(r.Context(), p, op)
		if err != nil || !d.Permits() {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		backend.ServeHTTP(w, r)
	}))
	good := basicCredential("invoice-assistant-ops", "Tq7!harbor-lantern-42")

	rec := httptest.NewRecorder()
	gateway.ServeHTTP(rec, request(good))
	if reached != 0 || rec.Code != http.StatusUnauthorized {
		t.Fatalf("no presentation: status %d, backend reached %d times; want 401 and none", rec.Code, reached)
	}
	r := request(good)
	r.Header.Set("PACT-Presentation", "presentation")
	gateway.ServeHTTP(httptest.NewRecorder(), r)
	if reached != 1 {
		t.Fatalf("with a presentation the validator accepts: backend reached %d times, want 1", reached)
	}
}

func TestReadNativeClaimRoles(t *testing.T) {
	a := newAdapter(t, nil)
	c, err := a.ReadNativeClaim(context.Background(), basic.PathPrincipalRoles, adapter.ClaimContext{Principal: adapter.Principal{ID: testID, Realm: testRealm}})
	if err != nil {
		t.Fatal(err)
	}
	roles, _ := c.Value.([]any)
	if len(roles) != 1 || roles[0] != "invoice-reader" {
		t.Errorf("roles = %v, want [invoice-reader]: translated, unmapped dropped, no duplicates", c.Value)
	}
	if !c.ObservedAt.IsZero() || c.SourceID != "legacy-accounts" || c.SourceRef != "" {
		t.Errorf("claim provenance %+v: a database that gives no time gives the zero time, and no source reference", c)
	}
	other := adapter.Realm{TenantID: "globex", EnvironmentID: testRealm.EnvironmentID}
	if _, err := a.ReadNativeClaim(context.Background(), basic.PathPrincipalRoles, adapter.ClaimContext{Principal: adapter.Principal{ID: testID, Realm: other}}); !errors.Is(err, basic.ErrNoAccount) {
		t.Errorf("same principal ID in another realm: %v, want no account", err)
	}
	ahead := newAdapter(t, func(c *basic.Config) {
		s := oneAccount(t)
		s.accounts[0].AnsweredAt = testNow.Add(6 * time.Second)
		c.Accounts = s
	})
	if _, err := ahead.ReadNativeClaim(context.Background(), basic.PathPrincipalID, adapter.ClaimContext{Principal: adapter.Principal{ID: testID, Realm: testRealm}}); !codeIs(err, adapter.CodeDependencyUnavailable) {
		t.Errorf("answer time after now plus the skew: %v, want DEPENDENCY_UNAVAILABLE", err)
	}
}

func TestPurposeOperation(t *testing.T) {
	check := basic.PurposeOperation("gateway-purposes", map[string][]string{"invoice-lookup": {"invoice.read"}}, clock.NewFake(testNow))
	a := newAdapter(t, func(c *basic.Config) {
		c.Checks = map[string]basic.InstalledCheck{basic.CheckIDPurposeOperation: {Check: check}}
	})
	run := func(purposeID, action string) adapter.CheckOutcome {
		return a.CheckContext(context.Background(), basic.CheckIDPurposeOperation, adapter.CheckInput{Intent: core.Intent{PurposeID: purposeID}, Operation: core.OperationContext{Action: action}})
	}
	cases := []struct {
		purpose, action string
		want            adapter.Verdict
		code            string
	}{
		{"invoice-lookup", "invoice.read", adapter.VerdictPass, "REQUIREMENT_SATISFIED"},
		{"invoice-lookup", "invoice.approve", adapter.VerdictFail, "CONTEXT_MISMATCH"},
		{"invoice-approval", "invoice.read", adapter.VerdictFail, "UNSUPPORTED_PURPOSE"},
		{"", "invoice.read", adapter.VerdictFail, "UNSUPPORTED_PURPOSE"},
	}
	for _, c := range cases {
		out := run(c.purpose, c.action)
		if out.Result != c.want || out.ReasonCode != c.code || out.SourceID != "gateway-purposes" {
			t.Errorf("purpose %q, action %q: %+v, want %s %s", c.purpose, c.action, out, c.want, c.code)
		}
	}
	if out := a.CheckContext(context.Background(), "Purpose-Operation-V1", adapter.CheckInput{Intent: core.Intent{PurposeID: "invoice-lookup"}, Operation: core.OperationContext{Action: "invoice.read"}}); out.Result != adapter.VerdictUnknown || out.ReasonCode != "UNSUPPORTED_REQUIREMENT" {
		t.Errorf("check id in another case: %+v, want UNKNOWN UNSUPPORTED_REQUIREMENT", out)
	}
}

func TestAuthorizeNativeRefusesUnusableDecisions(t *testing.T) {
	p := adapter.Principal{ID: testID, Realm: testRealm}
	cases := map[string]adapter.Decision{
		"no source":     {Effect: adapter.EffectAllow},
		"no effect":     {SourceID: "legacy-permissions"},
		"decided ahead": {Effect: adapter.EffectAllow, SourceID: "legacy-permissions", DecidedAt: testNow.Add(6 * time.Second)},
	}
	for name, d := range cases {
		a := newAdapter(t, func(c *basic.Config) { c.Permissions = stubLookup{d: d} })
		if got, err := a.AuthorizeNative(context.Background(), p, core.OperationContext{}); !codeIs(err, adapter.CodeDependencyUnavailable) || got.Permits() {
			t.Errorf("%s: %+v, %v; want DEPENDENCY_UNAVAILABLE and no decision", name, got, err)
		}
	}
	atSkew := adapter.Decision{Effect: adapter.EffectAllow, SourceID: "legacy-permissions", DecidedAt: testNow.Add(5 * time.Second), PolicyRevision: "rev-7"}
	a := newAdapter(t, func(c *basic.Config) { c.Permissions = stubLookup{d: atSkew} })
	if got, err := a.AuthorizeNative(context.Background(), p, core.OperationContext{}); err != nil || got.PolicyRevision != "rev-7" || !got.DecidedAt.Equal(atSkew.DecidedAt) {
		t.Errorf("decision at now plus the skew: %+v, %v; want it unchanged", got, err)
	}
	down := newAdapter(t, func(c *basic.Config) { c.Permissions = stubLookup{err: errors.New("lookup timed out")} })
	if _, err := down.AuthorizeNative(context.Background(), p, core.OperationContext{}); !codeIs(err, adapter.CodeDependencyUnavailable) {
		t.Errorf("lookup down: %v, want DEPENDENCY_UNAVAILABLE", err)
	}
}

func TestResolveAgentBindingGuards(t *testing.T) {
	agent := adapter.AgentID("https://agents.northstar.example/invoice-assistant")
	active := adapter.AgentBinding{AgentID: string(agent), OperatorID: "op", HolderJKT: "xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M", Status: adapter.BindingActive, SourceID: "enrollment-registry"}
	ahead := active
	ahead.StatusCheckedAt = testNow.Add(6 * time.Second)
	bad := active
	bad.Status = "SUSPENDED"
	for name, b := range map[string]adapter.AgentBinding{"status checked ahead": ahead, "undefined status": bad} {
		a := newAdapter(t, func(c *basic.Config) { c.Registry = stubRegistry{b: b} })
		if got, err := a.ResolveAgentBinding(context.Background(), testRealm, adapter.Workload(testID), agent); !codeIs(err, adapter.CodeDependencyUnavailable) || got.Status != "" {
			t.Errorf("%s: %+v, %v; want DEPENDENCY_UNAVAILABLE and no binding", name, got, err)
		}
	}
	elsewhere := active
	elsewhere.EnrolledElsewhere = true
	a := newAdapter(t, func(c *basic.Config) { c.Registry = stubRegistry{b: elsewhere} })
	if got, err := a.ResolveAgentBinding(context.Background(), testRealm, adapter.Workload(testID), agent); err != nil || got.EnrolledElsewhere {
		t.Errorf("active binding: %+v, %v; EnrolledElsewhere belongs to UNKNOWN only", got, err)
	}
	cfgErr := newAdapter(t, func(c *basic.Config) { c.Registry = stubRegistry{err: adapter.ErrUnsupportedRequirement} })
	if _, err := cfgErr.ResolveAgentBinding(context.Background(), testRealm, adapter.Workload(testID), agent); !codeIs(err, adapter.CodeUnsupportedRequirement) {
		t.Errorf("registry configuration error: %v, want UNSUPPORTED_REQUIREMENT kept", err)
	}
}

func TestRecordOutcomeVisibility(t *testing.T) {
	key, err := signingKey()
	if err != nil {
		t.Fatal(err)
	}
	a := newAdapter(t, func(c *basic.Config) {
		c.Reporting = &basic.Reporting{Issuer: "https://invoices.northstar.example/reporters/gateway", Audience: "https://reputation.northstar.example", KID: "k1", Key: key}
	})
	obs := adapter.Observation{
		EventID: "e1", ObservedAt: testNow,
		Context: core.ReputationContext{TenantID: testRealm.TenantID, EnvironmentID: testRealm.EnvironmentID, AgentID: "https://agents.northstar.example/invoice-assistant"},
	}
	obs.EventKind, obs.Result = core.EventExecution, core.OutcomeSuccess
	rec, err := a.RecordOutcome(context.Background(), obs)
	if _, ok := rec.(adapter.NoVisibility); err != nil || !ok {
		t.Errorf("execution: %T %v, want NoVisibility: the backend reports execution", rec, err)
	}
	obs.EventKind = core.EventQuality
	if _, err := a.RecordOutcome(context.Background(), obs); !codeIs(err, adapter.CodeUnsupportedRequirement) {
		t.Errorf("quality event: %v, want UNSUPPORTED_REQUIREMENT", err)
	}
	obs.EventKind, obs.Context.TenantID = core.EventAuthorization, "globex"
	if _, err := a.RecordOutcome(context.Background(), obs); !codeIs(err, adapter.CodeContextMismatch) {
		t.Errorf("another realm: %v, want CONTEXT_MISMATCH", err)
	}
}
