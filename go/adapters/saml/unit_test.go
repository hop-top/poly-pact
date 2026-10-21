package saml_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/enroll"
	enrollmem "hop.top/pact-go/adapter/enroll/memory"
	"hop.top/pact-go/adapters/saml"
	"hop.top/pact-go/core"
	"hop.top/pact-go/core/clock"
)

// The values of the unit tests, those of the saml cases (see the cases
// README): the principal is SB-4 with IM-2 escaping, computed by hand.
const (
	uOrigin    = "https://portal.northstar.example"
	uMaya      = "saml:https%3A%2F%2Fportal.northstar.example%2Fsaml%2Fmetadata:https%3A%2F%2Fidp.northstar.example%2Fsaml:8f3e1c5a2b"
	uLena      = "saml:https%3A%2F%2Fportal.northstar.example%2Fsaml%2Fmetadata:https%3A%2F%2Fidp.northstar.example%2Fsaml:c41d9e07aa"
	uIDP       = "https://idp.northstar.example/saml"
	uAgent     = "https://agents.northstar.example/purchasing-assistant"
	uWorkload  = "x-broker:portal-broker:client-assistant"
	uToken     = "brk-assistant-7Qm2xV9pL4tR8sW1"
	uTask      = "task-5b21c0"
	uSessionID = "sps-maya-1"
	uJKT       = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
	uReviewer  = "https://agents.northstar.example/contract-reviewer"
	uRevWork   = "x-broker:portal-broker:client-reviewer"
	uRevToken  = "brk-reviewer-3Hk8nB5cZ2yD6fJ0"
)

var uAdmin = enroll.Actor{Kind: enroll.Admin, ID: "iam-admin", Realm: uRealm}

var uRealm = adapter.Realm{TenantID: "northstar", EnvironmentID: "https://portal.northstar.example/environments/purchasing"}

// rig is an adapter over in-memory stores with one live session of Maya, one
// live grant of task-5b21c0 for the assistant, and the assistant enrolled on
// its broker workload, at a fixed now.
type rig struct {
	now      time.Time
	clk      *clock.Fake
	sessions *saml.Sessions
	grants   *saml.Grants
	reg      *enrollmem.Registry
	cfg      saml.Config
}

func newRig(t *testing.T) *rig {
	t.Helper()
	now := time.Unix(1792080000, 0)
	r := &rig{now: now, clk: clock.NewFake(now), sessions: saml.NewSessions(sessionSource), grants: saml.NewGrants(grantSource)}
	if err := r.sessions.Put(saml.SPSession{SessionID: uSessionID, Principal: uMaya, IDPRealm: uIDP,
		AuthnInstant: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := r.grants.Put(saml.TaskGrant{TaskID: uTask, SessionID: uSessionID, User: uMaya, AgentID: uAgent,
		ExpiresAt: now.Add(30 * time.Minute)}); err != nil {
		t.Fatal(err)
	}
	r.reg = enrollmem.New(enrollmem.WithClock(r.clk))
	if err := r.reg.Enroll(context.Background(), uAdmin, enrollmem.Enrollment{AgentID: uAgent,
		OperatorID: "https://operators.northstar.example/procurement", Workload: uWorkload, HolderJKT: uJKT}); err != nil {
		t.Fatal(err)
	}
	r.cfg = saml.Config{
		Realm: uRealm, Origin: uOrigin,
		Agents:      tokenAgents{{Ref: "assistant", Token: uToken, Workload: uWorkload}, {Ref: "reviewer", Token: uRevToken, Workload: uRevWork}},
		Sessions:    r.sessions,
		Grants:      r.grants,
		Registry:    r.reg,
		Permissions: commonPolicy{},
		Clock:       r.clk,
	}
	return r
}

func (r *rig) adapter(t *testing.T) *saml.Adapter {
	t.Helper()
	a, err := saml.New(r.cfg)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func r1Request(t *testing.T, path string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, uOrigin+path, nil)
	req.Header.Set("Authorization", "Bearer "+uToken)
	return saml.Mark(req)
}

func r1Operation(task, principal string) core.OperationContext {
	return core.OperationContext{
		OperationID: "op-1", EnvironmentID: uRealm.EnvironmentID, PrincipalID: principal,
		Action: "record.read", Resources: []string{"record:SUP-1042"}, Method: http.MethodGet,
		TargetURI:  uOrigin + "/broker/v1/tasks/" + task + "/records/SUP-1042",
		BodyDigest: "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU", Headers: map[string]string{},
	}
}

func codeOf(err error) adapter.Code {
	c, _ := adapter.CodeOf(err)
	return c
}

func TestStoresRefuseIncompleteAndChangedRecords(t *testing.T) {
	r := newRig(t)
	if err := r.sessions.Put(saml.SPSession{SessionID: uSessionID, Principal: uLena, IDPRealm: uIDP, ExpiresAt: r.now.Add(time.Hour)}); err == nil {
		t.Error("a second session with the same id is accepted")
	}
	if err := r.sessions.Put(saml.SPSession{SessionID: "s2", Principal: uLena, IDPRealm: uIDP}); err == nil {
		t.Error("a session without an end is accepted")
	}
	if err := r.grants.Put(saml.TaskGrant{TaskID: uTask, SessionID: uSessionID, User: uMaya, AgentID: uAgent, ExpiresAt: r.now.Add(time.Hour)}); err == nil {
		t.Error("a second grant for the task, with a later end, is accepted (SB-9)")
	}
	if err := r.grants.Put(saml.TaskGrant{TaskID: "t2", SessionID: uSessionID, User: uMaya, ExpiresAt: r.now.Add(time.Hour)}); err == nil {
		t.Error("a grant without an agent is accepted")
	}
	if err := r.sessions.Logout("nope"); !errors.Is(err, saml.ErrNoSession) {
		t.Errorf("Logout of an unknown session = %v", err)
	}
	if err := r.grants.Revoke("nope"); !errors.Is(err, saml.ErrNoGrant) {
		t.Errorf("Revoke of an unknown grant = %v", err)
	}
	ctx := context.Background()
	if err := r.sessions.Logout(uSessionID); err != nil {
		t.Fatal(err)
	}
	if s, _ := r.sessions.Session(ctx, uSessionID); !s.LoggedOut || s.Live(r.now) {
		t.Errorf("session after logout: %+v", s)
	}
	if err := r.grants.Revoke(uTask); err != nil {
		t.Fatal(err)
	}
	if g, _ := r.grants.Grant(ctx, uTask); !g.Revoked {
		t.Errorf("grant after revocation: %+v", g)
	}
}

func TestSessionLiveness(t *testing.T) {
	now := time.Unix(1792080000, 0)
	cases := []struct {
		s    saml.SPSession
		live bool
	}{
		{saml.SPSession{ExpiresAt: now.Add(time.Second)}, true},
		{saml.SPSession{ExpiresAt: now}, false},
		{saml.SPSession{ExpiresAt: now.Add(-time.Second)}, false},
		{saml.SPSession{ExpiresAt: now.Add(time.Hour), LoggedOut: true}, false},
		{saml.SPSession{}, false},
	}
	for i, c := range cases {
		if got := c.s.Live(now); got != c.live {
			t.Errorf("case %d: Live = %v, want %v", i, got, c.live)
		}
	}
}

func TestNewRefusesIncompleteConfiguration(t *testing.T) {
	r := newRig(t)
	for name, edit := range map[string]func(*saml.Config){
		"no clock":                  func(c *saml.Config) { c.Clock = nil },
		"no realm":                  func(c *saml.Config) { c.Realm = adapter.Realm{} },
		"no agents":                 func(c *saml.Config) { c.Agents = nil },
		"no sessions":               func(c *saml.Config) { c.Sessions = nil },
		"no grants":                 func(c *saml.Config) { c.Grants = nil },
		"no registry":               func(c *saml.Config) { c.Registry = nil },
		"no policy":                 func(c *saml.Config) { c.Permissions = nil },
		"paths without a directory": func(c *saml.Config) { c.DirectoryPaths = []string{"/attributes/environment/roles"} },
		"session path in directory": func(c *saml.Config) {
			c.Directory = directory{}
			c.DirectoryPaths = []string{saml.PathPrincipalID}
		},
		"delegation check in checks": func(c *saml.Config) {
			c.Checks = map[string]saml.InstalledCheck{saml.CheckNativeDelegation: {Check: commonCheck{}}}
		},
	} {
		cfg := r.cfg
		edit(&cfg)
		if _, err := saml.New(cfg); err == nil {
			t.Errorf("%s: New accepts the configuration", name)
		}
	}
}

func TestAuthenticateRefusals(t *testing.T) {
	ctx := context.Background()
	t.Run("session store down", func(t *testing.T) {
		r := newRig(t)
		r.cfg.Sessions = downSessions{SessionStore: r.sessions, down: true}
		_, err := r.adapter(t).AuthenticateNative(ctx, r1Request(t, "/broker/v1/tasks/"+uTask+"/records/SUP-1042"))
		if codeOf(err) != adapter.CodeDependencyUnavailable {
			t.Errorf("error %v, want DEPENDENCY_UNAVAILABLE", err)
		}
	})
	t.Run("grant store down", func(t *testing.T) {
		r := newRig(t)
		r.cfg.Grants = downGrants{TaskBroker: r.grants, down: true}
		_, err := r.adapter(t).AuthenticateNative(ctx, r1Request(t, "/broker/v1/tasks/"+uTask+"/records/SUP-1042"))
		if codeOf(err) != adapter.CodeDependencyUnavailable {
			t.Errorf("error %v, want DEPENDENCY_UNAVAILABLE", err)
		}
	})
	t.Run("agent workload in the saml namespace", func(t *testing.T) {
		r := newRig(t)
		r.cfg.Agents = tokenAgents{{Ref: "assistant", Token: uToken, Workload: uMaya}}
		_, err := r.adapter(t).AuthenticateNative(ctx, r1Request(t, "/broker/v1/tasks/"+uTask+"/records/SUP-1042"))
		if codeOf(err) != adapter.CodeDependencyUnavailable {
			t.Errorf("error %v, want DEPENDENCY_UNAVAILABLE", err)
		}
	})
	t.Run("session principal not a saml identifier", func(t *testing.T) {
		r := newRig(t)
		bad := saml.NewSessions(sessionSource)
		if err := bad.Put(saml.SPSession{SessionID: uSessionID, Principal: "maya@northstar.example", IDPRealm: uIDP, ExpiresAt: r.now.Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
		g := saml.NewGrants(grantSource)
		if err := g.Put(saml.TaskGrant{TaskID: uTask, SessionID: uSessionID, User: "maya@northstar.example", AgentID: uAgent, ExpiresAt: r.now.Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
		r.cfg.Sessions, r.cfg.Grants = bad, g
		_, err := r.adapter(t).AuthenticateNative(ctx, r1Request(t, "/broker/v1/tasks/"+uTask+"/records/SUP-1042"))
		if codeOf(err) != adapter.CodeDependencyUnavailable {
			t.Errorf("error %v, want DEPENDENCY_UNAVAILABLE", err)
		}
	})
	for _, path := range []string{
		"/broker/v1/tasks/task%2D5b21c0/records/SUP-1042",
		"/broker/v1/tasks//records/SUP-1042",
		"/broker/v1/tasks/" + uTask + "/records/SUP-1042/extra",
	} {
		t.Run("path "+path, func(t *testing.T) {
			r := newRig(t)
			_, err := r.adapter(t).AuthenticateNative(ctx, r1Request(t, path))
			var d *adapter.NativeDenial
			if !errors.As(err, &d) || d.PublicReason() != adapter.DenialCredentialRejected {
				t.Errorf("error %v, want CREDENTIAL_REJECTED", err)
			}
		})
	}
	t.Run("enforce marks", func(t *testing.T) {
		r := newRig(t)
		a := r.adapter(t)
		var got adapter.Principal
		var err error
		h := saml.Enforce(http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) { got, err = a.AuthenticateNative(ctx, req) }))
		req := httptest.NewRequest(http.MethodGet, uOrigin+"/broker/v1/tasks/"+uTask+"/records", nil)
		req.Header.Set("Authorization", "Bearer "+uToken)
		h.ServeHTTP(httptest.NewRecorder(), req)
		if err != nil || got.ID != uMaya || got.Workload != uWorkload || got.Realm != uRealm {
			t.Errorf("principal %+v, error %v", got, err)
		}
	})
}

func TestNativeDelegation(t *testing.T) {
	ctx := context.Background()
	intent := core.Intent{IntentID: "i1", PurposeID: "p", TaskID: uTask}
	// agent is the binding of the grant's agent, which the validator
	// established; withBinding runs the check for another one.
	agent := adapter.AgentBinding{AgentID: uAgent, Status: adapter.BindingActive}
	withBinding := func(t *testing.T, a *saml.Adapter, b adapter.AgentBinding, in core.Intent, op core.OperationContext, want adapter.Verdict, code string) {
		t.Helper()
		got := a.CheckContext(ctx, saml.CheckNativeDelegation, adapter.CheckInput{Binding: b, Intent: in, Operation: op})
		if got.Result != want || got.ReasonCode != code || got.SourceID != grantSource {
			t.Errorf("outcome %+v, want %s %s from %s", got, want, code, grantSource)
		}
	}
	check := func(t *testing.T, a *saml.Adapter, in core.Intent, op core.OperationContext, want adapter.Verdict, code string) {
		t.Helper()
		withBinding(t, a, agent, in, op, want, code)
	}
	t.Run("a usable grant is PASS", func(t *testing.T) {
		r := newRig(t)
		check(t, r.adapter(t), intent, r1Operation(uTask, uMaya), adapter.VerdictPass, saml.CodeRequirementSatisfied)
	})
	scoped := func(t *testing.T, scope saml.GrantScope) *rig {
		t.Helper()
		r := newRig(t)
		r.grants = saml.NewGrants(grantSource)
		if err := r.grants.Put(saml.TaskGrant{TaskID: uTask, SessionID: uSessionID, User: uMaya, AgentID: uAgent,
			Scope: &scope, ExpiresAt: r.now.Add(30 * time.Minute)}); err != nil {
			t.Fatal(err)
		}
		r.cfg.Grants = r.grants
		return r
	}
	within := saml.GrantScope{Purposes: []string{"p"}, Actions: []string{"record.list", "record.read"}, Resources: []string{"record:SUP-1042"}}
	t.Run("an operation within the scope", func(t *testing.T) {
		check(t, scoped(t, within).adapter(t), intent, r1Operation(uTask, uMaya), adapter.VerdictPass, saml.CodeRequirementSatisfied)
	})
	for name, scope := range map[string]saml.GrantScope{
		"another purpose":  {Purposes: []string{"q"}, Actions: within.Actions, Resources: within.Resources},
		"another action":   {Purposes: within.Purposes, Actions: []string{"record.list"}, Resources: within.Resources},
		"another resource": {Purposes: within.Purposes, Actions: within.Actions, Resources: []string{"record:SUP-1043"}},
		"an empty scope":   {},
		"a prefix only":    {Purposes: within.Purposes, Actions: []string{"record"}, Resources: []string{"record:SUP-104"}},
	} {
		t.Run("outside the scope: "+name, func(t *testing.T) {
			check(t, scoped(t, scope).adapter(t), intent, r1Operation(uTask, uMaya), adapter.VerdictFail, string(adapter.CodeContextMismatch))
		})
	}
	t.Run("task before principal before scope", func(t *testing.T) {
		r := scoped(t, saml.GrantScope{})
		check(t, r.adapter(t), core.Intent{TaskID: "task-other"}, r1Operation(uTask, uLena), adapter.VerdictFail, saml.CodeTaskMismatch)
	})
	// SB-11, condition 5: the grant's agent is the agent of the binding.
	t.Run("the binding of another agent", func(t *testing.T) {
		other := adapter.AgentBinding{AgentID: uReviewer, Status: adapter.BindingActive}
		withBinding(t, newRig(t).adapter(t), other, intent, r1Operation(uTask, uMaya), adapter.VerdictFail, string(adapter.CodeContextMismatch))
	})
	t.Run("no binding", func(t *testing.T) {
		withBinding(t, newRig(t).adapter(t), adapter.AgentBinding{}, intent, r1Operation(uTask, uMaya), adapter.VerdictFail, string(adapter.CodeContextMismatch))
	})
	t.Run("the binding of another agent after the task", func(t *testing.T) {
		other := adapter.AgentBinding{AgentID: uReviewer, Status: adapter.BindingActive}
		withBinding(t, newRig(t).adapter(t), other, core.Intent{TaskID: "task-other"}, r1Operation(uTask, uMaya), adapter.VerdictFail, saml.CodeTaskMismatch)
	})
	t.Run("the binding of another agent after revocation", func(t *testing.T) {
		r := newRig(t)
		if err := r.grants.Revoke(uTask); err != nil {
			t.Fatal(err)
		}
		other := adapter.AgentBinding{AgentID: uReviewer, Status: adapter.BindingActive}
		withBinding(t, r.adapter(t), other, intent, r1Operation(uTask, uMaya), adapter.VerdictFail, saml.CodeRevokedEvidence)
	})
	t.Run("a grant the user revoked", func(t *testing.T) {
		r := newRig(t)
		if err := r.grants.Revoke(uTask); err != nil {
			t.Fatal(err)
		}
		check(t, r.adapter(t), intent, r1Operation(uTask, uMaya), adapter.VerdictFail, saml.CodeRevokedEvidence)
	})
	t.Run("a grant whose session does not exist", func(t *testing.T) {
		r := newRig(t)
		r.cfg.Sessions = saml.NewSessions(sessionSource)
		check(t, r.adapter(t), intent, r1Operation(uTask, uMaya), adapter.VerdictFail, saml.CodeRevokedEvidence)
	})
	t.Run("a task with no grant", func(t *testing.T) {
		r := newRig(t)
		check(t, r.adapter(t), core.Intent{TaskID: "task-0"}, r1Operation("task-0", uMaya), adapter.VerdictFail, saml.CodeMissingField)
	})
	t.Run("an operation on no task route", func(t *testing.T) {
		r := newRig(t)
		op := r1Operation(uTask, uMaya)
		op.TargetURI = uOrigin + "/broker/v1/records/SUP-1042"
		check(t, r.adapter(t), intent, op, adapter.VerdictUnknown, string(adapter.CodeUnsupportedRequirement))
	})
	t.Run("an operation of another principal", func(t *testing.T) {
		r := newRig(t)
		check(t, r.adapter(t), intent, r1Operation(uTask, uLena), adapter.VerdictFail, string(adapter.CodeContextMismatch))
	})
	t.Run("a grant store that cannot answer", func(t *testing.T) {
		r := newRig(t)
		r.cfg.Grants = downGrants{TaskBroker: r.grants, down: true}
		check(t, r.adapter(t), intent, r1Operation(uTask, uMaya), adapter.VerdictUnknown, string(adapter.CodeDependencyUnavailable))
	})
	t.Run("a session store that cannot answer", func(t *testing.T) {
		r := newRig(t)
		r.cfg.Sessions = downSessions{SessionStore: r.sessions, down: true}
		check(t, r.adapter(t), intent, r1Operation(uTask, uMaya), adapter.VerdictUnknown, string(adapter.CodeDependencyUnavailable))
	})
	t.Run("revocation before expiry before task", func(t *testing.T) {
		r := newRig(t)
		if err := r.grants.Revoke(uTask); err != nil {
			t.Fatal(err)
		}
		r.clk.Set(r.now.Add(time.Hour))
		check(t, r.adapter(t), core.Intent{TaskID: "task-other"}, r1Operation(uTask, uMaya), adapter.VerdictFail, saml.CodeRevokedEvidence)
	})
}

func TestSessionClaims(t *testing.T) {
	ctx := context.Background()
	maya := adapter.Principal{ID: uMaya, Realm: uRealm, Workload: uWorkload}
	cc := adapter.ClaimContext{Principal: maya, Intent: core.Intent{TaskID: uTask}}
	r := newRig(t)
	a := r.adapter(t)
	for path, want := range map[string]string{saml.PathPrincipalID: uMaya, saml.PathIDPRealm: uIDP} {
		c, err := a.ReadNativeClaim(ctx, path, cc)
		if err != nil || c.Value != want || !c.ObservedAt.Equal(r.now) || !c.StatusCheckedAt.Equal(r.now) || c.SourceRef != "" || c.SourceID != sessionSource {
			t.Errorf("%s: claim %+v, error %v; want %q read now with no source reference", path, c, err, want)
		}
	}
	lena := cc
	lena.Principal.ID = uLena
	if _, err := a.ReadNativeClaim(ctx, saml.PathPrincipalID, lena); codeOf(err) != adapter.CodeContextMismatch {
		t.Errorf("another principal: error %v, want CONTEXT_MISMATCH", err)
	}
	other := cc
	other.Principal.Realm = adapter.Realm{TenantID: "globex", EnvironmentID: uRealm.EnvironmentID}
	if _, err := a.ReadNativeClaim(ctx, saml.PathPrincipalID, other); codeOf(err) != adapter.CodeContextMismatch {
		t.Errorf("another realm: error %v, want CONTEXT_MISMATCH", err)
	}
	if _, err := a.ReadNativeClaim(ctx, saml.PathPrincipalID, adapter.ClaimContext{Principal: maya}); err == nil {
		t.Error("no task: a claim is returned")
	}
	if _, err := a.ReadNativeClaim(ctx, "/attributes/environment/roles", cc); codeOf(err) != adapter.CodeUnsupportedRequirement {
		t.Errorf("unapproved path: error %v, want UNSUPPORTED_REQUIREMENT", err)
	}
	if err := r.sessions.Logout(uSessionID); err != nil {
		t.Fatal(err)
	}
	if c, err := a.ReadNativeClaim(ctx, saml.PathPrincipalID, cc); err == nil {
		t.Errorf("logged-out session: claim %+v", c)
	} else if _, ok := adapter.CodeOf(err); ok {
		t.Errorf("logged-out session: error %v carries a code; the source holds no value", err)
	}
	r.cfg.Sessions = downSessions{SessionStore: r.sessions, down: true}
	if _, err := r.adapter(t).ReadNativeClaim(ctx, saml.PathIDPRealm, cc); codeOf(err) != adapter.CodeDependencyUnavailable {
		t.Errorf("store down: error %v, want DEPENDENCY_UNAVAILABLE", err)
	}
}

// fixedDirectory is a directory adapter that returns one claim.
type fixedDirectory struct{ c adapter.NativeClaim }

func (f fixedDirectory) ReadNativeClaim(context.Context, string, adapter.ClaimContext) (adapter.NativeClaim, error) {
	return f.c, nil
}

func TestDirectoryClaims(t *testing.T) {
	ctx := context.Background()
	const roles = "/attributes/environment/roles"
	r := newRig(t)
	cc := adapter.ClaimContext{Principal: adapter.Principal{ID: uMaya, Realm: uRealm}}
	for name, c := range map[string]adapter.NativeClaim{
		"no source":     {Value: []any{"purchasing.analyst"}, ObservedAt: r.now},
		"ahead of skew": {Value: []any{"purchasing.analyst"}, ObservedAt: r.now.Add(6 * time.Second), SourceID: "dir"},
	} {
		r.cfg.Directory, r.cfg.DirectoryPaths = fixedDirectory{c}, []string{roles}
		if _, err := r.adapter(t).ReadNativeClaim(ctx, roles, cc); codeOf(err) != adapter.CodeDependencyUnavailable {
			t.Errorf("%s: error %v, want DEPENDENCY_UNAVAILABLE", name, err)
		}
	}
	at := r.now.Add(-120 * time.Second)
	r.cfg.Directory = fixedDirectory{adapter.NativeClaim{Value: "x", ObservedAt: at, StatusCheckedAt: at, SourceID: "dir", SourceRef: "e1"}}
	c, err := r.adapter(t).ReadNativeClaim(ctx, roles, cc)
	if err != nil || !c.ObservedAt.Equal(at) || c.SourceRef != "e1" {
		t.Errorf("claim %+v, error %v; want the directory's own time and reference", c, err)
	}
}

func TestResolveBindingThroughEnrollment(t *testing.T) {
	ctx := context.Background()
	r := newRig(t)
	reg := enrollmem.New(enrollmem.WithClock(r.clk))
	admin := enroll.Actor{Kind: enroll.Admin, ID: "iam-admin", Realm: uRealm}
	if err := reg.Enroll(ctx, admin, enrollmem.Enrollment{AgentID: uAgent, OperatorID: "https://operators.northstar.example/procurement",
		Workload: uWorkload, HolderJKT: "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"}); err != nil {
		t.Fatal(err)
	}
	r.cfg.Registry = reg
	a := r.adapter(t)
	b, err := a.ResolveAgentBinding(ctx, uRealm, uWorkload, uAgent)
	if err != nil || b.Status != adapter.BindingActive || b.HolderJKT != "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs" {
		t.Errorf("binding %+v, error %v", b, err)
	}
	b, err = a.ResolveAgentBinding(ctx, uRealm, uMaya, uAgent)
	if err != nil || b.Status != adapter.BindingUnknown {
		t.Errorf("the user's identifier as workload: binding %+v, error %v; want UNKNOWN (SB-14)", b, err)
	}
}

func TestDescribe(t *testing.T) {
	d := newRig(t).adapter(t).Describe()
	if d != (adapter.Descriptor{Protocol: "saml", Version: "2.0", MappingRevision: "pact-saml-1"}) {
		t.Errorf("descriptor %+v", d)
	}
}

// TestAuthenticateGrantee: the broker serves a grant only to the agent it
// names, enrolled in force on the workload the agent's own credential gives
// (SB-16, identity mapping IM-18).
func TestAuthenticateGrantee(t *testing.T) {
	ctx := context.Background()
	path := "/broker/v1/tasks/" + uTask + "/records/SUP-1042"
	rejected := func(t *testing.T, err error) {
		t.Helper()
		var d *adapter.NativeDenial
		if !errors.As(err, &d) || d.PublicReason() != adapter.DenialCredentialRejected {
			t.Errorf("error %v, want CREDENTIAL_REJECTED", err)
		}
	}
	t.Run("another agent's credential on the grant", func(t *testing.T) {
		r := newRig(t)
		if err := r.reg.Enroll(ctx, uAdmin, enrollmem.Enrollment{AgentID: uReviewer,
			OperatorID: "https://operators.northstar.example/legal", Workload: uRevWork, HolderJKT: "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"}); err != nil {
			t.Fatal(err)
		}
		req := r1Request(t, path)
		req.Header.Set("Authorization", "Bearer "+uRevToken)
		_, err := r.adapter(t).AuthenticateNative(ctx, req)
		rejected(t, err)
	})
	t.Run("the grantee not enrolled", func(t *testing.T) {
		r := newRig(t)
		r.cfg.Registry = enrollmem.New(enrollmem.WithClock(r.clk))
		_, err := r.adapter(t).AuthenticateNative(ctx, r1Request(t, path))
		rejected(t, err)
	})
	t.Run("the grantee revoked", func(t *testing.T) {
		r := newRig(t)
		if err := r.reg.Revoke(ctx, uAdmin, uAgent); err != nil {
			t.Fatal(err)
		}
		_, err := r.adapter(t).AuthenticateNative(ctx, r1Request(t, path))
		rejected(t, err)
	})
	t.Run("the grantee compromised is authenticated", func(t *testing.T) {
		r := newRig(t)
		if err := r.reg.MarkCompromised(ctx, uAdmin, uAgent); err != nil {
			t.Fatal(err)
		}
		p, err := r.adapter(t).AuthenticateNative(ctx, r1Request(t, path))
		if err != nil || p.ID != uMaya || p.Workload != uWorkload {
			t.Errorf("principal %+v, error %v", p, err)
		}
	})
	for name, c := range map[string]struct {
		err  error
		want adapter.Code
	}{
		"a registry that cannot answer":         {errors.New("registry offline"), adapter.CodeDependencyUnavailable},
		"a workload with two enrollments":       {fmt.Errorf("two in force: %w", adapter.ErrUnsupportedRequirement), adapter.CodeUnsupportedRequirement},
		"a registry outage that carries a code": {fmt.Errorf("down: %w", adapter.ErrDependencyUnavailable), adapter.CodeDependencyUnavailable},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			r.cfg.Registry = failingRegistry{Registry: r.reg, err: c.err}
			_, err := r.adapter(t).AuthenticateNative(ctx, r1Request(t, path))
			var d *adapter.NativeDenial
			if errors.As(err, &d) || codeOf(err) != c.want {
				t.Errorf("error %v, want %s and no denial", err, c.want)
			}
		})
	}
}

// failingRegistry is a registry whose lookup fails with err.
type failingRegistry struct {
	enroll.Registry
	err error
}

func (f failingRegistry) Lookup(context.Context, adapter.Realm, adapter.Workload, adapter.AgentID) (adapter.AgentBinding, error) {
	return adapter.AgentBinding{}, f.err
}
