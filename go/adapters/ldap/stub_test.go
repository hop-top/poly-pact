package ldap_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/adaptertest"
	"hop.top/pact-go/core"
	"hop.top/pact-go/core/clock"
	"hop.top/pact-go/core/jws"
)

// stub is the red baseline of the LDAP cases: the adapter a gateway gets by
// wiring LDAP in the obvious way. It never checks the enforcement marker,
// binds with whatever password it is given (an empty one is an
// unauthenticated bind, which the directory answers with success), matches
// the login name against cn or uid of any realm and takes the first entry,
// as an unescaped filter would, names the principal and the groups by cn,
// never binds the lookup account and ignores outages and hidden attributes,
// reads a state by lock time only, answers the nested path with an empty
// list, passes every check, authorizes as the lookup account, and resolves
// the first enrollment of a workload whatever agent is named.
//
// Every LDAP case except those of stubPasses must fail against it; see
// TestStubFailsTheLDAPCases. The cases written against the mutant of profile
// Appendix G, which maps a login name or a group by cn and ignores the realm,
// are LDAP-04 and LDAP-09.
type stub struct {
	w     *world
	clk   clock.Clock
	hooks *adaptertest.Hooks
	key   *ecdsa.PrivateKey
}

// stubPasses are the LDAP cases that the stub passes: a check it passes
// anyway, and the one enrollment of an account, which is also the first.
var stubPasses = map[string]bool{
	"LDAP-10.executor-principal": true,
	"LDAP-11.dedicated":          true,
}

// stubFactory builds the stub for an ldap/1 case; it realizes no other model.
func stubFactory(_ testing.TB, env adaptertest.Env) (adaptertest.Subject, error) {
	model, err := modelOf(env.State)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	if model != ldapModel {
		return adaptertest.Subject{}, fmt.Errorf("stub: model %q is not realized", model)
	}
	fsys, err := fixtures()
	if err != nil {
		return adaptertest.Subject{}, err
	}
	w, err := loadWorld(env.State, fsys)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	s := &stub{w: w, clk: env.Clock, hooks: env.Hooks, key: key}
	return adaptertest.Subject{
		Adapter:    s,
		Arrive:     func(r *http.Request) *http.Request { return r },
		Credential: func(r *http.Request, ref string) error { return attachCredential(w.st.Credentials, r, ref) },
	}, nil
}

func (s *stub) Describe() adapter.Descriptor {
	return adapter.Descriptor{Protocol: "ldap", Version: "3", MappingRevision: "pact-ldap-1"}
}

// match finds the first entry of any server whose cn or uid matches name, with
// a trailing * read as a wildcard.
func (s *stub) match(name string) (*server, *entry) {
	ok := func(v string) bool {
		if p, wild := strings.CutSuffix(name, "*"); wild {
			return strings.HasPrefix(strings.ToLower(v), strings.ToLower(p))
		}
		return strings.EqualFold(v, name)
	}
	for _, d := range s.w.st.Directories {
		srv := s.w.servers[d.Name]
		for _, e := range srv.entries {
			if ok(e.first("cn")) || ok(e.first("uid")) {
				return srv, e
			}
		}
	}
	return nil, nil
}

func (s *stub) id(realm string, e *entry) string { return "ldap:" + realm + ":" + e.first("cn") }

func (s *stub) AuthenticateNative(_ context.Context, r *http.Request) (adapter.Principal, error) {
	s.hooks.Fire(hookDirectory)
	user, password, _ := r.BasicAuth()
	_, e := s.match(user)
	if e == nil {
		return adapter.Principal{}, &adapter.NativeDenial{Reason: adapter.DenialNoCredential}
	}
	if password != "" && e.first("userPassword") != password {
		return adapter.Principal{}, &adapter.NativeDenial{Reason: adapter.DenialNoCredential}
	}
	id := s.id(s.w.st.LoginRealm, e)
	return adapter.Principal{
		ID: id, Realm: s.w.pactRealm(), Workload: adapter.Workload(id),
		Mechanism: "ldap-simple-bind", AuthenticatedAt: s.clk.Now(),
	}, nil
}

func (s *stub) ResolveAgentBinding(_ context.Context, realm adapter.Realm, workload adapter.Workload, _ adapter.AgentID) (adapter.AgentBinding, error) {
	for _, e := range s.w.st.Enrollments {
		if e.Workload != string(workload) || e.Realm.TenantID != realm.TenantID || e.Realm.EnvironmentID != realm.EnvironmentID {
			continue
		}
		return adapter.AgentBinding{
			AgentID: e.AgentID, OperatorID: e.OperatorID, HolderJKT: core.Digest(e.HolderJKT),
			Status: adapter.BindingStatus(e.Status), SourceID: e.SourceID, SourceRef: e.SourceRef,
			ObservedAt: s.clk.Now(), StatusCheckedAt: s.clk.Now(),
		}, nil
	}
	return adapter.AgentBinding{Status: adapter.BindingUnknown}, nil
}

func (s *stub) MapOperation(_ context.Context, r *http.Request, p adapter.Principal, _ string) (core.OperationContext, error) {
	headers := map[string]string{}
	for name := range r.Header {
		headers[strings.ToLower(name)] = r.Header.Get(name)
	}
	segs := strings.Split(r.URL.Path, "/")
	wh := ""
	if len(segs) > 2 {
		wh = segs[len(segs)-2]
	}
	return core.OperationContext{
		OperationID: "op-stub", EnvironmentID: s.w.st.Gateway.EnvironmentID, PrincipalID: p.ID,
		Action: "stock.read", Resources: []string{"warehouse:" + wh}, Method: r.Method,
		TargetURI: s.w.st.Gateway.Origin + r.URL.Path, BodyDigest: core.Digest("47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"),
		Headers: headers,
	}, nil
}

// subject finds the entry the principal names by its last segment, as a cn or
// a unique id, in any server.
func (s *stub) subject(principal string) *entry {
	i := strings.LastIndex(principal, ":")
	key := principal[i+1:]
	for _, d := range s.w.st.Directories {
		srv := s.w.servers[d.Name]
		for _, e := range srv.entries {
			if strings.EqualFold(e.first("cn"), key) || srv.uniqueID(e) == key {
				return e
			}
		}
	}
	return nil
}

func (s *stub) ReadNativeClaim(_ context.Context, nativePath string, c adapter.ClaimContext) (adapter.NativeClaim, error) {
	s.hooks.Fire(hookDirectory)
	claim := adapter.NativeClaim{ObservedAt: s.clk.Now(), StatusCheckedAt: s.clk.Now(), SourceID: "ldap-directory"}
	e := s.subject(c.Principal.ID)
	switch nativePath {
	case "/principal/id":
		claim.Value = c.Principal.ID
	case "/principal/account_state":
		switch {
		case e == nil:
			claim.Value = "active"
		case e.first("pwdAccountLockedTime") != "":
			claim.Value = "disabled"
		default:
			claim.Value = "active"
		}
	case "/principal/group_ids":
		groups := []any{}
		if e != nil {
			for _, g := range e.get("memberOf") {
				cn, _, _ := strings.Cut(strings.TrimPrefix(strings.ToLower(string(g)), "cn="), ",")
				groups = append(groups, "ldap:"+s.w.st.LoginRealm+":"+cn)
			}
		}
		claim.Value = groups
	default:
		claim.Value = []any{}
	}
	return claim, nil
}

func (s *stub) CheckContext(_ context.Context, _ string, in adapter.CheckInput) adapter.CheckOutcome {
	return adapter.CheckOutcome{
		Result: adapter.VerdictPass, ReasonCode: "REQUIREMENT_SATISFIED",
		SourceID: "stub-checks", SourceRef: strings.Join(in.EvidenceRefs, " "), ObservedAt: s.clk.Now(),
	}
}

// AuthorizeNative asks the permissions about the lookup account of the login
// realm, the connector's own identity, and runs the read while it asks.
func (s *stub) AuthorizeNative(_ context.Context, _ adapter.Principal, op core.OperationContext) (adapter.Decision, error) {
	s.hooks.Fire("execute")
	r, _ := s.w.realm(s.w.st.LoginRealm)
	connector := ""
	if len(r.DeniedPrincipals) > 0 {
		connector = r.DeniedPrincipals[0]
	}
	d := adapter.Decision{Effect: adapter.EffectDeny, SourceID: permissionSource}
	for _, p := range s.w.st.Permissions {
		if p.Principal == connector && p.Action == op.Action && len(op.Resources) == 1 && op.Resources[0] == p.Resource {
			d.Effect = adapter.EffectAllow
		}
	}
	return d, nil
}

func (s *stub) RecordOutcome(_ context.Context, o adapter.Observation) (adapter.Recorded, error) {
	if s.w.st.Reporting == nil {
		return nil, adapter.ErrUnsupportedRequirement
	}
	now := s.clk.Now()
	rep := core.OutcomeReport{
		PactVersion: core.Version, Issuer: s.w.st.Reporting.Issuer, Subject: o.Context.AgentID,
		Audience: s.w.st.Reporting.Audience, JTI: o.EventID, IssuedAt: now.Unix(), NotBefore: now.Unix(),
		Expiry: now.Unix() + 300, TenantID: o.Context.TenantID, EventID: o.EventID,
		EnvironmentID: o.Context.EnvironmentID, TaskID: o.TaskID, OperationID: o.OperationID,
		AdmissionReceiptID: o.AdmissionReceiptID, ObservedAt: o.ObservedAt.Unix(),
		ReporterRole: core.ReporterGateway, Context: o.Context, EventKind: o.EventKind, Result: o.Result,
		Dimension: o.Dimension, Severity: o.Severity, EvidenceRefs: o.EvidenceRefs, Attribution: o.Attribution,
		Supersedes: append([]string{}, o.Supersedes...), Details: o.Details,
	}
	payload, err := json.Marshal(rep)
	if err != nil {
		return nil, err
	}
	compact, err := jws.Sign(jws.Header{Typ: jws.TypOutcome, Kid: s.w.st.Reporting.KID}, payload, s.key)
	if err != nil {
		return nil, err
	}
	return adapter.Signed{JWS: compact}, nil
}

// TestStubFailsTheLDAPCases is the red baseline: the LDAP cases catch the
// naive adapter. Every LDAP case fails against the stub except those of
// stubPasses, which pass.
func TestStubFailsTheLDAPCases(t *testing.T) {
	results, err := adaptertest.Evaluate(t, stubFactory, adaptertest.Options{Adapter: "ldap"})
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, r := range results {
		if !strings.HasPrefix(r.ID, "LDAP-") {
			continue
		}
		seen++
		switch {
		case stubPasses[r.ID] && !r.Passed():
			t.Errorf("%s fails against the stub, which is expected to pass it: %v", r.ID, r.Failures)
		case !stubPasses[r.ID] && r.Passed():
			t.Errorf("%s passes against the stub: the case does not catch the naive adapter", r.ID)
		}
	}
	if seen == 0 {
		t.Fatal("no LDAP case ran")
	}
}
