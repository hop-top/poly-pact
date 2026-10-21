package basic_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
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

// stub is the red baseline of the Basic cases: the adapter a gateway gets by
// wiring Basic authentication in the obvious way. It reads any scheme as
// Basic, splits the credential at its last colon, never checks the password,
// the account status or the enforcement marker, names the principal by its
// login, resolves the first enrollment of the account whatever agent is
// named, copies every request header into the operation, forwards the roles
// the principal asserts or the untranslated native roles, opens the backend
// while authorizing, and echoes what it is given in its errors, check
// outcomes and reports.
//
// Every Basic case except those of stubPasses must fail against it; see
// TestStubFailsTheBasicCases.
type stub struct {
	w     *world
	clk   clock.Clock
	hooks *adaptertest.Hooks
	key   *ecdsa.PrivateKey
}

// stubPasses are the Basic cases that the stub passes: the one enrollment of
// an account is also the first one.
var stubPasses = map[string]bool{"BASIC-07.dedicated": true}

// stubFactory builds the stub for a basic/1 case; it realizes no other model.
func stubFactory(_ testing.TB, env adaptertest.Env) (adaptertest.Subject, error) {
	model, err := modelOf(env.State)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	if model != basicModel {
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
	return adapter.Descriptor{Protocol: "http-basic", Version: "rfc7617", MappingRevision: "pact-basic-1"}
}

func (s *stub) account(match func(accountRecord) bool) (accountRecord, bool) {
	for _, a := range s.w.store.Accounts {
		if match(a) {
			return a, true
		}
	}
	return accountRecord{}, false
}

func (s *stub) name(a accountRecord) string { return "basic:" + s.w.store.StoreID + ":" + a.UserID }

func (s *stub) AuthenticateNative(_ context.Context, r *http.Request) (adapter.Principal, error) {
	s.hooks.Fire(hookAccountLookup)
	_, value, _ := strings.Cut(r.Header.Get("Authorization"), " ")
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return adapter.Principal{}, fmt.Errorf("stub: cannot decode %q: %w", value, adapter.ErrInvalidMessage)
	}
	pair := string(raw)
	i := strings.LastIndex(pair, ":")
	user := pair
	if i >= 0 {
		user = pair[:i]
	}
	a, ok := s.account(func(a accountRecord) bool { return a.UserID == user })
	if !ok {
		return adapter.Principal{}, &adapter.NativeDenial{Reason: adapter.DenialNoCredential}
	}
	return adapter.Principal{
		ID:              s.name(a),
		Realm:           s.w.realm(),
		Workload:        adapter.Workload(s.name(a)),
		Mechanism:       "basic",
		AuthenticatedAt: s.clk.Now(),
	}, nil
}

func (s *stub) ResolveAgentBinding(_ context.Context, realm adapter.Realm, workload adapter.Workload, _ adapter.AgentID) (adapter.AgentBinding, error) {
	for _, e := range s.w.st.Enrollments {
		if e.Workload != string(workload) || e.Realm.TenantID != realm.TenantID || e.Realm.EnvironmentID != realm.EnvironmentID {
			continue
		}
		b := adapter.AgentBinding{
			AgentID: e.AgentID, OperatorID: e.OperatorID, HolderJKT: core.Digest(e.HolderJKT),
			Status: adapter.BindingStatus(e.Status), SourceID: e.SourceID, SourceRef: e.SourceRef,
			ObservedAt: s.clk.Now(), StatusCheckedAt: s.clk.Now(),
		}
		return b, nil
	}
	return adapter.AgentBinding{Status: adapter.BindingUnknown}, nil
}

func (s *stub) MapOperation(_ context.Context, r *http.Request, p adapter.Principal, _ string) (core.OperationContext, error) {
	if r.URL.Fragment != "" {
		return core.OperationContext{}, fmt.Errorf("stub: cannot map %s sent with %s: %w", r.URL, r.Header.Get("Authorization"), adapter.ErrInvalidMessage)
	}
	headers := map[string]string{}
	for name := range r.Header {
		headers[strings.ToLower(name)] = r.Header.Get(name)
	}
	segs := strings.Split(r.URL.Path, "/")
	sum := core.Digest("47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU")
	return core.OperationContext{
		OperationID:   "op-stub",
		EnvironmentID: s.w.st.Gateway.EnvironmentID,
		PrincipalID:   p.ID,
		Action:        "invoice.read",
		Resources:     []string{"invoice:" + segs[len(segs)-1]},
		Method:        r.Method,
		TargetURI:     s.w.st.Gateway.Origin + r.URL.Path,
		BodyDigest:    sum,
		Headers:       headers,
	}, nil
}

func (s *stub) ReadNativeClaim(_ context.Context, nativePath string, c adapter.ClaimContext) (adapter.NativeClaim, error) {
	a, ok := s.account(func(a accountRecord) bool {
		return c.Principal.ID == "basic:"+s.w.store.StoreID+":"+a.AccountID
	})
	if !ok {
		return adapter.NativeClaim{}, fmt.Errorf("stub: no account for %q", c.Principal.ID)
	}
	claim := adapter.NativeClaim{ObservedAt: s.clk.Now(), StatusCheckedAt: s.clk.Now(), SourceID: s.w.store.StoreID}
	switch nativePath {
	case "/principal/roles":
		if roles, ok := c.Principal.Attributes["roles"]; ok {
			claim.Value = roles
			return claim, nil
		}
		roles := make([]any, len(a.Roles))
		for i, r := range a.Roles {
			roles[i] = r
		}
		claim.Value = roles
	case "/principal/id":
		claim.Value = s.name(a)
	default:
		claim.Value = a.Department
	}
	return claim, nil
}

func (s *stub) CheckContext(_ context.Context, _ string, in adapter.CheckInput) adapter.CheckOutcome {
	return adapter.CheckOutcome{
		Result: adapter.VerdictPass, ReasonCode: "REQUIREMENT_SATISFIED",
		SourceID: "stub-checks", SourceRef: strings.Join(in.EvidenceRefs, " "), ObservedAt: s.clk.Now(),
	}
}

func (s *stub) AuthorizeNative(_ context.Context, p adapter.Principal, op core.OperationContext) (adapter.Decision, error) {
	s.hooks.Fire("execute")
	d := adapter.Decision{Effect: adapter.EffectDeny, SourceID: permissionSource}
	a, ok := s.account(func(a accountRecord) bool { return p.ID == "basic:"+s.w.store.StoreID+":"+a.AccountID })
	for _, inv := range s.w.st.Invoices {
		if ok && len(op.Resources) == 1 && op.Resources[0] == "invoice:"+inv.ID && inv.Department == a.Department {
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

// TestStubFailsTheBasicCases is the red baseline: the Basic cases catch the
// naive adapter. Every Basic case fails against the stub except those of
// stubPasses, which pass.
func TestStubFailsTheBasicCases(t *testing.T) {
	results, err := adaptertest.Evaluate(t, stubFactory, adaptertest.Options{Adapter: "basic"})
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, r := range results {
		if !strings.HasPrefix(r.ID, "BASIC-") {
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
		t.Fatal("no Basic case ran")
	}
}
