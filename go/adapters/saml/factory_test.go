package saml_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/adaptertest"
	"hop.top/pact-go/adapter/enroll"
	"hop.top/pact-go/adapter/freshness"
	"hop.top/pact-go/adapter/installed"
	"hop.top/pact-go/adapters/memory"
	"hop.top/pact-go/adapters/saml"
	"hop.top/pact-go/core"
	"hop.top/pact-go/core/clock"
)

// tokenMechanism is the mechanism of the harness's agent authentication.
const tokenMechanism adapter.Mechanism = "broker-token"

// samlFactory builds the SAML adapter for a case: from the saml/1 state of a
// SAML case or from the common/1 state of a common case. The fixtures realize
// the SP's session store through the fake SP, the broker's grant store and
// the native systems; the adapter is the package's.
func samlFactory(_ testing.TB, env adaptertest.Env) (adaptertest.Subject, error) {
	model, err := modelOf(env.State)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	switch model {
	case samlModel:
		w, err := loadWorld(env.State)
		if err != nil {
			return adaptertest.Subject{}, err
		}
		return worldSubject(w, env.Clock)
	case memory.Model:
		return commonSubject(env)
	}
	return adaptertest.Subject{}, fmt.Errorf("model %q is not realized", model)
}

// worldSubject realizes a saml/1 world.
func worldSubject(w *world, clk clock.Clock) (adaptertest.Subject, error) {
	st := memory.State{
		Model: memory.Model, Gateway: w.st.Gateway, Enrollments: w.st.Enrollments,
		ApprovedPaths: w.st.DirectoryPaths, Claims: w.st.Claims, UnavailableSources: w.st.UnavailableSources,
	}
	ref, err := memory.New(st, clk)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	sessions := saml.NewSessions(sessionSource)
	for _, s := range w.sessions {
		if err := sessions.Put(saml.SPSession{
			SessionID: s.SessionID, Principal: s.Principal, IDPRealm: s.IDPRealm,
			AuthnInstant: time.Unix(s.AuthnInstant, 0), ExpiresAt: time.Unix(s.ExpiresAt, 0),
		}); err != nil {
			return adaptertest.Subject{}, err
		}
		if s.LoggedOut {
			if err := sessions.Logout(s.SessionID); err != nil {
				return adaptertest.Subject{}, err
			}
		}
	}
	grants := saml.NewGrants(grantSource)
	for _, g := range w.st.Grants {
		var scope *saml.GrantScope
		if g.Scope != nil {
			scope = &saml.GrantScope{Purposes: g.Scope.Purposes, Actions: g.Scope.Actions, Resources: g.Scope.Resources}
		}
		if err := grants.Put(saml.TaskGrant{
			TaskID: g.TaskID, SessionID: g.SessionID, User: g.User, AgentID: g.AgentID,
			Scope: scope, ExpiresAt: time.Unix(g.ExpiresAt, 0),
		}); err != nil {
			return adaptertest.Subject{}, err
		}
		if g.Revoked {
			if err := grants.Revoke(g.TaskID); err != nil {
				return adaptertest.Subject{}, err
			}
		}
	}
	cfg := saml.Config{
		Realm:           w.realm(),
		Origin:          w.st.Gateway.Origin,
		HeaderAllowlist: w.st.Gateway.HeaderAllowlist,
		Agents:          tokenAgents(w.st.Agents),
		Sessions:        downSessions{SessionStore: sessions, down: w.unavailable(sessionSource)},
		Grants:          downGrants{TaskBroker: grants, down: w.unavailable(grantSource)},
		Registry:        referenceRegistry{ref},
		Permissions:     commonPolicy{},
		Checks:          checksOf(w.st.Checks, w.st.UnavailableSources),
		Guard:           guardOf(w.st.Sightings),
		Clock:           clk,
	}
	if len(w.st.DirectoryPaths) > 0 {
		cfg.Directory = directory{st: st, now: clk}
		cfg.DirectoryPaths = w.st.DirectoryPaths
	}
	a, err := saml.New(cfg)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	return adaptertest.Subject{
		Adapter:    a,
		Arrive:     saml.Mark,
		Credential: func(r *http.Request, ref string) error { return attachCredential(w.st.Agents, r, ref) },
	}, nil
}

// commonSubject realizes a common/1 state: each identity is an agent whose
// broker token is its secret and whose workload is its workload; there are no
// sessions and no grants, and the claim sources, checks, policy, mappings and
// signer of the state are the deployment's parts.
func commonSubject(env adaptertest.Env) (adaptertest.Subject, error) {
	st, err := memory.ParseState(env.State)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	ref, err := memory.New(st, env.Clock)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	var agents []agentCredential
	for _, id := range st.Identities {
		agents = append(agents, agentCredential{Ref: id.Ref, Token: id.Secret, Workload: id.Workload})
	}
	rp, err := reporting(st.Reporting)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	var mappings map[string][]saml.Route
	if len(st.Mappings) > 0 {
		mappings = map[string][]saml.Route{}
		for _, m := range st.Mappings {
			for _, rt := range m.Routes {
				mappings[m.Version] = append(mappings[m.Version], saml.Route{Method: rt.Method, Path: rt.Path, Action: rt.Action, Resource: rt.Resource})
			}
		}
	}
	checks := checksOf(st.Checks, st.UnavailableSources)
	var delegation *saml.InstalledCheck
	if dc, ok := checks[saml.CheckNativeDelegation]; ok {
		delete(checks, saml.CheckNativeDelegation)
		delegation = &dc
	}
	cfg := saml.Config{
		Realm:            adapter.Realm{TenantID: st.Gateway.TenantID, EnvironmentID: st.Gateway.EnvironmentID},
		Origin:           st.Gateway.Origin,
		HeaderAllowlist:  st.Gateway.HeaderAllowlist,
		Mappings:         mappings,
		Agents:           tokenAgents(agents),
		Sessions:         saml.NewSessions(sessionSource),
		Grants:           saml.NewGrants(grantSource),
		Registry:         referenceRegistry{ref},
		Checks:           checks,
		DelegationCheck:  delegation,
		Guard:            guardOf(st.Sightings),
		Permissions:      commonPolicy{rules: st.Policy},
		Reporting:        rp,
		ExecutionVisible: st.Visibility == "execution",
		Clock:            env.Clock,
	}
	if len(st.ApprovedPaths) > 0 {
		cfg.Directory = directory{st: st, now: env.Clock}
		cfg.DirectoryPaths = st.ApprovedPaths
	}
	a, err := saml.New(cfg)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	return adaptertest.Subject{
		Adapter:    a,
		Arrive:     saml.Mark,
		Credential: func(r *http.Request, ref string) error { return attachCredential(agents, r, ref) },
	}, nil
}

// tokenAgents is the harness's broker authentication: a single Authorization
// header with a bearer token (RFC 6750, section 2.1) that one of agents
// holds. Every token is compared, so the time does not depend on which one
// matches.
type tokenAgents []agentCredential

func (t tokenAgents) AuthenticateAgent(_ context.Context, r *http.Request) (saml.AgentIdentity, error) {
	values := r.Header.Values("Authorization")
	if len(values) == 0 {
		return saml.AgentIdentity{}, &adapter.NativeDenial{Reason: adapter.DenialNoCredential}
	}
	scheme, token, ok := strings.Cut(values[0], " ")
	if len(values) != 1 || !ok || !strings.EqualFold(scheme, "Bearer") || token == "" {
		return saml.AgentIdentity{}, &adapter.NativeDenial{Reason: adapter.DenialCredentialRejected}
	}
	var found *agentCredential
	for i := range t {
		if t[i].Token == token {
			found = &t[i]
		}
	}
	if found == nil {
		return saml.AgentIdentity{}, &adapter.NativeDenial{Reason: adapter.DenialCredentialRejected}
	}
	return saml.AgentIdentity{Workload: adapter.Workload(found.Workload), Mechanism: tokenMechanism}, nil
}

// downSessions is a session store that cannot answer when down is set.
type downSessions struct {
	saml.SessionStore
	down bool
}

func (d downSessions) Session(ctx context.Context, id string) (saml.SPSession, error) {
	if d.down {
		return saml.SPSession{}, fmt.Errorf("source %s cannot answer: %w", d.SourceID(), adapter.ErrDependencyUnavailable)
	}
	return d.SessionStore.Session(ctx, id)
}

// downGrants is a grant store that cannot answer when down is set.
type downGrants struct {
	saml.TaskBroker
	down bool
}

func (d downGrants) Grant(ctx context.Context, task string) (saml.TaskGrant, error) {
	if d.down {
		return saml.TaskGrant{}, fmt.Errorf("source %s cannot answer: %w", d.SourceID(), adapter.ErrDependencyUnavailable)
	}
	return d.TaskBroker.Grant(ctx, task)
}

// directory is the directory adapter of a case: the claim records of the
// state, read with the claim context's scoping and the source's own times.
type directory struct {
	st  memory.State
	now clock.Clock
}

func (d directory) ReadNativeClaim(ctx context.Context, path string, cc adapter.ClaimContext) (adapter.NativeClaim, error) {
	return installed.ReadClaim(ctx, commonClaims{st: d.st}, path, cc, d.now.Now())
}

// commonClaims is the claim source of a state's claim records.
type commonClaims struct{ st memory.State }

func (c commonClaims) Claims(_ context.Context, realm adapter.Realm, principal, path string) ([]installed.ClaimRecord, error) {
	var out []installed.ClaimRecord
	for _, r := range c.st.Claims {
		if r.Path != path || r.Principal != principal || r.Realm.TenantID != realm.TenantID || r.Realm.EnvironmentID != realm.EnvironmentID {
			continue
		}
		if slices.Contains(c.st.UnavailableSources, r.SourceID) {
			return nil, fmt.Errorf("source %s cannot answer: %w", r.SourceID, adapter.ErrDependencyUnavailable)
		}
		var v any
		if err := json.Unmarshal(r.Value, &v); err != nil {
			return nil, err
		}
		out = append(out, installed.ClaimRecord{
			Value: v, Resource: r.Resource, TaskID: r.TaskID,
			ObservedAt: unixTime(r.ObservedAt), StatusCheckedAt: unixTime(r.StatusCheckedAt),
			SourceID: r.SourceID, SourceRef: r.SourceRef,
		})
	}
	return out, nil
}

// checksOf installs the check records of a state.
func checksOf(recs []memory.CheckRecord, down []string) map[string]saml.InstalledCheck {
	checks := map[string]saml.InstalledCheck{}
	for _, c := range recs {
		ic := saml.InstalledCheck{Check: commonCheck{rec: c, down: slices.Contains(down, c.SourceID)}, PinnedRevision: c.PinnedRevision}
		if f := c.Freshness; f != nil {
			ic.Freshness = &installed.Freshness{MaxAgeSeconds: *f.MaxAgeSeconds, StatusMaxAgeSeconds: *f.StatusMaxAgeSeconds}
		}
		checks[c.ID] = ic
	}
	return checks
}

// guardOf is a guard against re-stamping that holds the sightings of a state.
func guardOf(sightings []memory.Sighting) *freshness.Monotonic {
	guard := freshness.NewMonotonic(len(sightings) + 4096)
	for _, s := range sightings {
		guard.Check(adapter.NativeClaim{SourceID: s.SourceID, SourceRef: s.SourceRef, ObservedAt: unixTime(s.ObservedAt)})
	}
	return guard
}

// commonCheck is an installed check of a state: its record, with the verdict
// of its native state.
type commonCheck struct {
	rec  memory.CheckRecord
	down bool
}

func (c commonCheck) Consult(_ context.Context, in adapter.CheckInput) (installed.CheckRecord, error) {
	if !c.rec.Applies(in) {
		return installed.CheckRecord{Result: adapter.VerdictFail, ReasonCode: memory.CodeApprovalScopeMismatch, SourceID: c.rec.SourceID}, nil
	}
	if c.down {
		return installed.CheckRecord{SourceID: c.rec.SourceID}, fmt.Errorf("source %s cannot answer: %w", c.rec.SourceID, adapter.ErrDependencyUnavailable)
	}
	return installed.CheckRecord{
		Result: adapter.Verdict(c.rec.Result), ReasonCode: c.rec.ReasonCode,
		SourceID: c.rec.SourceID, SourceRef: c.rec.SourceRef,
		ObservedAt: unixTime(c.rec.ObservedAt), StatusCheckedAt: unixTime(c.rec.StatusCheckedAt),
		Revision: c.rec.Revision,
	}, nil
}

// referenceRegistry is the enrollment source of the records of a case: the
// lookup of the reference adapter over them, with dedicated workloads.
type referenceRegistry struct{ ref *memory.Adapter }

func (r referenceRegistry) Lookup(ctx context.Context, realm adapter.Realm, workload adapter.Workload, agent adapter.AgentID) (adapter.AgentBinding, error) {
	return r.ref.ResolveAgentBinding(ctx, realm, workload, agent)
}

func (referenceRegistry) Rotate(context.Context, enroll.Actor, string, core.Digest) error {
	return errors.New("the fixture registry is read-only")
}

func (referenceRegistry) MarkCompromised(context.Context, enroll.Actor, string) error {
	return errors.New("the fixture registry is read-only")
}

// commonPolicy is the native policy of a state: the rules that name the
// principal in its realm and the action, and the resource when they name one,
// apply; a deny wins over an unknown and an unknown over an allow; no rule is
// a deny of the policy's own source.
type commonPolicy struct{ rules []memory.PolicyRule }

const ownPolicySource = "portal-access-policy"

func (c commonPolicy) Decide(_ context.Context, p adapter.Principal, op core.OperationContext) (adapter.Decision, error) {
	rank := map[string]int{"DENY": 3, "UNKNOWN": 2, "ALLOW": 1}
	var best *memory.PolicyRule
	for i := range c.rules {
		r := &c.rules[i]
		if r.Principal != p.ID || r.Realm.TenantID != p.Realm.TenantID || r.Realm.EnvironmentID != p.Realm.EnvironmentID ||
			r.Action != op.Action || (r.Resource != "" && !slices.Contains(op.Resources, r.Resource)) {
			continue
		}
		if best == nil || rank[r.Effect] > rank[best.Effect] {
			best = r
		}
	}
	if best == nil {
		return adapter.Decision{Effect: adapter.EffectDeny, Reason: "no rule allows this principal", SourceID: ownPolicySource}, nil
	}
	d := adapter.Decision{
		Effect: adapter.Effect(best.Effect), Reason: best.Reason, SourceID: best.SourceID,
		SourceRef: best.SourceRef, DecidedAt: unixTime(best.DecidedAt), PolicyRevision: best.PolicyRevision,
	}
	if d.SourceID == "" {
		d.SourceID = ownPolicySource
	}
	for _, o := range best.Obligations {
		d.Obligations = append(d.Obligations, adapter.Obligation{ID: o.ID, Attributes: o.Attributes})
	}
	return d, nil
}

func reporting(r *memory.Reporting) (*installed.Reporting, error) {
	if r == nil {
		return nil, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &installed.Reporting{Issuer: r.Issuer, Audience: r.Audience, KID: r.KID, Key: key}, nil
}

func unixTime(sec *int64) time.Time {
	if sec == nil {
		return time.Time{}
	}
	return time.Unix(*sec, 0)
}
