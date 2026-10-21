package oauth_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/adaptertest"
	"hop.top/pact-go/adapter/enroll"
	"hop.top/pact-go/adapter/freshness"
	"hop.top/pact-go/adapter/installed"
	"hop.top/pact-go/adapters/memory"
	"hop.top/pact-go/adapters/oauth"
	"hop.top/pact-go/core"
	"hop.top/pact-go/core/clock"
)

// harnessTimeout bounds the adapter's requests to the world's endpoints, so
// that a case whose endpoint never answers ends quickly.
const harnessTimeout = 200 * time.Millisecond

// oauthFactory builds the OAuth adapter for a case: from the oauth/1 state of
// an OAuth case or from the common/1 state of a common case. The fixtures
// realize the gateway's configuration and its native systems; the adapter is
// the package's.
func oauthFactory(_ testing.TB, env adaptertest.Env) (adaptertest.Subject, error) {
	model, err := modelOf(env.State)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	switch model {
	case oauthModel:
		w, err := loadWorld(env.State, env.Hooks)
		if err != nil {
			return adaptertest.Subject{}, err
		}
		st := w.commonState()
		return worldSubject(w, st, env.Clock, nil)
	case memory.Model:
		return commonSubject(env)
	}
	return adaptertest.Subject{}, fmt.Errorf("model %q is not realized", model)
}

// pinnedClock is the case's clock, or the instant of a prefetch while one
// runs.
type pinnedClock struct {
	base clock.Clock
	mu   sync.Mutex
	at   time.Time
}

func (c *pinnedClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.at.IsZero() {
		return c.at
	}
	return c.base.Now()
}

func (c *pinnedClock) pin(t time.Time) {
	c.mu.Lock()
	c.at = t
	c.mu.Unlock()
}

// configOf returns the adapter configuration of a world: its realm, issuer
// entries and routes, with the world's transport.
func configOf(w *world) oauth.Config {
	cfg := oauth.Config{
		Realm:      adapter.Realm{TenantID: w.st.Gateway.TenantID, EnvironmentID: w.st.Gateway.EnvironmentID},
		HTTPClient: w.client(),
		Timeout:    harnessTimeout,
	}
	for _, e := range w.st.Entries {
		cfg.Entries = append(cfg.Entries, oauth.Entry{
			ID: e.ID, Form: oauth.Form(e.Form), Issuer: e.Issuer, Tenant: e.Tenant,
			Audiences: e.Audiences, Clients: e.Clients, SenderConstraint: oauth.SenderConstraint(e.SenderConstraint),
			Lifetime:              time.Duration(e.LifetimeSeconds) * time.Second,
			IntrospectionEndpoint: e.IntrospectionEndpoint, ClientID: e.GatewayClientID, ClientSecret: e.GatewayClientSecret,
			Binding: oauth.ResourceBinding(e.ResourceBinding), CacheBound: time.Duration(e.CacheSeconds) * time.Second,
			Algorithms: e.Algorithms, KeyRefresh: time.Duration(e.KeyRefreshSeconds) * time.Second,
			KeyMaxAge: time.Duration(e.KeyMaxAgeSeconds) * time.Second, TrustedOrigins: e.TrustedOrigins,
		})
	}
	for _, rt := range w.st.Routes {
		cfg.Routes = append(cfg.Routes, oauth.Route{Method: rt.Method, Path: rt.Path, Entry: rt.Entry, Scope: rt.Scope})
	}
	return cfg
}

// worldSubject realizes a world with the deployment parts of the common/1
// state st, which holds the enrollments and the policy. extra, when set,
// fills in the rest of the configuration.
func worldSubject(w *world, st memory.State, clk clock.Clock, extra func(*oauth.Config)) (adaptertest.Subject, error) {
	ref, err := memory.New(st, clk)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	pc := &pinnedClock{base: clk}
	cfg := configOf(w)
	cfg.Origin = st.Gateway.Origin
	cfg.HeaderAllowlist = st.Gateway.HeaderAllowlist
	cfg.Registry = referenceRegistry{ref}
	cfg.Permissions = commonPolicy{rules: st.Policy}
	cfg.Clock = pc
	if extra != nil {
		extra(&cfg)
	}
	a, err := oauth.New(cfg)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	if id, at, ok := w.prefetchAt(); ok {
		pc.pin(at)
		err := w.withPrefetch(context.Background(), func(ctx context.Context) error { return a.RefreshKeys(ctx, id) })
		pc.pin(time.Time{})
		if err != nil {
			return adaptertest.Subject{}, fmt.Errorf("prefetch: %w", err)
		}
	}
	w.attachProof = func(r *http.Request, kind string) *http.Request {
		return oauth.WithSenderProof(r, oauth.SenderConstraint(kind))
	}
	return adaptertest.Subject{Adapter: a, Arrive: oauth.Mark, Credential: w.Credential}, nil
}

// commonIssuer is the issuer entry of a common/1 state whose identifiers are
// not all oauth: identifiers of one issuer and tenant.
const commonIssuer = "https://as.common.example"

// splitIdentifier splits an oauth: identifier into its three components,
// unescaped.
func splitIdentifier(id string) (issuer, tenant, local string, ok bool) {
	parts := strings.Split(id, ":")
	if len(parts) != 4 || parts[0] != "oauth" {
		return "", "", "", false
	}
	var err error
	out := make([]string, 3)
	for i, p := range parts[1:] {
		if out[i], err = url.PathUnescape(p); err != nil {
			return "", "", "", false
		}
	}
	return out[0], out[1], out[2], true
}

// commonWorld realizes the identities of a common/1 state as opaque tokens of
// one form I issuer entry that serves every route (the cases README, "Common
// cases").
func commonWorld(st memory.State, now time.Time, hooks *adaptertest.Hooks) (*world, error) {
	issuer, tenant := "", ""
	subjects := map[string][2]string{}
	derived := len(st.Identities) > 0
	for _, id := range st.Identities {
		iss, ten, sub, ok1 := splitIdentifier(id.ID)
		wiss, wten, client, ok2 := splitIdentifier(id.Workload)
		if !ok1 || !ok2 || iss != wiss || ten != wten || (issuer != "" && (iss != issuer || ten != tenant)) {
			derived = false
			break
		}
		issuer, tenant = iss, ten
		subjects[id.Ref] = [2]string{sub, client}
	}
	if !derived {
		issuer, tenant = commonIssuer, "none"
		subjects = map[string][2]string{}
		for _, id := range st.Identities {
			subjects[id.Ref] = [2]string{id.Ref, id.Ref}
		}
	}
	const endpoint = "https://as.common.example/oauth2/introspect"
	const aud = "https://gateway.common.example"
	e := entryState{
		ID: "common", Form: "introspection", Issuer: issuer, Tenant: tenant, Audiences: []string{aud},
		SenderConstraint: "none", LifetimeSeconds: 3600, IntrospectionEndpoint: endpoint,
		GatewayClientID: "pact-gateway", GatewayClientSecret: "gw-common-secret-3f9a", ResourceBinding: "aud",
	}
	ost := oauthState{Model: oauthModel, Gateway: st.Gateway, Entries: []entryState{e}}
	w := &world{hooks: hooks, tokens: map[string]string{}}
	for _, id := range st.Identities {
		sc := subjects[id.Ref]
		if !slices.Contains(ost.Entries[0].Clients, sc[1]) {
			ost.Entries[0].Clients = append(ost.Entries[0].Clients, sc[1])
		}
		resp := map[string]any{"active": true, "sub": sc[0], "client_id": sc[1], "scope": "pact.common",
			"aud": aud, "iss": issuer, "exp": now.Unix() + 3000, "iat": now.Unix() - 600}
		if dn, ok := id.Attributes["display_name"].(string); ok {
			resp["username"] = dn
		}
		raw, err := json.Marshal(resp)
		if err != nil {
			return nil, err
		}
		ost.Introspection = append(ost.Introspection, introspectionState{Endpoint: endpoint, Token: id.Secret, Status: http.StatusOK, Response: raw})
		w.tokens[id.Ref] = id.Secret
	}
	if len(ost.Entries[0].Clients) == 0 {
		// A state without identities authenticates nobody; the entry still
		// needs an allowlist.
		ost.Entries[0].Clients = []string{"common-client"}
	}
	w.st = ost
	return w, nil
}

// commonSubject realizes a common/1 state: the identities as tokens of
// commonWorld, and the claim sources, checks, policy, mappings and signer of
// the state as the deployment's parts.
func commonSubject(env adaptertest.Env) (adaptertest.Subject, error) {
	st, err := memory.ParseState(env.State)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	w, err := commonWorld(st, env.Clock.Now(), env.Hooks)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	rp, err := reporting(st.Reporting)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	mappings := map[string][]installed.Route{}
	for _, m := range st.Mappings {
		for _, rt := range m.Routes {
			mappings[m.Version] = append(mappings[m.Version], installed.Route{Method: rt.Method, Path: rt.Path, Action: rt.Action, Resource: rt.Resource})
		}
	}
	claims := map[string]installed.ClaimSource{}
	for _, path := range st.ApprovedPaths {
		claims[path] = commonClaims{st: st}
	}
	checks := map[string]installed.InstalledCheck{}
	for _, c := range st.Checks {
		ic := installed.InstalledCheck{Check: commonCheck{rec: c, down: slices.Contains(st.UnavailableSources, c.SourceID)}, PinnedRevision: c.PinnedRevision}
		if f := c.Freshness; f != nil {
			ic.Freshness = &installed.Freshness{MaxAgeSeconds: *f.MaxAgeSeconds, StatusMaxAgeSeconds: *f.StatusMaxAgeSeconds}
		}
		checks[c.ID] = ic
	}
	guard := freshness.NewMonotonic(len(st.Sightings) + 4096)
	for _, s := range st.Sightings {
		guard.Check(adapter.NativeClaim{SourceID: s.SourceID, SourceRef: s.SourceRef, ObservedAt: unixTime(s.ObservedAt)})
	}
	return worldSubject(w, st, env.Clock, func(cfg *oauth.Config) {
		cfg.DefaultEntry = "common"
		cfg.Claims = claims
		cfg.Checks = checks
		cfg.Guard = guard
		cfg.Reporting = rp
		cfg.ExecutionVisible = st.Visibility == "execution"
		if len(mappings) > 0 {
			cfg.Mappings = mappings
		}
	})
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

func unixTime(sec *int64) time.Time {
	if sec == nil {
		return time.Time{}
	}
	return time.Unix(*sec, 0)
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

// commonClaims is the claim source of a common/1 state.
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

// commonCheck is an installed check of a common/1 state: its record, with the
// verdict of its native state.
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

// commonPolicy is the native policy of a state: the rules that name the
// principal in its realm and the action, and the resource when they name one,
// apply; a deny wins over an unknown and an unknown over an allow; no rule is
// a deny of the policy's own source.
type commonPolicy struct{ rules []memory.PolicyRule }

const ownPolicySource = "native-policy"

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
