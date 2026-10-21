package basic_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"testing"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/adaptertest"
	"hop.top/pact-go/adapter/enroll"
	"hop.top/pact-go/adapter/freshness"
	"hop.top/pact-go/adapters/basic"
	"hop.top/pact-go/adapters/memory"
	"hop.top/pact-go/core"
)

// basicFactory builds the Basic adapter for a case: from the basic/1 state of
// a Basic case or from the common/1 state of a common case. The fixtures
// realize the gateway's native systems; the adapter is the package's.
func basicFactory(_ testing.TB, env adaptertest.Env) (adaptertest.Subject, error) {
	model, err := modelOf(env.State)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	switch model {
	case basicModel:
		return basicSubject(env)
	case memory.Model:
		return commonSubject(env)
	}
	return adaptertest.Subject{}, fmt.Errorf("model %q is not realized", model)
}

// fixtureStore is an account database in memory. It fires the account_lookup
// hook on every lookup.
type fixtureStore struct {
	source   string
	accounts []basic.Account
	userIDs  []string
	down     bool
	hooks    *adaptertest.Hooks
}

func (s *fixtureStore) SourceID() string { return s.source }

func (s *fixtureStore) ByUserID(_ context.Context, userID string) (basic.Account, error) {
	s.hooks.Fire(hookAccountLookup)
	if s.down {
		return basic.Account{}, fmt.Errorf("account database %s cannot answer: %w", s.source, adapter.ErrDependencyUnavailable)
	}
	for i, u := range s.userIDs {
		if u == userID {
			return s.accounts[i], nil
		}
	}
	return basic.Account{}, basic.ErrNoAccount
}

func (s *fixtureStore) ByPrincipal(_ context.Context, realm adapter.Realm, principal string) (basic.Account, error) {
	s.hooks.Fire(hookAccountLookup)
	if s.down {
		return basic.Account{}, fmt.Errorf("account database %s cannot answer: %w", s.source, adapter.ErrDependencyUnavailable)
	}
	for _, a := range s.accounts {
		if a.Principal == principal && a.Realm == realm {
			return a, nil
		}
	}
	return basic.Account{}, basic.ErrNoAccount
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

func signingKey() (*ecdsa.PrivateKey, error) { return ecdsa.GenerateKey(elliptic.P256(), rand.Reader) }

func reporting(r *memory.Reporting) (*basic.Reporting, error) {
	if r == nil {
		return nil, nil
	}
	key, err := signingKey()
	if err != nil {
		return nil, err
	}
	return &basic.Reporting{Issuer: r.Issuer, Audience: r.Audience, KID: r.KID, Key: key}, nil
}

func subject(a *basic.Adapter, credential func(*http.Request, string) error) adaptertest.Subject {
	return adaptertest.Subject{Adapter: a, Arrive: basic.Mark, Credential: credential}
}

// basicSubject realizes a basic/1 state.
func basicSubject(env adaptertest.Env) (adaptertest.Subject, error) {
	fsys, err := fixtures()
	if err != nil {
		return adaptertest.Subject{}, err
	}
	w, err := loadWorld(env.State, fsys)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	store := &fixtureStore{source: w.store.StoreID, down: w.unavailable(w.store.StoreID), hooks: env.Hooks}
	var decoy basic.PasswordHash
	departments := map[string]string{}
	for _, rec := range w.store.Accounts {
		h, err := decodeHash(rec.Password)
		if err != nil {
			return adaptertest.Subject{}, fmt.Errorf("account %s: %w", rec.AccountID, err)
		}
		if decoy.Iterations == 0 {
			decoy = basic.PasswordHash{Iterations: h.Iterations, Salt: []byte("decoy-salt-01234"), Key: make([]byte, len(h.Key))}
		}
		id := basic.PrincipalID(w.store.StoreID, rec.AccountID)
		store.accounts = append(store.accounts, basic.Account{
			Principal: id, Workload: adapter.Workload(id), Realm: w.realm(), Password: h,
			Roles: rec.Roles, Disabled: rec.Status == "disabled", AnsweredAt: unixTime(w.st.AccountsAnsweredAt),
		})
		store.userIDs = append(store.userIDs, rec.UserID)
		if rec.Status == "active" {
			departments[id] = rec.Department
		}
	}
	ref, err := memory.New(w.commonState(), env.Clock)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	rp, err := reporting(w.st.Reporting)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	purposes := map[string][]string{}
	for _, p := range w.st.Purposes {
		purposes[p.PurposeID] = p.Actions
	}
	a, err := basic.New(basic.Config{
		Realm:           w.realm(),
		Origin:          w.st.Gateway.Origin,
		HeaderAllowlist: w.st.Gateway.HeaderAllowlist,
		Accounts:        store,
		Decoy:           decoy,
		RoleMap:         w.st.RoleMap,
		Checks: map[string]basic.InstalledCheck{
			basic.CheckIDPurposeOperation: {Check: basic.PurposeOperation("gateway-purposes", purposes, env.Clock)},
		},
		Registry:    referenceRegistry{ref},
		Permissions: departmentLookup{departments: departments, invoices: w.st.Invoices},
		Reporting:   rp,
		Clock:       env.Clock,
	})
	if err != nil {
		return adaptertest.Subject{}, err
	}
	return subject(a, func(r *http.Request, name string) error { return attachCredential(w.st.Credentials, r, name) }), nil
}

func decodeHash(p passwordRecord) (basic.PasswordHash, error) {
	salt, err := base64.RawURLEncoding.DecodeString(p.Salt)
	if err != nil {
		return basic.PasswordHash{}, err
	}
	key, err := base64.RawURLEncoding.DecodeString(p.Key)
	if err != nil {
		return basic.PasswordHash{}, err
	}
	return basic.PasswordHash{Iterations: p.Iterations, Salt: salt, Key: key}, nil
}

// departmentLookup is the native permission lookup of basic/1: an active
// account may read an invoice of its own department.
type departmentLookup struct {
	departments map[string]string
	invoices    []invoice
}

func (l departmentLookup) Decide(_ context.Context, p adapter.Principal, op core.OperationContext) (adapter.Decision, error) {
	d := adapter.Decision{Effect: adapter.EffectDeny, SourceID: permissionSource, Reason: "no permission of the account allows this"}
	dept, ok := l.departments[p.ID]
	if !ok || op.Action != "invoice.read" || len(op.Resources) != 1 {
		return d, nil
	}
	for _, inv := range l.invoices {
		if op.Resources[0] == "invoice:"+inv.ID && inv.Department == dept {
			d.Effect, d.Reason = adapter.EffectAllow, ""
		}
	}
	return d, nil
}

// commonSubject realizes a common/1 state: each identity is an account whose
// user-id is its ref and whose password is its secret.
func commonSubject(env adaptertest.Env) (adaptertest.Subject, error) {
	st, err := memory.ParseState(env.State)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	store := &fixtureStore{source: "accounts", hooks: env.Hooks}
	for _, id := range st.Identities {
		salt := sha256.Sum256([]byte("salt:" + id.Ref))
		h, err := basic.HashPassword(id.Secret, salt[:16], 1, 32)
		if err != nil {
			return adaptertest.Subject{}, err
		}
		store.accounts = append(store.accounts, basic.Account{
			Principal: id.ID, Workload: adapter.Workload(id.Workload),
			Realm:    adapter.Realm{TenantID: id.Realm.TenantID, EnvironmentID: id.Realm.EnvironmentID},
			Password: h, Attributes: maps.Clone(id.Attributes),
		})
		store.userIDs = append(store.userIDs, id.Ref)
	}
	ref, err := memory.New(st, env.Clock)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	rp, err := reporting(st.Reporting)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	mappings := map[string][]basic.Route{}
	for _, m := range st.Mappings {
		for _, rt := range m.Routes {
			mappings[m.Version] = append(mappings[m.Version], basic.Route{Method: rt.Method, Path: rt.Path, Action: rt.Action, Resource: rt.Resource})
		}
	}
	claims := map[string]basic.ClaimSource{}
	for _, path := range st.ApprovedPaths {
		claims[path] = commonClaims{st: st}
	}
	checks := map[string]basic.InstalledCheck{}
	for _, c := range st.Checks {
		ic := basic.InstalledCheck{Check: commonCheck{rec: c, down: slices.Contains(st.UnavailableSources, c.SourceID)}, PinnedRevision: c.PinnedRevision}
		if f := c.Freshness; f != nil {
			ic.Freshness = &basic.Freshness{MaxAgeSeconds: *f.MaxAgeSeconds, StatusMaxAgeSeconds: *f.StatusMaxAgeSeconds}
		}
		checks[c.ID] = ic
	}
	guard := freshness.NewMonotonic(len(st.Sightings) + 4096)
	for _, s := range st.Sightings {
		guard.Check(adapter.NativeClaim{SourceID: s.SourceID, SourceRef: s.SourceRef, ObservedAt: unixTime(s.ObservedAt)})
	}
	cfg := basic.Config{
		Realm:            adapter.Realm{TenantID: st.Gateway.TenantID, EnvironmentID: st.Gateway.EnvironmentID},
		Origin:           st.Gateway.Origin,
		HeaderAllowlist:  st.Gateway.HeaderAllowlist,
		Accounts:         store,
		Decoy:            basic.PasswordHash{Iterations: 1, Salt: []byte("decoy-salt-01234"), Key: make([]byte, 32)},
		Claims:           claims,
		Checks:           checks,
		Guard:            guard,
		Registry:         referenceRegistry{ref},
		Permissions:      commonPolicy{rules: st.Policy},
		Reporting:        rp,
		ExecutionVisible: st.Visibility == "execution",
		Clock:            env.Clock,
	}
	if len(mappings) > 0 {
		cfg.Mappings = mappings
	}
	a, err := basic.New(cfg)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	return subject(a, func(r *http.Request, name string) error {
		for _, id := range st.Identities {
			if id.Ref == name {
				if r.Header.Get("Authorization") == "" {
					r.Header.Set("Authorization", basicCredential(id.Ref, id.Secret))
				}
				return nil
			}
		}
		return fmt.Errorf("no identity %q", name)
	}), nil
}

// commonClaims is the claim source of a common/1 state.
type commonClaims struct{ st memory.State }

func (c commonClaims) Claims(_ context.Context, realm adapter.Realm, principal, path string) ([]basic.ClaimRecord, error) {
	var out []basic.ClaimRecord
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
		out = append(out, basic.ClaimRecord{
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

func (c commonCheck) Consult(_ context.Context, in adapter.CheckInput) (basic.CheckRecord, error) {
	if !c.rec.Applies(in) {
		return basic.CheckRecord{Result: adapter.VerdictFail, ReasonCode: memory.CodeApprovalScopeMismatch, SourceID: c.rec.SourceID}, nil
	}
	rec := basic.CheckRecord{
		Result: adapter.Verdict(c.rec.Result), ReasonCode: c.rec.ReasonCode,
		SourceID: c.rec.SourceID, SourceRef: c.rec.SourceRef,
		ObservedAt: unixTime(c.rec.ObservedAt), StatusCheckedAt: unixTime(c.rec.StatusCheckedAt),
		Revision: c.rec.Revision,
	}
	if c.down {
		return basic.CheckRecord{SourceID: c.rec.SourceID}, fmt.Errorf("source %s cannot answer: %w", c.rec.SourceID, adapter.ErrDependencyUnavailable)
	}
	return rec, nil
}

// commonPolicy is the native policy of a common/1 state: the rules that name
// the principal in its realm and the action, and the resource when they name
// one, apply; a deny wins over an unknown and an unknown over an allow; no
// rule is a deny of the policy's own source.
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
