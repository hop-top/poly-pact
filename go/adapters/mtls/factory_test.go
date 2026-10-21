package mtls_test

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
	"testing"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/adaptertest"
	"hop.top/pact-go/adapter/enroll"
	"hop.top/pact-go/adapter/freshness"
	"hop.top/pact-go/adapter/installed"
	"hop.top/pact-go/adapters/memory"
	"hop.top/pact-go/adapters/mtls"
	"hop.top/pact-go/core"
	"hop.top/pact-go/core/clock"
)

// mtlsFactory builds the mTLS adapter for a case: from the mtls/1 state of an
// mTLS case or from the common/1 state of a common case. The fixtures realize
// the listener's configuration and the gateway's native systems; the adapter
// is the package's.
func mtlsFactory(_ testing.TB, env adaptertest.Env) (adaptertest.Subject, error) {
	model, err := modelOf(env.State)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	switch model {
	case mtlsModel:
		w, err := loadWorld(env.State)
		if err != nil {
			return adaptertest.Subject{}, err
		}
		return worldSubject(w, w.commonState(), env.Clock)
	case memory.Model:
		return commonSubject(env)
	}
	return adaptertest.Subject{}, fmt.Errorf("model %q is not realized", model)
}

// adapterOf builds the adapter of a world: its listener, pinned set,
// terminators and snapshots, with the deployment parts of cfg.
func adapterOf(w *world, cfg mtls.Config) (*mtls.Adapter, error) {
	cfg.Role = mtls.Role(w.st.Listener.Role)
	cfg.Realm = adapter.Realm{TenantID: w.st.Listener.TenantID, EnvironmentID: w.st.Listener.EnvironmentID}
	cfg.StatusBound = time.Duration(w.st.StatusBound) * time.Second
	for _, p := range w.st.PinnedCAs {
		a, ok := w.authorities[p.Authority]
		if !ok {
			return nil, fmt.Errorf("pinned CA %s names no authority %q", p.CAID, p.Authority)
		}
		cfg.PinnedCAs = append(cfg.PinnedCAs, mtls.CAEntry{CAID: p.CAID, Certificate: a.cert, SANKind: mtls.SANKind(p.SANKind)})
	}
	for _, t := range w.st.Terminators {
		cfg.Terminators = append(cfg.Terminators, adapter.Workload(t))
	}
	a, err := mtls.New(cfg)
	if err != nil {
		return nil, err
	}
	for _, s := range w.st.Snapshots {
		if err := a.Adopt(s.CAID, w.crls[s.CAID]); err != nil {
			return nil, fmt.Errorf("snapshot of %s: %w", s.CAID, err)
		}
	}
	return a, nil
}

// worldSubject realizes an mtls/1 world: the deployment parts are those of
// the common/1 state st, which holds the enrollments.
func worldSubject(w *world, st memory.State, clk clock.Clock) (adaptertest.Subject, error) {
	ref, err := memory.New(st, clk)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	a, err := adapterOf(w, mtls.Config{
		Origin:          st.Gateway.Origin,
		HeaderAllowlist: st.Gateway.HeaderAllowlist,
		Registry:        referenceRegistry{ref},
		Permissions:     commonPolicy{},
		Clock:           clk,
	})
	if err != nil {
		return adaptertest.Subject{}, err
	}
	return adaptertest.Subject{Adapter: a, Arrive: a.Arrive, Credential: w.Credential}, nil
}

// commonWorld realizes the identities of a common/1 state as peers of one
// pinned authority, ca-id common, san-kind uri, with an empty snapshot one
// second old. An identity's URI name is its workload when that is an
// absolute URI, and urn:pact:common:<ref> otherwise.
func commonWorld(st memory.State, now time.Time) (*world, error) {
	ms := mtlsState{
		Model:       mtlsModel,
		Listener:    listenerState{Role: "direct", TenantID: st.Gateway.TenantID, EnvironmentID: st.Gateway.EnvironmentID},
		StatusBound: 360,
		Authorities: []authorityState{{
			Ref: "common", SubjectCN: "PACT Common Test CA", KeySeed: "pact-mtls-fixture/common-ca",
			NotBefore: now.Add(-365 * 24 * time.Hour).Unix(), NotAfter: now.Add(365 * 24 * time.Hour).Unix(),
		}},
		PinnedCAs: []pinnedState{{CAID: "common", Authority: "common", SANKind: "uri"}},
		Snapshots: []snapshotState{{CAID: "common", Number: 1, ThisUpdate: now.Unix() - 1, NextUpdate: now.Unix() + 600}},
	}
	eku, ku := []string{"client_auth"}, []string{"digital_signature"}
	for i, id := range st.Identities {
		name := "urn:pact:common:" + id.Ref
		if u, err := url.Parse(id.Workload); err == nil && u.IsAbs() {
			name = id.Workload
		}
		ms.Peers = append(ms.Peers, peerState{
			Ref: id.Ref, Issuer: "common", Serial: int64(i + 1), SubjectCN: id.Ref, URIs: []string{name},
			NotBefore: now.Add(-24 * time.Hour).Unix(), NotAfter: now.Add(30 * 24 * time.Hour).Unix(),
			ExtKeyUsage: &eku, KeyUsage: &ku, KeySeed: "pact-mtls-fixture/common/" + id.Ref,
		})
	}
	return buildWorld(ms)
}

// commonSubject realizes a common/1 state: the identities as certificates of
// commonWorld, and the claim sources, checks, policy, mappings and signer of
// the state as the deployment's parts.
func commonSubject(env adaptertest.Env) (adaptertest.Subject, error) {
	st, err := memory.ParseState(env.State)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	w, err := commonWorld(st, env.Clock.Now())
	if err != nil {
		return adaptertest.Subject{}, err
	}
	ref, err := memory.New(st, env.Clock)
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
	cfg := mtls.Config{
		Origin:           st.Gateway.Origin,
		HeaderAllowlist:  st.Gateway.HeaderAllowlist,
		Registry:         referenceRegistry{ref},
		Claims:           claims,
		Checks:           checks,
		Guard:            guard,
		Permissions:      commonPolicy{rules: st.Policy},
		Reporting:        rp,
		ExecutionVisible: st.Visibility == "execution",
		Clock:            env.Clock,
	}
	if len(mappings) > 0 {
		cfg.Mappings = mappings
	}
	a, err := adapterOf(w, cfg)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	return adaptertest.Subject{Adapter: a, Arrive: a.Arrive, Credential: w.Credential}, nil
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

// requestOf returns a request of the reconciliation route for tests.
func requestOf(t *testing.T) *http.Request {
	t.Helper()
	r, err := http.NewRequest(http.MethodGet, "https://gateway.acme.example/api/v1/reconciliation/records/REC-2041", nil)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
