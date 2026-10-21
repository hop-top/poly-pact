package abac_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"testing"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/adaptertest"
	"hop.top/pact-go/adapter/freshness"
	"hop.top/pact-go/adapters/abac"
	"hop.top/pact-go/adapters/memory"
	"hop.top/pact-go/core/clock"
)

// gatewaySource is the source id of the facts the gateway observes itself.
const gatewaySource = "gateway"

// pdpTimeout is the PDP timeout of the adapters the harness builds, with
// room for a loaded test machine or a real OPA server; the
// timeout case's PDP never answers.
const pdpTimeout = 2 * time.Second

// abacFactory builds the ABAC adapter for a case: from the abac/1 state of an
// ABAC case or from the common/1 state of a common case. The fixtures realize
// the gateway's native systems; the adapter is the package's.
func abacFactory(tb testing.TB, env adaptertest.Env) (adaptertest.Subject, error) {
	model, err := modelOf(env.State)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	switch model {
	case abacModel:
		w, err := loadWorld(tb, env.State, env.Hooks)
		if err != nil {
			return adaptertest.Subject{}, err
		}
		a, ref, err := worldAdapter(w, env.Clock)
		if err != nil {
			return adaptertest.Subject{}, err
		}
		return subjectOf(a, ref), nil
	case memory.Model:
		return commonSubject(tb, env)
	}
	return adaptertest.Subject{}, fmt.Errorf("model %q is not realized", model)
}

// worldAdapter builds the adapter over an abac/1 world. The inherited
// authentication and binding resolution are the reference adapter's over the
// gateway alone: the ABAC cases call neither.
func worldAdapter(w *world, clk clock.Clock) (*abac.Adapter, *memory.Adapter, error) {
	ref, err := memory.New(memory.State{Model: memory.Model, Gateway: w.st.Gateway}, clk)
	if err != nil {
		return nil, nil, err
	}
	src := worldFacts{w: w}
	var zones []abac.Zone
	for _, z := range w.zones {
		zones = append(zones, abac.Zone{Prefix: z.prefix, Name: z.name})
	}
	var entry *abac.Entry
	if e := w.st.Entry; e != nil {
		entry = &abac.Entry{CheckID: e.CheckID, PinnedVersion: e.PolicyVersion, Obligations: e.Obligations}
	}
	a, err := abac.New(abac.Config{
		Realm:           adapter.Realm{TenantID: w.st.Gateway.TenantID, EnvironmentID: w.st.Gateway.EnvironmentID},
		Origin:          w.st.Gateway.Origin,
		HeaderAllowlist: w.st.Gateway.HeaderAllowlist,
		Authenticator:   ref,
		Bindings:        ref,
		Subjects:        src,
		Resources:       src,
		Devices:         src,
		Environment:     abac.Gateway{SourceID: gatewaySource, Zones: zones, Clock: clk},
		Guard:           guardOf(w.st.Sightings),
		PDP: abac.PDP{
			SourceID: w.st.PDP.SourceID, URL: w.pdp.URL, DecisionPath: w.st.PDP.DecisionPath,
			Client: w.pdp.Client, Timeout: pdpTimeout,
		},
		Entry: entry,
		Clock: clk,
	})
	return a, ref, err
}

// guardOf is a guard against re-stamping that holds the sightings.
func guardOf(sightings []memory.Sighting) *freshness.Monotonic {
	g := freshness.NewMonotonic(len(sightings) + 4096)
	for _, s := range sightings {
		g.Check(adapter.NativeClaim{SourceID: s.SourceID, SourceRef: s.SourceRef, ObservedAt: unixTime(s.ObservedAt)})
	}
	return g
}

func unixTime(sec *int64) time.Time {
	if sec == nil {
		return time.Time{}
	}
	return time.Unix(*sec, 0)
}

// worldFacts is the fact sources of an abac/1 world.
type worldFacts struct{ w *world }

func (s worldFacts) read(path, key string) (adapter.NativeClaim, error) {
	if src := s.w.sourceOf(path); src != "" && s.w.down(src) {
		return adapter.NativeClaim{}, fmt.Errorf("source %s cannot answer: %w", src, adapter.ErrDependencyUnavailable)
	}
	f, ok := s.w.fact(path, key)
	if !ok {
		return adapter.NativeClaim{}, abac.ErrNoFact
	}
	v, err := f.value()
	if err != nil {
		return adapter.NativeClaim{}, err
	}
	return adapter.NativeClaim{
		Value: v, ObservedAt: unixTime(f.ObservedAt), StatusCheckedAt: unixTime(f.StatusCheckedAt),
		SourceID: f.SourceID, SourceRef: f.SourceRef,
	}, nil
}

func (s worldFacts) SubjectFact(_ context.Context, realm adapter.Realm, principal, path string) (adapter.NativeClaim, error) {
	if !s.inRealm(realm) {
		return adapter.NativeClaim{}, abac.ErrNoFact
	}
	return s.read(path, principal)
}

func (s worldFacts) ResourceFact(_ context.Context, realm adapter.Realm, resource, path string) (adapter.NativeClaim, error) {
	if !s.inRealm(realm) {
		return adapter.NativeClaim{}, abac.ErrNoFact
	}
	return s.read(path, resource)
}

func (s worldFacts) DeviceCompliance(_ context.Context, realm adapter.Realm, device string) (adapter.NativeClaim, error) {
	if !s.inRealm(realm) {
		return adapter.NativeClaim{}, abac.ErrNoFact
	}
	return s.read(pathDeviceCompliant, device)
}

func (s worldFacts) inRealm(r adapter.Realm) bool {
	return r.TenantID == s.w.st.Gateway.TenantID && r.EnvironmentID == s.w.st.Gateway.EnvironmentID
}

// The facts and the policy defaults of a common/1 realization. The common
// policy reads none of the facts (the adapters README, "Native state").
const (
	commonDepartment = "x-dept:common-hr:finance"
	commonPolicyID   = "common-pdp"
	commonVersion    = "common-policy-1"
	commonDecision   = "decision-common"
)

// commonSubject realizes a common/1 state: the inherited functions are the
// reference adapter's, and the PDP evaluates the policy rules of the state.
func commonSubject(tb testing.TB, env adaptertest.Env) (adaptertest.Subject, error) {
	st, err := memory.ParseState(env.State)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	ref, err := memory.New(st, env.Clock)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	realm := adapter.Realm{TenantID: st.Gateway.TenantID, EnvironmentID: st.Gateway.EnvironmentID}
	pdpID := commonPolicyID
	for _, r := range st.Policy {
		if r.SourceID != "" {
			pdpID = r.SourceID
		}
	}
	pdp := startPDP(tb, pdpState{SourceID: pdpID, DecisionPath: "pact/abac/decision"}, env.Hooks,
		func(in any) (int, string) { return commonDecide(st.Policy, realm, in) })
	rp, err := reporting(st.Reporting)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	mappings := map[string][]abac.Route{}
	for _, m := range st.Mappings {
		for _, rt := range m.Routes {
			mappings[m.Version] = append(mappings[m.Version], abac.Route{Method: rt.Method, Path: rt.Path, Action: rt.Action, Resource: rt.Resource})
		}
	}
	claims := map[string]abac.ClaimSource{}
	for _, path := range st.ApprovedPaths {
		if !isFact(path) {
			claims[path] = commonClaims{st: st}
		}
	}
	checks := map[string]abac.InstalledCheck{}
	for _, c := range st.Checks {
		ic := abac.InstalledCheck{Check: commonCheck{rec: c, down: slices.Contains(st.UnavailableSources, c.SourceID)}, PinnedRevision: c.PinnedRevision}
		if f := c.Freshness; f != nil {
			ic.Freshness = &abac.Freshness{MaxAgeSeconds: *f.MaxAgeSeconds, StatusMaxAgeSeconds: *f.StatusMaxAgeSeconds}
		}
		checks[c.ID] = ic
	}
	src := commonFacts{st: st, clk: env.Clock}
	cfg := abac.Config{
		Realm:            realm,
		Origin:           st.Gateway.Origin,
		HeaderAllowlist:  st.Gateway.HeaderAllowlist,
		Authenticator:    ref,
		Bindings:         ref,
		Subjects:         src,
		Resources:        src,
		Devices:          src,
		Environment:      abac.Gateway{SourceID: gatewaySource, Zones: anyZone(), Clock: env.Clock},
		Guard:            guardOf(st.Sightings),
		PDP:              abac.PDP{SourceID: pdpID, URL: pdp.URL, DecisionPath: "pact/abac/decision", Client: pdp.Client, Timeout: pdpTimeout},
		Claims:           claims,
		Checks:           checks,
		Reporting:        rp,
		ExecutionVisible: st.Visibility == "execution",
		Clock:            env.Clock,
	}
	if len(mappings) > 0 {
		cfg.Mappings = mappings
	}
	a, err := abac.New(cfg)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	return subjectOf(a, ref), nil
}

// subjectOf is the subject of the adapter, with the enforcement marker and the
// credentials of the reference adapter it inherits authentication from. The
// adapter signs with its own key, so the reference adapter's verifier is not
// used.
func subjectOf(a *abac.Adapter, ref *memory.Adapter) adaptertest.Subject {
	sub := memory.SubjectOf(ref)
	sub.Adapter, sub.VerifyOutcome = a, nil
	return sub
}

// anyZone is a zone map that gives every address the zone corporate.
func anyZone() []abac.Zone {
	return []abac.Zone{
		{Prefix: netip.MustParsePrefix("0.0.0.0/0"), Name: "corporate"},
		{Prefix: netip.MustParsePrefix("::/0"), Name: "corporate"},
	}
}

// commonDecide is the PDP of a common/1 state: the rules that name the
// gateway's realm, the input's principal and action, and its resource when
// they name one, apply; a deny wins over an unknown and an unknown over an
// allow; an unknown is an undefined document; no rule is the default denial.
func commonDecide(rules []memory.PolicyRule, realm adapter.Realm, in any) (int, string) {
	str := func(path ...string) string {
		v, _ := member(in, path...)
		s, _ := v.(string)
		return s
	}
	principal, action, resource := str("subject", "principal_id"), str("action", "id"), str("resource", "id")
	order := map[string]int{"DENY": 3, "UNKNOWN": 2, "ALLOW": 1}
	var best *memory.PolicyRule
	for i := range rules {
		r := &rules[i]
		if r.Realm.TenantID != realm.TenantID || r.Realm.EnvironmentID != realm.EnvironmentID ||
			r.Principal != principal || r.Action != action || r.Resource != "" && r.Resource != resource {
			continue
		}
		if best == nil || order[r.Effect] > order[best.Effect] {
			best = r
		}
	}
	doc := map[string]any{"allow": false, "obligations": []any{}, "policy_version": commonVersion}
	id := commonDecision
	if best != nil {
		if best.SourceRef != "" {
			id = best.SourceRef
		}
		if best.Effect == "UNKNOWN" {
			b, _ := json.Marshal(map[string]any{"decision_id": id})
			return http.StatusOK, string(b)
		}
		obl := []any{}
		for _, o := range best.Obligations {
			params := o.Attributes
			if params == nil {
				params = map[string]any{}
			}
			obl = append(obl, map[string]any{"type": o.ID, "params": params})
		}
		doc["allow"], doc["obligations"] = best.Effect == "ALLOW", obl
		if best.PolicyRevision != "" {
			doc["policy_version"] = best.PolicyRevision
		}
	}
	b, _ := json.Marshal(map[string]any{"decision_id": id, "result": doc})
	return http.StatusOK, string(b)
}

// commonFacts realizes the claims a common/1 state states for a fact path,
// such as /resource/classification, and gives the facts F1 to F6 the state
// does not state for any principal and resource, fresh at the clock: the
// common policy reads none of them.
type commonFacts struct {
	st  memory.State
	clk clock.Clock
}

// isFact reports whether path is a fact path of the profile.
func isFact(path string) bool {
	switch path {
	case pathPrincipalID, pathDepartment, pathClearance, pathDeviceCompliant, pathClassification, pathOwningDepartment, pathNetworkZone, pathTime:
		return true
	}
	return false
}

// stated returns the claim the state states for path, principal and
// resource; stated is false when the state states no claim of path at all.
func (c commonFacts) stated(realm adapter.Realm, path, principal, resource string) (adapter.NativeClaim, bool, error) {
	seen := false
	for _, r := range c.st.Claims {
		if r.Path != path {
			continue
		}
		seen = true
		if r.Realm.TenantID != realm.TenantID || r.Realm.EnvironmentID != realm.EnvironmentID ||
			principal != "" && r.Principal != principal || r.Resource != resource {
			continue
		}
		if slices.Contains(c.st.UnavailableSources, r.SourceID) {
			return adapter.NativeClaim{}, true, fmt.Errorf("source %s cannot answer: %w", r.SourceID, adapter.ErrDependencyUnavailable)
		}
		v, err := decodeJSON(r.Value)
		if err != nil {
			return adapter.NativeClaim{}, true, err
		}
		return adapter.NativeClaim{
			Value: v, ObservedAt: unixTime(r.ObservedAt), StatusCheckedAt: unixTime(r.StatusCheckedAt),
			SourceID: r.SourceID, SourceRef: r.SourceRef,
		}, true, nil
	}
	if seen {
		return adapter.NativeClaim{}, true, abac.ErrNoFact
	}
	return adapter.NativeClaim{}, false, nil
}

func (c commonFacts) claim(v any) adapter.NativeClaim {
	now := c.clk.Now()
	return adapter.NativeClaim{Value: v, ObservedAt: now, StatusCheckedAt: now, SourceID: "common-facts"}
}

func (c commonFacts) SubjectFact(_ context.Context, realm adapter.Realm, principal, path string) (adapter.NativeClaim, error) {
	if claim, ok, err := c.stated(realm, path, principal, ""); ok {
		return claim, err
	}
	switch path {
	case pathPrincipalID:
		return c.claim(principal), nil
	case pathDepartment:
		return c.claim(commonDepartment), nil
	case pathClearance:
		return c.claim("confidential"), nil
	}
	return adapter.NativeClaim{}, abac.ErrNoFact
}

func (c commonFacts) ResourceFact(_ context.Context, realm adapter.Realm, resource, path string) (adapter.NativeClaim, error) {
	if claim, ok, err := c.stated(realm, path, "", resource); ok {
		return claim, err
	}
	switch path {
	case pathClassification:
		return c.claim("internal"), nil
	case pathOwningDepartment:
		return c.claim(commonDepartment), nil
	}
	return adapter.NativeClaim{}, abac.ErrNoFact
}

func (c commonFacts) DeviceCompliance(context.Context, adapter.Realm, string) (adapter.NativeClaim, error) {
	return c.claim(true), nil
}

// commonClaims is the claim source of a common/1 state.
type commonClaims struct{ st memory.State }

func (c commonClaims) Claims(_ context.Context, realm adapter.Realm, principal, path string) ([]abac.ClaimRecord, error) {
	var out []abac.ClaimRecord
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
		out = append(out, abac.ClaimRecord{
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

func (c commonCheck) Consult(_ context.Context, in adapter.CheckInput) (abac.CheckRecord, error) {
	if !c.rec.Applies(in) {
		return abac.CheckRecord{Result: adapter.VerdictFail, ReasonCode: memory.CodeApprovalScopeMismatch, SourceID: c.rec.SourceID}, nil
	}
	if c.down {
		return abac.CheckRecord{SourceID: c.rec.SourceID}, fmt.Errorf("source %s cannot answer: %w", c.rec.SourceID, adapter.ErrDependencyUnavailable)
	}
	return abac.CheckRecord{
		Result: adapter.Verdict(c.rec.Result), ReasonCode: c.rec.ReasonCode,
		SourceID: c.rec.SourceID, SourceRef: c.rec.SourceRef,
		ObservedAt: unixTime(c.rec.ObservedAt), StatusCheckedAt: unixTime(c.rec.StatusCheckedAt),
		Revision: c.rec.Revision,
	}, nil
}

func reporting(r *memory.Reporting) (*abac.Reporting, error) {
	if r == nil {
		return nil, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &abac.Reporting{Issuer: r.Issuer, Audience: r.Audience, KID: r.KID, Key: key}, nil
}
