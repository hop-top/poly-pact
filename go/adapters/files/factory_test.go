package files_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/adaptertest"
	"hop.top/pact-go/adapter/enroll"
	"hop.top/pact-go/adapter/freshness"
	"hop.top/pact-go/adapter/installed"
	"hop.top/pact-go/adapters/files"
	"hop.top/pact-go/adapters/memory"
	"hop.top/pact-go/core"
)

// filesFactory builds the file broker for a case: from the files/1 state of
// a files case or from the common/1 state of a common case. The fixtures
// realize the security package, the impersonation and the file system as
// fakes, and the deployment's other sources; the broker is the package's.
func filesFactory(_ testing.TB, env adaptertest.Env) (adaptertest.Subject, error) {
	model, err := modelOf(env.State)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	switch model {
	case filesModel:
		w, err := loadWorld(env.State)
		if err != nil {
			return adaptertest.Subject{}, err
		}
		return worldSubject(w, env)
	case memory.Model:
		return commonSubject(env)
	}
	return adaptertest.Subject{}, fmt.Errorf("model %q is not realized", model)
}

// worldSubject realizes a files/1 world: the deployment parts are the
// enrollments and the signer of the state, read as common/1 members.
func worldSubject(w *world, env adaptertest.Env) (adaptertest.Subject, error) {
	w.hooks = env.Hooks
	doc := map[string]any{"model": memory.Model, "gateway": w.st.Gateway}
	if len(w.st.Enrollments) > 0 {
		doc["enrollments"] = w.st.Enrollments
	}
	if len(w.st.Reporting) > 0 {
		doc["reporting"] = w.st.Reporting
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	st, err := memory.ParseState(raw)
	if err != nil {
		return adaptertest.Subject{}, fmt.Errorf("deployment parts: %w", err)
	}
	ref, err := memory.New(st, env.Clock, memory.WithSharedWorkloads())
	if err != nil {
		return adaptertest.Subject{}, err
	}
	rp, err := reporting(st.Reporting)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	sc := &seedClock{base: env.Clock}
	cfg, err := w.config(sc)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	cfg.Registry = referenceRegistry{ref}
	cfg.Reporting = rp
	cfg.ExecutionVisible = true
	b, err := files.New(cfg)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	if err := w.seedContexts(b, sc); err != nil {
		return adaptertest.Subject{}, err
	}
	if w.st.Unhealthy {
		b.MarkUnhealthy(errors.New("fixture: an earlier revert failed"))
	}
	return adaptertest.Subject{Adapter: b, Arrive: w.arrive(b, sc), Credential: w.Credential}, nil
}

// commonDomain is the domain SID of the accounts that realize the identities
// and the policy principals of a common/1 state.
const commonDomain = "S-1-5-21-3000000001-3000000002-3000000003"

// commonRealizer gives each principal of a common/1 state, in its realm, a
// SID of its own, so that equal ids of two realms are two accounts.
type commonRealizer struct {
	mu   sync.Mutex
	sids map[string]string
}

func (c *commonRealizer) sid(realm adapter.Realm, id string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	k := realm.TenantID + "\x00" + realm.EnvironmentID + "\x00" + id
	if s, ok := c.sids[k]; ok {
		return s
	}
	s := fmt.Sprintf("%s-%d", commonDomain, 2000+len(c.sids))
	c.sids[k] = s
	return s
}

// commonSubject realizes a common/1 state: the identities as accounts whose
// secret is their Negotiate token, the policy as registered files whose lists
// grant or deny each rule's principal the rule's action as an access right,
// and the claim sources, checks, mappings, enrollments and signer as the
// deployment's parts. Every principal a call names has a completed context,
// a fact the cases do not state and the expected results do not depend on
// (adapters README, "Native state").
func commonSubject(env adaptertest.Env) (adaptertest.Subject, error) {
	st, err := memory.ParseState(env.State)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	re := &commonRealizer{sids: map[string]string{}}
	fs := filesState{Model: filesModel, ServiceAccount: "pact-common-service", OpenSourceID: commonOpenSource}
	fs.Gateway.TenantID, fs.Gateway.EnvironmentID = st.Gateway.TenantID, st.Gateway.EnvironmentID
	fs.Gateway.Origin, fs.Gateway.HeaderAllowlist = st.Gateway.Origin, st.Gateway.HeaderAllowlist
	fs.Parameters.ContextMaxAge, fs.Parameters.HandleMaxLifetime = 300, 300
	fs.Accounts = append(fs.Accounts, accountState{Ref: "pact-common-service", SID: commonDomain + "-1999",
		NegotiateToken: base64.StdEncoding.EncodeToString([]byte("pact-common-service"))})
	for _, id := range st.Identities {
		r := adapter.Realm{TenantID: id.Realm.TenantID, EnvironmentID: id.Realm.EnvironmentID}
		fs.Accounts = append(fs.Accounts, accountState{Ref: id.Ref, SID: re.sid(r, id.ID),
			NegotiateToken: base64.StdEncoding.EncodeToString([]byte(id.Secret))})
	}
	actions := map[string]files.Access{}
	byResource := map[string]*objectState{}
	var order []string
	for _, rule := range st.Policy {
		actions[rule.Action] = files.Access(rule.Action)
		if rule.Resource == "" || rule.Effect == string(adapter.EffectUnknown) {
			continue
		}
		o, ok := byResource[rule.Resource]
		if !ok {
			o = commonObject(rule.Resource)
			byResource[rule.Resource] = o
			order = append(order, rule.Resource)
		}
		r := adapter.Realm{TenantID: rule.Realm.TenantID, EnvironmentID: rule.Realm.EnvironmentID}
		e := aceState{SID: re.sid(r, rule.Principal), Effect: "allow", Access: []string{rule.Action}}
		if rule.Effect == string(adapter.EffectDeny) {
			// Explicit denials come first in a canonical list.
			e.Effect = "deny"
			o.ACL = append([]aceState{e}, o.ACL...)
			continue
		}
		o.ACL = append(o.ACL, e)
	}
	for _, m := range st.Mappings {
		for _, rt := range m.Routes {
			actions[rt.Action] = files.Access(rt.Action)
		}
	}
	reg := files.StaticRegistry{}
	for _, res := range order {
		o := byResource[res]
		fs.Objects = append(fs.Objects, *o)
		vs, _ := parseHex64(o.VolumeSerial)
		id, _ := objectID(o.ObjectID)
		reg[res] = files.Entry{Resource: res, Path: o.Path, FinalPath: o.FinalPath, VolumeSerial: vs, ObjectID: id}
	}
	w, err := buildWorld(fs)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	w.hooks = env.Hooks

	ref, err := memory.New(st, env.Clock, memory.WithSharedWorkloads())
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
	cfg, err := w.config(env.Clock)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	cfg.Files = reg
	cfg.Actions = actions
	cfg.Contexts = commonContexts{w: w, re: re, clk: env.Clock}
	cfg.Registry = referenceRegistry{ref}
	cfg.Claims = claims
	cfg.Checks = checks
	cfg.Guard = guard
	cfg.Reporting = rp
	cfg.ExecutionVisible = st.Visibility == "execution"
	if len(mappings) > 0 {
		cfg.Mappings = mappings
	}
	b, err := files.New(cfg)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	return adaptertest.Subject{Adapter: b, Arrive: b.Arrive, Credential: w.Credential}, nil
}

// commonOpenSource is the source a decision of the open names in a common case.
const commonOpenSource = "files-native-open"

// commonObject is the registered file that realizes a resource of a common
// policy, with an empty list: no rule, no access.
func commonObject(resource string) *objectState {
	h := sha256.Sum256([]byte(resource))
	name := hex.EncodeToString(h[:8])
	path := `C:\Common\` + name + `.dat`
	return &objectState{
		Path: path, FinalPath: `\\?\` + path, VolumeSerial: "00000000c0ffee01",
		ObjectID: hex.EncodeToString(h[:16]), ContentB64: base64.StdEncoding.EncodeToString([]byte(resource)),
	}
}

func parseHex64(s string) (uint64, error) {
	var v uint64
	_, err := fmt.Sscanf(s, "%x", &v)
	return v, err
}

// commonContexts holds a completed context for every principal a common case
// names: the account of its realm and id, with no groups, completed now.
type commonContexts struct {
	w   *world
	re  *commonRealizer
	clk interface{ Now() time.Time }
}

func (c commonContexts) Get(realm adapter.Realm, principalID string) (files.Context, bool) {
	a := &accountState{Ref: principalID, SID: c.re.sid(realm, principalID)}
	return files.Context{Token: &fakeToken{acc: a}, CompletedAt: c.clk.Now()}, true
}

func (commonContexts) Put(adapter.Realm, string, files.Context) {}

// referenceRegistry is the enrollment source of the records of a case: the
// lookup of the reference adapter over them, with shared workloads.
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
