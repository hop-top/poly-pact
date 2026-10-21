package graph_test

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
	"math/big"
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
	"hop.top/pact-go/adapters/graph"
	"hop.top/pact-go/adapters/memory"
	"hop.top/pact-go/core"
	"hop.top/pact-go/core/clock"
)

func init() {
	conformanceFactory = graphFactory
	unitBroker = realBrokerFactory
}

// graphFactory builds the Graph adapter for a case: from the graph/1 state
// of a Graph case or from the common/1 state of a common case.
func graphFactory(t testing.TB, env adaptertest.Env) (adaptertest.Subject, error) {
	model, err := modelOf(env.State)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	switch model {
	case graphModel:
		return graphSubject(t, env)
	case memory.Model:
		return commonSubject(t, env)
	}
	return adaptertest.Subject{}, fmt.Errorf("model %q is not realized", model)
}

// fixtureRegistry is an executor registry over registry records.
type fixtureRegistry struct {
	records []bindingRec
	down    func() bool
}

func (r fixtureRegistry) Bindings(_ context.Context, realm adapter.Realm) ([]graph.ExecutorBinding, error) {
	if r.down != nil && r.down() {
		return nil, errors.New("the executor registry cannot answer")
	}
	var out []graph.ExecutorBinding
	for _, b := range r.records {
		if b.Realm.TenantID != realm.TenantID || b.Realm.EnvironmentID != realm.EnvironmentID {
			continue
		}
		out = append(out, graph.ExecutorBinding{
			Realm: adapter.Realm(b.Realm), Row: graph.Row(b.Row), Workload: b.Workload, Class: b.Class, Grant: graph.Grant(b.Grant),
			AppID: b.AppID, ServicePrincipalID: b.ServicePrincipalID, MailboxID: b.MailboxID, Ref: b.Ref, ChangedAt: time.Unix(b.ChangedAt, 0),
		})
	}
	return out, nil
}

// attestSource is the operator's attestation as the world holds it.
type attestSource struct{ get func() *attestation }

func (s attestSource) Attestation(context.Context, string, string) (graph.RBACAttestation, error) {
	a := s.get()
	if a == nil {
		return graph.RBACAttestation{}, errors.New("no attestation")
	}
	rows := make([]graph.RBACRow, len(a.Rows))
	for i, r := range a.Rows {
		rows[i] = graph.RBACRow(r)
	}
	return graph.RBACAttestation{Identity: a.Identity, Resource: a.Resource, RanAt: time.Unix(a.RanAt, 0), Rows: rows, Ref: fmt.Sprintf("rbac-attestation:%d", a.RanAt)}, nil
}

// noFrontDoor authenticates nobody.
type noFrontDoor struct{}

func (noFrontDoor) AuthenticateNative(context.Context, *http.Request) (adapter.Principal, error) {
	return adapter.Principal{}, &adapter.NativeDenial{Reason: adapter.DenialNoCredential}
}

// acquirers are the one acquirer of a form and the auditor's, against the
// fake cloud.
func acquirers(form string, tenant, gatewayApp, executorApp string, client *http.Client, clk clock.Clock) (graph.TokenAcquirer, graph.TokenAcquirer, error) {
	if form == formDelegated {
		a, err := graph.NewOnBehalfOf(graph.AcquirerConfig{Tenant: tenant, ClientID: gatewayApp, Auth: graph.ClientAuth{Secret: secretOBO}, HTTPClient: client, Clock: clk})
		return a, nil, err
	}
	a, err := graph.NewClientCredentials(graph.AcquirerConfig{Tenant: tenant, ClientID: executorApp, Auth: graph.ClientAuth{Secret: secretExecutor}, HTTPClient: client, Clock: clk})
	if err != nil {
		return nil, nil, err
	}
	aud, err := graph.NewClientCredentials(graph.AcquirerConfig{Tenant: tenant, ClientID: uAuditorApp, Auth: graph.ClientAuth{Secret: secretAuditor}, HTTPClient: client, Clock: clk})
	return a, aud, err
}

// graphSubject realizes a graph/1 state with the fake cloud, and runs the
// state's preflight runs at their times.
func graphSubject(t testing.TB, env adaptertest.Env) (adaptertest.Subject, error) {
	st, err := parseState(env.State)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	clk, ok := env.Clock.(*clock.Fake)
	if !ok {
		return adaptertest.Subject{}, errors.New("the harness needs a settable clock")
	}
	cloud := newCloud(t, env.Hooks)
	acq, aud, err := acquirers(st.Form, st.Entra.TenantID, st.Entra.GatewayAppID, st.ExecutorAppID, cloud.client, clk)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	var current *attestation
	cfg := graph.Config{
		Form: graph.Form(st.Form), Realm: st.realm(), Origin: st.Gateway.Origin, HeaderAllowlist: st.Gateway.HeaderAllowlist,
		Tenant: st.Entra.TenantID, Acquirer: acq,
		Registry:      fixtureRegistry{records: st.Registry, down: func() bool { return st.down(sourceRegistry) }},
		HTTPClient:    cloud.client,
		Authenticator: noFrontDoor{}, Enrollments: noEnrollments{}, Permissions: noPolicy{},
		ExecutionVisible: true, Clock: clk,
	}
	store := graph.NewMemoryContinuations(nil)
	for _, c := range st.Continuations {
		store.Put(c.PageToken, graph.Continuation{Row: graph.Row(c.Row), Principal: c.Principal, TaskID: c.TaskID, AgentID: c.AgentID, MappingVersion: c.MappingVersion, Link: c.Link})
	}
	cfg.Continuations = store
	if st.Form == formApplication {
		pc := &graph.PreflightConfig{Auditor: aud, RBAC: attestSource{func() *attestation { return current }}}
		if st.Preflight != nil {
			for _, e := range st.Preflight.Allowlist {
				pc.Allowlist = append(pc.Allowlist, graph.AppRole{ResourceID: e.ResourceID, AppRoleID: e.AppRoleID})
			}
		}
		cfg.Preflight = pc
	}
	rp, err := reporting(st.Reporting)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	cfg.Reporting = rp
	a, err := graph.New(cfg)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	if st.Preflight != nil {
		now := clk.Now()
		for _, run := range st.Preflight.Runs {
			clk.Set(time.Unix(run.At, 0))
			cloud.mu.Lock()
			cloud.pages, cloud.auditUnreachable = run.AssignmentPages, run.Unreachable
			cloud.mu.Unlock()
			current = run.RBAC
			a.RunPreflight(context.Background())
		}
		clk.Set(now)
	}
	sub := adaptertest.Subject{
		Adapter: a,
		Arrive:  func(r *http.Request) *http.Request { return r },
		Credential: func(*http.Request, string) error {
			return errors.New("the graph/1 cases name no credential")
		},
	}
	if rp != nil {
		sub.VerifyOutcome = verifier(&rp.Key.PublicKey)
	}
	return sub, nil
}

// commonSubject realizes a common/1 state (spec/v1.0/fixtures/adapters/graph/README.md):
// the reference adapter is the inbound authentication and the enrollment
// source, the claims, checks and policy come from the state, and each
// mapping's routes are installed as further routes.
func commonSubject(t testing.TB, env adaptertest.Env) (adaptertest.Subject, error) {
	st, err := memory.ParseState(env.State)
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
	acq, _, err := acquirers(formDelegated, uTID, uGatewayApp, "", nil, env.Clock)
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
		guard.Check(adapter.NativeClaim{SourceID: s.SourceID, SourceRef: s.SourceRef, ObservedAt: optTime(s.ObservedAt)})
	}
	a, err := graph.New(graph.Config{
		Form: graph.FormDelegated, Realm: adapter.Realm{TenantID: st.Gateway.TenantID, EnvironmentID: st.Gateway.EnvironmentID},
		Origin: st.Gateway.Origin, HeaderAllowlist: st.Gateway.HeaderAllowlist,
		Tenant: uTID, Acquirer: acq, Registry: fixtureRegistry{},
		Mappings: mappings, Authenticator: ref, Enrollments: referenceRegistry{ref}, Permissions: commonPolicy{rules: st.Policy},
		Claims: claims, Checks: checks, Guard: guard, Reporting: rp, ExecutionVisible: st.Visibility == "execution", Clock: env.Clock,
	})
	if err != nil {
		return adaptertest.Subject{}, err
	}
	sub := adaptertest.Subject{Adapter: a, Arrive: memory.Arrive, Credential: ref.Credential}
	if rp != nil {
		sub.VerifyOutcome = verifier(&rp.Key.PublicKey)
	}
	return sub, nil
}

// realBroker is the adapter as a broker of the unit tier.
type realBroker struct{ *graph.Adapter }

func (b realBroker) execute(ctx context.Context, in execInput) execution {
	res, err := b.Execute(ctx, graph.ExecuteInput{Request: in.req, Principal: in.principal, Operation: in.op, TaskID: in.task, AgentID: in.agent})
	status, h := graph.StatusOf(err)
	ex := execution{
		status: status, wwwAuthenticate: h.Get("WWW-Authenticate"), retryAfter: h.Get("Retry-After"),
		messages: res.Messages, pageToken: res.PageToken, mismatch: errors.Is(err, graph.ErrExecutorMismatch), err: err,
	}
	ex.code, _ = adapter.CodeOf(err)
	if o, ok := graph.OutcomeOf(res, err); ok {
		ex.report = &report{kind: o.EventKind, result: o.Result, dimension: o.Dimension, details: o.Details, evidence: o.EvidenceRefs}
	}
	return ex
}

func (b realBroker) preflight(ctx context.Context) { b.RunPreflight(ctx) }

// realBrokerFactory builds the adapter of a unit world, with the world's
// task ledger when it has one.
func realBrokerFactory(_ testing.TB, w *unitWorld) (broker, error) {
	acq, aud, err := acquirers(w.form, uTID, uGatewayApp, uExecApp, w.cloud.client, w.clk)
	if err != nil {
		return nil, err
	}
	store := graph.NewMemoryContinuations(nil)
	for _, c := range w.continuations {
		store.Put(c.PageToken, graph.Continuation{Row: graph.Row(c.Row), Principal: c.Principal, TaskID: c.TaskID, AgentID: c.AgentID, MappingVersion: c.MappingVersion, Link: c.Link})
	}
	cfg := graph.Config{
		Form: graph.Form(w.form), Realm: uRealm, Origin: uOrigin, Tenant: uTID, Acquirer: acq,
		Registry:      fixtureRegistry{records: w.registry, down: func() bool { return w.registryDown }},
		Continuations: store, HTTPClient: w.cloud.client,
		Authenticator: noFrontDoor{}, Enrollments: noEnrollments{}, Permissions: noPolicy{}, ExecutionVisible: true, Clock: w.clk,
	}
	if w.tasks != nil {
		cfg.Tasks = w.tasks
	}
	if w.frontDoor != nil {
		cfg.Authenticator = w.frontDoor
	}
	if w.form == formApplication {
		cfg.Preflight = &graph.PreflightConfig{Auditor: aud, RBAC: attestSource{func() *attestation { return w.attest }}}
	}
	a, err := graph.New(cfg)
	if err != nil {
		return nil, err
	}
	return realBroker{a}, nil
}

// verifier checks the ES256 signature of a compact JWS with key.
func verifier(key *ecdsa.PublicKey) func(string) error {
	return func(compact string) error {
		parts := strings.Split(compact, ".")
		if len(parts) != 3 {
			return errors.New("not a compact JWS")
		}
		sig, err := base64.RawURLEncoding.DecodeString(parts[2])
		if err != nil || len(sig) != 64 {
			return errors.New("malformed signature")
		}
		sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
		if !ecdsa.Verify(key, sum[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
			return errors.New("the signature does not verify")
		}
		return nil
	}
}

// reporting builds the signer of a state's reporting member with a fresh
// key; nil without one.
func reporting(r any) (*installed.Reporting, error) {
	var iss, aud, kid string
	switch v := r.(type) {
	case *reportingState:
		if v == nil {
			return nil, nil
		}
		iss, aud, kid = v.Issuer, v.Audience, v.KID
	case *memory.Reporting:
		if v == nil {
			return nil, nil
		}
		iss, aud, kid = v.Issuer, v.Audience, v.KID
	default:
		return nil, fmt.Errorf("reporting %T", r)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &installed.Reporting{Issuer: iss, Audience: aud, KID: kid, Key: key}, nil
}

// referenceRegistry is the enrollment source of a common/1 state.
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

func optTime(sec *int64) time.Time {
	if sec == nil {
		return time.Time{}
	}
	return time.Unix(*sec, 0)
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
			ObservedAt: optTime(r.ObservedAt), StatusCheckedAt: optTime(r.StatusCheckedAt),
			SourceID: r.SourceID, SourceRef: r.SourceRef,
		})
	}
	return out, nil
}

// commonCheck is an installed check of a common/1 state.
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
		ObservedAt: optTime(c.rec.ObservedAt), StatusCheckedAt: optTime(c.rec.StatusCheckedAt),
		Revision: c.rec.Revision,
	}, nil
}

// commonPolicy is the gateway policy of a common/1 state: a deny wins over
// an unknown and an unknown over an allow; no rule is a deny of the policy's
// own source.
type commonPolicy struct{ rules []memory.PolicyRule }

const ownPolicySource = "gateway-policy"

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
		SourceRef: best.SourceRef, DecidedAt: optTime(best.DecidedAt), PolicyRevision: best.PolicyRevision,
	}
	if d.SourceID == "" {
		d.SourceID = ownPolicySource
	}
	for _, o := range best.Obligations {
		d.Obligations = append(d.Obligations, adapter.Obligation{ID: o.ID, Attributes: o.Attributes})
	}
	return d, nil
}
