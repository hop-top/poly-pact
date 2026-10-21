package db_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"database/sql/driver"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/adaptertest"
	"hop.top/pact-go/adapter/enroll"
	"hop.top/pact-go/adapter/freshness"
	"hop.top/pact-go/adapters/db"
	"hop.top/pact-go/adapters/memory"
	"hop.top/pact-go/core"
	"hop.top/pact-go/core/clock"
)

func init() {
	conformanceFactory = dbFactory
	unitBroker = realBrokerFactory
}

// dbFactory builds the database adapter for a case: from the db/1 state of a
// database case or from the common/1 state of a common case.
func dbFactory(t testing.TB, env adaptertest.Env) (adaptertest.Subject, error) {
	model, err := modelOf(env.State)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	switch model {
	case dbModel:
		return dbSubject(t, env)
	case memory.Model:
		return commonSubject(t, env)
	}
	return adaptertest.Subject{}, fmt.Errorf("model %q is not realized", model)
}

// fixtureRegistry is a role and tenant registry over registry records.
type fixtureRegistry struct {
	cluster string
	records []dbRecord
	down    bool
}

func (r fixtureRegistry) Lookup(_ context.Context, realm adapter.Realm, principal string) (db.RoleRecord, error) {
	if r.down {
		return db.RoleRecord{}, errors.New("the role registry cannot answer")
	}
	for _, rec := range r.records {
		if rec.Principal == principal && rec.Realm.TenantID == realm.TenantID && rec.Realm.EnvironmentID == realm.EnvironmentID {
			out := db.RoleRecord{
				ClusterID: r.cluster, LoginRole: rec.LoginRole, RoleOID: uint32(rec.RoleOID), CredentialRef: rec.CredentialRef,
				TenantID: rec.TenantID, Revision: rec.Revision,
			}
			if rec.ChangedAt != 0 {
				out.ChangedAt = time.Unix(rec.ChangedAt, 0)
			}
			return out, nil
		}
	}
	return db.RoleRecord{}, db.ErrNoRecord
}

// fakeDialer opens connections of the fake cluster with the credentials of
// the secret store.
type fakeDialer struct {
	srv     *fakeServer
	secrets map[string]string
}

func (d fakeDialer) Connector(_ context.Context, rec db.RoleRecord) (driver.Connector, error) {
	secret, ok := d.secrets[rec.CredentialRef]
	if !ok {
		return nil, errors.New("no credential")
	}
	return d.srv.connector(rec.LoginRole, secret), nil
}

// noPolicy is the task policy of the db/1 cases, which call no
// authorize_native.
type noPolicy struct{}

func (noPolicy) Decide(context.Context, adapter.Principal, core.OperationContext) (adapter.Decision, error) {
	return adapter.Decision{Effect: adapter.EffectDeny, SourceID: "task-policy"}, nil
}

// noFrontDoor is the front door of the db/1 and unit cases, which
// authenticate nobody.
type noFrontDoor struct{}

func (noFrontDoor) AuthenticateNative(context.Context, *http.Request) (adapter.Principal, error) {
	return adapter.Principal{}, &adapter.NativeDenial{Reason: adapter.DenialNoCredential}
}

// noEnrollments is the enrollment registry of the db/1 and unit cases.
type noEnrollments struct{}

func (noEnrollments) Lookup(context.Context, adapter.Realm, adapter.Workload, adapter.AgentID) (adapter.AgentBinding, error) {
	return adapter.AgentBinding{Status: adapter.BindingUnknown}, nil
}

func (noEnrollments) Rotate(context.Context, enroll.Actor, string, core.Digest) error {
	return errors.New("read-only")
}

func (noEnrollments) MarkCompromised(context.Context, enroll.Actor, string) error {
	return errors.New("read-only")
}

// dbSubject realizes a db/1 state with the fake cluster.
func dbSubject(t testing.TB, env adaptertest.Env) (adaptertest.Subject, error) {
	st, err := parseState(env.State)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	srv := st.server(env.Hooks)
	secrets := map[string]string{}
	for _, c := range st.Credentials {
		secrets[c.Ref] = c.Secret
	}
	mappings := map[string][]db.Route{}
	var queries []db.Query
	for _, in := range st.Installed {
		mappings[in.Revision] = append(mappings[in.Revision], db.ReportRoutes()...)
		for range in.Queries {
			q := db.ReportQuery()
			q.Revision = in.Revision
			queries = append(queries, q)
		}
	}
	rp, err := reporting(st.Reporting)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	a, err := db.New(db.Config{
		Realm:            adapter.Realm{TenantID: st.Gateway.TenantID, EnvironmentID: st.Gateway.EnvironmentID},
		ClusterID:        st.ClusterID,
		Origin:           st.Gateway.Origin,
		HeaderAllowlist:  st.Gateway.HeaderAllowlist,
		Mappings:         mappings,
		Queries:          queries,
		Registry:         fixtureRegistry{cluster: st.ClusterID, records: st.Registry, down: st.down(sourceRegistry)},
		Dialer:           fakeDialer{srv: srv, secrets: secrets},
		OnExecute:        func() { env.Hooks.Fire("execute") },
		Authenticator:    noFrontDoor{},
		Enrollments:      noEnrollments{},
		Permissions:      noPolicy{},
		Reporting:        rp,
		ExecutionVisible: true,
		Clock:            env.Clock,
	})
	if err != nil {
		return adaptertest.Subject{}, err
	}
	t.Cleanup(func() { _ = a.Close() })
	sub := adaptertest.Subject{
		Adapter: a,
		Arrive:  func(r *http.Request) *http.Request { return r },
		Credential: func(*http.Request, string) error {
			return errors.New("the db/1 cases name no credential")
		},
	}
	if rp != nil {
		sub.VerifyOutcome = verifier(&rp.Key.PublicKey)
	}
	return sub, nil
}

// commonGrammar is the parameter grammar of the routes the harness installs
// for common/1 mappings: RB-34's unreserved characters, 1 to 64.
var commonGrammar = db.UnreservedPattern

// placeholderRE finds the placeholders of a path template.
var placeholderRE = regexp.MustCompile(`\{([^{}/]+)\}`)

// commonSubject realizes a common/1 state (spec/v1.0/fixtures/adapters/db/README.md):
// the reference adapter is the front door and the enrollment source, the
// claims, checks and policy come from the state, and each mapping's routes
// are installed with a query registry entry for each action.
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
	mappings := map[string][]db.Route{db.MappingRevision: db.ReportRoutes()}
	queries := []db.Query{db.ReportQuery()}
	seen := map[string]bool{}
	for _, m := range st.Mappings {
		for _, rt := range m.Routes {
			params := map[string]*regexp.Regexp{}
			var args []string
			for _, ph := range placeholderRE.FindAllStringSubmatch(rt.Path, -1) {
				params[ph[1]] = commonGrammar
				args = append(args, ph[1])
			}
			mappings[m.Version] = append(mappings[m.Version], db.Route{Method: rt.Method, Path: rt.Path, Action: rt.Action, Resource: rt.Resource, Params: params, AcceptsBody: true})
			if k := rt.Action + "|" + m.Version; !seen[k] {
				seen[k] = true
				queries = append(queries, db.Query{Action: rt.Action, Revision: m.Version, Text: commonText(len(args)), Args: args})
			}
		}
	}
	claims := map[string]db.ClaimSource{}
	for _, path := range st.ApprovedPaths {
		claims[path] = commonClaims{st: st}
	}
	checks := map[string]db.InstalledCheck{}
	for _, c := range st.Checks {
		ic := db.InstalledCheck{Check: commonCheck{rec: c, down: slices.Contains(st.UnavailableSources, c.SourceID)}, PinnedRevision: c.PinnedRevision}
		if f := c.Freshness; f != nil {
			ic.Freshness = &db.Freshness{MaxAgeSeconds: *f.MaxAgeSeconds, StatusMaxAgeSeconds: *f.StatusMaxAgeSeconds}
		}
		checks[c.ID] = ic
	}
	guard := freshness.NewMonotonic(len(st.Sightings) + 4096)
	for _, s := range st.Sightings {
		guard.Check(adapter.NativeClaim{SourceID: s.SourceID, SourceRef: s.SourceRef, ObservedAt: optTime(s.ObservedAt)})
	}
	srv := i13Server(env.Hooks)
	a, err := db.New(db.Config{
		Realm:            adapter.Realm{TenantID: st.Gateway.TenantID, EnvironmentID: st.Gateway.EnvironmentID},
		ClusterID:        "common-cluster",
		Origin:           st.Gateway.Origin,
		HeaderAllowlist:  st.Gateway.HeaderAllowlist,
		Mappings:         mappings,
		Queries:          queries,
		Registry:         fixtureRegistry{cluster: "common-cluster"},
		Dialer:           fakeDialer{srv: srv},
		OnExecute:        func() { env.Hooks.Fire("execute") },
		Authenticator:    ref,
		Enrollments:      referenceRegistry{ref},
		Permissions:      commonPolicy{rules: st.Policy},
		Claims:           claims,
		Checks:           checks,
		Guard:            guard,
		Reporting:        rp,
		ExecutionVisible: st.Visibility == "execution",
		Clock:            env.Clock,
	})
	if err != nil {
		return adaptertest.Subject{}, err
	}
	t.Cleanup(func() { _ = a.Close() })
	sub := adaptertest.Subject{Adapter: a, Arrive: memory.Arrive, Credential: ref.Credential}
	if rp != nil {
		sub.VerifyOutcome = verifier(&rp.Key.PublicKey)
	}
	return sub, nil
}

// commonText is a constant statement with n placeholders, for the query
// registry entries of common/1 routes; no common case executes it.
func commonText(n int) string {
	text := "SELECT 1"
	for i := range n {
		if i == 0 {
			text += " WHERE "
		} else {
			text += " AND "
		}
		text += fmt.Sprintf("$%d::text IS NOT NULL", i+1)
	}
	return text
}

// realBroker is the adapter as a broker of the unit tier.
type realBroker struct{ *db.Adapter }

func (b realBroker) execute(ctx context.Context, p adapter.Principal, op core.OperationContext) execution {
	res, err := b.Execute(ctx, p, op)
	o := db.OutcomeOf(res, err)
	ex := execution{
		rows: res.Rows, sessionUser: res.Executor.SessionUser, currentUser: res.Executor.CurrentUser,
		kind: o.EventKind, result: o.Result, dimension: o.Dimension, details: o.Details,
		mismatch: errors.Is(err, db.ErrExecutorMismatch), err: err,
	}
	ex.code, _ = adapter.CodeOf(err)
	return ex
}

// realBrokerFactory builds the adapter of a unit world.
func realBrokerFactory(t testing.TB, w *unitWorld) (broker, error) {
	a, err := db.New(db.Config{
		Realm:     unitRealm,
		ClusterID: "northstar-reports",
		Origin:    unitOrigin,
		Registry:  fixtureRegistry{cluster: "northstar-reports", records: w.registry, down: w.registryDown},
		Dialer:    fakeDialer{srv: w.srv, secrets: w.secrets},
		OnExecute: func() {
			if w.onExecute != nil {
				w.onExecute()
			}
			w.hooks.Fire("execute")
		},
		Authenticator:    noFrontDoor{},
		Enrollments:      noEnrollments{},
		Permissions:      noPolicy{},
		ExecutionVisible: true,
		Clock:            clock.NewFake(w.now),
	})
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() { _ = a.Close() })
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

// reportingConfig is the reporting member of a state.
type reportingConfig interface {
	fields() (issuer, audience, kid string)
}

func (r *dbReporting) fields() (string, string, string) { return r.Issuer, r.Audience, r.KID }

type memReporting struct{ r *memory.Reporting }

func (m memReporting) fields() (string, string, string) { return m.r.Issuer, m.r.Audience, m.r.KID }

// reporting builds the signer of a state's reporting member, with a fresh
// key; nil without one.
func reporting(r any) (*db.Reporting, error) {
	var rc reportingConfig
	switch v := r.(type) {
	case *dbReporting:
		if v == nil {
			return nil, nil
		}
		rc = v
	case *memory.Reporting:
		if v == nil {
			return nil, nil
		}
		rc = memReporting{v}
	default:
		return nil, fmt.Errorf("reporting %T", r)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	iss, aud, kid := rc.fields()
	return &db.Reporting{Issuer: iss, Audience: aud, KID: kid, Key: key}, nil
}

// referenceRegistry is the enrollment source of a common/1 state: the
// lookup of the reference adapter, with dedicated workloads.
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

func (c commonClaims) Claims(_ context.Context, realm adapter.Realm, principal, path string) ([]db.ClaimRecord, error) {
	var out []db.ClaimRecord
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
		out = append(out, db.ClaimRecord{
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

func (c commonCheck) Consult(_ context.Context, in adapter.CheckInput) (db.CheckRecord, error) {
	if !c.rec.Applies(in) {
		return db.CheckRecord{Result: adapter.VerdictFail, ReasonCode: memory.CodeApprovalScopeMismatch, SourceID: c.rec.SourceID}, nil
	}
	if c.down {
		return db.CheckRecord{SourceID: c.rec.SourceID}, fmt.Errorf("source %s cannot answer: %w", c.rec.SourceID, adapter.ErrDependencyUnavailable)
	}
	return db.CheckRecord{
		Result: adapter.Verdict(c.rec.Result), ReasonCode: c.rec.ReasonCode,
		SourceID: c.rec.SourceID, SourceRef: c.rec.SourceRef,
		ObservedAt: optTime(c.rec.ObservedAt), StatusCheckedAt: optTime(c.rec.StatusCheckedAt),
		Revision: c.rec.Revision,
	}, nil
}

// commonPolicy is the task policy of a common/1 state: a deny wins over an
// unknown and an unknown over an allow; no rule is a deny of the policy's
// own source.
type commonPolicy struct{ rules []memory.PolicyRule }

const ownPolicySource = "task-policy"

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
