package rebac_test

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
	"io/fs"
	"math/big"
	"net/http"
	"path"
	"slices"
	"strings"
	"testing"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/adaptertest"
	"hop.top/pact-go/adapter/enroll"
	"hop.top/pact-go/adapter/freshness"
	"hop.top/pact-go/adapters/memory"
	"hop.top/pact-go/adapters/rebac"
	"hop.top/pact-go/core"
)

// storeTimeout is the time limit of a Check in the unit tier: short, so that
// the hanging store of REBAC-06.timeout fails fast.
const storeTimeout = 300 * time.Millisecond

// rebacFactory builds the ReBAC adapter for a case: from the rebac/1 state of
// a ReBAC case or from the common/1 state of a common case. The fixtures
// realize the gateway's native systems and the OpenFGA server; the adapter is
// the package's.
func rebacFactory(t testing.TB, env adaptertest.Env) (adaptertest.Subject, error) {
	model, err := modelOf(env.State)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	switch model {
	case rebacModel:
		return rebacSubject(t, env)
	case memory.Model:
		return commonSubject(t, env)
	}
	return adaptertest.Subject{}, fmt.Errorf("model %q is not realized", model)
}

// rebacSubject realizes a rebac/1 state with the fake store.
func rebacSubject(t testing.TB, env adaptertest.Env) (adaptertest.Subject, error) {
	fsys, err := fixtures()
	if err != nil {
		return adaptertest.Subject{}, err
	}
	w, err := loadWorld(env.State, fsys)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	store, err := newFakeStore(w, env.Hooks)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	t.Cleanup(store.Close)
	a, err := newAdapter(w, store.url, store.Client(), env)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	return adaptertest.Subject{
		Adapter: a,
		Arrive:  func(r *http.Request) *http.Request { return r },
		Credential: func(*http.Request, string) error {
			return errors.New("the rebac/1 cases name no credential")
		},
	}, nil
}

// newAdapter builds the adapter of a rebac/1 world against the store at url.
func newAdapter(w *world, url string, client *http.Client, env adaptertest.Env) (*rebac.Adapter, error) {
	st := w.st
	realm := adapter.Realm{TenantID: st.Gateway.TenantID, EnvironmentID: st.Gateway.EnvironmentID}
	reg, err := registryOf(st)
	if err != nil {
		return nil, err
	}
	mappings := map[string][]rebac.Route{}
	for _, m := range st.Mappings {
		for _, rt := range m.Routes {
			mappings[m.Version] = append(mappings[m.Version], rebac.Route{Method: rt.Method, Path: rt.Path, Action: rt.Action, Resource: rt.Resource})
		}
	}
	var table []rebac.Relation
	for _, r := range st.Relations {
		table = append(table, rebac.Relation{Action: r.Action, Relation: r.Relation, ObjectType: r.ObjectType})
	}
	ref, err := memory.New(memory.State{Model: memory.Model, Gateway: st.Gateway}, env.Clock)
	if err != nil {
		return nil, err
	}
	return rebac.New(rebac.Config{
		Realm:           realm,
		Origin:          st.Gateway.Origin,
		HeaderAllowlist: st.Gateway.HeaderAllowlist,
		Mappings:        mappings,
		Relations:       map[string][]rebac.Relation{st.Pin.MappingRevision: table},
		Pin:             rebac.Pin{StoreID: st.Pin.StoreID, AuthorizationModelID: st.Pin.AuthorizationModelID, MappingRevision: st.Pin.MappingRevision},
		Registry:        reg,
		Store:           rebac.Store{URL: url, Credential: st.StoreCredential, Client: client, Timeout: storeTimeout},
		Authenticator:   ref,
		Enrollments:     referenceRegistry{ref},
		Clock:           env.Clock,
	})
}

func registryOf(st rebacState) (*rebac.StaticRegistry, error) {
	var subjects []rebac.SubjectEntry
	for _, s := range st.Subjects {
		subjects = append(subjects, rebac.SubjectEntry{Realm: adapter.Realm(s.Realm), Principal: s.Principal, SubjectID: s.SubjectID})
	}
	var objects []rebac.ObjectEntry
	for _, o := range st.Objects {
		objects = append(objects, rebac.ObjectEntry{Realm: adapter.Realm(o.Realm), Resource: o.Resource, ObjectID: o.ObjectID})
	}
	return rebac.NewStaticRegistry(subjects, objects)
}

// The store, model and mapping of the common cases' harness.
const (
	commonStore    = "01JC0MM0N0STARE0000000000A"
	commonModel    = "01JC0MM0N0MDE10000000000AB"
	commonRevision = "pact-rebac-common"
)

// commonRoutes are the routes the harness supplies for the operations the
// common authorize_native cases name: an invoice read and an invoice
// approval, on the invoice resource.
var commonRoutes = []rebac.Route{
	{Method: http.MethodGet, Path: "/invoices/{invoice_id}", Action: "invoice.read", Resource: "https://invoices.example/invoices/{invoice_id}"},
	{Method: http.MethodPost, Path: "/invoices/{invoice_id}/approve", Action: "invoice.approve", Resource: "https://invoices.example/invoices/{invoice_id}"},
}

// commonRelations are the rows the harness supplies for those actions, on
// the relations of the reference model.
var commonRelations = []rebac.Relation{
	{Action: "invoice.read", Relation: "viewer", ObjectType: "document"},
	{Action: "invoice.approve", Relation: "editor", ObjectType: "document"},
}

// commonSubject realizes a common/1 state (spec/v1.0/fixtures/adapters/rebac/README.md):
// the reference adapter is the deployment's identity mechanism and its
// enrollment source; claims, checks and reporting come from the state; the
// policy becomes tuples of a fake store under the reference model, with the
// registry entries of the principals and resources the policy names.
func commonSubject(t testing.TB, env adaptertest.Env) (adaptertest.Subject, error) {
	st, err := memory.ParseState(env.State)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	ref, err := memory.New(st, env.Clock)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	fsys, err := fixtures()
	if err != nil {
		return adaptertest.Subject{}, err
	}
	w, err := commonWorld(st, fsys)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	store, err := newFakeStore(w, env.Hooks)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	t.Cleanup(store.Close)
	reg, err := registryOf(w.st)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	rp, err := reporting(st.Reporting)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	mappings := map[string][]rebac.Route{commonRevision: commonRoutes}
	for _, m := range st.Mappings {
		for _, rt := range m.Routes {
			mappings[m.Version] = append(mappings[m.Version], rebac.Route{Method: rt.Method, Path: rt.Path, Action: rt.Action, Resource: rt.Resource})
		}
	}
	claims := map[string]rebac.ClaimSource{}
	for _, path := range st.ApprovedPaths {
		claims[path] = commonClaims{st: st}
	}
	checks := map[string]rebac.InstalledCheck{}
	for _, c := range st.Checks {
		ic := rebac.InstalledCheck{Check: commonCheck{rec: c, down: slices.Contains(st.UnavailableSources, c.SourceID)}, PinnedRevision: c.PinnedRevision}
		if f := c.Freshness; f != nil {
			ic.Freshness = &rebac.Freshness{MaxAgeSeconds: *f.MaxAgeSeconds, StatusMaxAgeSeconds: *f.StatusMaxAgeSeconds}
		}
		checks[c.ID] = ic
	}
	guard := freshness.NewMonotonic(len(st.Sightings) + 4096)
	for _, s := range st.Sightings {
		guard.Check(adapter.NativeClaim{SourceID: s.SourceID, SourceRef: s.SourceRef, ObservedAt: unixTime(s.ObservedAt)})
	}
	a, err := rebac.New(rebac.Config{
		Realm:            adapter.Realm{TenantID: st.Gateway.TenantID, EnvironmentID: st.Gateway.EnvironmentID},
		Origin:           st.Gateway.Origin,
		HeaderAllowlist:  st.Gateway.HeaderAllowlist,
		Mappings:         mappings,
		Relations:        map[string][]rebac.Relation{commonRevision: commonRelations},
		Pin:              rebac.Pin{StoreID: commonStore, AuthorizationModelID: commonModel, MappingRevision: commonRevision},
		Registry:         reg,
		Store:            rebac.Store{URL: store.url, Client: store.Client(), Timeout: storeTimeout},
		Authenticator:    ref,
		Enrollments:      referenceRegistry{ref},
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
	sub := adaptertest.Subject{Adapter: a, Arrive: memory.Arrive, Credential: ref.Credential}
	if rp != nil {
		sub.VerifyOutcome = verifier(&rp.Key.PublicKey)
	}
	return sub, nil
}

// commonWorld is the store of a common/1 policy under the reference model:
// each ALLOW rule is a direct tuple on the relation of its action, unless a
// DENY rule of the same principal, action and resource removes it; DENY,
// UNKNOWN and absent rules are no tuple. Each principal and resource the
// policy names gets a registry entry in the rule's realm.
func commonWorld(st memory.State, fsys fs.FS) (*world, error) {
	src, err := fs.ReadFile(fsys, path.Join(casesDir, "assets", "model.fga"))
	if err != nil {
		return nil, err
	}
	m, err := parseModel(src)
	if err != nil {
		return nil, err
	}
	relation := map[string]rebac.Relation{}
	for _, r := range commonRelations {
		relation[r.Action] = r
	}
	w := &world{models: map[string]*fgaModel{commonModel: m}, latest: commonModel}
	w.st.Store.ID = commonStore
	subjects, objects := map[memory.Realm]map[string]bool{}, map[memory.Realm]map[string]bool{}
	denied := map[string]bool{}
	key := func(r memory.PolicyRule) string {
		return r.Realm.TenantID + "|" + r.Realm.EnvironmentID + "|" + r.Principal + "|" + r.Action + "|" + r.Resource
	}
	for _, r := range st.Policy {
		if r.Effect == "DENY" {
			denied[key(r)] = true
		}
	}
	for _, r := range st.Policy {
		if subjects[r.Realm] == nil {
			subjects[r.Realm], objects[r.Realm] = map[string]bool{}, map[string]bool{}
		}
		if !subjects[r.Realm][r.Principal] {
			subjects[r.Realm][r.Principal] = true
			w.st.Subjects = append(w.st.Subjects, subjectEntry{Realm: r.Realm, Principal: r.Principal, SubjectID: opaqueID("s", r.Realm, r.Principal)})
		}
		if r.Resource != "" && !objects[r.Realm][r.Resource] {
			objects[r.Realm][r.Resource] = true
			w.st.Objects = append(w.st.Objects, objectEntry{Realm: r.Realm, Resource: r.Resource, ObjectID: opaqueID("o", r.Realm, r.Resource)})
		}
		rel, ok := relation[r.Action]
		if r.Effect != "ALLOW" || !ok || r.Resource == "" || denied[key(r)] {
			continue
		}
		w.st.Store.Tuples = append(w.st.Store.Tuples, tupleKey{
			User: "user:" + opaqueID("s", r.Realm, r.Principal), Relation: rel.Relation,
			Object: rel.ObjectType + ":" + opaqueID("o", r.Realm, r.Resource),
		})
	}
	return w, nil
}

// opaqueID is a registry id of the form of profile RB-6 for a name of a
// realm: a prefix and a digest, so that it carries no name (RB-6).
func opaqueID(prefix string, realm memory.Realm, name string) string {
	sum := sha256.Sum256([]byte(realm.TenantID + "\x00" + realm.EnvironmentID + "\x00" + name))
	return prefix + "-" + hex.EncodeToString(sum[:10])
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

func reporting(r *memory.Reporting) (*rebac.Reporting, error) {
	if r == nil {
		return nil, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &rebac.Reporting{Issuer: r.Issuer, Audience: r.Audience, KID: r.KID, Key: key}, nil
}

// commonClaims is the claim source of a common/1 state.
type commonClaims struct{ st memory.State }

func (c commonClaims) Claims(_ context.Context, realm adapter.Realm, principal, path string) ([]rebac.ClaimRecord, error) {
	var out []rebac.ClaimRecord
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
		out = append(out, rebac.ClaimRecord{
			Value: v, Resource: r.Resource, TaskID: r.TaskID,
			ObservedAt: unixTime(r.ObservedAt), StatusCheckedAt: unixTime(r.StatusCheckedAt),
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

func (c commonCheck) Consult(_ context.Context, in adapter.CheckInput) (rebac.CheckRecord, error) {
	if !c.rec.Applies(in) {
		return rebac.CheckRecord{Result: adapter.VerdictFail, ReasonCode: memory.CodeApprovalScopeMismatch, SourceID: c.rec.SourceID}, nil
	}
	if c.down {
		return rebac.CheckRecord{SourceID: c.rec.SourceID}, fmt.Errorf("source %s cannot answer: %w", c.rec.SourceID, adapter.ErrDependencyUnavailable)
	}
	return rebac.CheckRecord{
		Result: adapter.Verdict(c.rec.Result), ReasonCode: c.rec.ReasonCode,
		SourceID: c.rec.SourceID, SourceRef: c.rec.SourceRef,
		ObservedAt: unixTime(c.rec.ObservedAt), StatusCheckedAt: unixTime(c.rec.StatusCheckedAt),
		Revision: c.rec.Revision,
	}, nil
}
