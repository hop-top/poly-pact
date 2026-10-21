package rebac_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/adaptertest"
	"hop.top/pact-go/adapters/memory"
	"hop.top/pact-go/adapters/rebac"
	"hop.top/pact-go/core"
	"hop.top/pact-go/core/clock"
)

const (
	unitStore = "01JAB2C3D4E5F6G7H8J9K0MNPQ"
	unitModel = "01JAB2C3D4E5F6G7H8J9K0MNPR"
	unitEnv   = "https://gateway.northstar.example/environments/collaboration"
	unitMaya  = "https://idp.northstar.example/users/maya"
	unitDoc   = "https://docs.northstar.example/documents/orion-brief"
	unitKey   = "fga-preshared-unit-4f1a"
)

var unitRealm = adapter.Realm{TenantID: "northstar", EnvironmentID: unitEnv}

// recorder is an OpenFGA Check endpoint that records each request and
// answers with status and body.
type recorder struct {
	mu      sync.Mutex
	status  int
	body    string
	header  http.Header
	path    string
	request map[string]json.RawMessage
	calls   int
}

func (rc *recorder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	rc.mu.Lock()
	rc.calls++
	rc.header, rc.path = r.Header.Clone(), r.URL.Path
	rc.request = nil
	_ = json.Unmarshal(raw, &rc.request)
	status, body := rc.status, rc.body
	rc.mu.Unlock()
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}

func unitConfig(t *testing.T, url string, client *http.Client) rebac.Config {
	t.Helper()
	reg, err := rebac.NewStaticRegistry(
		[]rebac.SubjectEntry{{Realm: unitRealm, Principal: unitMaya, SubjectID: "u-0042"}},
		[]rebac.ObjectEntry{{Realm: unitRealm, Resource: unitDoc, ObjectID: "northstar.orion-brief"}},
	)
	if err != nil {
		t.Fatal(err)
	}
	clk := clock.NewFake(time.Unix(1792080000, 0))
	ref, err := memory.New(memory.State{Model: memory.Model, Gateway: memory.Gateway{TenantID: "northstar", EnvironmentID: unitEnv, Origin: "https://gateway.northstar.example"}}, clk)
	if err != nil {
		t.Fatal(err)
	}
	return rebac.Config{
		Realm:         unitRealm,
		Origin:        "https://gateway.northstar.example",
		Mappings:      map[string][]rebac.Route{rebac.MappingRevision: rebac.DocumentRoutes("https://docs.northstar.example/documents/{document_id}")},
		Pin:           rebac.Pin{StoreID: unitStore, AuthorizationModelID: unitModel, MappingRevision: rebac.MappingRevision},
		Registry:      reg,
		Store:         rebac.Store{URL: url, Credential: unitKey, Client: client, Timeout: time.Second},
		Authenticator: ref,
		Enrollments:   referenceRegistry{ref},
		Clock:         clk,
	}
}

func unitPrincipal() adapter.Principal {
	return adapter.Principal{ID: unitMaya, Realm: unitRealm, Workload: "https://workloads.northstar.example/research-assistant", Mechanism: "bearer"}
}

func unitOp(method, action string) core.OperationContext {
	return core.OperationContext{
		OperationID: "op-1", EnvironmentID: unitEnv, PrincipalID: unitMaya, Action: action,
		Resources: []string{unitDoc}, Method: method,
		TargetURI:  "https://gateway.northstar.example/documents/orion-brief",
		BodyDigest: "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU", Headers: map[string]string{},
	}
}

func newUnit(t *testing.T, status int, body string) (*rebac.Adapter, *recorder) {
	t.Helper()
	rc := &recorder{status: status, body: body}
	srv := httptest.NewTLSServer(rc)
	t.Cleanup(srv.Close)
	a, err := rebac.New(unitConfig(t, srv.URL, srv.Client()))
	if err != nil {
		t.Fatal(err)
	}
	return a, rc
}

// TestCheckRequest pins the Check of profile RB-2, RB-5, RB-7, RB-9 and
// RB-19, with the example of section 11.6: the pinned store in the path, the
// pre-shared key, the mapped subject and object, the relation of the action,
// the pinned model, HIGHER_CONSISTENCY, and nothing else.
func TestCheckRequest(t *testing.T) {
	for _, tc := range []struct {
		method, action, relation string
	}{
		{http.MethodGet, rebac.ActionRead, "viewer"},
		{http.MethodPatch, rebac.ActionWrite, "editor"},
	} {
		a, rc := newUnit(t, http.StatusOK, `{"allowed":true,"resolution":""}`)
		d, err := a.AuthorizeNative(context.Background(), unitPrincipal(), unitOp(tc.method, tc.action))
		if err != nil || d.Effect != adapter.EffectAllow {
			t.Fatalf("%s: decision %+v, error %v", tc.action, d, err)
		}
		if rc.path != "/stores/"+unitStore+"/check" {
			t.Errorf("%s: path %q", tc.action, rc.path)
		}
		if got := rc.header.Get("Authorization"); got != "Bearer "+unitKey {
			t.Errorf("%s: Authorization %q", tc.action, got)
		}
		want := map[string]string{
			"tuple_key":              `{"user":"user:u-0042","relation":"` + tc.relation + `","object":"document:northstar.orion-brief"}`,
			"authorization_model_id": `"` + unitModel + `"`,
			"consistency":            `"HIGHER_CONSISTENCY"`,
		}
		if len(rc.request) != len(want) {
			t.Errorf("%s: request members %v, want exactly %v", tc.action, keys(rc.request), keys(want))
		}
		for k, v := range want {
			if string(rc.request[k]) != v {
				t.Errorf("%s: %s is %s, want %s", tc.action, k, rc.request[k], v)
			}
		}
	}
}

func keys[V any](m map[string]V) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestDecisionProvenance checks REBAC-12 for both answers of a Check: the
// store as source, the model as revision, and no source reference, decision
// time or obligations (profile section 15).
func TestDecisionProvenance(t *testing.T) {
	for _, allowed := range []bool{true, false} {
		body := `{"allowed":false}`
		if allowed {
			body = `{"allowed":true}`
		}
		a, _ := newUnit(t, http.StatusOK, body)
		d, err := a.AuthorizeNative(context.Background(), unitPrincipal(), unitOp(http.MethodGet, rebac.ActionRead))
		if err != nil {
			t.Fatal(err)
		}
		if d.SourceID != unitStore || d.PolicyRevision != unitModel || d.SourceRef != "" || !d.DecidedAt.IsZero() || d.Obligations != nil {
			t.Errorf("allowed %v: decision %+v", allowed, d)
		}
		if d.Permits() != allowed {
			t.Errorf("allowed %v: Permits() = %v", allowed, d.Permits())
		}
	}
}

// TestAnswers maps the outcomes of a Check to results (profile RB-13).
func TestAnswers(t *testing.T) {
	for _, tc := range []struct {
		status int
		body   string
		want   error
	}{
		{http.StatusOK, `{"allowed":true,"extra":{"a":1}}`, nil},
		{http.StatusOK, ` {"allowed" : false} `, nil},
		{http.StatusOK, `{"allowed":null}`, adapter.ErrDependencyUnavailable},
		{http.StatusOK, `{"allowed":1}`, adapter.ErrDependencyUnavailable},
		{http.StatusOK, `{"allowed":true,"resolution":""}`, nil},
		{http.StatusOK, `{"allowed":true,"resolution":1}`, adapter.ErrDependencyUnavailable},
		{http.StatusOK, `[true]`, adapter.ErrDependencyUnavailable},
		{http.StatusOK, `{"allowed":true,"allowed":true}`, adapter.ErrDependencyUnavailable},
		{http.StatusOK, `{"allowed":true}` + strings.Repeat(" ", 70<<10), adapter.ErrDependencyUnavailable},
		{http.StatusTemporaryRedirect, ``, adapter.ErrDependencyUnavailable},
		{http.StatusNoContent, ``, adapter.ErrDependencyUnavailable},
		{http.StatusServiceUnavailable, ``, adapter.ErrDependencyUnavailable},
		{http.StatusBadRequest, `{"code":"authorization_model_not_found","message":"x"}`, adapter.ErrUnsupportedRequirement},
		{http.StatusNotFound, ``, adapter.ErrUnsupportedRequirement},
	} {
		a, _ := newUnit(t, tc.status, tc.body)
		_, err := a.AuthorizeNative(context.Background(), unitPrincipal(), unitOp(http.MethodGet, rebac.ActionRead))
		switch {
		case tc.want == nil && err != nil:
			t.Errorf("%d %.40q: error %v", tc.status, tc.body, err)
		case tc.want != nil && !errors.Is(err, tc.want):
			t.Errorf("%d %.40q: error %v, want %v", tc.status, tc.body, err, tc.want)
		}
		if err != nil && strings.Contains(err.Error(), unitKey) {
			t.Errorf("%d: the error names the key: %v", tc.status, err)
		}
	}
}

// TestNoRedirect checks that a redirect is not followed, whatever the
// configured client says.
func TestNoRedirect(t *testing.T) {
	target := &recorder{status: http.StatusOK, body: `{"allowed":true}`}
	tsrv := httptest.NewTLSServer(target)
	t.Cleanup(tsrv.Close)
	rsrv := httptest.NewTLSServer(http.RedirectHandler(tsrv.URL+"/stores/"+unitStore+"/check", http.StatusTemporaryRedirect))
	t.Cleanup(rsrv.Close)
	client := rsrv.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return nil }
	a, err := rebac.New(unitConfig(t, rsrv.URL, client))
	if err != nil {
		t.Fatal(err)
	}
	_, err = a.AuthorizeNative(context.Background(), unitPrincipal(), unitOp(http.MethodGet, rebac.ActionRead))
	if !errors.Is(err, adapter.ErrDependencyUnavailable) || target.calls != 0 {
		t.Errorf("error %v, %d calls at the redirect target", err, target.calls)
	}
}

// TestNoCheckBeforeMapping lists refusals that send no Check.
func TestNoCheckBeforeMapping(t *testing.T) {
	other := unitOp(http.MethodGet, rebac.ActionRead)
	other.TargetURI = "https://other.example/documents/orion-brief"
	wrongRes := unitOp(http.MethodGet, rebac.ActionRead)
	wrongRes.Resources = []string{unitDoc, "https://docs.northstar.example/documents/other"}
	otherPrincipal := unitOp(http.MethodGet, rebac.ActionRead)
	otherPrincipal.PrincipalID = "https://idp.northstar.example/users/ravi"
	unknown := unitPrincipal()
	unknown.ID = "https://idp.northstar.example/users/ravi"
	unknownOp := unitOp(http.MethodGet, rebac.ActionRead)
	unknownOp.PrincipalID = unknown.ID
	for _, tc := range []struct {
		name string
		p    adapter.Principal
		op   core.OperationContext
		want error
	}{
		{"another origin", unitPrincipal(), other, adapter.ErrUnsupportedRequirement},
		{"two resources", unitPrincipal(), wrongRes, adapter.ErrContextMismatch},
		{"operation of another principal", unitPrincipal(), otherPrincipal, adapter.ErrContextMismatch},
		{"principal without a subject", unknown, unknownOp, adapter.ErrContextMismatch},
		{"no principal", adapter.Principal{Realm: unitRealm}, unitOp(http.MethodGet, rebac.ActionRead), adapter.ErrContextMismatch},
	} {
		a, rc := newUnit(t, http.StatusOK, `{"allowed":true}`)
		_, err := a.AuthorizeNative(context.Background(), tc.p, tc.op)
		if !errors.Is(err, tc.want) || rc.calls != 0 {
			t.Errorf("%s: error %v, %d Checks; want %v and none", tc.name, err, rc.calls, tc.want)
		}
	}
}

// TestConfigRefusals checks that New refuses what the profile forbids.
func TestConfigRefusals(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*rebac.Config)
	}{
		{"no model id", func(c *rebac.Config) { c.Pin.AuthorizationModelID = "" }},
		{"model id not a ULID", func(c *rebac.Config) { c.Pin.AuthorizationModelID = "latest" }},
		{"store id with a slash", func(c *rebac.Config) { c.Pin.StoreID = "01JAB2C3D4E5F6G7H8J9K0MN/Q" }},
		{"cleartext store", func(c *rebac.Config) { c.Store.URL = "http://openfga.example:8080" }},
		{"store URL with userinfo", func(c *rebac.Config) { c.Store.URL = "https://u:p@openfga.example" }},
		{"no mapping of the pin", func(c *rebac.Config) { c.Pin.MappingRevision = "pact-rebac-9" }},
		{"no relation table", func(c *rebac.Config) { c.Relations = map[string][]rebac.Relation{} }},
		{"relation with a hash", func(c *rebac.Config) {
			c.Relations = map[string][]rebac.Relation{rebac.MappingRevision: {{Action: "a", Relation: "viewer#x", ObjectType: "document"}}}
		}},
		{"two rows for an action", func(c *rebac.Config) {
			c.Relations = map[string][]rebac.Relation{rebac.MappingRevision: append(rebac.DocumentRelations(), rebac.DocumentRelations()[0])}
		}},
		{"no authenticator", func(c *rebac.Config) { c.Authenticator = nil }},
		{"no registry", func(c *rebac.Config) { c.Registry = nil }},
	} {
		cfg := unitConfig(t, "https://openfga.example", nil)
		tc.edit(&cfg)
		if _, err := rebac.New(cfg); err == nil {
			t.Errorf("%s: New succeeded", tc.name)
		}
	}
	cfg := unitConfig(t, "http://127.0.0.1:8080/", nil)
	if _, err := rebac.New(cfg); err != nil {
		t.Errorf("loopback http: %v", err)
	}
}

// TestRegistry checks the form and the uniqueness rules of RB-6.
func TestRegistry(t *testing.T) {
	other := adapter.Realm{TenantID: "globex", EnvironmentID: unitEnv}
	if _, err := rebac.NewStaticRegistry([]rebac.SubjectEntry{
		{Realm: unitRealm, Principal: "a", SubjectID: "u-1"},
		{Realm: other, Principal: "a", SubjectID: "u-1"},
	}, nil); err != nil {
		t.Errorf("one subject id in two realms: %v", err)
	}
	for _, tc := range []struct {
		name string
		s    []rebac.SubjectEntry
		o    []rebac.ObjectEntry
	}{
		{"shared subject id", []rebac.SubjectEntry{{Realm: unitRealm, Principal: "a", SubjectID: "u-1"}, {Realm: unitRealm, Principal: "b", SubjectID: "u-1"}}, nil},
		{"principal twice", []rebac.SubjectEntry{{Realm: unitRealm, Principal: "a", SubjectID: "u-1"}, {Realm: unitRealm, Principal: "a", SubjectID: "u-2"}}, nil},
		{"userset subject", []rebac.SubjectEntry{{Realm: unitRealm, Principal: "a", SubjectID: "group:x#member"}}, nil},
		{"wildcard subject", []rebac.SubjectEntry{{Realm: unitRealm, Principal: "a", SubjectID: "*"}}, nil},
		{"long subject", []rebac.SubjectEntry{{Realm: unitRealm, Principal: "a", SubjectID: strings.Repeat("u", 508)}}, nil},
		{"object with a colon", nil, []rebac.ObjectEntry{{Realm: unitRealm, Resource: "r", ObjectID: "document:x"}}},
		{"object twice", nil, []rebac.ObjectEntry{{Realm: unitRealm, Resource: "r", ObjectID: "x"}, {Realm: unitRealm, Resource: "r", ObjectID: "y"}}},
	} {
		if _, err := rebac.NewStaticRegistry(tc.s, tc.o); err == nil {
			t.Errorf("%s: accepted", tc.name)
		}
	}
}

// TestMapOperation maps routes R1 and R2 of revision pact-rebac-1 and keeps
// the body for the next reader.
func TestMapOperation(t *testing.T) {
	a, _ := newUnit(t, http.StatusOK, `{"allowed":true}`)
	for _, tc := range []struct{ method, action string }{
		{http.MethodGet, rebac.ActionRead}, {http.MethodPatch, rebac.ActionWrite},
	} {
		body := ""
		if tc.method == http.MethodPatch {
			body = `{"title":"x"}`
		}
		r := httptest.NewRequest(tc.method, "https://gateway.northstar.example/documents/orion-brief", strings.NewReader(body))
		if body != "" {
			r.Header.Set("Content-Type", "application/json")
		}
		op, err := a.MapOperation(context.Background(), r, unitPrincipal(), rebac.MappingRevision)
		if err != nil || op.Action != tc.action || len(op.Resources) != 1 || op.Resources[0] != unitDoc {
			t.Errorf("%s: %+v, %v", tc.method, op, err)
		}
		if got, _ := io.ReadAll(r.Body); string(got) != body {
			t.Errorf("%s: body reads back as %q", tc.method, got)
		}
	}
	if d := a.Describe(); d.Protocol != "openfga-http" || d.Version != "1.x" || d.MappingRevision != "pact-rebac-1" {
		t.Errorf("Describe() = %+v", d)
	}
}

// membershipOnly is the mutant of the conformance task: the adapter, except
// that it denies when the stored membership of the document's project is
// absent, ignoring direct shares.
type membershipOnly struct {
	adapter.Adapter
	w *world
}

func (m membershipOnly) AuthorizeNative(ctx context.Context, p adapter.Principal, op core.OperationContext) (adapter.Decision, error) {
	d, err := m.Adapter.AuthorizeNative(ctx, p, op)
	if err != nil || !d.Permits() {
		return d, err
	}
	subject := "user:" + m.w.subject(memory.Realm(p.Realm), p.ID)
	object := "document:" + m.w.object(memory.Realm(p.Realm), op.Resources[0])
	for _, parent := range m.w.st.Store.Tuples {
		for _, k := range m.w.st.Store.Tuples {
			if parent.Relation == "parent" && parent.Object == object && k.Relation == "member" && k.Object == parent.User && k.User == subject {
				return d, nil
			}
		}
	}
	d.Effect = adapter.EffectDeny
	return d, nil
}

// TestMembershipMutantFailsDirectShare is the mutation rule of the ReBAC
// cases: the membership-only mutant fails REBAC-05.direct-share, and passes
// the cases that a stored membership decides.
func TestMembershipMutantFailsDirectShare(t *testing.T) {
	mutant := func(t testing.TB, env adaptertest.Env) (adaptertest.Subject, error) {
		sub, err := rebacFactory(t, env)
		if err != nil || !strings.Contains(string(env.State), `"rebac/1"`) {
			return sub, err
		}
		fsys, err := fixtures()
		if err != nil {
			return sub, err
		}
		w, err := loadWorld(env.State, fsys)
		if err != nil {
			return sub, err
		}
		sub.Adapter = membershipOnly{Adapter: sub.Adapter, w: w}
		return sub, nil
	}
	results, err := adaptertest.Evaluate(t, mutant, adaptertest.Options{Adapter: "rebac"})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range results {
		switch r.ID {
		case "REBAC-05.direct-share":
			if r.Passed() {
				t.Error("REBAC-05.direct-share passes against the membership-only mutant")
			}
		case "REBAC-10", "REBAC-04.added-membership", "REBAC-02.pinned-model", "REBAC-05.no-remaining-path":
			if !r.Passed() {
				t.Errorf("%s fails against the membership-only mutant: %v", r.ID, r.Failures)
			}
		}
	}
}
