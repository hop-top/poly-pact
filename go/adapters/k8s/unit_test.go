package k8s_test

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/adaptertest"
	"hop.top/pact-go/adapters/k8s"
	"hop.top/pact-go/adapters/memory"
	"hop.top/pact-go/core"
	"hop.top/pact-go/core/clock"
)

const caseNow = 1792080000

// caseWorld loads the native state of a Kubernetes case and builds the
// adapter over it with a clock the test controls.
func caseWorld(t *testing.T, id string) (*world, *k8s.Adapter, *clock.Fake) {
	t.Helper()
	fsys, err := adaptertest.DefaultFixtures()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := fs.ReadFile(fsys, "adapters/k8s/"+strings.ToLower(id)+".json")
	if err != nil {
		t.Fatal(err)
	}
	var c struct {
		NativeState json.RawMessage `json:"native_state"`
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	clk := clock.NewFake(time.Unix(caseNow, 0))
	w, err := loadWorld(t, c.NativeState, clk.Now())
	if err != nil {
		t.Fatal(err)
	}
	ref, err := memory.New(w.enrollmentState(), clk)
	if err != nil {
		t.Fatal(err)
	}
	sub, err := worldSubject(t, w, k8s.Config{Registry: referenceRegistry{ref}, Clock: clk})
	if err != nil {
		t.Fatal(err)
	}
	return w, sub.Adapter.(*k8s.Adapter), clk
}

// observerRequest is a marked request with the observer's token.
func observerRequest(t *testing.T, w *world) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "https://ops-gateway.northstar.example/api/v1/deployments", nil)
	if err := w.Credential(r, "observer"); err != nil {
		t.Fatal(err)
	}
	return k8s.Mark(r)
}

// TestForbiddenAccessesOfKR14 counts the accesses of the forbidden list for
// one claimed namespace, from the table of KR-14: K-F1 2, K-F2 4, K-F3 5,
// K-F4 2, K-F5 4, K-F6 2, K-F7 1, K-F7a 2, K-F8 4, K-F9 1.
func TestForbiddenAccessesOfKR14(t *testing.T) {
	got := k8s.ForbiddenAccesses([]string{"operations"})
	if len(got) != 27 {
		t.Fatalf("%d accesses, want 27", len(got))
	}
	want := map[k8s.ResourceAttributes]bool{
		{Namespace: "operations", Verb: "get", Resource: "secrets"}:                                     true,
		{Namespace: "", Verb: "get", Resource: "secrets"}:                                               true,
		{Namespace: "operations", Verb: "patch", Group: "apps", Resource: "deployments"}:                true,
		{Namespace: "", Verb: "list", Group: "apps", Resource: "deployments"}:                           true,
		{Namespace: "", Verb: "list", Resource: "namespaces"}:                                           true,
		{Namespace: "", Verb: "impersonate", Group: "authentication.k8s.io", Resource: "uids"}:          true,
		{Namespace: "operations", Verb: "create", Resource: "serviceaccounts", Subresource: "token"}:    true,
		{Namespace: "operations", Verb: "get", Resource: "pods", Subresource: "exec"}:                   true,
		{Namespace: "", Verb: "escalate", Group: "rbac.authorization.k8s.io", Resource: "clusterroles"}: true,
		{Namespace: "", Verb: "*", Group: "*", Resource: "*"}:                                           true,
	}
	for _, ra := range got {
		delete(want, ra)
	}
	for ra := range want {
		t.Errorf("missing %+v", ra)
	}
}

// TestPreflightHeldForP is the stale preflight of K8S-09: a passing
// preflight serves for P and no longer. At exactly P old it still serves
// while the authorization API is down; one second later the preflight must
// run again, cannot, and the request is DEPENDENCY_UNAVAILABLE.
func TestPreflightHeldForP(t *testing.T) {
	w, a, clk := caseWorld(t, "K8S-01.own-token")
	ctx := context.Background()
	if _, err := a.AuthenticateNative(ctx, observerRequest(t, w)); err != nil {
		t.Fatalf("first request: %v", err)
	}
	reviews := len(w.receivedHeaders())
	clk.Advance(k8s.DefaultPreflightInterval)
	w.setUnavailable(srcSARs, srcSelfReviews)
	if _, err := a.AuthenticateNative(ctx, observerRequest(t, w)); err != nil {
		t.Fatalf("preflight exactly P old: %v", err)
	}
	if got := len(w.receivedHeaders()) - reviews; got != 2 {
		t.Errorf("a held preflight sent %d requests, want the token review and the pod read only", got)
	}
	clk.Advance(time.Second)
	_, err := a.AuthenticateNative(ctx, observerRequest(t, w))
	if !errors.Is(err, adapter.ErrDependencyUnavailable) {
		t.Fatalf("preflight older than P with the API down: %v, want DEPENDENCY_UNAVAILABLE", err)
	}
	w.setUnavailable()
	if _, err := a.AuthenticateNative(ctx, observerRequest(t, w)); err != nil {
		t.Fatalf("after the API is back: %v", err)
	}
}

// TestFailedPreflightNotServed: a failed preflight is not served from the
// hold, and a later passing one serves again (KR-16, KR-17).
func TestFailedPreflightNotServed(t *testing.T) {
	w, a, clk := caseWorld(t, "K8S-08.secrets-get")
	ctx := context.Background()
	if _, err := a.AuthenticateNative(ctx, observerRequest(t, w)); !errors.Is(err, adapter.ErrDependencyUnavailable) {
		t.Fatalf("failing preflight: %v", err)
	}
	clk.Advance(time.Second)
	if _, err := a.AuthenticateNative(ctx, observerRequest(t, w)); !errors.Is(err, adapter.ErrDependencyUnavailable) {
		t.Fatalf("second request after a failed preflight: %v", err)
	}
	w.mu.Lock()
	w.st.Authorization = w.st.Authorization[:2]
	w.mu.Unlock()
	a.ResetPreflight()
	if _, err := a.AuthenticateNative(ctx, observerRequest(t, w)); err != nil {
		t.Fatalf("after the grant is removed: %v", err)
	}
}

// TestNoUserHeaderReachesAPIServer is the second half of K8S-01: no request
// the adapter sends carries an impersonation or authenticating-proxy header,
// and Enforce removes them from the request (KR-9).
func TestNoUserHeaderReachesAPIServer(t *testing.T) {
	w, a, _ := caseWorld(t, "K8S-01.impersonation-headers")
	r := observerRequest(t, w)
	r.Header.Set("Impersonate-User", "system:serviceaccount:operations:build-reporter")
	r.Header.Set("X-Remote-Group", "system:masters")
	if _, err := a.AuthenticateNative(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	for _, h := range w.receivedHeaders() {
		for name := range h {
			if n := strings.ToLower(name); strings.HasPrefix(n, "impersonate-") || strings.HasPrefix(n, "x-remote-") {
				t.Errorf("the API server received %s", name)
			}
		}
	}
	var seen http.Header
	k8s.Enforce(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen = r.Header
		if !k8s.Marked(r) {
			t.Error("Enforce did not mark the request")
		}
	})).ServeHTTP(httptest.NewRecorder(), r)
	if seen.Get("Impersonate-User") != "" || seen.Get("X-Remote-Group") != "" || seen.Get("Authorization") == "" {
		t.Errorf("after Enforce: %v", seen)
	}
}

// TestAuthorizeGetAsksForTheName: R2 is authorized as get of the named
// deployment in the row's namespace, for the principal's user, uid and
// groups (KR-12, KR-13, KR-15).
func TestAuthorizeGetAsksForTheName(t *testing.T) {
	w, a, _ := caseWorld(t, "K8S-11.binding-present")
	name := "web-frontend"
	w.mu.Lock()
	w.st.Authorization = []grantState{{
		Subject: subjectState{Group: "system:serviceaccounts:operations"}, Verb: "get", APIGroup: "apps",
		Resource: "deployments", Namespace: "operations", Name: &name, Status: json.RawMessage(`{"allowed":true,"reason":"named"}`),
	}}
	w.mu.Unlock()
	p := adapter.Principal{
		ID: k8s.Identifier("northstar-prod", "operations", "release-observer"), Mechanism: k8s.Mechanism,
		Realm: adapter.Realm{TenantID: "northstar", EnvironmentID: "https://ops-gateway.northstar.example/environments/operations"},
		Attributes: map[string]any{k8s.AttrK8s: map[string]any{
			"cluster_id": "northstar-prod", "namespace": "operations", "name": "release-observer",
			"uid": "4c1d7e2a-9b35-4f60-8a1e-7d2c5b9f0e31", "groups": []any{"system:serviceaccounts", "system:serviceaccounts:operations"},
			"issued_at": int64(caseNow - 600), "reviewed_at": int64(caseNow),
		}},
	}
	p.Workload = adapter.Workload(p.ID)
	op := core.OperationContext{PrincipalID: p.ID, Action: k8s.ActionGet, Resources: []string{k8s.ResourceBase("northstar-prod") + "/" + name}}
	d, err := a.AuthorizeNative(context.Background(), p, op)
	if err != nil || d.Effect != adapter.EffectAllow || d.Reason != "named" || d.SourceID != k8s.SourceAPIServer {
		t.Fatalf("get web-frontend: %+v, %v", d, err)
	}
	op.Resources = []string{k8s.ResourceBase("northstar-prod") + "/other"}
	if d, err := a.AuthorizeNative(context.Background(), p, op); err != nil || d.Effect != adapter.EffectDeny {
		t.Fatalf("get another name: %+v, %v", d, err)
	}
}

// TestNewRefusesUnsafeConfiguration: the configuration rules of KR-1, KR-3
// and KR-9.
func TestNewRefusesUnsafeConfiguration(t *testing.T) {
	w, _, clk := caseWorld(t, "K8S-01.own-token")
	ref, err := memory.New(w.enrollmentState(), clk)
	if err != nil {
		t.Fatal(err)
	}
	base := func() k8s.Config {
		return k8s.Config{
			Realm:     adapter.Realm{TenantID: "t", EnvironmentID: "https://e.example/env"},
			ClusterID: "c1", APIServer: w.apiServer(), RootCAs: w.roots(), GatewayAudience: "https://gw.example",
			Namespaces: []string{"operations"}, Origin: "https://gw.example",
			GatewayToken: func(context.Context) (string, error) { return "t", nil },
			Registry:     referenceRegistry{ref}, Clock: clk,
		}
	}
	if _, err := k8s.New(base()); err != nil {
		t.Fatalf("base configuration: %v", err)
	}
	for name, mutate := range map[string]func(*k8s.Config){
		"no trust anchors":          func(c *k8s.Config) { c.RootCAs = nil },
		"cleartext API server":      func(c *k8s.Config) { c.APIServer = "http://kube.example" },
		"API server with a path":    func(c *k8s.Config) { c.APIServer += "/proxy" },
		"no gateway token":          func(c *k8s.Config) { c.GatewayToken = nil },
		"audience not https":        func(c *k8s.Config) { c.GatewayAudience = "gateway" },
		"impersonation allowlisted": func(c *k8s.Config) { c.HeaderAllowlist = []string{"Impersonate-User"} },
		"proxy header allowlisted":  func(c *k8s.Config) { c.HeaderAllowlist = []string{"x-remote-user"} },
		"account outside the namespaces": func(c *k8s.Config) {
			c.Accounts = []k8s.Account{{Namespace: "staging", Name: "a", UID: "u"}}
		},
		"account without uid":       func(c *k8s.Config) { c.Accounts = []k8s.Account{{Namespace: "operations", Name: "a"}} },
		"cluster id not unreserved": func(c *k8s.Config) { c.ClusterID = "c 1" },
	} {
		c := base()
		mutate(&c)
		if _, err := k8s.New(c); err == nil {
			t.Errorf("%s: New accepted it", name)
		}
	}
}

// deploymentsServer answers the executor's requests for unit tests.
func deploymentsServer(t *testing.T, answer func(r *http.Request) (int, string)) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var n atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		n.Add(1)
		code, body := answer(r)
		rw.WriteHeader(code)
		_, _ = rw.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv, &n
}

func newTestExecutor(t *testing.T, srv *httptest.Server, token string) *k8s.Executor {
	t.Helper()
	file := filepath.Join(t.TempDir(), "token")
	if token != "" {
		if err := os.WriteFile(file, []byte(token+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	w := &world{server: srv}
	e, err := k8s.NewExecutor(k8s.ExecutorConfig{ClusterID: "northstar-prod", APIServer: srv.URL, RootCAs: w.roots(), TokenFile: file})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

var listOp = core.OperationContext{Action: k8s.ActionList, Resources: []string{k8s.ResourceBase("northstar-prod")}}

// TestExecutorSendsTheRowOnly: the translation of KR-13: a constant path, no
// query, the executor's own Authorization and Accept: application/json, and
// nothing else.
func TestExecutorSendsTheRowOnly(t *testing.T) {
	var got *http.Request
	srv, _ := deploymentsServer(t, func(r *http.Request) (int, string) {
		got = r
		return 200, `{"kind":"DeploymentList","metadata":{},"items":[]}`
	})
	e := newTestExecutor(t, srv, "exec-token")
	if _, err := e.Execute(context.Background(), listOp); err != nil {
		t.Fatal(err)
	}
	if got.URL.Path != "/apis/apps/v1/namespaces/operations/deployments" || got.URL.RawQuery != "" || got.Method != http.MethodGet {
		t.Errorf("request %s %s?%s", got.Method, got.URL.Path, got.URL.RawQuery)
	}
	if got.Header.Get("Authorization") != "Bearer exec-token" || got.Header.Get("Accept") != "application/json" {
		t.Errorf("headers %v", got.Header)
	}
	for name := range got.Header {
		switch strings.ToLower(name) {
		case "authorization", "accept", "accept-encoding", "user-agent":
		default:
			t.Errorf("unexpected header %s", name)
		}
	}
	getOp := core.OperationContext{Action: k8s.ActionGet, Resources: []string{k8s.ResourceBase("northstar-prod") + "/web-frontend"}}
	if p, ok := e.Path(getOp); !ok || p != "/apis/apps/v1/namespaces/operations/deployments/web-frontend" {
		t.Errorf("R2 path %q %v", p, ok)
	}
	if _, ok := e.Path(core.OperationContext{Action: k8s.ActionGet, Resources: []string{k8s.ResourceBase("northstar-prod") + "/Bad_Name"}}); ok {
		t.Error("a name outside the grammar has a path")
	}
}

// TestExecutorStopsAtContinuation: a list answer with a continue token is an
// error and nothing more is fetched (K8S-10, KR-13).
func TestExecutorStopsAtContinuation(t *testing.T) {
	srv, n := deploymentsServer(t, func(*http.Request) (int, string) {
		return 200, `{"kind":"DeploymentList","metadata":{"continue":"eyJ2IjoibWV0YSJ9"},"items":[]}`
	})
	e := newTestExecutor(t, srv, "exec-token")
	if _, err := e.Execute(context.Background(), listOp); !errors.Is(err, k8s.ErrContinuation) {
		t.Fatalf("Execute = %v, want ErrContinuation", err)
	}
	if n.Load() != 1 {
		t.Errorf("%d requests, want 1", n.Load())
	}
}

// TestExecutorNativeDenialIsFinal: a 403 is a native denial, not retried
// (K8S-11, KR-12).
func TestExecutorNativeDenialIsFinal(t *testing.T) {
	srv, n := deploymentsServer(t, func(*http.Request) (int, string) { return 403, `{"kind":"Status"}` })
	e := newTestExecutor(t, srv, "exec-token")
	if _, err := e.Execute(context.Background(), listOp); !errors.Is(err, k8s.ErrNativeDenial) {
		t.Fatalf("Execute = %v, want ErrNativeDenial", err)
	}
	if n.Load() != 1 {
		t.Errorf("%d requests, want 1", n.Load())
	}
}

// TestExecutorWithoutTokenSendsNothing: an executor whose token cannot be
// read sends no request under another identity (K8S-07, KR-11).
func TestExecutorWithoutTokenSendsNothing(t *testing.T) {
	srv, n := deploymentsServer(t, func(*http.Request) (int, string) { return 200, `{}` })
	e := newTestExecutor(t, srv, "")
	if _, err := e.Execute(context.Background(), listOp); !errors.Is(err, k8s.ErrNoToken) || !errors.Is(err, adapter.ErrDependencyUnavailable) {
		t.Fatalf("Execute = %v, want ErrNoToken and DEPENDENCY_UNAVAILABLE", err)
	}
	if _, err := e.SelfReview(context.Background()); !errors.Is(err, k8s.ErrNoToken) {
		t.Fatalf("SelfReview = %v, want ErrNoToken", err)
	}
	if n.Load() != 0 {
		t.Errorf("%d requests sent without a token", n.Load())
	}
	if kinds, _ := e.Credentials(context.Background()); len(kinds) != 1 || kinds[0] != k8s.CredentialProjectedToken {
		t.Errorf("Credentials = %v", kinds)
	}
}

// TestNewExecutorRefusesOtherSources: the executor takes only a projected
// token file; without one, or with a cleartext or proxied API server, it is
// not built (K8S-07, KR-11).
func TestNewExecutorRefusesOtherSources(t *testing.T) {
	srv, _ := deploymentsServer(t, func(*http.Request) (int, string) { return 200, `{}` })
	roots := (&world{server: srv}).roots()
	for name, cfg := range map[string]k8s.ExecutorConfig{
		"no token file":    {ClusterID: "c", APIServer: srv.URL, RootCAs: roots},
		"cleartext":        {ClusterID: "c", APIServer: "http://kube.example", RootCAs: roots, TokenFile: "t"},
		"path on server":   {ClusterID: "c", APIServer: srv.URL + "/proxy", RootCAs: roots, TokenFile: "t"},
		"no trust anchors": {ClusterID: "c", APIServer: srv.URL, TokenFile: "t"},
		"no cluster id":    {APIServer: srv.URL, RootCAs: roots, TokenFile: "t"},
	} {
		if _, err := k8s.NewExecutor(cfg); err == nil {
			t.Errorf("%s: NewExecutor accepted it", name)
		}
	}
}

// TestClaimTimesUseTheReviewBound: with a declared B of 120 s the status
// time of the review claims is the review time minus 120 s (KR-20).
func TestClaimTimesUseTheReviewBound(t *testing.T) {
	w, _, clk := caseWorld(t, "K8S-01.own-token")
	bound := int64(120)
	w.st.ReviewBound = &bound
	ref, err := memory.New(w.enrollmentState(), clk)
	if err != nil {
		t.Fatal(err)
	}
	sub, err := worldSubject(t, w, k8s.Config{Registry: referenceRegistry{ref}, Clock: clk})
	if err != nil {
		t.Fatal(err)
	}
	a := sub.Adapter.(*k8s.Adapter)
	p, err := a.AuthenticateNative(context.Background(), observerRequest(t, w))
	if err != nil {
		t.Fatal(err)
	}
	c, err := a.ReadNativeClaim(context.Background(), k8s.PathNamespace, adapter.ClaimContext{Principal: p})
	if err != nil {
		t.Fatal(err)
	}
	if c.Value != "operations" || c.ObservedAt.Unix() != caseNow-600 || c.StatusCheckedAt.Unix() != caseNow-120 {
		t.Errorf("claim %+v", c)
	}
}
