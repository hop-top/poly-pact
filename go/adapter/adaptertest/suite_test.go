package adaptertest

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/core/clock"
)

func TestBuildRequest(t *testing.T) {
	ctx := context.Background()

	t.Run("url is kept as stated", func(t *testing.T) {
		r, body, err := buildRequest(ctx, &Request{
			Method:  "POST",
			URL:     "https://svc:pw@internal.local:8443/a%2Fb/c?x=%2f&y=1#frag",
			Headers: map[string]string{"X-One": "1", "host": "front.example"},
			BodyB64: "aGVsbG8=",
		})
		if err != nil {
			t.Fatal(err)
		}
		if r.Method != "POST" || r.URL.User == nil || r.URL.Fragment != "frag" || r.URL.RawQuery != "x=%2f&y=1" || r.URL.EscapedPath() != "/a%2Fb/c" {
			t.Errorf("request = %s %v", r.Method, r.URL)
		}
		// The request is the one a server took off the wire: its
		// request-target is the url, in absolute-form, octet for octet.
		if r.RequestURI != "https://svc:pw@internal.local:8443/a%2Fb/c?x=%2f&y=1#frag" {
			t.Errorf("RequestURI = %q, want the url as stated", r.RequestURI)
		}
		if r.Host != "front.example" || r.Header.Get("X-One") != "1" || r.Header.Get("Host") != "" {
			t.Errorf("host %q headers %v", r.Host, r.Header)
		}
		got, _ := io.ReadAll(r.Body)
		if string(got) != "hello" || string(body) != "hello" || r.ContentLength != 5 {
			t.Errorf("body %q / %q, length %d", got, body, r.ContentLength)
		}
	})

	t.Run("no body", func(t *testing.T) {
		r, body, err := buildRequest(ctx, &Request{Method: "GET", URL: "https://gateway.example/"})
		if err != nil {
			t.Fatal(err)
		}
		if len(body) != 0 || (r.Body != nil && r.Body != http.NoBody) {
			t.Errorf("body = %q, %v", body, r.Body)
		}
	})

	t.Run("tls peer", func(t *testing.T) {
		r, _, err := buildRequest(ctx, &Request{Method: "GET", URL: "https://gateway.example/", TLSPeer: &TLSPeer{
			SubjectCN: "alice", IssuerCN: "Test CA", DNSNames: []string{"alice.example"}, URIs: []string{"spiffe://example/alice"},
		}})
		if err != nil {
			t.Fatal(err)
		}
		if r.TLS == nil || !r.TLS.HandshakeComplete || r.TLS.Version != tls.VersionTLS13 || len(r.TLS.PeerCertificates) != 1 {
			t.Fatalf("TLS = %+v", r.TLS)
		}
		c := r.TLS.PeerCertificates[0]
		if c.Subject.CommonName != "alice" || c.Issuer.CommonName != "Test CA" || c.DNSNames[0] != "alice.example" || c.URIs[0].String() != "spiffe://example/alice" {
			t.Errorf("certificate = %+v", c)
		}
	})

	t.Run("errors", func(t *testing.T) {
		for name, req := range map[string]*Request{
			"bad body":   {Method: "GET", URL: "https://x.example/", BodyB64: "***"},
			"bad url":    {Method: "GET", URL: "https://x.example/%zz"},
			"bad method": {Method: "G ET", URL: "https://x.example/"},
			"bad peer":   {Method: "GET", URL: "https://x.example/", TLSPeer: &TLSPeer{URIs: []string{"%zz"}}},
		} {
			if _, _, err := buildRequest(ctx, req); err == nil {
				t.Errorf("%s: no error", name)
			}
		}
	})
}

// authDenied is a case any denying fake passes.
func authDenied() *Case {
	return authCase(outDenied, Expect{})
}

func TestRunCaseHarness(t *testing.T) {
	denial := &adapter.NativeDenial{Reason: adapter.DenialNoCredential}
	denying := authFake(adapter.Principal{}, denial)

	t.Run("factory error", func(t *testing.T) {
		c := authDenied()
		c.NativeState, c.ID = []byte(`{}`), "T-01"
		got := runCase(t, func(testing.TB, Env) (Subject, error) { return Subject{}, errors.New("no such state") }, c)
		wantFails(t, got, "factory: no such state")
	})

	t.Run("factory panic", func(t *testing.T) {
		c := authDenied()
		c.NativeState, c.ID = []byte(`{}`), "T-01"
		got := runCase(t, func(testing.TB, Env) (Subject, error) { panic("boom") }, c)
		wantFails(t, got, "factory panicked: boom")
	})

	t.Run("no adapter", func(t *testing.T) {
		c := authDenied()
		c.NativeState, c.ID = []byte(`{}`), "T-01"
		got := runCase(t, func(testing.TB, Env) (Subject, error) { return Subject{}, nil }, c)
		wantFails(t, got, "no adapter")
	})

	t.Run("no Arrive hook", func(t *testing.T) {
		c := authDenied()
		c.NativeState, c.ID = []byte(`{}`), "T-01"
		got := runCase(t, func(testing.TB, Env) (Subject, error) { return Subject{Adapter: denying}, nil }, c)
		wantFails(t, got, "no Arrive hook")
	})

	t.Run("no Credential hook", func(t *testing.T) {
		c := authDenied()
		c.NativeState, c.ID = []byte(`{}`), "T-01"
		got := runCase(t, func(testing.TB, Env) (Subject, error) {
			return Subject{Adapter: denying, Arrive: func(r *http.Request) *http.Request { return r }}, nil
		}, c)
		wantFails(t, got, "no Credential hook", `"alice"`)
	})

	t.Run("credential error", func(t *testing.T) {
		c := authDenied()
		c.NativeState, c.ID = []byte(`{}`), "T-01"
		got := runCase(t, func(testing.TB, Env) (Subject, error) {
			return Subject{
				Adapter:    denying,
				Arrive:     func(r *http.Request) *http.Request { return r },
				Credential: func(*http.Request, string) error { return errors.New("unknown ref") },
			}, nil
		}, c)
		wantFails(t, got, "unknown ref")
	})

	t.Run("Arrive returns nil", func(t *testing.T) {
		c := authDenied()
		c.NativeState, c.ID = []byte(`{}`), "T-01"
		got := runCase(t, func(testing.TB, Env) (Subject, error) {
			return Subject{
				Adapter:    denying,
				Arrive:     func(*http.Request) *http.Request { return nil },
				Credential: func(*http.Request, string) error { return nil },
			}, nil
		}, c)
		wantFails(t, got, "Arrive returned a nil request")
	})

	t.Run("adapter panic", func(t *testing.T) {
		f := &fake{auth: func(context.Context, *http.Request) (adapter.Principal, error) { panic("nil map") }}
		wantFails(t, runFake(t, f, authDenied()), "AuthenticateNative panicked: nil map")
	})

	t.Run("Arrive runs, unless the request is direct", func(t *testing.T) {
		var marked []bool
		f := &fake{auth: func(_ context.Context, r *http.Request) (adapter.Principal, error) {
			marked = append(marked, r.Header.Get("X-Arrived") == "1")
			return adapter.Principal{}, denial
		}}
		factory := func(testing.TB, Env) (Subject, error) {
			return Subject{
				Adapter: f,
				Arrive: func(r *http.Request) *http.Request {
					r.Header.Set("X-Arrived", "1")
					return r
				},
				Credential: func(*http.Request, string) error { return nil },
			}, nil
		}
		via, direct := authDenied(), authDenied()
		direct.Request.Arrival = arrivalDirect
		for _, c := range []*Case{via, direct} {
			c.NativeState, c.ID = []byte(`{}`), "T-01"
			wantClean(t, runCase(t, factory, c))
		}
		if len(marked) != 2 || !marked[0] || marked[1] {
			t.Errorf("marked = %v, want [true false]", marked)
		}
	})

	t.Run("env: state, clock, hooks", func(t *testing.T) {
		var env Env
		factory := func(_ testing.TB, e Env) (Subject, error) {
			env = e
			return factoryFor(denying)(t, e)
		}
		c := authDenied()
		c.ID, c.NativeState = "T-01", []byte(`{"model":"x"}`)
		wantClean(t, runCase(t, factory, c))
		if string(env.State) != `{"model":"x"}` {
			t.Errorf("state = %s", env.State)
		}
		if !env.Clock.Now().Equal(now) {
			t.Errorf("clock = %v, want the default now %v", env.Clock.Now(), now)
		}
		if env.Hooks == nil {
			t.Error("no hooks")
		}

		at := int64(1_900_000_000)
		c.Now = &at
		wantClean(t, runCase(t, factory, c))
		if !env.Clock.Now().Equal(time.Unix(at, 0)) {
			t.Errorf("clock = %v, want %v", env.Clock.Now(), time.Unix(at, 0))
		}
		if _, ok := env.Clock.(*clock.Fake); !ok {
			t.Errorf("clock is %T, want a fake the adapter cannot advance", env.Clock)
		}
	})

	t.Run("each case gets a fresh adapter and fresh hooks", func(t *testing.T) {
		var seen []*Hooks
		factory := func(_ testing.TB, e Env) (Subject, error) {
			seen = append(seen, e.Hooks)
			e.Hooks.Fire("execute")
			return factoryFor(denying)(t, e)
		}
		for range 2 {
			c := authDenied()
			c.ID, c.NativeState = "T-01", []byte(`{}`)
			runCase(t, factory, c)
		}
		if len(seen) != 2 || seen[0] == seen[1] || len(seen[1].Fired()) != 1 {
			t.Errorf("hooks = %v", seen)
		}
	})
}

func TestMustNotCall(t *testing.T) {
	deny := authzFake(adapter.Decision{Effect: adapter.EffectDeny, SourceID: "policy-1"}, nil)
	fires := func(names ...string) Factory {
		return func(_ testing.TB, e Env) (Subject, error) {
			for _, n := range names {
				e.Hooks.Fire(n)
			}
			return factoryFor(deny)(nil, e)
		}
	}
	c := func(forbidden ...string) *Case {
		cs := authzCase(outDeny, Expect{MustNotCall: forbidden})
		cs.ID, cs.NativeState = "T-01", []byte(`{}`)
		return cs
	}
	wantClean(t, runCase(t, fires(), c("execute")))
	wantClean(t, runCase(t, fires("audit"), c("execute")))
	wantClean(t, runCase(t, fires("execute"), c()))
	wantFails(t, runCase(t, fires("execute"), c("execute")), `hook "execute" fired`)
	wantFails(t, runCase(t, fires("audit", "execute"), c("grant", "execute")), `hook "execute" fired`)
}

func TestRunAndEvaluate(t *testing.T) {
	fixtures := treeOf(map[string]string{
		"adapters/_common/a.json": minimalCase,
		"adapters/_common/b.json": strings.Replace(strings.Replace(minimalCase, "COMMON-01.one", "COMMON-01.two", 1), `"denied"`, `"error"`, 1),
	})
	denying := authFake(adapter.Principal{}, &adapter.NativeDenial{Reason: adapter.DenialNoCredential})

	t.Run("evaluate", func(t *testing.T) {
		res, err := Evaluate(t, factoryFor(denying), Options{Fixtures: fixtures})
		if err != nil {
			t.Fatal(err)
		}
		if len(res) != 2 || res[0].ID != "COMMON-01.one" || !res[0].Passed() {
			t.Fatalf("results = %+v", res)
		}
		res, err = Evaluate(t, factoryFor(authFake(goodPrincipal(), nil)), Options{Fixtures: fixtures})
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range res {
			if r.Passed() {
				t.Errorf("%s passes against an adapter that authenticates everyone", r.ID)
			}
		}
	})

	t.Run("evaluate reports a load error", func(t *testing.T) {
		if _, err := Evaluate(t, factoryFor(denying), Options{Fixtures: fstest.MapFS{}}); err == nil {
			t.Error("no error for an empty fixture tree")
		}
	})

	t.Run("run passes when the adapter does", func(t *testing.T) {
		Run(t, factoryFor(denying), Options{Fixtures: treeOf(map[string]string{"adapters/_common/a.json": minimalCase})})
	})
}

// TestWorkloadModes: a case marked "shared" runs only when the adapter's
// profile supports workloads shared by several agents, one marked "dedicated"
// only when it does not, and an unmarked case in both runs.
func TestWorkloadModes(t *testing.T) {
	mark := func(id, mode, outcome string) string {
		s := strings.Replace(minimalCase, "COMMON-01.one", id, 1)
		s = strings.Replace(s, `"denied"`, `"`+outcome+`"`, 1)
		if mode != "" {
			s = strings.Replace(s, `"title": "A case",`, `"title": "A case", "workloads": "`+mode+`",`, 1)
		}
		return s
	}
	// The denying adapter fails the cases that expect an error, so a case
	// that runs in the wrong mode fails the run below.
	fixtures := treeOf(map[string]string{
		"adapters/_common/a.json": mark("COMMON-01.both", "", "denied"),
		"adapters/_common/b.json": mark("COMMON-01.shared", "shared", "error"),
		"adapters/_common/c.json": mark("COMMON-01.dedicated", "dedicated", "error"),
		"adapters/_common/d.json": mark("COMMON-01.shared-denied", "shared", "denied"),
		"adapters/_common/e.json": mark("COMMON-01.dedicated-denied", "dedicated", "denied"),
	})
	denying := authFake(adapter.Principal{}, &adapter.NativeDenial{Reason: adapter.DenialNoCredential})
	for _, tc := range []struct {
		name   string
		shared bool
		want   []string
	}{
		{"dedicated by default", false, []string{"COMMON-01.both", "COMMON-01.dedicated", "COMMON-01.dedicated-denied"}},
		{"shared", true, []string{"COMMON-01.both", "COMMON-01.shared", "COMMON-01.shared-denied"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, err := Evaluate(t, factoryFor(denying), Options{Fixtures: fixtures, SharedWorkloads: tc.shared})
			if err != nil {
				t.Fatal(err)
			}
			var ids []string
			for _, r := range res {
				ids = append(ids, r.ID)
			}
			slices.Sort(ids)
			if !slices.Equal(ids, tc.want) {
				t.Errorf("cases run = %v, want %v", ids, tc.want)
			}
		})
	}
	t.Run("run skips the cases of the other mode", func(t *testing.T) {
		only := treeOf(map[string]string{
			"adapters/_common/a.json": mark("COMMON-01.both", "", "denied"),
			"adapters/_common/b.json": mark("COMMON-01.shared", "shared", "error"),
			"adapters/_common/d.json": mark("COMMON-01.dedicated-denied", "dedicated", "denied"),
		})
		Run(t, factoryFor(denying), Options{Fixtures: only})
		only = treeOf(map[string]string{
			"adapters/_common/a.json": mark("COMMON-01.both", "", "denied"),
			"adapters/_common/c.json": mark("COMMON-01.dedicated", "dedicated", "error"),
			"adapters/_common/e.json": mark("COMMON-01.shared-denied", "shared", "denied"),
		})
		Run(t, factoryFor(denying), Options{Fixtures: only, SharedWorkloads: true})
	})
}

func TestDefaultFixtures(t *testing.T) {
	fsys, err := DefaultFixtures()
	if err != nil {
		t.Fatalf("DefaultFixtures from %s: %v", "the package directory", err)
	}
	cases, err := Load(fsys, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(cases) == 0 {
		t.Error("the default fixture tree has no common cases")
	}
}
