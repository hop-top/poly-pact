package gateway_test

import (
	"net/http"
	"testing"

	"hop.top/pact-go/core"
	"hop.top/pact-go/gateway"
)

func TestObserveNeverBlocks(t *testing.T) {
	cases := map[string]func(w *world, r *http.Request){
		"no presentation":      func(*world, *http.Request) {},
		"garbage presentation": func(_ *world, r *http.Request) { r.Header.Set(gateway.HeaderPresentation, "not.a.jws") },
		"no credential":        func(_ *world, r *http.Request) { r.Header.Del("Authorization") },
		"store outage": func(w *world, r *http.Request) {
			w.present(r)
			w.receipts.down.Store(true)
		},
		"replayed": func(w *world, r *http.Request) {
			w.present(r)
			w.send(r)
		},
		"ambiguous encoding": func(_ *world, r *http.Request) { r.URL.RawPath, r.URL.Path = "/observed/%7Ex", "/observed/~x" },
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			w := newWorld(t, withPolicy(deny("invoice.read"))).start()
			r := w.request(http.MethodGet, "/observed/INV-1042", nil)
			setup(w, r)
			sent := r.Header.Get(gateway.HeaderPresentation)
			before := w.app.count()
			resp, out := w.send(r)
			if resp.StatusCode != http.StatusOK || string(out) != "native result" {
				t.Fatalf("status %d %s: an observe route blocked", resp.StatusCode, out)
			}
			if w.app.count() != before+1 {
				t.Fatal("the handler was not reached")
			}
			v := w.app.last(t)
			if v.admitted {
				t.Error("an observe route put an admission in the context")
			}
			if v.header.Get(gateway.HeaderPresentation) != sent {
				t.Error("an observe route changed the request headers")
			}
			if resp.Header.Get(gateway.HeaderAdmission) != "" {
				t.Error("an observe route answered with an admission receipt")
			}
		})
	}
}

func TestObserveRecords(t *testing.T) {
	w := newWorld(t).start()
	r := w.request(http.MethodGet, "/observed/INV-1042", nil)
	w.present(r)
	if resp, _ := w.send(r); resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	all := w.receipts.All()
	if len(all) != 1 {
		t.Fatalf("%d receipts, want 1", len(all))
	}
	for _, res := range all {
		if res.Attestation.Mode != core.ModeObserve || res.Attestation.Decision != core.DecisionAdmissible {
			t.Errorf("receipt %s %s, want an ADMISSIBLE observe receipt", res.Attestation.Mode, res.Attestation.Decision)
		}
	}
}

func TestObserveContractOnEnforceRoute(t *testing.T) {
	w := newWorld(t)
	w.cfg.Routes = map[string]gateway.Class{"GET /invoices/{id}": gateway.ClassObserve}
	w.start()
	r := w.request(http.MethodGet, "/invoices/INV-1042", nil)
	w.present(r)
	enforce := w.cfg
	enforce.Routes = routes
	w.serve(enforce)
	w.retarget(r)
	resp, out := w.send(r)
	problem(t, resp, out, "CONTEXT_MISMATCH", http.StatusForbidden)
	if w.app.count() != 0 {
		t.Fatal("an observation-mode admission opened an enforce route")
	}
}

func TestOffRoute(t *testing.T) {
	w := newWorld(t).start()
	r := w.request(http.MethodGet, "/health", nil)
	r.Header.Del("Authorization")
	if resp, _ := w.send(r); resp.StatusCode != http.StatusOK || w.app.count() != 1 {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

func TestDefaultEnforces(t *testing.T) {
	w := newWorld(t).start()
	resp, out := w.send(w.request(http.MethodGet, "/elsewhere", nil))
	problem(t, resp, out, "INVALID_PROOF", http.StatusUnauthorized)
	if w.app.count() != 0 {
		t.Fatal("an unclassified route reached the handler")
	}
}

func TestNoAdmissionFromClient(t *testing.T) {
	w := newWorld(t).start()
	r := w.request(http.MethodGet, "/health", nil)
	r.Header.Set("PACT-Admission", "x.y.z")
	r.Header.Set("X-Principal", principal)
	w.send(r)
	if w.app.last(t).admitted {
		t.Fatal("a client header produced an admission")
	}
}
