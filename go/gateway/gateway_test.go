package gateway_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapters/memory"
	"hop.top/pact-go/core"
	"hop.top/pact-go/core/digest"
	"hop.top/pact-go/gateway"
)

// TestEndToEnd: the agent's holder builds a presentation for a request, the
// gateway admits it, and the wrapped handler sees the admitted principal in
// the request context, the exact bytes the presentation bound, and no
// presentation header (draft 4.4 in-gateway form, 11.1, 12.2, 2.3).
func TestEndToEnd(t *testing.T) {
	w := newWorld(t).start()
	body := []byte(`{"note":"paid in full"}`)
	r := w.request(http.MethodPost, "/invoices/INV-1042/notes?lang=en", body)
	r.Header.Set("If-Match", `"v7"`)
	p := w.present(r)
	resp, out := w.send(r)
	if resp.StatusCode != http.StatusOK || string(out) != "native result" {
		t.Fatalf("status %d %s, want the native result", resp.StatusCode, out)
	}
	v := w.app.last(t)
	if !v.admitted {
		t.Fatal("the handler sees no admission in its request context")
	}
	a := v.admission
	if a.Principal.ID != principal || a.Principal.Realm != realm || a.Principal.Workload != workload {
		t.Errorf("principal %+v, want alice of the authenticated workload", a.Principal)
	}
	if a.Operation.Action != "invoice.annotate" || a.Operation.Resources[0] != "https://invoices.example/invoices/INV-1042" {
		t.Errorf("operation %+v", a.Operation)
	}
	if !bytes.Equal(v.body, body) || a.Operation.BodyDigest != digest.BytesDigest(body) {
		t.Errorf("the handler read %q; the gateway bound %s", v.body, a.Operation.BodyDigest)
	}
	if v.requestURI != "/invoices/INV-1042/notes?lang=en" {
		t.Errorf("the handler sees request-target %q", v.requestURI)
	}
	if v.header.Get(gateway.HeaderPresentation) != "" {
		t.Error("the presentation header reaches the handler")
	}
	for name, vals := range v.header {
		for _, val := range vals {
			if strings.Contains(val, principal) {
				t.Errorf("header %s carries the principal", name)
			}
		}
	}
	att := a.Receipt.Attestation
	if att.Decision != core.DecisionAdmissible || att.Mode != core.ModeEnforced || att.PrincipalID != principal {
		t.Errorf("receipt %s %s %s", att.Decision, att.Mode, att.PrincipalID)
	}
	if att.PresentationID != p.Claims.JTI {
		t.Errorf("receipt presentation_id %s, want %s", att.PresentationID, p.Claims.JTI)
	}
	if a.Native.Effect != adapter.EffectAllow {
		t.Errorf("native decision %+v", a.Native)
	}
	if got := receiptOf(t, resp); got.JTI != att.JTI || got.Decision != core.DecisionAdmissible {
		t.Errorf("PACT-Admission carries %s %s, want the receipt %s", got.JTI, got.Decision, att.JTI)
	}
	if _, err := w.receipts.Get(context.Background(), att.JTI); err != nil {
		t.Errorf("the receipt was not recorded before admission: %v", err)
	}
}

// TestModifiedAfterBinding: a request that differs from the one the
// presentation binds (body, query, consequential header) is refused, and the
// handler is not reached (draft 10.3, 11.3 step 5, 22.2).
func TestModifiedAfterBinding(t *testing.T) {
	for name, mutate := range map[string]func(*http.Request){
		"body": func(r *http.Request) {
			b := []byte(`{"note":"refund"}`)
			r.Body, r.ContentLength = io.NopCloser(bytes.NewReader(b)), int64(len(b))
			r.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(b)), nil }
		},
		"query":  func(r *http.Request) { r.URL.RawQuery = "lang=fr" },
		"header": func(r *http.Request) { r.Header.Set("If-Match", `"v8"`) },
		"path":   func(r *http.Request) { r.URL.Path = "/invoices/INV-1043/notes" },
	} {
		t.Run(name, func(t *testing.T) {
			w := newWorld(t).start()
			r := w.request(http.MethodPost, "/invoices/INV-1042/notes?lang=en", []byte(`{"note":"paid"}`))
			r.Header.Set("If-Match", `"v7"`)
			w.present(r)
			mutate(r)
			resp, out := w.send(r)
			problem(t, resp, out, "CONTEXT_MISMATCH", http.StatusForbidden)
			if w.app.count() != 0 {
				t.Fatal("a modified request reached the handler")
			}
			if a := receiptOf(t, resp); a.Decision != core.DecisionInadmissible {
				t.Errorf("receipt %s, want INADMISSIBLE", a.Decision)
			}
		})
	}
}

// TestReplay: the same presented request twice is admitted once; the second
// is REPLAY (draft 7.5, 11.3 step 4, 13.4).
func TestReplay(t *testing.T) {
	w := newWorld(t).start()
	r := w.request(http.MethodGet, "/invoices/INV-1042", nil)
	w.present(r)
	if resp, out := w.send(r); resp.StatusCode != http.StatusOK {
		t.Fatalf("first: %d %s", resp.StatusCode, out)
	}
	resp, out := w.send(r)
	problem(t, resp, out, "REPLAY", http.StatusConflict)
	if w.app.count() != 1 {
		t.Fatalf("handler reached %d times, want once", w.app.count())
	}
}

// TestStoreOutage: a replay, receipt, hold or contract record store that
// cannot answer fails closed: no admission, 503 (draft 12.2, 18; RB-45).
func TestStoreOutage(t *testing.T) {
	for name, down := range map[string]func(*world){
		"receipts": func(w *world) { w.receipts.down.Store(true) },
		"replay":   func(w *world) { w.replay.down.Store(true) },
		"holds":    func(w *world) { w.holds.SetUnavailable(true) },
		"records":  func(w *world) { w.records.down.Store(true) },
	} {
		t.Run(name, func(t *testing.T) {
			w := newWorld(t).start()
			r := w.request(http.MethodGet, "/invoices/INV-1042", nil)
			w.present(r)
			down(w)
			resp, out := w.send(r)
			problem(t, resp, out, "DEPENDENCY_UNAVAILABLE", http.StatusServiceUnavailable)
			if w.app.count() != 0 {
				t.Fatal("the handler was reached during a store outage")
			}
			for _, res := range w.receipts.All() {
				if res.Attestation.Decision == core.DecisionAdmissible {
					t.Fatal("an ADMISSIBLE receipt was recorded during a store outage")
				}
			}
		})
	}
}

// TestNativeDenialAfterAdmission: PACT admits, native authorization denies;
// the denial wins and the handler is not reached (draft 2.3, 11.1 step 7).
// The default answer is the native denial, HTTP 403, not a PACT transport
// error (draft 13.4).
func TestNativeDenialAfterAdmission(t *testing.T) {
	w := newWorld(t, withPolicy(allow("invoice.read"), deny("report.read"))).start()
	r := w.request(http.MethodGet, "/reports/R-7", nil)
	w.present(r)
	resp, out := w.send(r)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status %d %s, want 403", resp.StatusCode, out)
	}
	if ct := resp.Header.Get("Content-Type"); strings.HasPrefix(ct, "application/problem+json") {
		t.Fatalf("a native denial answered with a PACT problem: %s", out)
	}
	if strings.Contains(string(out), "private reason") {
		t.Error("the native policy's reason is disclosed")
	}
	if w.app.count() != 0 {
		t.Fatal("a natively denied request reached the handler")
	}
	admissible := 0
	for _, res := range w.receipts.All() {
		if res.Attestation.Decision == core.DecisionAdmissible {
			admissible++
		}
	}
	if admissible != 1 {
		t.Fatalf("%d ADMISSIBLE receipts, want the one admission native authorization then denied", admissible)
	}
}

// TestNativeDenialHandler: the gateway answers a native denial with the
// handler the configuration names.
func TestNativeDenialHandler(t *testing.T) {
	w := newWorld(t, withPolicy(deny("report.read")))
	w.cfg.NativeDenial = http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) { rw.WriteHeader(http.StatusTeapot) })
	w.start()
	r := w.request(http.MethodGet, "/reports/R-7", nil)
	w.present(r)
	if resp, _ := w.send(r); resp.StatusCode != http.StatusTeapot || w.app.count() != 0 {
		t.Fatalf("status %d, handler reached %d times", resp.StatusCode, w.app.count())
	}
}

// TestMissingPresentationOnEnforce: a natively authenticated request with no
// presentation on an enforce route, or an empty one, is refused
// INVALID_PROOF, HTTP 401, with no receipt, and does not reach the handler
// (draft 12.2, 13.2).
func TestMissingPresentationOnEnforce(t *testing.T) {
	w := newWorld(t).start()
	resp, out := w.send(w.request(http.MethodGet, "/invoices/INV-1042", nil))
	problem(t, resp, out, "INVALID_PROOF", http.StatusUnauthorized)
	r := w.request(http.MethodGet, "/invoices/INV-1042", nil)
	r.Header.Set(gateway.HeaderPresentation, " ")
	resp, out = w.send(r)
	problem(t, resp, out, "INVALID_PROOF", http.StatusUnauthorized)
	if resp.Header.Get(gateway.HeaderAdmission) != "" || len(w.receipts.All()) != 0 {
		t.Fatal("a request without a presentation received a receipt")
	}
	if w.app.count() != 0 {
		t.Fatal("a request without a presentation reached the handler")
	}
}

// TestNativeAuthenticationFirst: without native authentication an enforce
// route answers INVALID_PROOF, presentation or not (draft 2.3, 12.2, 13.4).
func TestNativeAuthenticationFirst(t *testing.T) {
	w := newWorld(t).start()
	r := w.request(http.MethodGet, "/invoices/INV-1042", nil)
	w.present(r)
	r.Header.Del("Authorization")
	resp, out := w.send(r)
	problem(t, resp, out, "INVALID_PROOF", http.StatusUnauthorized)
	if w.app.count() != 0 {
		t.Fatal("an unauthenticated request reached the handler")
	}
}

// TestPresentationOfAnotherRequest: a presentation for one request attached
// to another protected request is refused.
func TestPresentationOfAnotherRequest(t *testing.T) {
	w := newWorld(t).start()
	r := w.request(http.MethodGet, "/invoices/INV-1042", nil)
	p := w.present(r)
	other := w.request(http.MethodGet, "/invoices/INV-1043", nil)
	other.Header.Set(gateway.HeaderPresentation, p.Compact)
	resp, out := w.send(other)
	problem(t, resp, out, "CONTEXT_MISMATCH", http.StatusForbidden)
	if w.app.count() != 0 {
		t.Fatal("the handler was reached")
	}
}

// TestObserveNeverBlocks: an observe route lets every request through
// unchanged, whatever PACT would decide, and puts no admission in the
// context (draft 2.3, 4.4).
// TestObserveRecords: a presentation on an observe route is evaluated and
// its receipt recorded in observation mode (draft 4.4: every record declares
// observation mode).
// TestObserveContractOnEnforceRoute: an admission in observation mode is not
// enforced protection (draft 2.3), so it does not open an enforce route.
// TestOffRoute: an off route is not touched: no authentication, no
// presentation.
// TestDefaultEnforces: a route the configuration does not classify is
// enforced (fail closed).
// TestBindingRefusals: an enforce request the baseline HTTP mapping refuses
// is INVALID_MESSAGE (draft 10.2, 13.4; request binding section 4).
func TestBindingRefusals(t *testing.T) {
	for name, mutate := range map[string]func(*http.Request){
		"encoded unreserved": func(r *http.Request) { r.URL.RawPath, r.URL.Path = "/invoices/INV%2D1042", "/invoices/INV-1042" },
		"lowercase hex":      func(r *http.Request) { r.URL.RawQuery = "q=%c3%a9" },
		"content encoding":   func(r *http.Request) { r.Header.Set("Content-Encoding", "gzip") },
	} {
		t.Run(name, func(t *testing.T) {
			w := newWorld(t).start()
			r := w.request(http.MethodGet, "/invoices/INV-1042", nil)
			w.present(r)
			mutate(r)
			resp, out := w.send(r)
			problem(t, resp, out, "INVALID_MESSAGE", http.StatusBadRequest)
			if w.app.count() != 0 {
				t.Fatal("a refused request reached the handler")
			}
		})
	}
}

// TestHostRules: RB-65 and RB-66, on requests a program builds (a net/http
// server refuses them itself).
func TestHostRules(t *testing.T) {
	for name, mutate := range map[string]func(*http.Request){
		"two Host lines": func(r *http.Request) { r.Header["Host"] = []string{"gateway.example", "gateway.example"} },
		"no Host":        func(r *http.Request) { r.Host = "" },
	} {
		t.Run(name, func(t *testing.T) {
			w := newWorld(t)
			mw, err := gateway.New(w.cfg)
			if err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest(http.MethodGet, "/invoices/INV-1042", nil)
			r.Header.Set("Authorization", "Bearer "+token)
			r.Header.Set(gateway.HeaderPresentation, "a.b.c")
			mutate(r)
			rec := httptest.NewRecorder()
			mw(w.app).ServeHTTP(rec, memory.Arrive(r))
			if rec.Code != http.StatusBadRequest || w.app.count() != 0 {
				t.Fatalf("status %d, handler reached %d times; want 400 and none", rec.Code, w.app.count())
			}
		})
	}
}

// TestMappingVersionChanged: a contract recorded under another mapping
// version, or not recorded at all, is no longer active (RB-43).
func TestMappingVersionChanged(t *testing.T) {
	t.Run("other version", func(t *testing.T) {
		w := newWorld(t).start()
		r := w.request(http.MethodGet, "/invoices/INV-1042", nil)
		w.present(r)
		v2 := w.cfg
		v2.MappingVersion = mappingV2
		w.serve(v2)
		w.retarget(r)
		resp, out := w.send(r)
		problem(t, resp, out, "REQUIREMENTS_CHANGED", http.StatusConflict)
		if w.app.count() != 0 {
			t.Fatal("the handler was reached")
		}
	})
	t.Run("not recorded", func(t *testing.T) {
		w := newWorld(t).start()
		r := w.request(http.MethodGet, "/invoices/INV-1042", nil)
		w.present(r)
		fresh := w.cfg
		fresh.Records = gateway.NewMemoryRecords(16)
		w.serve(fresh)
		w.retarget(r)
		resp, out := w.send(r)
		problem(t, resp, out, "REQUIREMENTS_CHANGED", http.StatusConflict)
	})
}

// TestSecurityHold: a hold in force makes the evaluation INADMISSIBLE.
func TestSecurityHold(t *testing.T) {
	w := newWorld(t).start()
	r := w.request(http.MethodGet, "/invoices/INV-1042", nil)
	w.present(r)
	w.holds.Set(realm, agentID, "hold-1")
	resp, out := w.send(r)
	problem(t, resp, out, "SECURITY_HOLD", http.StatusForbidden)
	if w.app.count() != 0 {
		t.Fatal("the handler was reached under a security hold")
	}
}

// TestNoAdmissionFromClient: nothing a client sends puts an admission in the
// context of an off route.
// TestPresentationField: more than one PACT-Presentation line, or one larger
// than a maximal presentation, is INVALID_MESSAGE (draft 12.2, 20.1).
func TestPresentationField(t *testing.T) {
	for name, set := range map[string]func(r *http.Request, p string){
		"two lines": func(r *http.Request, p string) { r.Header.Add(gateway.HeaderPresentation, p) },
		"oversized": func(r *http.Request, p string) {
			r.Header.Set(gateway.HeaderPresentation, p+strings.Repeat("A", 360448))
		},
	} {
		t.Run(name, func(t *testing.T) {
			w := newWorld(t).start()
			r := w.request(http.MethodGet, "/invoices/INV-1042", nil)
			p := w.present(r)
			set(r, p.Compact)
			// The field is refused before the gateway reads anything of it:
			// a record store that cannot answer is never consulted.
			w.records.down.Store(true)
			resp, out := w.send(r)
			problem(t, resp, out, "INVALID_MESSAGE", http.StatusBadRequest)
			if w.app.count() != 0 {
				t.Fatal("the handler was reached")
			}
		})
	}
}

// TestNativeAuthorizationUnknown: an unknown native decision does not
// authorize execution (draft 2.3).
func TestNativeAuthorizationUnknown(t *testing.T) {
	rule := allow("report.read")
	rule.Effect = string(adapter.EffectUnknown)
	w := newWorld(t, withPolicy(rule)).start()
	r := w.request(http.MethodGet, "/reports/R-7", nil)
	w.present(r)
	resp, out := w.send(r)
	problem(t, resp, out, "DEPENDENCY_UNAVAILABLE", http.StatusServiceUnavailable)
	if w.app.count() != 0 {
		t.Fatal("the handler was reached on an unknown native decision")
	}
}

// TestAdmissionHeaderLimit: a negative limit sends no PACT-Admission; the
// receipt is still recorded and referenced in the context.
func TestAdmissionHeaderLimit(t *testing.T) {
	w := newWorld(t)
	w.cfg.AdmissionHeaderBytes = -1
	w.start()
	r := w.request(http.MethodGet, "/invoices/INV-1042", nil)
	w.present(r)
	resp, _ := w.send(r)
	if resp.StatusCode != http.StatusOK || resp.Header.Get(gateway.HeaderAdmission) != "" {
		t.Fatalf("status %d, PACT-Admission %q", resp.StatusCode, resp.Header.Get(gateway.HeaderAdmission))
	}
	if w.app.last(t).admission.Receipt.Receipt == "" {
		t.Fatal("the admission carries no receipt")
	}
}

// TestRefusalReferencesReceipt: a refusal after an evaluation names the
// decision and the recorded receipt.
func TestRefusalReferencesReceipt(t *testing.T) {
	w := newWorld(t).start()
	r := w.request(http.MethodGet, "/invoices/INV-1042", nil)
	w.present(r)
	w.holds.Set(realm, agentID, "hold-1")
	resp, out := w.send(r)
	p := problem(t, resp, out, "SECURITY_HOLD", http.StatusForbidden)
	a := receiptOf(t, resp)
	if string(p.Extensions["decision"]) != `"INADMISSIBLE"` || string(p.Extensions["receipt_id"]) != `"`+a.JTI+`"` {
		t.Fatalf("extensions %s", mustJSON(t, p.Extensions))
	}
	if _, err := w.receipts.Get(context.Background(), a.JTI); err != nil {
		t.Fatalf("the referenced receipt is not recorded: %v", err)
	}
}

// TestRequirementsChangedDefers: a contract that a policy change made
// inactive is evaluated, its active-policy check fails with
// REQUIREMENTS_CHANGED and the decision defers; the gateway refuses with
// REQUIREMENTS_CHANGED, obtain a new contract (draft 11.4, 12.2, 13.4).
func TestRequirementsChangedDefers(t *testing.T) {
	w := newWorld(t).start()
	r := w.request(http.MethodGet, "/invoices/INV-1042", nil)
	w.present(r)
	pol := w.val.Policies.(gateway.StaticPolicy)
	pol.ActivePolicy.Policy.BaseRevision = "base-2"
	w.val.Policies = pol
	resp, out := w.send(r)
	problem(t, resp, out, "REQUIREMENTS_CHANGED", http.StatusConflict)
	if a := receiptOf(t, resp); a.Decision != core.DecisionDeferred {
		t.Fatalf("receipt %s, want DEFERRED", a.Decision)
	}
	if w.app.count() != 0 {
		t.Fatal("the handler was reached under an inactive contract")
	}
}
