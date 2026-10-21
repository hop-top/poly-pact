package gateway_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapters/memory"
	"hop.top/pact-go/contract"
	"hop.top/pact-go/core"
	"hop.top/pact-go/core/digest"
	"hop.top/pact-go/core/jws"
	"hop.top/pact-go/gateway"
)

// TestRequirementsServed: the requirements endpoint answers a natively
// authenticated ContractRequest with a signed contract (draft 9.1, 13.2) for
// the proposed operation, in the mode of its route, and records the
// installed mapping version with it (RB-42).
func TestRequirementsServed(t *testing.T) {
	for name, tc := range map[string]struct {
		path string
		mode core.Mode
	}{
		"enforce": {"/invoices/INV-1042", core.ModeEnforced},
		"observe": {"/observed/INV-1042", core.ModeObserve},
	} {
		t.Run(name, func(t *testing.T) {
			w := newWorld(t).start()
			op := w.proposal(w.request(http.MethodGet, tc.path, nil))
			resp, compact := w.contractFor(op)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status %d: %s", resp.StatusCode, compact)
			}
			if ct := resp.Header.Get("Content-Type"); ct != "application/jose" {
				t.Errorf("Content-Type %q, want application/jose", ct)
			}
			c, err := contract.Verifier{Publishers: map[string]*jws.KeySet{publisher: w.val.Config.Publishers[publisher]}}.Verify(compact, w.clk.Now())
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			opDigest, _ := digest.ObjectDigest(op)
			if c.Claims.Mode != tc.mode || c.Claims.Subject != agentID || c.Claims.HolderJKT != w.jkt || c.Claims.OperationDigest != opDigest {
				t.Errorf("contract %+v", c.Claims)
			}
			rec, err := w.records.Lookup(context.Background(), c.Digest, w.clk.Now())
			if err != nil || rec.MappingVersion != mappingV1 || rec.OperationID != op.OperationID {
				t.Errorf("record %+v, %v; want version %s and the proposed operation_id %s", rec, err, mappingV1, op.OperationID)
			}
		})
	}
}

// TestRequirementsRefusals: the endpoint issues nothing when native
// authentication, the agent binding, or the proposed operation does not hold
// (draft 9.1, 13.4; RB-42).
func TestRequirementsRefusals(t *testing.T) {
	type tc struct {
		mutate func(*world, *core.ContractRequest)
		strip  bool
		code   string
		status int
	}
	for name, c := range map[string]tc{
		"no native authentication": {strip: true, code: "INVALID_PROOF", status: 401},
		"unknown agent": {mutate: func(_ *world, r *core.ContractRequest) {
			r.AgentID = "https://identity.example/agents/other"
		}, code: "INVALID_PROOF", status: 401},
		"another key": {mutate: func(_ *world, r *core.ContractRequest) {
			r.HolderJKT = digest.BytesDigest([]byte("another key"))
		}, code: "INVALID_PROOF", status: 401},
		"another principal": {mutate: func(_ *world, r *core.ContractRequest) {
			r.Operation.PrincipalID = "https://identity.example/principals/bob"
		}, code: "CONTEXT_MISMATCH", status: 403},
		"another environment": {mutate: func(_ *world, r *core.ContractRequest) {
			r.Operation.EnvironmentID = "https://gateway.example/environments/test"
		}, code: "CONTEXT_MISMATCH", status: 403},
		"another action": {mutate: func(_ *world, r *core.ContractRequest) {
			r.Operation.Action = "invoice.pay"
		}, code: "CONTEXT_MISMATCH", status: 403},
		"another resource": {mutate: func(_ *world, r *core.ContractRequest) {
			r.Operation.Resources = []string{"https://invoices.example/invoices/INV-1"}
		}, code: "CONTEXT_MISMATCH", status: 403},
		"another origin": {mutate: func(_ *world, r *core.ContractRequest) {
			r.Operation.TargetURI = "https://other.example/invoices/INV-1042"
		}, code: "CONTEXT_MISMATCH", status: 403},
		"header not allowlisted": {mutate: func(_ *world, r *core.ContractRequest) {
			r.Operation.Headers = map[string]string{"x-dry-run": "1"}
		}, code: "CONTEXT_MISMATCH", status: 403},
		"ambiguous target": {mutate: func(_ *world, r *core.ContractRequest) {
			r.Operation.TargetURI = origin + "/invoices/INV%2D1042"
		}, code: "INVALID_MESSAGE", status: 400},
		"no operation id": {mutate: func(_ *world, r *core.ContractRequest) {
			r.Operation.OperationID = ""
		}, code: "INVALID_MESSAGE", status: 400},
		"no route": {mutate: func(_ *world, r *core.ContractRequest) {
			r.Operation.TargetURI = origin + "/nowhere"
		}, code: "UNSUPPORTED_REQUIREMENT", status: 422},
		"off route": {mutate: func(_ *world, r *core.ContractRequest) {
			// The mapping has a route for it, so only its class refuses it.
			r.Operation.TargetURI = origin + "/health"
			r.Operation.Action = "health.read"
			r.Operation.Resources = []string{"https://gateway.example/health"}
		}, code: "UNSUPPORTED_REQUIREMENT", status: 422},
	} {
		t.Run(name, func(t *testing.T) {
			w := newWorld(t).start()
			op := w.proposal(w.request(http.MethodGet, "/invoices/INV-1042", nil))
			cr := core.ContractRequest{AgentID: agentID, HolderJKT: w.jkt, Intent: intent(), Operation: op}
			if c.mutate != nil {
				c.mutate(w, &cr)
			}
			r := w.request(http.MethodPost, gateway.RequirementsPath, []byte(mustJSON(t, cr)))
			if c.strip {
				r.Header.Del("Authorization")
			}
			resp, out := w.send(r)
			problem(t, resp, out, c.code, c.status)
			if n := w.records.recorded.Load(); n != 0 {
				t.Errorf("%d contracts recorded, want none", n)
			}
		})
	}
}

// TestRequirementsMalformed: a body that is not a strict ContractRequest is
// INVALID_MESSAGE; another method is not served.
func TestRequirementsMalformed(t *testing.T) {
	w := newWorld(t).start()
	for name, body := range map[string]string{
		"not json":       "{",
		"duplicate key":  `{"agent_id":"a","agent_id":"b"}`,
		"unknown member": `{"agent_id":"a","x":1}`,
	} {
		t.Run(name, func(t *testing.T) {
			resp, out := w.send(w.request(http.MethodPost, gateway.RequirementsPath, []byte(body)))
			problem(t, resp, out, "INVALID_MESSAGE", http.StatusBadRequest)
		})
	}
	resp, _ := w.send(w.request(http.MethodGet, gateway.RequirementsPath, nil))
	if resp.StatusCode != http.StatusMethodNotAllowed || resp.Header.Get("Allow") != http.MethodPost {
		t.Errorf("GET: status %d Allow %q", resp.StatusCode, resp.Header.Get("Allow"))
	}
	if w.app.count() != 0 {
		t.Error("the requirements endpoint reached the application")
	}
}

// TestRequirementsRecordFailure: a contract whose mapping version cannot be
// recorded is not returned (RB-42, draft 18).
func TestRequirementsRecordFailure(t *testing.T) {
	w := newWorld(t)
	w.cfg.Records = failingRecords{}
	w.start()
	resp, out := w.contractFor(w.proposal(w.request(http.MethodGet, "/invoices/INV-1042", nil)))
	problem(t, resp, []byte(out), "DEPENDENCY_UNAVAILABLE", http.StatusServiceUnavailable)
}

type failingRecords struct{}

func (failingRecords) Record(context.Context, core.Digest, gateway.ContractRecord, time.Time, time.Time) error {
	return adapter.ErrDependencyUnavailable
}

func (failingRecords) Lookup(context.Context, core.Digest, time.Time) (gateway.ContractRecord, error) {
	return gateway.ContractRecord{}, adapter.ErrDependencyUnavailable
}

// TestRequirementsCompromisedBinding: a contract request for an agent whose
// binding is marked compromised is refused with SECURITY_HOLD (403), and no
// contract is issued (draft 6.4, 9.1).
func TestRequirementsCompromisedBinding(t *testing.T) {
	w := newWorld(t, func(w *world) {
		st := w.native.State()
		st.Enrollments[0].Status = string(adapter.BindingCompromised)
		a, err := memory.New(st, w.clk)
		if err != nil {
			w.t.Fatal(err)
		}
		w.native = a
	}).start()
	resp, out := w.contractFor(w.proposal(w.request(http.MethodGet, "/invoices/INV-1042", nil)))
	problem(t, resp, []byte(out), "SECURITY_HOLD", http.StatusForbidden)
}
