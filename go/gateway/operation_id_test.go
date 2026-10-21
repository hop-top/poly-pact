package gateway_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"hop.top/pact-go/core"
	"hop.top/pact-go/core/binding"
	"hop.top/pact-go/core/jws"
	"hop.top/pact-go/gateway"
	"hop.top/pact-go/holder"
)

// The operation_id of the actual operation is the one the agent proposed in
// its ContractRequest, which the gateway records with the contract when it
// issues it; the gateway's own mapping does not choose it (draft 10.2, 12.1).

// invoiceRead is r, a GET of invoice INV-1042 on an enforce or an observe
// route, as the agent binds it from the gateway's published route table
// alone: the installed action and resource, and an operation_id of the
// agent's choosing. The agent never calls the gateway's map_operation.
func (w *world) invoiceRead(r *http.Request, operationID string) core.OperationContext {
	w.t.Helper()
	cfg := binding.Config{Origin: origin, HeaderAllowlist: []string{"if-match"}, HeaderNormalizationID: "memory-header-normalization-1", MappingVersion: mappingV1, MaxBody: 8 << 20}
	op, err := holder.OperationFromRequest(cfg, r, operationID, env, principal, "invoice.read", []string{"https://invoices.example/invoices/INV-1042"})
	if err != nil {
		w.t.Fatalf("OperationFromRequest: %v", err)
	}
	return op
}

// presentOp runs the agent side for r with the proposed operation op and
// attaches the presentation to r.
func (w *world) presentOp(r *http.Request, op core.OperationContext) holder.Presentation {
	w.t.Helper()
	resp, compact := w.contractFor(op)
	if resp.StatusCode != http.StatusOK {
		w.t.Fatalf("requirements: %d %s", resp.StatusCode, compact)
	}
	p, err := w.holder.Present(context.Background(), holder.Input{Contract: compact, Intent: intent(), Operation: op, Profile: w.profile()}, w.clk.Now())
	if err != nil {
		w.t.Fatalf("Present: %v", err)
	}
	r.Header.Set(gateway.HeaderPresentation, p.Compact)
	return p
}

func checkResult(a core.AdmissionAttestation, id string) core.CheckStatus {
	for _, c := range a.Checks {
		if c.CheckID == id {
			return c.Result
		}
	}
	return ""
}

// TestOperationIDProposed: an agent that never calls map_operation proposes
// an operation_id of its own; the gateway admits the request, and the
// admitted operation and its receipt carry that operation_id.
func TestOperationIDProposed(t *testing.T) {
	const id = "agent-chosen-operation-7f3a"
	w := newWorld(t).start()
	r := w.request(http.MethodGet, "/invoices/INV-1042", nil)
	w.presentOp(r, w.invoiceRead(r, id))
	resp, out := w.send(r)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d %s, want the request admitted", resp.StatusCode, out)
	}
	a := w.app.last(t).admission
	if a.Operation.OperationID != id {
		t.Errorf("admitted operation_id %q, want the proposed %q", a.Operation.OperationID, id)
	}
	if got := receiptOf(t, resp); got.OperationID != id || got.Decision != core.DecisionAdmissible {
		t.Errorf("receipt %s operation_id %q, want ADMISSIBLE %q", got.Decision, got.OperationID, id)
	}
}

// TestOperationIDObserved: on an observe route the recorded receipt carries
// the proposed operation_id too.
func TestOperationIDObserved(t *testing.T) {
	const id = "agent-chosen-operation-observed"
	w := newWorld(t).start()
	r := w.request(http.MethodGet, "/observed/INV-1042", nil)
	w.presentOp(r, w.invoiceRead(r, id))
	if resp, _ := w.send(r); resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	all := w.receipts.All()
	if len(all) != 1 {
		t.Fatalf("%d receipts, want 1", len(all))
	}
	for _, res := range all {
		if a := res.Attestation; a.Decision != core.DecisionAdmissible || a.OperationID != id {
			t.Errorf("observe receipt %s operation_id %q, want ADMISSIBLE %q", a.Decision, a.OperationID, id)
		}
	}
}

// TestOperationIDOtherThanContract: a presentation whose operation carries
// another operation_id than the one its contract was issued for fails
// operation binding (draft 11.3 step 5): INADMISSIBLE, CONTEXT_MISMATCH,
// and the handler is not reached.
func TestOperationIDOtherThanContract(t *testing.T) {
	w := newWorld(t).start()
	r := w.request(http.MethodGet, "/invoices/INV-1042", nil)
	p := w.presentOp(r, w.invoiceRead(r, "operation-a"))
	claims := p.Claims
	claims.Operation.OperationID = "operation-b"
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	forged, err := jws.Sign(jws.Header{Typ: jws.TypPresentation}, payload, w.hkey)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set(gateway.HeaderPresentation, forged)
	resp, out := w.send(r)
	problem(t, resp, out, "CONTEXT_MISMATCH", http.StatusForbidden)
	if w.app.count() != 0 {
		t.Fatal("the handler was reached")
	}
	a := receiptOf(t, resp)
	if a.Decision != core.DecisionInadmissible || checkResult(a, "operation-binding") != core.CheckFail {
		t.Errorf("receipt %s, operation-binding %q; want INADMISSIBLE and FAIL", a.Decision, checkResult(a, "operation-binding"))
	}
}

// TestOperationIDPerContract: two contracts for the same request under
// different proposed operation_ids are kept apart: each presentation is
// admitted with the operation_id of its own contract, whatever the order.
func TestOperationIDPerContract(t *testing.T) {
	w := newWorld(t).start()
	ra := w.request(http.MethodGet, "/invoices/INV-1042", nil)
	rb := w.request(http.MethodGet, "/invoices/INV-1042", nil)
	w.presentOp(ra, w.invoiceRead(ra, "operation-a"))
	w.presentOp(rb, w.invoiceRead(rb, "operation-b"))
	for _, c := range []struct {
		r  *http.Request
		id string
	}{{rb, "operation-b"}, {ra, "operation-a"}} {
		resp, out := w.send(c.r)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: status %d %s", c.id, resp.StatusCode, out)
		}
		if got := w.app.last(t).admission.Operation.OperationID; got != c.id {
			t.Errorf("admitted operation_id %q, want %q", got, c.id)
		}
		if got := receiptOf(t, resp).OperationID; got != c.id {
			t.Errorf("receipt operation_id %q, want %q", got, c.id)
		}
	}
}
