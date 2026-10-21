package gateway_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/contract"
	"hop.top/pact-go/core"
	"hop.top/pact-go/core/digest"
	"hop.top/pact-go/gateway"
)

// stdioIPC makes the effective requirements name the stdio-ipc transport
// profile (draft 13.3.1, Appendix A.2), and the validator and holder
// support the extension.
func stdioIPC(w *world) {
	decl := json.RawMessage(`{"channels":["uds"],"framing":"ndjson","identity_assurance":["kernel-peer"],"max_frame_bytes":360448,"transport_profile":"stdio-ipc","version":"0.1"}`)
	inner := w.cfg.Requirements
	w.cfg.Requirements = gateway.RequirementsFunc(func(ctx context.Context, p adapter.Principal, req core.ContractRequest) (contract.Requirements, error) {
		rs, err := inner.Requirements(ctx, p, req)
		rs.Extensions = core.Object{"pact-transport-profile-v1": decl}
		return rs, err
	})
	w.val.Config.SupportedExtensions = []string{"pact-transport-profile-v1"}
	w.holder.Extensions = []string{"pact-transport-profile-v1"}
}

// TestTransportContractRequest: the HTTP gateway does not return, over
// HTTPS, an enforced-mode contract that names another transport: the
// contract request is refused with CONTEXT_MISMATCH and no contract is
// recorded (draft 13.3.1, the downgrade rule; 13.4).
func TestTransportContractRequest(t *testing.T) {
	w := newWorld(t)
	stdioIPC(w)
	w.start()
	resp, out := w.contractFor(w.proposal(w.request(http.MethodGet, "/invoices/INV-1042", nil)))
	problem(t, resp, []byte(out), "CONTEXT_MISMATCH", http.StatusForbidden)
	if n := w.records.recorded.Load(); n != 0 {
		t.Errorf("%d contracts recorded, want none", n)
	}
}

// TestTransportObserve: in observe mode the mismatch does not refuse: the
// contract is returned, the presentation over HTTPS is evaluated and its
// receipt recorded in observation mode, and the request reaches the
// handler (draft 13.3.1, 2.3).
func TestTransportObserve(t *testing.T) {
	w := newWorld(t)
	stdioIPC(w)
	w.start()
	r := w.request(http.MethodGet, "/observed/INV-1042", nil)
	p := w.present(r)
	resp, _ := w.send(r)
	if resp.StatusCode != http.StatusOK || w.app.count() != 1 {
		t.Fatalf("status %d, %d visits; want the request to reach the handler", resp.StatusCode, w.app.count())
	}
	d, err := digest.ArtifactDigest(p.Claims.Contract)
	if err != nil {
		t.Fatal(err)
	}
	rs, err := w.receipts.ByContract(context.Background(), d)
	if err != nil || len(rs) != 1 {
		t.Fatalf("%d receipts, %v; want the observation recorded", len(rs), err)
	}
	if a := rs[0].Attestation; a.Mode != core.ModeObserve {
		t.Errorf("receipt mode %s, want observe", a.Mode)
	}
}
