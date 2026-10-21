package validator_test

import (
	"context"
	"testing"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/core"
	"hop.top/pact-go/validator"
)

// TestTransportBinding: an enforced-mode presentation received over a
// transport other than the one its contract names is rejected with
// CONTEXT_MISMATCH before an authenticated evaluation, so no receipt is
// issued and the nonce is not consumed (draft 13.3.1, the downgrade rule;
// 12.2; 13.4). The contract names the transport_profile of its
// pact-transport-profile-v1 declaration, or https when it carries none; the
// transport the presentation arrived over is the one the gateway
// established, Request.Transport. Over the transport the contract names,
// the same presentation is evaluated and admitted.
func TestTransportBinding(t *testing.T) {
	for _, tc := range []struct {
		id      string
		arrived string // the transport of the case's submission
		named   string // the transport the contract names
	}{
		{"transport/stdio-ipc-contract-over-https", "https", "stdio-ipc"},
		{"transport/https-contract-over-stdio-ipc", "stdio-ipc", "https"},
		{"admission/valid", "https", "https"},
	} {
		t.Run(tc.id, func(t *testing.T) {
			f := prepare(t, tc.id)
			if f.Request.Transport != tc.arrived {
				t.Fatalf("request transport %q, want the submission's %q", f.Request.Transport, tc.arrived)
			}
			for _, other := range []string{"", "https", "stdio-ipc", "HTTPS", "http"} {
				if other == tc.named {
					continue
				}
				f.Request.Transport = other
				res, err := f.Validator.Evaluate(context.Background(), f.Request)
				if res.Receipt != "" || codeOf(t, err) != adapter.CodeContextMismatch {
					t.Fatalf("arrived over %q: %v, receipt %q; want CONTEXT_MISMATCH and no receipt", other, err, res.Receipt)
				}
				if p, ok := validator.ProblemOf(err, "r1"); !ok || p.Code != string(adapter.CodeContextMismatch) || p.Status != 403 {
					t.Errorf("problem %+v", p)
				}
			}
			f.Request.Transport = tc.named
			res := evaluate(t, f)
			if a := res.Attestation; a.Decision != core.DecisionAdmissible || a.Mode != core.ModeEnforced {
				t.Fatalf("over %q: %s %s, want an enforced ADMISSIBLE receipt (the rejections consumed no nonce)", tc.named, a.Decision, a.Mode)
			}
		})
	}
}
