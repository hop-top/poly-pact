package abac_test

import (
	"testing"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/adaptertest"
	"hop.top/pact-go/core/clock"
)

// replaced is the common authorize_native case whose expected decision
// carries a member the Data API answer cannot carry, with the ABAC case that
// shows the same property (profile section 10, "Replaced common cases").
var replaced = map[string]adaptertest.Replacement{
	"COMMON-06.decision-provenance": {
		By:     "ABAC-37.provenance",
		Reason: "expects decided_at 1792079998; the OPA Data API answer gives no decision time (ABAC-15), so DecidedAt is the zero time",
	},
}

// conformanceFactory builds the adapter under test for a case.
var conformanceFactory adaptertest.Factory = abacFactory

// integrationAdapter builds the adapter under test over the world of a case
// whose PDP is a real OPA server.
var integrationAdapter = func(_ testing.TB, w *world, clk clock.Clock, _ *adaptertest.Hooks) (adapter.Adapter, error) {
	a, _, err := worldAdapter(w, clk)
	return a, err
}

// TestConformance runs the conformance suite, the common cases and the ABAC
// cases of spec/v1.0/fixtures/adapters/abac, with the replaced common case
// declared. The profile inherits the workload rule of the authenticating
// mechanism; the reference one has dedicated workloads, so the dedicated
// cases run.
func TestConformance(t *testing.T) {
	adaptertest.Run(t, conformanceFactory, adaptertest.Options{Adapter: "abac", Replaced: replaced})
}
