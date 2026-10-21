package learning

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"hop.top/pact-go/core"
)

// TestPolicyDataPolicyBounds: ValidatePolicy applies every bound of the
// data policy (Appendix A.3 DataPolicy; draft Sections 14.3 and 15.3), and
// a policy outside one is not installed.
func TestPolicyDataPolicyBounds(t *testing.T) {
	long := strings.Repeat("x", 1024)
	ext := func(n int) core.Object {
		o := core.Object{}
		for i := range n {
			o[fmt.Sprintf("https://ext.example/%d", i)] = json.RawMessage("true")
		}
		return o
	}
	for _, tc := range []struct {
		name string
		edit func(*core.DataPolicy)
		// member is the member an invalid edit names; "" for a valid one.
		member string
	}{
		{"window 1", func(d *core.DataPolicy) { d.IngestionWindowSeconds = 1 }, ""},
		{"window 2^53-1", func(d *core.DataPolicy) { d.IngestionWindowSeconds = 1<<53 - 1 }, ""},
		{"window 0", func(d *core.DataPolicy) { d.IngestionWindowSeconds = 0 }, "ingestion_window_seconds"},
		{"window 2^53", func(d *core.DataPolicy) { d.IngestionWindowSeconds = 1 << 53 }, "ingestion_window_seconds"},
		{"positive cap 0", func(d *core.DataPolicy) { d.PositiveWeightCapPerTask = 0 }, "positive_weight_cap_per_task"},
		{"positive cap 2", func(d *core.DataPolicy) { d.PositiveWeightCapPerTask = 2 }, "positive_weight_cap_per_task"},
		{"failure weight 1", func(d *core.DataPolicy) { d.MaximumFailureWeight = 1 }, ""},
		{"failure weight 0", func(d *core.DataPolicy) { d.MaximumFailureWeight = 0 }, "maximum_failure_weight"},
		{"failure weight 6", func(d *core.DataPolicy) { d.MaximumFailureWeight = 6 }, "maximum_failure_weight"},
		{"identifiers of 1024", func(d *core.DataPolicy) {
			d.QualificationPolicyID, d.TaskAttributionSource, d.ReporterIndependencePolicyID = long, long, long
		}, ""},
		{"no attribution source", func(d *core.DataPolicy) { d.TaskAttributionSource = "" }, "task_attribution_source"},
		{"qualification policy of 1025", func(d *core.DataPolicy) { d.QualificationPolicyID = long + "x" }, "qualification_policy_id"},
		{"no independence policy", func(d *core.DataPolicy) { d.ReporterIndependencePolicyID = "" }, "reporter_independence_policy_id"},
		{"128 extensions", func(d *core.DataPolicy) { d.Extensions = ext(128) }, ""},
		{"129 extensions", func(d *core.DataPolicy) { d.Extensions = ext(129) }, "extensions"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := basePolicy()
			tc.edit(&p.DataPolicy)
			err := ValidatePolicy(p)
			switch {
			case tc.member == "" && err != nil:
				t.Fatalf("ValidatePolicy = %v, want valid", err)
			case tc.member != "" && (err == nil || !strings.Contains(err.Error(), "data_policy") || !strings.Contains(err.Error(), tc.member)):
				t.Fatalf("ValidatePolicy = %v, want an error naming data_policy and %s", err, tc.member)
			}
			if tc.member != "" {
				wantReject(t, newFixture(t).start().install(func(q *core.LearningPolicy) { q.DataPolicy = p.DataPolicy }), CodeInvalidMessage)
			}
		})
	}
}
