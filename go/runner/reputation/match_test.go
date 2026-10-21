package reputation_test

import (
	"strings"
	"testing"

	"hop.top/pact-go/runner/reputation"
)

// TestMatchValue: the expected value is a subset, score_bps and
// confidence_bps match within one basis point and every other member
// exactly (spec/v1.0/fixtures/README.md, section snapshot.json).
func TestMatchValue(t *testing.T) {
	got := `{"context":{"action_class":"invoice.read"},"dimensions":{"reliability":{"score_bps":6666,"confidence_bps":476,"independent_tasks":1,"qualified_events":1,"newest_event_at":5}},"hold_refs":["a","b"],"security_status":"HOLD"}`
	for _, tc := range []struct {
		want  string
		parts []string
	}{
		{`{}`, nil},
		{`{"dimensions":{"reliability":{"score_bps":6667,"confidence_bps":475}}}`, nil},
		{`{"dimensions":{"reliability":{"score_bps":6668}}}`, []string{"/value/dimensions/reliability/score_bps is 6666, want 6668 within 1 bp"}},
		{`{"dimensions":{"reliability":{"confidence_bps":474}}}`, []string{"/value/dimensions/reliability/confidence_bps is 476, want 474"}},
		{`{"dimensions":{"reliability":{"independent_tasks":2}}}`, []string{"/value/dimensions/reliability/independent_tasks is 1, want 2"}},
		{`{"dimensions":{"task_quality":{"score_bps":5000}}}`, []string{"/value/dimensions/task_quality is missing"}},
		{`{"hold_refs":["a"]}`, []string{`/value/hold_refs is ["a","b"], want ["a"]`}},
		{`{"hold_refs":["b","a"]}`, []string{"/value/hold_refs"}},
		{`{"security_status":"CLEAR"}`, []string{`/value/security_status is "HOLD", want "CLEAR"`}},
		{`{"context":"x"}`, []string{"/value/context is"}},
		{`{"context":{"action_class":"payment.approve"}}`, []string{"/value/context/action_class"}},
		{`{"dimensions":{"reliability":{"score_bps":"6666"}}}`, []string{"want the integer"}},
	} {
		ps := reputation.MatchValue([]byte(tc.want), []byte(got))
		if len(ps) != len(tc.parts) {
			t.Errorf("%s: problems %q, want %d", tc.want, ps, len(tc.parts))
			continue
		}
		for i, p := range tc.parts {
			if !strings.Contains(ps[i], p) {
				t.Errorf("%s: problem %q, want %q", tc.want, ps[i], p)
			}
		}
	}
	if ps := reputation.MatchValue([]byte(`{`), []byte(got)); len(ps) != 1 {
		t.Errorf("a broken expected value: %q", ps)
	}
	if ps := reputation.MatchValue([]byte(`{}`), []byte(`[`)); len(ps) != 1 {
		t.Errorf("a broken value: %q", ps)
	}
}
