package runner

// The delegation group (spec/v1.0/fixtures/delegation): the actor transitions of
// draft Section 17.5. The evaluate entries assert native-principal-binding-v1,
// native-delegation-v1 and execution-identity-v1 through the per-check
// comparison of decision.json; the outcomes entry asserts the qualification
// and the snapshot of a report whose executor class differs from the
// declared one (Section 14.2). The bad modes are those of testdata/fakeimpl.

import (
	"slices"
	"strings"
	"testing"
)

// delegationIDs are the committed entries of the delegation group.
func delegationIDs(t *testing.T) []string {
	t.Helper()
	var ids []string
	for _, e := range repoEntries(t) {
		if id := e["id"].(string); strings.HasPrefix(id, "delegation/") {
			ids = append(ids, id)
		}
	}
	if len(ids) != 9 {
		t.Fatalf("%d delegation entries, want the 9 of spec/v1.0/fixtures/delegation/README.md", len(ids))
	}
	return ids
}

// runDelegation runs the fake implementation in mode over the delegation
// group and returns the result of each entry.
func runDelegation(t *testing.T, mode string) map[string]Result {
	t.Helper()
	ids := delegationIDs(t)
	rep, err := Run(fakeImplCfg(t, mode, outcomesRoot(t, ids...)))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]Result{}
	for _, id := range ids {
		out[id] = result(t, rep, id)
	}
	return out
}

// TestDelegationGoodImplPasses: the good fake implementation passes every
// delegation entry with every sub-check run.
func TestDelegationGoodImplPasses(t *testing.T) {
	for id, r := range runDelegation(t, "good") {
		if r.Status != StatusPass || len(r.Skipped) > 0 {
			t.Errorf("%s = %s %q, skipped %q; want PASS with every sub-check", id, r.Status, r.Details, r.Skipped)
		}
	}
}

// TestDelegationBadModes: each bad mode fails exactly the delegation entry
// it breaks, and every other delegation entry passes. An evaluate mode
// reports exactly the difference lines listed; an outcomes mode a detail
// with each string of one entry.
func TestDelegationBadModes(t *testing.T) {
	const fallback = "delegation/broader-credential-fallback"
	tests := []struct {
		mode, id string
		// lines are the substrings of each difference line of an evaluate
		// mode, in order.
		lines [][]string
		// details are substrings that some detail of an outcomes mode names.
		details [][]string
		// skipped is the sub-check the mode leaves unrun.
		skipped string
	}{
		{mode: "fallback-executor-admitted", id: fallback, lines: [][]string{
			{"decision ADMISSIBLE", "want INADMISSIBLE"},
			{"check execution-identity-v1", "result PASS", "want FAIL"},
			{"check execution-identity-v1", "reason_code REQUIREMENT_SATISFIED", "want EXECUTOR_MISMATCH"},
		}},
		{mode: "fallback-executor-passes", id: fallback, lines: [][]string{
			{"check execution-identity-v1", "result PASS", "want FAIL"},
			{"check execution-identity-v1", "reason_code REQUIREMENT_SATISFIED", "want EXECUTOR_MISMATCH"},
		}},
		{mode: "qualifies-executor-mismatch", id: mismatchCase, details: [][]string{
			{"classifications[execution-event-0001] is QUALIFIED, want UNQUALIFIED", "executor-class-mismatch"},
			{"provenance qualified_event_ids", "want []"},
			{"/value/dimensions/reliability/score_bps", "6666"},
		}},
		{mode: "counts-executor-mismatch", id: mismatchCase, details: [][]string{
			{"provenance qualified_event_ids", "want []"},
			{"/value/dimensions/reliability/score_bps", "6666"},
			{"/value/dimensions/reliability/qualified_events", "1"},
		}, skipped: SkipQualification},
	}
	for _, tt := range tests {
		t.Run(tt.mode, func(t *testing.T) {
			for id, r := range runDelegation(t, tt.mode) {
				if id != tt.id {
					if r.Status != StatusPass {
						t.Errorf("%s = %s %q, want PASS: the mode does not touch it", id, r.Status, r.Details)
					}
					continue
				}
				if r.Status != StatusFail {
					t.Fatalf("%s = %s %q, want FAIL", id, r.Status, r.Details)
				}
				if tt.skipped != "" && !slices.Contains(r.Skipped, tt.skipped) {
					t.Errorf("%s skipped %q, want %q", id, r.Skipped, tt.skipped)
				}
				for _, subs := range tt.details {
					if !detailsContain(r.Details, subs...) {
						t.Errorf("%s details %q, want one naming %q", id, r.Details, subs)
					}
				}
				if tt.lines == nil {
					continue
				}
				// The details end with the command summary line, which no
				// difference line is.
				diffs := r.Details
				if n := len(diffs); n > 0 && strings.HasPrefix(diffs[n-1], "[") {
					diffs = diffs[:n-1]
				}
				if len(diffs) != len(tt.lines) {
					t.Fatalf("%s details %q, want %d difference lines", id, r.Details, len(tt.lines))
				}
				for i, subs := range tt.lines {
					if !detailsContain(diffs[i:i+1], subs...) {
						t.Errorf("%s detail %d = %q, want it to name %q", id, i+1, diffs[i], subs)
					}
				}
			}
		})
	}
}
