package runner

// A native field rule whose mapping names its source's declared capability
// (spec/v1.0/fixtures/README.md, config.json additions, native_mappings[].source)
// is compared with it before the claim is read. In the three cases the roles
// rule is the one so mapped:
//
//   - admission/source-snapshot-only: a snapshot source, best bounds 600 and
//     600 seconds, no live check; the rule demands 30 and 0, below both, so
//     roles is UNKNOWN UNSUPPORTED_REQUIREMENT and the exchange DEFERRED
//     (draft 17.2).
//   - admission/source-poll-delta-within-bound: a poll-delta source, best
//     bounds 60 and 30, no live check; the rule demands 120 and 60, and the
//     claim is 20 seconds old: roles PASS, ADMISSIBLE.
//   - admission/source-push-outage: a push source, best bounds 30 and 30, no
//     live check; the rule demands 120 and 60, which the source can meet,
//     and the claim is 90 seconds old: a cached answer the source cannot
//     refresh, roles UNKNOWN DEPENDENCY_UNAVAILABLE, DEFERRED (draft 18).

import (
	"path/filepath"
	"testing"
)

const pollDeltaCase = "admission/source-poll-delta-within-bound"

var sourceCases = []string{snapshotSourceCase, pollDeltaCase, pushOutageCase}

// rolesAs sets the roles check of the receipt.
func rolesAs(t *testing.T, result, reason string) func(map[string]any) {
	return func(p map[string]any) {
		c := check(t, p, "roles")
		c["result"], c["reason_code"] = result, reason
	}
}

func TestEvaluateNativeSourceCases(t *testing.T) {
	for id, r := range runMode(t, "good", sourceCases...) {
		if r.Status != StatusPass {
			t.Errorf("good %s = %+v, want PASS", id, r)
		}
	}
	got := runMode(t, "ignores-capability", sourceCases...)
	for _, id := range []string{snapshotSourceCase, pushOutageCase} {
		if r := got[id]; r.Status != StatusFail || !detailsContain(r.Details, "check roles") {
			t.Errorf("ignores-capability %s = %+v, want FAIL naming roles", id, r)
		}
	}
	if r := got[pollDeltaCase]; r.Status != StatusPass {
		t.Errorf("ignores-capability %s = %+v, want PASS: the source meets the rule", pollDeltaCase, r)
	}
}

// TestEvaluateNativeSourceUnlisted: the runner judges the roles check by the
// capability rule also when the expected result does not list it, and only
// a check the rule decides.
func TestEvaluateNativeSourceUnlisted(t *testing.T) {
	type edit struct {
		file string
		f    func(map[string]any)
	}
	mapping := func(f func(src map[string]any)) edit {
		return edit{"config.json", func(c map[string]any) {
			for _, m := range c["native_mappings"].([]any) {
				if m := m.(map[string]any); m["native_path"] == "/principal/roles" {
					if f == nil {
						m["source"] = nil
						continue
					}
					f(m["source"].(map[string]any))
				}
			}
		}}
	}
	rolesClaimAt := func(at int64) edit {
		return edit{"native_context.json", func(nc map[string]any) {
			for _, c := range nc["native_claims"].([]any) {
				if c := c.(map[string]any); c["native_path"] == "/principal/roles" {
					c["observed_at"], c["status_checked_at"] = at, at
				}
			}
		}}
	}
	tests := []struct {
		name, id string
		edits    []edit
		receipt  func(map[string]any)
		want     Status
		subs     []string
	}{
		{"snapshot as printed", snapshotSourceCase, nil, nil, StatusPass, nil},
		{"snapshot: roles passed", snapshotSourceCase, nil, rolesAs(t, "PASS", "REQUIREMENT_SATISFIED"), StatusFail, []string{"check roles", "UNKNOWN UNSUPPORTED_REQUIREMENT", "17.2"}},
		{"snapshot: roles stale", snapshotSourceCase, nil, rolesAs(t, "FAIL", "STALE_EVIDENCE"), StatusFail, []string{"check roles", "UNKNOWN UNSUPPORTED_REQUIREMENT"}},
		{"snapshot: roles deferred for the outage", snapshotSourceCase, nil, rolesAs(t, "UNKNOWN", "DEPENDENCY_UNAVAILABLE"), StatusFail, []string{"check roles", "UNSUPPORTED_REQUIREMENT"}},
		// No declared source: v1 behaviour, the check is not judged.
		{"snapshot without a source", snapshotSourceCase, []edit{mapping(nil)}, rolesAs(t, "PASS", "REQUIREMENT_SATISFIED"), StatusPass, nil},
		// Bounds at the rule's limits can be met: not judged.
		{"snapshot bounds at the limits", snapshotSourceCase, []edit{mapping(func(s map[string]any) {
			s["best_max_age_seconds"], s["best_status_max_age_seconds"], s["live_check"] = 30, 0, true
		})}, rolesAs(t, "FAIL", "STALE_EVIDENCE"), StatusPass, nil},
		// One bound above its limit is enough.
		{"snapshot status bound only", snapshotSourceCase, []edit{mapping(func(s map[string]any) { s["best_max_age_seconds"] = 30 })}, rolesAs(t, "PASS", "REQUIREMENT_SATISFIED"), StatusFail, []string{"check roles", "UNSUPPORTED_REQUIREMENT"}},
		{"snapshot max age bound only", snapshotSourceCase, []edit{mapping(func(s map[string]any) {
			s["best_max_age_seconds"], s["best_status_max_age_seconds"], s["live_check"] = 31, 0, true
		})}, rolesAs(t, "PASS", "REQUIREMENT_SATISFIED"), StatusFail, []string{"check roles", "UNSUPPORTED_REQUIREMENT"}},

		{"outage as printed", pushOutageCase, nil, nil, StatusPass, nil},
		{"outage: roles stale", pushOutageCase, nil, rolesAs(t, "FAIL", "STALE_EVIDENCE"), StatusFail, []string{"check roles", "UNKNOWN DEPENDENCY_UNAVAILABLE", "18"}},
		{"outage: roles passed", pushOutageCase, nil, rolesAs(t, "PASS", "REQUIREMENT_SATISFIED"), StatusFail, []string{"check roles", "UNKNOWN DEPENDENCY_UNAVAILABLE"}},
		// A source that can check live refreshes the answer: a stale one is
		// its failure, not an outage, and the runner does not judge it.
		{"outage source checks live", pushOutageCase, []edit{mapping(func(s map[string]any) { s["live_check"] = true })}, rolesAs(t, "FAIL", "STALE_EVIDENCE"), StatusPass, nil},
		// A cached status inside its limit is not an outage: 60 seconds old,
		// the limit 60.
		{"outage claim at the limit", pushOutageCase, []edit{rolesClaimAt(1792079940)}, rolesAs(t, "FAIL", "STALE_EVIDENCE"), StatusPass, nil},
		{"outage claim one past the limit", pushOutageCase, []edit{rolesClaimAt(1792079939)}, rolesAs(t, "FAIL", "STALE_EVIDENCE"), StatusFail, []string{"check roles", "DEPENDENCY_UNAVAILABLE"}},

		{"poll delta as printed", pollDeltaCase, nil, nil, StatusPass, nil},
		// Within the bound: the capability rule decides nothing.
		{"poll delta: roles stale", pollDeltaCase, nil, rolesAs(t, "FAIL", "STALE_EVIDENCE"), StatusPass, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := subsetRoot(t, tt.id)
			editExpected(t, root, tt.id, func(d map[string]any) { d["checks"] = []any{} })
			for _, e := range tt.edits {
				editJSONFile(t, filepath.Join(root, filepath.FromSlash(tt.id), e.file), e.f)
			}
			lines := readLines(t, filepath.Join(goldenDir, filepath.FromSlash(tt.id), "evaluate.out"))
			if tt.receipt != nil {
				lines[0] = mutator{keys: loadKeys(t)}.resign(t, lines[0], "", nil, tt.receipt)
			}
			r := runPrinted(t, root, tt.id, lines)
			if r.Status != tt.want {
				t.Fatalf("= %+v, want %s", r, tt.want)
			}
			if tt.want == StatusFail && !detailsContain(r.Details, tt.subs...) {
				t.Errorf("details %q, want one naming %q", r.Details, tt.subs)
			}
		})
	}
}

// TestEvaluateNativeSourceListed: a listed check is judged by its expected
// result alone, one difference per member, and not again by the capability
// rule.
func TestEvaluateNativeSourceListed(t *testing.T) {
	r := customRun(t, snapshotSourceCase, 0, "", nil, rolesAs(t, "PASS", "REQUIREMENT_SATISFIED"))
	wantDiffs(t, r, StatusFail, [][]string{
		{"check roles", "result PASS", "want UNKNOWN"},
		{"check roles", "reason_code REQUIREMENT_SATISFIED", "want UNSUPPORTED_REQUIREMENT"},
	})
}
