package runner

// Tests of the checks on selection cases beyond the comparison with the
// expected results: the same inputs give the same result (draft 11.3 step 9),
// and the checks reputation-context and selection-consistency-v1 name the
// presented snapshot and the selection record (draft A.2). The cases are the
// committed selection group; the bad implementations are the modes of
// testdata/fakeimpl.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"hop.top/pact-go/runner/evalcase"
)

// selectionIDs returns the committed selection cases, all of them.
func selectionIDs(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, e := range repoEntries(t) {
		if id, _ := e["id"].(string); strings.HasPrefix(id, "selection/") && kindOf(e) == "evaluate" {
			out = append(out, id)
		}
	}
	if len(out) < 10 {
		t.Fatalf("selection cases %v, want the 10 of the group", out)
	}
	return out
}

func TestSelectionGoodImplPasses(t *testing.T) {
	rep, err := Run(receiptCfg(t, "good", subsetRoot(t, selectionIDs(t)...)))
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range selectionIDs(t) {
		if r := result(t, rep, id); r.Status != StatusPass {
			t.Errorf("%s = %+v, want PASS", id, r)
		}
	}
}

// TestSelectionBadModes: each bad implementation fails the cases it breaks
// and no other, naming the difference.
func TestSelectionBadModes(t *testing.T) {
	tests := []struct {
		mode, id string
		details  [][]string
		// also are further cases the mode breaks, with their details.
		also map[string][][]string
	}{
		// The weaker set is kept silently after a stricter gateway input.
		{"weaker-set-kept", "selection/agent-presents-stale-favorable", [][]string{
			{"decision ADMISSIBLE", "want DEFERRED"},
			{"check selection-consistency-v1", "result PASS", "want FAIL"},
			{"check selection-consistency-v1", "REQUIREMENT_SATISFIED", "SELECTION_INPUT_CHANGED"},
		}, nil},
		// The same defect on the second evaluation only.
		{"flip-flop", "selection/agent-presents-stale-favorable", [][]string{
			{"second evaluation", "same inputs", "draft 11.3", "decision DEFERRED, then ADMISSIBLE", "check selection-consistency-v1 FAIL/SELECTION_INPUT_CHANGED, then PASS/REQUIREMENT_SATISFIED"},
		}, nil},
		// The snapshot jti is missing from evidence_ids of a check that the
		// expected result does not list.
		{"omit-snapshot-jti", "selection/hold-added-after-issuance", [][]string{
			{"check reputation-context", "evidence_ids", "presented snapshot", "VW7HSF227CWWBU7wN09Q5A", "draft A.2"},
		}, nil},
		// The checks that the expected results do not list name a
		// configured validation record, not the selection record.
		{"selection-source-configured", "selection/hold-added-after-issuance", [][]string{
			{"check reputation-context", "configured-validation-record:example-reputation-context", "selection record configured-selection-record:hold-added-after-issuance", "draft A.2"},
		}, map[string][][]string{
			"selection/policy-revision-changed": {
				{"check selection-consistency-v1", "configured-validation-record:example-selection-consistency-v1", "selection record configured-selection-record:policy-revision-changed", "draft A.2"},
			},
			"selection/selector-rolled-back": {
				{"check reputation-context", "configured-validation-record:example-reputation-context", "selection record configured-selection-record:selector-rolled-back", "draft A.2"},
				{"check selection-consistency-v1", "configured-validation-record:example-selection-consistency-v1", "selection record configured-selection-record:selector-rolled-back", "draft A.2"},
			},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.mode, func(t *testing.T) {
			t.Setenv("FAKEIMPL_COUNTER", t.TempDir())
			rep, err := Run(receiptCfg(t, tt.mode, subsetRoot(t, selectionIDs(t)...)))
			if err != nil {
				t.Fatal(err)
			}
			for _, id := range selectionIDs(t) {
				r := result(t, rep, id)
				details, broken := tt.also[id]
				if id == tt.id {
					details, broken = tt.details, true
				}
				if !broken {
					if r.Status != StatusPass {
						t.Errorf("%s = %+v, want PASS: the mode does not touch it", id, r)
					}
					continue
				}
				if r.Status != StatusFail {
					t.Fatalf("%s = %+v, want FAIL", id, r)
				}
				diffs := r.Details
				if n := len(diffs); n > 0 && strings.HasPrefix(diffs[n-1], "[") {
					diffs = diffs[:n-1]
				}
				if len(diffs) != len(details) {
					t.Fatalf("%s details %q, want %d difference lines", id, r.Details, len(details))
				}
				for i, subs := range details {
					if !detailsContain(diffs[i:i+1], subs...) {
						t.Errorf("%s detail %d = %q, want it to name %q", id, i+1, diffs[i], subs)
					}
				}
			}
		})
	}
}

// TestSelectionAudit: the checks reputation-context and
// selection-consistency-v1 of every receipt name the presented snapshot in
// evidence_ids and carry as source_ref the record_ref of the exchange's
// selection record, whether or not the expected result lists them (draft
// A.2): that of config.json, or the Appendix B record when config.json names
// no selection (B.7). The expected result of selector-rolled-back lists
// neither check; that of hold-added-after-issuance lists only
// selection-consistency-v1; that of approval/pending-established-request,
// no selection case, lists neither; that of admission/valid pins both
// members of reputation-context.
func TestSelectionAudit(t *testing.T) {
	tests := []struct {
		name, id string
		edit     func(map[string]any)
		want     Status
		subs     []string
	}{
		{"as printed", "selection/selector-rolled-back", func(p map[string]any) {}, StatusPass, nil},
		{"jti missing from reputation-context", "selection/selector-rolled-back", func(p map[string]any) {
			check(t, p, "reputation-context")["evidence_ids"] = []any{"another"}
		}, StatusFail, []string{"check reputation-context", "presented snapshot", "VW7HSF227CWWBU7wN09Q5A"}},
		{"jti missing from selection-consistency-v1", "selection/selector-rolled-back", func(p map[string]any) {
			check(t, p, "selection-consistency-v1")["evidence_ids"] = []any{}
		}, StatusFail, []string{"check selection-consistency-v1", "presented snapshot", "VW7HSF227CWWBU7wN09Q5A"}},
		{"source_ref null on selection-consistency-v1", "selection/selector-rolled-back", func(p map[string]any) {
			check(t, p, "selection-consistency-v1")["source_ref"] = nil
		}, StatusFail, []string{"check selection-consistency-v1", "source_ref", "null", "selection record"}},
		{"source_ref null on reputation-context", "selection/selector-rolled-back", func(p map[string]any) {
			check(t, p, "reputation-context")["source_ref"] = nil
		}, StatusFail, []string{"check reputation-context", "source_ref", "null"}},
		{"source_ref empty", "selection/selector-rolled-back", func(p map[string]any) {
			check(t, p, "reputation-context")["source_ref"] = ""
		}, StatusFail, []string{"check reputation-context", "source_ref"}},
		// A record other than the selection record does not do, whether a
		// validation record or the selection record of another case.
		{"source_ref of a validation record", "selection/selector-rolled-back", func(p map[string]any) {
			check(t, p, "reputation-context")["source_ref"] = "configured-validation-record:example-reputation-context"
		}, StatusFail, []string{"check reputation-context", `source_ref "configured-validation-record:example-reputation-context"`, "selection record configured-selection-record:selector-rolled-back", "draft A.2"}},
		{"source_ref of another selection record", "selection/selector-rolled-back", func(p map[string]any) {
			check(t, p, "selection-consistency-v1")["source_ref"] = "configured-selection-record:same-snapshot"
		}, StatusFail, []string{"check selection-consistency-v1", `source_ref "configured-selection-record:same-snapshot"`, "selection record configured-selection-record:selector-rolled-back"}},
		{"source_ref of the record with a suffix", "selection/hold-added-after-issuance", func(p map[string]any) {
			check(t, p, "reputation-context")["source_ref"] = "configured-selection-record:hold-added-after-issuance/1"
		}, StatusFail, []string{"check reputation-context", "selection record configured-selection-record:hold-added-after-issuance"}},
		{"another id beside the jti", "selection/selector-rolled-back", func(p map[string]any) {
			c := check(t, p, "reputation-context")
			c["evidence_ids"] = append([]any{"another"}, c["evidence_ids"].([]any)...)
		}, StatusPass, nil},
		// A newer snapshot is the presented one: the jti of the B.6 snapshot
		// does not do.
		{"jti of another snapshot", "selection/newer-snapshot-still-eligible", func(p map[string]any) {
			check(t, p, "selection-consistency-v1")["evidence_ids"] = []any{"VW7HSF227CWWBU7wN09Q5A"}
		}, StatusFail, []string{"check selection-consistency-v1", "B4jqsRY111cD8G4fMEzpGQ"}},
		// A case that is no selection case has the Appendix B record.
		{"no selection, as printed", pendingCase, func(p map[string]any) {}, StatusPass, nil},
		{"no selection, validation record", pendingCase, func(p map[string]any) {
			check(t, p, "reputation-context")["source_ref"] = "configured-validation-record:example-reputation-context"
		}, StatusFail, []string{"check reputation-context", `source_ref "configured-validation-record:example-reputation-context"`, "selection record configured-selection-record:example-selection", "draft A.2"}},
		{"no selection, record of another case", pendingCase, func(p map[string]any) {
			check(t, p, "reputation-context")["source_ref"] = "configured-selection-record:selector-rolled-back"
		}, StatusFail, []string{"check reputation-context", "selection record configured-selection-record:example-selection"}},
		{"no selection, source_ref null", pendingCase, func(p map[string]any) {
			check(t, p, "reputation-context")["source_ref"] = nil
		}, StatusFail, []string{"check reputation-context", "source_ref null", "selection record"}},
		{"no selection, jti missing", pendingCase, func(p map[string]any) {
			check(t, p, "reputation-context")["evidence_ids"] = []any{}
		}, StatusFail, []string{"check reputation-context", "presented snapshot", "VW7HSF227CWWBU7wN09Q5A"}},
		// admission/valid pins both members, which the comparison judges.
		{"no selection, pinned", "admission/valid", func(p map[string]any) {
			c := check(t, p, "reputation-context")
			c["evidence_ids"], c["source_ref"] = []any{}, nil
		}, StatusFail, []string{"check reputation-context", "source_ref null", `want "configured-selection-record:example-selection"`}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := customRun(t, tt.id, 0, "", nil, tt.edit)
			if r.Status != tt.want || (tt.subs != nil && !detailsContain(r.Details, tt.subs...)) {
				t.Errorf("= %+v, want %s naming %q", r, tt.want, tt.subs)
			}
		})
	}
}

// TestSelectionAuditNoRecord: a case whose gateway installs
// selection-consistency-v1 but names no selection in config.json has the
// selection record of the Appendix B exchange, and the source_ref of the two
// checks is its record_ref (draft A.2, B.7); no other reference does.
func TestSelectionAuditNoRecord(t *testing.T) {
	const id = "selection/selector-rolled-back"
	keys, err := evalcase.LoadKeys(repoFixtures)
	if err != nil {
		t.Fatal(err)
	}
	good := readLines(t, filepath.Join(goldenDir, filepath.FromSlash(id), "evaluate.out"))
	tests := []struct {
		name string
		ref  any
		want Status
	}{
		{"default record", "configured-selection-record:example-selection", StatusPass},
		{"another record", "configured-validation-record:example-reputation-context", StatusFail},
		{"record of another case", "configured-selection-record:selector-rolled-back", StatusFail},
		{"null", nil, StatusFail},
		{"empty", "", StatusFail},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := subsetRoot(t, id)
			cfgPath := filepath.Join(root, filepath.FromSlash(id), "config.json")
			raw, err := os.ReadFile(cfgPath)
			if err != nil {
				t.Fatal(err)
			}
			var cfg map[string]any
			if err := json.Unmarshal(raw, &cfg); err != nil {
				t.Fatal(err)
			}
			cfg["selection"] = nil
			b, err := json.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			writeFile(t, cfgPath, string(b))
			line := mutator{keys: keys}.resign(t, good[0], "", nil, func(p map[string]any) {
				check(t, p, "reputation-context")["source_ref"] = tt.ref
				check(t, p, "selection-consistency-v1")["source_ref"] = tt.ref
			})
			r := runPrinted(t, root, id, []string{line})
			if r.Status != tt.want || (tt.want == StatusFail && !detailsContain(r.Details, "check reputation-context", "source_ref", "selection record configured-selection-record:example-selection")) {
				t.Errorf("= %+v, want %s", r, tt.want)
			}
		})
	}
}

// twoRuns runs the case id with a command that prints the lines first on its
// first run and the lines second on every other, and returns the result.
func twoRuns(t *testing.T, id string, first, second []string) Result {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "first"), strings.Join(first, "\n")+"\n")
	writeFile(t, filepath.Join(dir, "second"), strings.Join(second, "\n")+"\n")
	body := `n=0; [ -f "` + dir + `/count" ] && n=$(cat "` + dir + `/count"); echo $((n+1)) > "` + dir + `/count"
if [ "$n" -eq 0 ]; then cat "` + dir + `/first"; else cat "` + dir + `/second"; fi`
	rep, err := Run(Config{FixturesRoot: subsetRoot(t, id), Fixtures: []string{id}, EvaluateCmd: script(t, body) + " {dir}"})
	if err != nil {
		t.Fatal(err)
	}
	return result(t, rep, id)
}

// TestSelectionDeterminism: a selection case is evaluated twice with the
// same inputs, and the decision, the terminal reason and the result and
// reason code of every check agree (draft 11.3 step 9). A receipt differs
// from the other one in its jti and signature, and that is not judged. A case
// that is no selection case is evaluated once.
func TestSelectionDeterminism(t *testing.T) {
	const id = "selection/agent-presents-stale-favorable"
	m := loadMutator(t)
	good := readLines(t, filepath.Join(goldenDir, filepath.FromSlash(id), "evaluate.out"))
	resigned := m.resign(t, good[0], "", nil, func(p map[string]any) { p["jti"] = "another-jti" })
	reason := m.resign(t, good[0], "", nil, func(p map[string]any) {
		check(t, p, "selection-consistency-v1")["reason_code"] = "REQUIREMENTS_CHANGED"
	})
	terminal := m.resign(t, good[0], "", nil, set("terminal_reason", "EXPIRED"))
	tests := []struct {
		name   string
		second []string
		want   Status
		subs   []string
	}{
		{"same receipt", good, StatusPass, nil},
		{"another jti and signature", []string{resigned}, StatusPass, nil},
		{"another reason code", []string{reason}, StatusFail, []string{"second evaluation", "selection-consistency-v1", "SELECTION_INPUT_CHANGED", "REQUIREMENTS_CHANGED"}},
		{"another terminal reason", []string{terminal}, StatusFail, []string{"second evaluation", "terminal_reason", "COMPLETED", "EXPIRED"}},
		{"a Problem", []string{`{"type":"about:blank","title":"Rejected","status":401,"code":"INVALID_PROOF","request_id":"r"}`}, StatusFail, []string{"second evaluation", "Problem INVALID_PROOF"}},
		{"no output", []string{""}, StatusFail, []string{"second evaluation", "no receipt or Problem"}},
		{"two lines", []string{good[0], good[0]}, StatusFail, []string{"second evaluation", "2 lines", "1"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := twoRuns(t, id, good, tt.second)
			if r.Status != tt.want || (tt.subs != nil && !detailsContain(r.Details, tt.subs...)) {
				t.Errorf("= %+v, want %s naming %q", r, tt.want, tt.subs)
			}
		})
	}
	t.Run("not a selection case", func(t *testing.T) {
		// A second run would print a Problem; it is not made.
		const plain = "admission/valid"
		g := readLines(t, filepath.Join(goldenDir, filepath.FromSlash(plain), "evaluate.out"))
		if r := twoRuns(t, plain, g, []string{`{"type":"about:blank","title":"Rejected","status":401,"code":"INVALID_PROOF","request_id":"r"}`}); r.Status != StatusPass {
			t.Errorf("= %+v, want PASS: evaluated once", r)
		}
	})
}
