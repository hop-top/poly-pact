package runner

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"hop.top/pact-go/runner/manifest"
)

// The four modes of the fake implementation against the committed positive
// control admission/valid (draft Appendix B: ADMISSIBLE with a signed
// pact-admission+jwt receipt).

func TestRunGoodImplPasses(t *testing.T) {
	rep, err := Run(fakeImplCfg(t, "good", subsetRoot(t, "admission/valid")))
	if err != nil {
		t.Fatal(err)
	}
	if r := result(t, rep, "admission/valid"); r.Status != StatusPass || r.Verb != VerbEvaluate {
		t.Errorf("admission/valid = %+v, want evaluate PASS", r)
	}
	if rep.Manifest.Status != StatusPass {
		t.Errorf("manifest = %+v, want PASS", rep.Manifest)
	}
	if rep.Failed() {
		t.Error("good implementation must not fail")
	}
	if got, want := rep.Summary(), (Summary{Pass: 2}); got != want {
		t.Errorf("summary = %+v, want %+v (the manifest check and one fixture)", got, want)
	}
}

func TestRunWrongDecisionFails(t *testing.T) {
	rep, err := Run(fakeImplCfg(t, "wrong-decision", subsetRoot(t, "admission/valid")))
	if err != nil {
		t.Fatal(err)
	}
	r := result(t, rep, "admission/valid")
	if r.Status != StatusFail || !detailsContain(r.Details, "INADMISSIBLE", "ADMISSIBLE") {
		t.Errorf("admission/valid = %+v, want FAIL naming both decisions", r)
	}
	if !rep.Failed() {
		t.Error("report must fail")
	}
}

func TestRunNoReceiptFails(t *testing.T) {
	rep, err := Run(fakeImplCfg(t, "no-receipt", subsetRoot(t, "admission/valid")))
	if err != nil {
		t.Fatal(err)
	}
	r := result(t, rep, "admission/valid")
	if r.Status != StatusFail || !detailsContain(r.Details, "no receipt") {
		t.Errorf("admission/valid = %+v, want FAIL: no receipt", r)
	}
}

func TestRunCrashFails(t *testing.T) {
	rep, err := Run(fakeImplCfg(t, "crash", subsetRoot(t, "admission/valid")))
	if err != nil {
		t.Fatal(err)
	}
	r := result(t, rep, "admission/valid")
	if r.Status != StatusFail || !detailsContain(r.Details, "exited 70", "crash mode") {
		t.Errorf("admission/valid = %+v, want FAIL with the exit status and stderr", r)
	}
}

func TestRunMissingCommandSkips(t *testing.T) {
	cfg := fakeImplCfg(t, "good", subsetRoot(t, "admission/valid"))
	cfg.EvaluateCmd = ""
	rep, err := Run(cfg)
	if err != nil {
		t.Fatal(err)
	}
	r := result(t, rep, "admission/valid")
	if r.Status != StatusSkip || !detailsContain(r.Details, "no --evaluate-cmd") {
		t.Errorf("admission/valid = %+v, want SKIP: no --evaluate-cmd", r)
	}
	if rep.Failed() {
		t.Error("a missing command skips; it must not fail")
	}
}

func TestRunCommandThatCannotStartFails(t *testing.T) {
	cfg := Config{
		FixturesRoot: subsetRoot(t, "admission/valid"),
		EvaluateCmd:  filepath.Join(t.TempDir(), "no-such-tool") + " evaluate {dir}",
	}
	rep, err := Run(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if r := result(t, rep, "admission/valid"); r.Status != StatusFail {
		t.Errorf("admission/valid = %+v, want FAIL", r)
	}
}

// TestEvaluateInvocation: the command gets the absolute case directory as
// {dir}, substituted inside an argument too, and no standard input.
func TestEvaluateInvocation(t *testing.T) {
	root := subsetRoot(t, "admission/valid")
	out := t.TempDir()
	receipt := filepath.Join("testdata", "fakeimpl", "golden", "admission", "valid", "evaluate.out")
	receipt, _ = filepath.Abs(receipt)
	cmd := script(t, `printf '%s\n' "$@" > `+out+`/args; cat > `+out+`/stdin; cat `+receipt)
	rep, err := Run(Config{FixturesRoot: root, EvaluateCmd: cmd + " evaluate {dir} --case={dir}"})
	if err != nil {
		t.Fatal(err)
	}
	if r := result(t, rep, "admission/valid"); r.Status != StatusPass {
		t.Errorf("admission/valid = %+v, want PASS", r)
	}
	dir, err := filepath.Abs(filepath.Join(root, "admission", "valid"))
	if err != nil {
		t.Fatal(err)
	}
	args, _ := os.ReadFile(filepath.Join(out, "args"))
	if got, want := string(args), "evaluate\n"+dir+"\n--case="+dir+"\n"; got != want {
		t.Errorf("argv = %q, want %q", got, want)
	}
	if stdin, _ := os.ReadFile(filepath.Join(out, "stdin")); len(stdin) != 0 {
		t.Errorf("stdin = %q, want none", stdin)
	}
}

// TestEvaluateResponses: a case the draft admits needs a receipt with the
// expected decision; a case the draft rejects before an authenticated
// evaluation (Section 12.2) needs a Problem (Section 13.4) with the expected
// code and no receipt. The exit status is informational.
func TestEvaluateResponses(t *testing.T) {
	golden, err := os.ReadFile(filepath.Join("testdata", "fakeimpl", "golden", "admission", "valid", "evaluate.out"))
	if err != nil {
		t.Fatal(err)
	}
	receipt := string(golden)
	b64 := base64.RawURLEncoding.EncodeToString
	sig := b64(make([]byte, 64))
	evidence := b64([]byte(`{"alg":"ES256","typ":"pact-evidence+jwt","kid":"k"}`)) + "." +
		b64([]byte(`{"decision":"ADMISSIBLE"}`)) + "." + sig
	problem := func(code string) string {
		return `{"type":"about:blank","title":"Rejected","status":401,"code":"` + code + `","request_id":"r-1"}`
	}

	files := merge(
		evalFiles("admission/ok", `{"decision":"ADMISSIBLE","transport_code":null}`),
		evalFiles("admission/pre-auth", `{"transport_code":"INVALID_PROOF","rejected_before_crypto":false}`),
	)
	root := evalTree(t, []entry{evalEntry("admission/ok", "ADMISSIBLE"), evalEntry("admission/pre-auth", "REJECTED")}, files)

	tests := []struct {
		name, id, stdout string
		exit             int
		want             Status
		detail           []string
	}{
		{"receipt", "admission/ok", receipt, 0, StatusPass, nil},
		{"receipt with trailing newline", "admission/ok", receipt + "\n", 0, StatusPass, nil},
		{"receipt, nonzero exit", "admission/ok", receipt, 3, StatusPass, nil},
		{"problem instead of receipt", "admission/ok", problem("INVALID_PROOF"), 0, StatusFail, []string{"no receipt", "INVALID_PROOF"}},
		{"empty", "admission/ok", "", 0, StatusFail, []string{"no receipt"}},
		{"not a response", "admission/ok", "hello", 0, StatusFail, []string{"compact JWS"}},
		{"two segments", "admission/ok", "e30.e30", 0, StatusFail, []string{"compact JWS"}},
		{"json, not a problem", "admission/ok", `{"decision":"ADMISSIBLE"}`, 0, StatusFail, []string{"Problem"}},
		{"wrong typ", "admission/ok", evidence, 0, StatusFail, []string{"pact-evidence+jwt", "pact-admission+jwt"}},
		{"problem", "admission/pre-auth", problem("INVALID_PROOF"), 0, StatusPass, nil},
		{"problem, nonzero exit", "admission/pre-auth", problem("INVALID_PROOF"), 1, StatusPass, nil},
		{"wrong code", "admission/pre-auth", problem("INVALID_MESSAGE"), 0, StatusFail, []string{"INVALID_MESSAGE", "INVALID_PROOF"}},
		{"receipt for a rejected request", "admission/pre-auth", receipt, 0, StatusFail, []string{"receipt", "INVALID_PROOF"}},
		{"nothing, nonzero exit", "admission/pre-auth", "", 1, StatusFail, []string{"exited 1"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "stdout")
			writeFile(t, out, tt.stdout)
			cmd := script(t, "cat "+out+"\nexit "+strconv.Itoa(tt.exit))
			rep, err := Run(Config{FixturesRoot: root, Fixtures: []string{tt.id}, EvaluateCmd: cmd + " {dir}"})
			if err != nil {
				t.Fatal(err)
			}
			r := result(t, rep, tt.id)
			if r.Status != tt.want {
				t.Fatalf("%s = %+v, want %s", tt.id, r, tt.want)
			}
			if tt.detail != nil && !detailsContain(r.Details, tt.detail...) {
				t.Errorf("details %q do not name %q", r.Details, tt.detail)
			}
		})
	}
}

func TestEvaluateBadExpectedFileFails(t *testing.T) {
	for name, decision := range map[string]string{
		"unknown member":     `{"decision":"ADMISSIBLE","transport_code":null,"verdict":"ok"}`,
		"not json":           `decision: ADMISSIBLE`,
		"no decision":        `{"transport_code":null}`,
		"duplicate member":   `{"decision":"ADMISSIBLE","decision":"DEFERRED","transport_code":null}`,
		"transport code int": `{"transport_code":400}`,
	} {
		t.Run(name, func(t *testing.T) {
			root := evalTree(t, []entry{evalEntry("admission/ok", "ADMISSIBLE")}, evalFiles("admission/ok", decision))
			cmd := script(t, "exit 0")
			rep, err := Run(Config{FixturesRoot: root, EvaluateCmd: cmd + " {dir}"})
			if err != nil {
				t.Fatal(err)
			}
			if r := result(t, rep, "admission/ok"); r.Status != StatusFail || !detailsContain(r.Details, "expected/admission/ok/decision.json") {
				t.Errorf("admission/ok = %+v, want FAIL naming the expected file", r)
			}
		})
	}
}

func TestEvaluatePathNotADirectoryFails(t *testing.T) {
	e := evalEntry("admission/file", "ADMISSIBLE")
	e["path"] = "admission/file.json"
	root := tree(t, []entry{e}, map[string]string{
		"admission/file.json":                   `{}`,
		"expected/admission/file/decision.json": `{"decision":"ADMISSIBLE","transport_code":null}`,
	})
	marker := filepath.Join(t.TempDir(), "ran")
	rep, err := Run(Config{FixturesRoot: root, EvaluateCmd: script(t, "touch "+marker) + " {dir}"})
	if err != nil {
		t.Fatal(err)
	}
	if r := result(t, rep, "admission/file"); r.Status != StatusFail || !detailsContain(r.Details, "not a case directory") {
		t.Errorf("admission/file = %+v, want FAIL: not a case directory", r)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Error("the command ran on a file")
	}
}

// selectionTree has one entry of each kind pactc runs, two of them in one
// group, and kinds it does not run.
func selectionTree(t *testing.T, extra map[string]string) string {
	t.Helper()
	entries := []entry{
		evalEntry("admission/a", "ADMISSIBLE"),
		evalEntry("admission/b", "INADMISSIBLE"),
		{
			"id": "keys/k", "kind": "key", "scope": "core", "path": "keys/k.jwk.json",
			"expected": nil, "outcome": nil, "spec_map_row": "CL-C", "draft_section": "C",
		},
		{
			"id": "learning/l", "kind": "learning", "scope": "runner", "path": "learning/l",
			"expected": "expected/learning/l/registry.json", "outcome": "ACCEPTED",
			"spec_map_row": "R21", "draft_section": "16.5",
		},
		{
			"id": "outcomes/o", "kind": "outcomes", "scope": "runner", "path": "outcomes/o",
			"expected": "expected/outcomes/o/snapshot.json", "outcome": "QUALIFIED",
			"spec_map_row": "R15", "draft_section": "14.3",
		},
		{
			"id": "parse/p", "kind": "schema", "scope": "core", "path": "parse/p.jws",
			"expected": "expected/parse/p/decision.json", "outcome": "REJECTED",
			"spec_map_row": "CL-21", "draft_section": "21",
		},
		{
			"id": "vectors/v/x", "kind": "vector", "scope": "core", "path": "vectors/v/x.json",
			"expected": "vectors/v/x.json", "outcome": "MATCH",
			"spec_map_row": "CL-7.4", "draft_section": "7.4",
		},
	}
	files := merge(
		evalFiles("admission/a", `{"decision":"ADMISSIBLE","transport_code":null}`),
		evalFiles("admission/b", `{"decision":"INADMISSIBLE","transport_code":null}`),
		map[string]string{
			"keys/k.jwk.json":                   `{}`,
			"learning/l/policy.json":            `{}`,
			"expected/learning/l/registry.json": `{}`,
			"outcomes/o/reports.json":           `{}`,
			"expected/outcomes/o/snapshot.json": `{}`,
			"parse/p.jws":                       `e30.e30.e30`,
			"expected/parse/p/decision.json":    `{"transport_code":"INVALID_MESSAGE"}`,
			"vectors/v/x.json":                  `{}`,
		},
		extra,
	)
	return tree(t, entries, files)
}

func TestSelection(t *testing.T) {
	root := selectionTree(t, nil)
	tests := []struct {
		name      string
		selectors []string
		want      []string
	}{
		{"all entries pactc runs, in manifest order", nil, []string{"admission/a", "admission/b", "learning/l", "outcomes/o", "parse/p"}},
		{"id prefix selects a group", []string{"admission/"}, []string{"admission/a", "admission/b"}},
		{"exact id", []string{"parse/p"}, []string{"parse/p"}},
		{"overlapping selectors run an entry once", []string{"admission/", "admission/b"}, []string{"admission/a", "admission/b"}},
		{"several groups", []string{"outcomes/", "learning/l"}, []string{"learning/l", "outcomes/o"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rep, err := Run(Config{FixturesRoot: root, Fixtures: tt.selectors})
			if err != nil {
				t.Fatal(err)
			}
			if got := ids(rep); !slices.Equal(got, tt.want) {
				t.Errorf("ran %v, want %v", got, tt.want)
			}
			if rep.Failed() {
				t.Errorf("no command given: every entry skips, got %+v", rep)
			}
		})
	}
}

func TestSelectionMatchingNothingErrors(t *testing.T) {
	root := selectionTree(t, nil)
	for _, sel := range []string{"approval/", "admission/c", "keys/", "vectors/v/x"} {
		if _, err := Run(Config{FixturesRoot: root, Fixtures: []string{"admission/", sel}}); err == nil || !strings.Contains(err.Error(), sel) {
			t.Errorf("selector %q: err = %v, want an error naming it", sel, err)
		}
	}
}

// TestUnlistedFixtureFileFails: pactc never walks the tree to find cases. A
// case directory the manifest does not list is not run and not skipped: its
// files make the manifest check FAIL as manifest-incomplete.
func TestUnlistedFixtureFileFails(t *testing.T) {
	root := selectionTree(t, map[string]string{
		"admission/c/config.json":            `{}`,
		"expected/admission/c/decision.json": `{"decision":"ADMISSIBLE","transport_code":null}`,
	})
	for _, selectors := range [][]string{nil, {"admission/"}} {
		rep, err := Run(Config{FixturesRoot: root, Fixtures: selectors})
		if err != nil {
			t.Fatal(err)
		}
		if rep.Manifest.Status != StatusFail {
			t.Errorf("%v: manifest = %+v, want FAIL", selectors, rep.Manifest)
		}
		for _, f := range []string{"admission/c/config.json", "expected/admission/c/decision.json"} {
			if !detailsContain(rep.Manifest.Details, "["+RuleManifestIncomplete+"] "+f) {
				t.Errorf("%v: manifest details %q do not name %s", selectors, rep.Manifest.Details, f)
			}
		}
		if slices.Contains(ids(rep), "admission/c") {
			t.Errorf("%v: unlisted case admission/c was run: %v", selectors, ids(rep))
		}
		if !rep.Failed() || rep.Summary().Fail != 1 {
			t.Errorf("%v: Failed %v, summary %+v; want the manifest FAIL counted", selectors, rep.Failed(), rep.Summary())
		}
	}
}

func TestManifestFieldProblemFails(t *testing.T) {
	root := tree(t, []entry{evalEntry("admission/b", "ADMISSIBLE"), evalEntry("admission/a", "ADMISSIBLE")}, merge(
		evalFiles("admission/a", `{"decision":"ADMISSIBLE","transport_code":null}`),
		evalFiles("admission/b", `{"decision":"ADMISSIBLE","transport_code":null}`),
	))
	rep, err := Run(Config{FixturesRoot: root})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Manifest.Status != StatusFail || !detailsContain(rep.Manifest.Details, "[entry-order]") {
		t.Errorf("manifest = %+v, want FAIL [entry-order]", rep.Manifest)
	}
}

func TestManifestMissingFilesFail(t *testing.T) {
	root := tree(t, []entry{evalEntry("admission/a", "ADMISSIBLE")}, nil)
	rep, err := Run(Config{FixturesRoot: root})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Manifest.Status != StatusFail || !detailsContain(rep.Manifest.Details, "[path-missing] admission/a") {
		t.Errorf("manifest = %+v, want FAIL [path-missing]", rep.Manifest)
	}
}

func TestUnreadableManifestErrors(t *testing.T) {
	if _, err := Run(Config{FixturesRoot: t.TempDir()}); err == nil {
		t.Error("no manifest.json: want an error")
	}
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "manifest.json"), `{"manifest_version":1,"entries":[],"entries":[]}`)
	if _, err := Run(Config{FixturesRoot: root}); err == nil {
		t.Error("duplicate member in manifest.json: want an error")
	}
}

// TestVerbsWithoutCommandSkip: the entries of a verb without its command are
// SKIP and name the missing flag. The learning, outcomes and schema verbs
// have their own tests (learning_test.go, outcomes_test.go,
// schemaverb_test.go).
func TestVerbsWithoutCommandSkip(t *testing.T) {
	root := selectionTree(t, nil)
	cfg := Config{FixturesRoot: root, Fixtures: []string{"learning/", "outcomes/", "parse/"}}
	rep, err := Run(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for id, flag := range map[string]string{"learning/l": "--learning-cmd", "outcomes/o": "--outcomes-cmd", "parse/p": "--schema-cmd"} {
		if r := result(t, rep, id); r.Status != StatusSkip || !detailsContain(r.Details, "no "+flag) {
			t.Errorf("%s = %+v, want SKIP: no %s", id, r, flag)
		}
	}
}

// TestRepoFixtures runs the committed manifest with the good fake
// implementation under the default conformance profile over every
// transport: every entry of a kind pactc runs that lists that profile is
// reported once, none fails, and the positive control passes. The manifest
// check of the committed tree is pactfix check manifest's job; it is logged
// here.
func TestRepoFixtures(t *testing.T) {
	cfg := fakeImplCfg(t, "good", repoFixtures)
	cfg.Transport = manifest.Transports()
	rep, err := Run(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("manifest: %s %q", rep.Manifest.Status, rep.Manifest.Details)
	var want []string
	for _, e := range repoEntries(t) {
		if _, ok := verbOf(manifest.Kind(kindOf(e))); ok && listsProfile(e, manifest.DefaultConformanceProfile) {
			want = append(want, e["id"].(string))
		}
	}
	if got := ids(rep); !slices.Equal(got, want) {
		t.Errorf("ran %v, want %v", got, want)
	}
	for _, r := range rep.Fixtures {
		if r.Status == StatusFail {
			t.Errorf("%s %s FAIL: %q", r.ID, r.Verb, r.Details)
		}
	}
	if r := result(t, rep, "admission/valid"); r.Status != StatusPass {
		t.Errorf("admission/valid = %+v, want PASS", r)
	}
}

// listsProfile reports whether the entry e, as written, runs under the
// conformance profile p: its conformance_profile lists p, or it has none and
// p is the default.
func listsProfile(e entry, p string) bool {
	ps, ok := e["conformance_profile"].([]any)
	if !ok {
		return p == manifest.DefaultConformanceProfile
	}
	return slices.Contains(ps, any(p))
}

func kindOf(e entry) string {
	k, _ := e["kind"].(string)
	return k
}
