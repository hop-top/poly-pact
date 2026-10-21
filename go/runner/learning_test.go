package runner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"hop.top/pact-go/runner/evalcase"
	"hop.top/pact-go/runner/manifest"
)

func learningIDs(t *testing.T) []string {
	t.Helper()
	var ids []string
	for _, e := range repoEntries(t) {
		if kindOf(e) == "learning" {
			ids = append(ids, e["id"].(string))
		}
	}
	if len(ids) != 15 {
		t.Fatalf("%d committed learning entries, want 15", len(ids))
	}
	return ids
}

// learningRun runs the learning verb on the committed case id with a command
// that prints the output file, and returns the result.
func learningRun(t *testing.T, id string, output string) Result {
	t.Helper()
	root := subsetRoot(t, id)
	p := filepath.Join(t.TempDir(), "out.json")
	if err := os.WriteFile(p, []byte(output), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := script(t, `cat `+p)
	rep, err := Run(Config{FixturesRoot: root, LearningCmd: cmd + " {dir} {state}"})
	if err != nil {
		t.Fatal(err)
	}
	return result(t, rep, id)
}

func goodFor(t *testing.T, id string) out {
	t.Helper()
	c, err := evalcase.ReadLearning(repoFixtures, id)
	if err != nil {
		t.Fatal(err)
	}
	return goodOutput(t, c)
}

// roundTrip returns o as a decoded file has it, numbers float64.
func roundTrip(t testing.TB, o out) out {
	t.Helper()
	var rt out
	if err := json.Unmarshal([]byte(marshalLine(t, o)), &rt); err != nil {
		t.Fatal(err)
	}
	return rt
}

// TestLearningPassesTheExpectedState: for every committed case, the output
// that its expected registry.json describes passes.
func TestLearningPassesTheExpectedState(t *testing.T) {
	for _, id := range learningIDs(t) {
		t.Run(id, func(t *testing.T) {
			r := learningRun(t, id, marshalLine(t, goodFor(t, id)))
			if r.Verb != VerbLearning || r.Status != StatusPass {
				t.Fatalf("%+v, want learning PASS", r)
			}
		})
	}
}

// TestLearningMutantsFail: each defect fails the case it breaks, with a
// detail that names it.
func TestLearningMutantsFail(t *testing.T) {
	for _, mu := range learningMutants() {
		t.Run(mu.id+" "+mu.mode, func(t *testing.T) {
			c, err := evalcase.ReadLearning(repoFixtures, mu.id)
			if err != nil {
				t.Fatal(err)
			}
			o := roundTrip(t, goodOutput(t, c))
			mu.edit(t, c, o)
			r := learningRun(t, mu.id, marshalLine(t, o))
			if r.Status != StatusFail {
				t.Fatalf("%+v, want FAIL", r)
			}
			for _, want := range mu.detail {
				if !detailsContain(r.Details, want) {
					t.Errorf("details %q do not mention %q", r.Details, want)
				}
			}
		})
	}
}

// TestLearningOutputShape: an output that is not the registry state of
// spec/v1.0/fixtures/README.md, section Learning output, fails whatever its
// registry says.
func TestLearningOutputShape(t *testing.T) {
	const id = "learning/gate-not-met"
	tests := []struct {
		name string
		edit func(o out)
		raw  string
		want []string
	}{
		{name: "nothing printed", raw: "", want: []string{"no registry state"}},
		{name: "not JSON", raw: "registry: fine\n", want: []string{"not the registry state"}},
		{name: "an array", raw: "[]", want: []string{"not the registry state"}},
		{name: "two documents", raw: "{} {}", want: []string{"not the registry state"}},
		{name: "duplicate member", raw: `{"artifacts":{},"artifacts":{}}`, want: []string{"not the registry state", "duplicate"}},
		{name: "unknown member", edit: func(o out) { o["subject"] = "/rejections/0" }, want: []string{"subject"}},
		{name: "artifacts missing", edit: func(o out) { delete(o, "artifacts") }, want: []string{"artifacts", "required"}},
		{name: "active missing", edit: func(o out) { delete(o, "active") }, want: []string{"active", "required"}},
		{name: "acknowledgments missing", edit: func(o out) { delete(o, "acknowledgments") }, want: []string{"acknowledgments", "required"}},
		{name: "rejections missing", edit: func(o out) { delete(o, "rejections") }, want: []string{"rejections", "required"}},
		{name: "holds and reevaluation_required may be absent", edit: func(o out) { delete(o, "holds"); delete(o, "reevaluation_required") }},
		{name: "unknown state", edit: func(o out) {
			for k := range o["artifacts"].(map[string]any) {
				o["artifacts"].(map[string]any)[k] = "LIVE"
			}
		}, want: []string{"LIVE", "not a lifecycle state"}},
		{name: "acknowledgment without ack", edit: func(o out) { delete(list(o, "acknowledgments")[0].(map[string]any), "ack") }, want: []string{"acknowledgments[0]", "ack"}},
		{name: "ack status differs", edit: func(o out) {
			list(o, "acknowledgments")[0].(map[string]any)["ack"].(map[string]any)["status"] = "DUPLICATE"
		}, want: []string{"acknowledgments[0]", "ack.status DUPLICATE", "ACCEPTED"}},
		{name: "ack without request_id", edit: func(o out) {
			delete(list(o, "acknowledgments")[0].(map[string]any)["ack"].(map[string]any), "request_id")
		}, want: []string{"acknowledgments[0]", "request_id"}},
		{name: "ack received_at negative", edit: func(o out) {
			list(o, "acknowledgments")[0].(map[string]any)["ack"].(map[string]any)["received_at"] = -1
		}, want: []string{"received_at"}},
		{name: "acknowledgment without step", edit: func(o out) { delete(list(o, "acknowledgments")[0].(map[string]any), "step") }, want: []string{"acknowledgments[0]", "step is required"}},
		{name: "rejection without step", edit: func(o out) { delete(list(o, "rejections")[0].(map[string]any), "step") }, want: []string{"rejections[0]", "step is required"}},
		{name: "problem reason codes not an array of strings", edit: func(o out) {
			list(o, "rejections")[0].(map[string]any)["problem"].(map[string]any)["extensions"] = map[string]any{"reason_codes": "GATE_NOT_MET"}
		}, want: []string{"rejections[0]", "extensions.reason_codes is not an array of strings"}},
		{name: "ack with an unknown member", edit: func(o out) {
			list(o, "acknowledgments")[0].(map[string]any)["ack"].(map[string]any)["bogus"] = 1
		}, want: []string{"/acknowledgments/0/ack/bogus"}},
		{name: "rejection without problem", edit: func(o out) { delete(list(o, "rejections")[0].(map[string]any), "problem") }, want: []string{"rejections[0]", "problem"}},
		{name: "problem code differs", edit: func(o out) {
			list(o, "rejections")[0].(map[string]any)["problem"].(map[string]any)["code"] = "INVALID_MESSAGE"
		}, want: []string{"rejections[0]", "problem.code INVALID_MESSAGE", "LEARNING_REJECTED"}},
		{name: "problem reason codes differ", edit: func(o out) {
			list(o, "rejections")[0].(map[string]any)["problem"].(map[string]any)["extensions"] = map[string]any{"reason_codes": []any{"POLICY_EXPIRED"}}
		}, want: []string{"rejections[0]", "extensions.reason_codes", "POLICY_EXPIRED", "GATE_NOT_MET"}},
		{name: "problem without the reason codes", edit: func(o out) {
			delete(list(o, "rejections")[0].(map[string]any)["problem"].(map[string]any), "extensions")
		}, want: []string{"rejections[0]", "extensions.reason_codes", "GATE_NOT_MET"}},
		{name: "problem status is not an error status", edit: func(o out) {
			list(o, "rejections")[0].(map[string]any)["problem"].(map[string]any)["status"] = 200
		}, want: []string{"rejections[0]", "status"}},
		{name: "problem without a title", edit: func(o out) {
			delete(list(o, "rejections")[0].(map[string]any)["problem"].(map[string]any), "title")
		}, want: []string{"rejections[0]", "title"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			output := tc.raw
			if tc.edit != nil {
				o := roundTrip(t, goodFor(t, id))
				tc.edit(o)
				output = marshalLine(t, o)
			}
			r := learningRun(t, id, output)
			if len(tc.want) == 0 {
				if r.Status != StatusPass {
					t.Fatalf("%+v, want PASS", r)
				}
				return
			}
			if r.Status != StatusFail {
				t.Fatalf("%+v, want FAIL", r)
			}
			for _, w := range tc.want {
				if !detailsContain(r.Details, w) {
					t.Errorf("details %q do not mention %q", r.Details, w)
				}
			}
		})
	}
}

// TestLearningDigestsNameTheCommittedManifests: the output names an artifact
// by the artifact_digest of its signed manifest; one the harness cannot
// match with a committed file is an unexpected artifact.
func TestLearningDigestsNameTheCommittedManifests(t *testing.T) {
	const id = "learning/happy-path"
	o := roundTrip(t, goodFor(t, id))
	for k, v := range o["artifacts"].(map[string]any) {
		delete(o["artifacts"].(map[string]any), k)
		o["artifacts"].(map[string]any)["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"] = v
	}
	r := learningRun(t, id, marshalLine(t, o))
	if r.Status != StatusFail || !detailsContain(r.Details, "unexpected artifact", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA") ||
		!detailsContain(r.Details, "artifacts[signed/artifacts/baseline-v1.jws]", "absent") {
		t.Fatalf("%+v", r)
	}
}

func TestLearningCommandFailures(t *testing.T) {
	const id = "learning/happy-path"
	root := subsetRoot(t, id)
	for name, tc := range map[string]struct {
		cmd  string
		want string
	}{
		"cannot start":         {filepath.Join(t.TempDir(), "missing") + " {dir} {state}", "cannot run the learning command"},
		"crash with no output": {script(t, `echo boom >&2; exit 70`) + " {dir} {state}", "no registry state"},
	} {
		want := tc.want
		t.Run(name, func(t *testing.T) {
			cfg := Config{FixturesRoot: root, LearningCmd: tc.cmd}
			rep, err := Run(cfg)
			if err != nil {
				t.Fatal(err)
			}
			r := result(t, rep, id)
			if r.Status != StatusFail || !detailsContain(r.Details, want) {
				t.Fatalf("%+v, want FAIL: %s", r, want)
			}
		})
	}
	t.Run("exit status is informational", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "out.json")
		if err := os.WriteFile(p, []byte(marshalLine(t, goodFor(t, id))), 0o644); err != nil {
			t.Fatal(err)
		}
		rep, err := Run(Config{FixturesRoot: root, LearningCmd: script(t, "cat "+p+"; exit 3") + " {dir} {state}"})
		if err != nil {
			t.Fatal(err)
		}
		if r := result(t, rep, id); r.Status != StatusPass {
			t.Fatalf("%+v, want PASS: the registry state on stdout is what is judged", r)
		}
	})
}

// TestLearningStateIsAFreshScratchPath: {state} does not exist before the
// command runs and differs from one entry to the next.
func TestLearningStateIsAFreshScratchPath(t *testing.T) {
	ids := []string{"learning/happy-path", "learning/gate-not-met"}
	root := subsetRoot(t, ids...)
	log := filepath.Join(t.TempDir(), "states")
	body := `[ ! -e "$2" ] || { echo "state exists" >&2; exit 9; }; mkdir "$2"; echo "$1 $2" >> ` + log + "; exit 1"
	rep, err := Run(Config{FixturesRoot: root, LearningCmd: script(t, body) + " {dir} {state}"})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rep.Fixtures {
		if detailsContain(r.Details, "state exists") {
			t.Errorf("%s: the state path existed before the command", r.ID)
		}
	}
	b, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 2 {
		t.Fatalf("log %q", lines)
	}
	a, b2 := strings.Fields(lines[0]), strings.Fields(lines[1])
	if a[1] == b2[1] {
		t.Errorf("both entries got the state path %s", a[1])
	}
	for i, f := range [][]string{a, b2} {
		if !filepath.IsAbs(f[0]) || !strings.HasSuffix(f[0], "learning/"+[]string{"gate-not-met", "happy-path"}[i]) {
			t.Errorf("dir %s is not the absolute path of the case", f[0])
		}
	}
	if _, err := os.Stat(a[1]); err == nil {
		t.Errorf("the scratch state %s is left behind", a[1])
	}
}

func TestLearningUnreadableCaseFails(t *testing.T) {
	const id = "learning/happy-path"
	root := subsetRoot(t, id)
	if err := os.Remove(filepath.Join(root, "learning", "happy-path", "steps.json")); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(t.TempDir(), "ran")
	rep, err := Run(Config{FixturesRoot: root, LearningCmd: script(t, "touch "+marker) + " {dir} {state}"})
	if err != nil {
		t.Fatal(err)
	}
	r := result(t, rep, id)
	if r.Status != StatusFail || !detailsContain(r.Details, "steps.json") {
		t.Fatalf("%+v, want FAIL naming steps.json", r)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Error("the command ran on a case the runner cannot read")
	}
}

// TestLearningWithoutCommandSkips: with no --learning-cmd the entries are
// SKIP, never FAIL.
func TestLearningWithoutCommandSkips(t *testing.T) {
	rep, err := Run(Config{FixturesRoot: subsetRoot(t, "learning/happy-path")})
	if err != nil {
		t.Fatal(err)
	}
	if r := result(t, rep, "learning/happy-path"); r.Status != StatusSkip || !detailsContain(r.Details, "no --learning-cmd") {
		t.Fatalf("%+v", r)
	}
}

// TestRepoLearningBadModes runs the committed learning cases through every
// bad mode of the fake implementation: a mode fails exactly the case it
// breaks and every other case passes.
func TestRepoLearningBadModes(t *testing.T) {
	broken := map[string][]string{}
	for _, mu := range learningMutants() {
		broken[mu.mode] = append(broken[mu.mode], mu.id)
	}
	for mode, ids := range broken {
		t.Run(mode, func(t *testing.T) {
			cfg := fakeImplCfg(t, mode, repoFixtures)
			m, err := manifest.Load(repoFixtures)
			if err != nil {
				t.Fatal(err)
			}
			// The entries run one by one: the manifest check of the whole tree
			// is not what this test is about.
			var results []Result
			for _, e := range m.Entries {
				if e.Kind == manifest.KindLearning {
					results = append(results, runEntry(cfg, e))
				}
			}
			if len(results) != 15 {
				t.Fatalf("%d learning entries ran, want 15", len(results))
			}
			for _, r := range results {
				broke := false
				for _, id := range ids {
					broke = broke || id == r.ID
				}
				switch {
				case broke && r.Status != StatusFail:
					t.Errorf("%s = %s under %s, want FAIL", r.ID, r.Status, mode)
				case !broke && r.Status != StatusPass:
					t.Errorf("%s = %s %q under %s, want PASS: the mode breaks only %v", r.ID, r.Status, r.Details, mode, ids)
				}
			}
		})
	}
	// Every mutant is a distinct defect of one case, so a mode name names
	// exactly one.
	if len(broken) != len(learningMutants()) {
		t.Errorf("%d modes for %d mutants: a mode names one defect", len(broken), len(learningMutants()))
	}
}
