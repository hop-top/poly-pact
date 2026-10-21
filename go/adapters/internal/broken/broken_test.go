package broken_test

import (
	"bufio"
	"bytes"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strings"
	"testing"

	"hop.top/pact-go/adapter/adaptertest"
	"hop.top/pact-go/adapters/internal/broken"
)

// mode is one workload mode the suite runs the adapter in: dedicated
// workloads, the default of every profile, or workloads shared by several
// agents (identity mapping IM-19). Each mode runs the cases that apply to it.
type mode struct {
	name    string
	factory func(...broken.Defect) adaptertest.Factory
	opts    adaptertest.Options
}

var modes = []mode{
	{"dedicated", broken.Factory, adaptertest.Options{}},
	{"shared", broken.SharedFactory, adaptertest.Options{SharedWorkloads: true}},
}

// evaluate runs the suite against the broken adapter with the given defects on,
// in mode m, and returns the results by case id.
func evaluate(t *testing.T, m mode, defects ...broken.Defect) map[string]adaptertest.Result {
	t.Helper()
	results, err := adaptertest.Evaluate(t, m.factory(defects...), m.opts)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if len(results) == 0 {
		t.Fatal("the suite has no cases")
	}
	out := make(map[string]adaptertest.Result, len(results))
	for _, r := range results {
		out[r.ID] = r
	}
	return out
}

func caseIDs(res map[string]adaptertest.Result) []string {
	ids := make([]string, 0, len(res))
	for id := range res {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids
}

// TestNoDefectsPassesTheSuite: with every defect off, the wrapper is the memory
// adapter and passes every case of each mode, so a failure below is the
// defect's doing.
func TestNoDefectsPassesTheSuite(t *testing.T) {
	for _, m := range modes {
		for id, r := range evaluate(t, m) {
			if !r.Passed() {
				t.Errorf("%s: %s fails with no defect on: %v", m.name, id, r.Failures)
			}
		}
	}
}

// TestCatalogueIsConsistent: defects are unique, each one is declared as a
// constant the catalogue lists once, and every target is a case that exists
// in a mode. A case that no defect targets cannot be shown to catch anything,
// so it fails.
func TestCatalogueIsConsistent(t *testing.T) {
	res := map[string]adaptertest.Result{}
	for _, m := range modes {
		for id, r := range evaluate(t, m) {
			res[id] = r
		}
	}
	seen := map[broken.Defect]bool{}
	targeted := map[string]bool{}
	for _, s := range broken.Catalogue {
		if seen[s.Defect] {
			t.Errorf("defect %q is listed twice", s.Defect)
		}
		seen[s.Defect] = true
		if s.What == "" || len(s.Targets) == 0 {
			t.Errorf("defect %q has no description or no target", s.Defect)
		}
		for _, id := range s.Targets {
			if _, ok := res[id]; !ok {
				t.Errorf("defect %q targets %q, which is not a case", s.Defect, id)
			}
			targeted[id] = true
		}
	}
	for _, id := range caseIDs(res) {
		if !targeted[id] {
			t.Errorf("no defect targets case %s: add a mutant that it catches", id)
		}
	}
}

// TestEachDefectFailsItsCases: the mutation proof, one defect at a time. The
// cases a defect targets must fail with only that defect on, in every mode
// that runs them. Other cases that fail with it are logged, not required: some
// defects spoil several cases.
func TestEachDefectFailsItsCases(t *testing.T) {
	for _, s := range broken.Catalogue {
		t.Run(string(s.Defect), func(t *testing.T) {
			ran := map[string]bool{}
			for _, m := range modes {
				res := evaluate(t, m, s.Defect)
				for _, id := range s.Targets {
					r, ok := res[id]
					if !ok {
						continue
					}
					ran[id] = true
					if r.Passed() {
						t.Errorf("%s: case %s passes although %q (%s) is on", m.name, id, s.Defect, s.What)
					}
				}
				var collateral []string
				for _, id := range caseIDs(res) {
					if !res[id].Passed() && !slices.Contains(s.Targets, id) {
						collateral = append(collateral, id)
					}
				}
				if len(collateral) > 0 {
					t.Logf("%s: also fails: %s", m.name, strings.Join(collateral, ", "))
				}
			}
			for _, id := range s.Targets {
				if !ran[id] {
					t.Errorf("no case %s in any mode", id)
				}
			}
		})
	}
}

// TestAllDefectsFailEveryCase: the adapter with every defect on fails every
// case of the suite, in each mode.
func TestAllDefectsFailEveryCase(t *testing.T) {
	for _, m := range modes {
		res := evaluate(t, m, broken.Defects()...)
		for _, id := range caseIDs(res) {
			if res[id].Passed() {
				t.Errorf("%s: case %s passes against the adapter with every defect on", m.name, id)
			}
		}
	}
}

// runAgainstBroken is the body that the subprocess test below runs: the public
// entry point, Run, against the adapter with every defect on, in each mode. It
// fails, by design, and only runs when the parent test asks for it.
func TestRunAgainstBroken(t *testing.T) {
	if os.Getenv("PACT_RUN_BROKEN") != "1" {
		t.Skip("runs as a subprocess of TestRunFailsEveryCase")
	}
	for _, m := range modes {
		t.Run(m.name, func(t *testing.T) {
			adaptertest.Run(t, m.factory(broken.Defects()...), m.opts)
		})
	}
}

// TestRunFailsEveryCase: Run itself, not only Evaluate, reports a failure for
// every case of each mode when the adapter is broken. The test binary runs
// again with the subtest above enabled and its output is read.
func TestRunFailsEveryCase(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestRunAgainstBroken$", "-test.v")
	cmd.Env = append(os.Environ(), "PACT_RUN_BROKEN=1")
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	if err == nil {
		t.Fatalf("Run against the broken adapter exited successfully:\n%s", out.String())
	}

	line := regexp.MustCompile(`^\s+--- (PASS|FAIL|SKIP): TestRunAgainstBroken/(dedicated|shared)/(\S+)`)
	failed := map[string]map[string]bool{}
	sc := bufio.NewScanner(&out)
	for sc.Scan() {
		if m := line.FindStringSubmatch(sc.Text()); m != nil {
			if m[1] != "FAIL" {
				t.Errorf("%s: case %s is reported %s", m[2], m[3], m[1])
			}
			if failed[m[2]] == nil {
				failed[m[2]] = map[string]bool{}
			}
			failed[m[2]][m[3]] = true
		}
	}
	for _, m := range modes {
		want := caseIDs(evaluate(t, m))
		for _, id := range want {
			if !failed[m.name][id] {
				t.Errorf("%s: Run reports no failure for case %s", m.name, id)
			}
		}
		if len(failed[m.name]) != len(want) {
			t.Errorf("%s: Run reported %d cases, the suite has %d", m.name, len(failed[m.name]), len(want))
		}
	}
}
