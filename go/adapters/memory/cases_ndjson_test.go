package memory_test

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"hop.top/pact-go/adapter/adaptertest"
	"hop.top/pact-go/adapters/internal/broken"
	"hop.top/pact-go/adapters/memory"
	"hop.top/pact-go/runner/manifest"
)

// The test binary of this package doubles as the adapter-case leg of the
// cross-language parity check. Built with go test -c and run with -ndjson,
// it runs the conformance suite against the memory adapter in both workload
// modes and prints one line per common case on standard output,
// {"id","kind","result"}, the id being the case's manifest id, and nothing
// else. The details of a failed case go to standard error, and the binary
// exits 1. A command binary cannot do this: the suite takes a testing.TB.
var ndjsonFlag = flag.Bool("ndjson", false, "print one NDJSON line per common adapter case on stdout and run no other test")

// ndjsonOut is the process's standard output while -ndjson is set. TestMain
// then points os.Stdout at standard error, so the PASS or FAIL line of the
// testing package does not reach standard output.
var ndjsonOut io.Writer

func TestMain(m *testing.M) {
	flag.Parse()
	if *ndjsonFlag {
		ndjsonOut = os.Stdout
		os.Stdout = os.Stderr
		if err := flag.Set("test.run", "^TestCaseResultsNDJSON$"); err != nil {
			_, _ = fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
	}
	os.Exit(m.Run())
}

// caseMode is one workload mode the suite runs an adapter in.
type caseMode struct {
	name    string
	factory adaptertest.Factory
	opts    adaptertest.Options
}

// memoryModes are the modes of TestSuite: dedicated workloads, the default
// of every profile, and workloads shared by several agents (identity
// mapping IM-19). Each runs the cases that apply to it, so every common case
// runs in at least one.
var memoryModes = []caseMode{
	{"dedicated", memory.Factory, adaptertest.Options{}},
	{"shared", memory.FactoryWith(memory.WithSharedWorkloads()), adaptertest.Options{SharedWorkloads: true}},
}

// caseLine is one NDJSON line, with the failures that go to standard error.
type caseLine struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	Result   string `json:"result"`
	failures []string
}

// commonCaseID is the manifest id of the common case id: its file,
// adapters/_common/<id in lowercase>.json, without .json
// (spec/v1.0/fixtures/adapters/README.md).
func commonCaseID(id string) string { return "adapters/_common/" + strings.ToLower(id) }

// mergeCaseResults turns the results of each mode, runs[i] being those of
// modes[i], into one line per case, sorted by id. A case passes when it
// passed in every mode that ran it, and fails otherwise.
func mergeCaseResults(modes []string, runs [][]adaptertest.Result) []caseLine {
	byID := map[string]*caseLine{}
	for i, rs := range runs {
		for _, r := range rs {
			id := commonCaseID(r.ID)
			l := byID[id]
			if l == nil {
				l = &caseLine{ID: id, Kind: "adapter-case", Result: "pass"}
				byID[id] = l
			}
			if !r.Passed() {
				l.Result = "fail"
				for _, f := range r.Failures {
					l.failures = append(l.failures, modes[i]+": "+f)
				}
			}
		}
	}
	lines := make([]caseLine, 0, len(byID))
	for _, id := range slices.Sorted(maps.Keys(byID)) {
		lines = append(lines, *byID[id])
	}
	return lines
}

// evaluateModes runs the common cases in every mode and merges the results.
func evaluateModes(tb testing.TB, modes []caseMode) ([]caseLine, error) {
	tb.Helper()
	names := make([]string, len(modes))
	runs := make([][]adaptertest.Result, len(modes))
	for i, m := range modes {
		rs, err := adaptertest.Evaluate(tb, m.factory, m.opts)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", m.name, err)
		}
		names[i], runs[i] = m.name, rs
	}
	return mergeCaseResults(names, runs), nil
}

// manifestCaseIDs returns the ids of the adapter-case entries of the real
// manifest whose files are common cases.
func manifestCaseIDs(t *testing.T) []string {
	t.Helper()
	m, err := manifest.Load(filepath.Join("..", "..", "..", "spec", "v1.0", "fixtures"))
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, e := range m.Entries {
		if e.Kind == manifest.KindAdapterCase && strings.HasPrefix(e.ID, "adapters/_common/") {
			ids = append(ids, e.ID)
		}
	}
	slices.Sort(ids)
	return ids
}

// TestCaseResultsNDJSON prints the lines under -ndjson. Without it, it
// checks them: one line per common adapter-case entry of the manifest, and
// every one passes, as TestSuite requires.
func TestCaseResultsNDJSON(t *testing.T) {
	lines, err := evaluateModes(t, memoryModes)
	if err != nil {
		t.Fatal(err)
	}
	if ndjsonOut != nil {
		enc := json.NewEncoder(ndjsonOut)
		enc.SetEscapeHTML(false)
		for _, l := range lines {
			if err := enc.Encode(l); err != nil {
				t.Fatal(err)
			}
			for _, f := range l.failures {
				t.Errorf("FAIL %s: %s", l.ID, f)
			}
		}
		return
	}
	var ids []string
	for _, l := range lines {
		ids = append(ids, l.ID)
		if l.Kind != "adapter-case" || l.Result != "pass" {
			t.Errorf("%s: %s %s, want adapter-case pass: %v", l.ID, l.Kind, l.Result, l.failures)
		}
	}
	if want := manifestCaseIDs(t); !slices.Equal(ids, want) {
		t.Errorf("line ids\n%v\nwant the manifest's common adapter cases\n%v", ids, want)
	}
}

// TestCaseResultsNDJSONBroken: against an adapter that resolves a shared
// workload to its first agent, the lines still cover every case, and the
// shared-workload cases that defect breaks are fail; they run only in the
// shared mode.
func TestCaseResultsNDJSONBroken(t *testing.T) {
	lines, err := evaluateModes(t, []caseMode{
		{"dedicated", broken.Factory(broken.FirstOfShared), adaptertest.Options{}},
		{"shared", broken.SharedFactory(broken.FirstOfShared), adaptertest.Options{SharedWorkloads: true}},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	var ids []string
	for _, l := range lines {
		got[l.ID] = l.Result
		ids = append(ids, l.ID)
	}
	if want := manifestCaseIDs(t); !slices.Equal(ids, want) {
		t.Errorf("line ids\n%v\nwant\n%v", ids, want)
	}
	for _, id := range []string{"IDENT-09.shared-workload", "IDENT-09.other-agent", "IDENT-09.unenrolled-agent"} {
		if r := got[commonCaseID(id)]; r != "fail" {
			t.Errorf("%s: %q, want fail", id, r)
		}
	}
	if r := got[commonCaseID("COMMON-01.credential-wins")]; r != "pass" {
		t.Errorf("COMMON-01.credential-wins: %q, want pass", r)
	}
}

// TestMergeCaseResults: a case passes only when it passed in every mode
// that ran it; a case that ran in one mode takes that mode's result; the
// failures name their mode.
func TestMergeCaseResults(t *testing.T) {
	fail := []string{"wrong outcome"}
	got := mergeCaseResults([]string{"dedicated", "shared"}, [][]adaptertest.Result{
		{{ID: "COMMON-02.b"}, {ID: "IDENT-10.a", Failures: fail}, {ID: "COMMON-01.a"}, {ID: "COMMON-03.c", Failures: fail}},
		{{ID: "COMMON-02.b", Failures: fail}, {ID: "IDENT-09.a"}, {ID: "COMMON-01.a"}, {ID: "IDENT-09.b", Failures: fail}, {ID: "COMMON-03.c"}},
	})
	want := []caseLine{
		{ID: "adapters/_common/common-01.a", Kind: "adapter-case", Result: "pass"},
		{ID: "adapters/_common/common-02.b", Kind: "adapter-case", Result: "fail", failures: []string{"shared: wrong outcome"}},
		{ID: "adapters/_common/common-03.c", Kind: "adapter-case", Result: "fail", failures: []string{"dedicated: wrong outcome"}},
		{ID: "adapters/_common/ident-09.a", Kind: "adapter-case", Result: "pass"},
		{ID: "adapters/_common/ident-09.b", Kind: "adapter-case", Result: "fail", failures: []string{"shared: wrong outcome"}},
		{ID: "adapters/_common/ident-10.a", Kind: "adapter-case", Result: "fail", failures: []string{"dedicated: wrong outcome"}},
	}
	if len(got) != len(want) {
		t.Fatalf("%d lines, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		g, w := got[i], want[i]
		if g.ID != w.ID || g.Kind != w.Kind || g.Result != w.Result || !slices.Equal(g.failures, w.failures) {
			t.Errorf("line %d: %+v, want %+v", i, g, w)
		}
	}
	b, err := json.Marshal(got[0])
	if err != nil || string(b) != `{"id":"adapters/_common/common-01.a","kind":"adapter-case","result":"pass"}` {
		t.Errorf("line JSON %s (%v)", b, err)
	}
}

// TestCaseResultsNDJSONBinary runs this test binary with -ndjson (and -v):
// standard output holds exactly one JSON line per common adapter case; the
// testing package's own lines go to standard error and show that no other
// test ran.
func TestCaseResultsNDJSONBinary(t *testing.T) {
	if ndjsonOut != nil {
		t.Skip("running under -ndjson")
	}
	var stdout, stderr strings.Builder
	cmd := exec.Command(os.Args[0], "-ndjson", "-test.v")
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("%v\nstdout:\n%s\nstderr:\n%s", err, stdout.String(), stderr.String())
	}
	var ids []string
	for line := range strings.Lines(stdout.String()) {
		var l map[string]string
		if err := json.Unmarshal([]byte(line), &l); err != nil || len(l) != 3 || l["kind"] != "adapter-case" || l["result"] != "pass" {
			t.Errorf("stdout line %q is not an adapter-case pass line (%v)", line, err)
		}
		ids = append(ids, l["id"])
	}
	if want := manifestCaseIDs(t); !slices.Equal(ids, want) {
		t.Errorf("line ids\n%v\nwant\n%v", ids, want)
	}
	var ran []string
	for line := range strings.Lines(stderr.String()) {
		if name, ok := strings.CutPrefix(line, "=== RUN   "); ok {
			ran = append(ran, strings.TrimSpace(name))
		}
	}
	if !slices.Equal(ran, []string{"TestCaseResultsNDJSON"}) {
		t.Errorf("tests run under -ndjson: %v, want TestCaseResultsNDJSON only", ran)
	}
	if !strings.Contains(stderr.String(), "\nPASS\n") {
		t.Errorf("stderr lacks the PASS line of the testing package:\n%s", stderr.String())
	}
}
