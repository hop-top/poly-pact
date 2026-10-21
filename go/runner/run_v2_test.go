package runner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// v2Root is the synthetic tree of format v2 evaluation cases
// (spec/v1.0/fixtures/README.md, section Format v2): a replay in order, a
// concurrent replay, handoff attempts and a multi-exchange sequence.
var v2Root = filepath.Join("testdata", "fixtures-v2")

var v2Cases = []string{"v2/concurrent-replay", "v2/handoff", "v2/replay", "v2/sequence"}

func TestV2GoodImplPasses(t *testing.T) {
	rep, err := Run(fakeImplCfg(t, "good", v2Root))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Manifest.Status != StatusPass {
		t.Errorf("manifest = %+v, want PASS", rep.Manifest)
	}
	for _, id := range v2Cases {
		if r := result(t, rep, id); r.Status != StatusPass {
			t.Errorf("%s = %+v, want PASS", id, r)
		}
	}
}

// TestV2ResponseOrder: responses are compared in submission order, then the
// handoff lines; only the responses of a concurrent batch may come in any
// order.
func TestV2ResponseOrder(t *testing.T) {
	rep, err := Run(fakeImplCfg(t, "swapped-order", v2Root))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]Status{
		"v2/concurrent-replay": StatusPass,
		"v2/handoff":           StatusFail,
		"v2/replay":            StatusFail,
		"v2/sequence":          StatusFail,
	}
	for id, st := range want {
		if r := result(t, rep, id); r.Status != st {
			t.Errorf("%s = %+v, want %s", id, r, st)
		}
	}
}

func TestV2WrongResponseFails(t *testing.T) {
	rep, err := Run(fakeImplCfg(t, "wrong-decision", v2Root))
	if err != nil {
		t.Fatal(err)
	}
	details := map[string][]string{
		"v2/concurrent-replay": {"REPLAY", "ADMISSIBLE"},
		"v2/handoff":           {"handoff 2", "REPLAY"},
		"v2/replay":            {"response 2", "INVALID_PROOF", "REPLAY"},
		"v2/sequence":          {"exchanges/2", "INADMISSIBLE", "ADMISSIBLE"},
	}
	for id, subs := range details {
		r := result(t, rep, id)
		if r.Status != StatusFail || !detailsContain(r.Details, subs...) {
			t.Errorf("%s = %+v, want FAIL naming %q", id, r, subs)
		}
	}
}

// v2Tree is one format v2 case "admission/v2" with the given case files and
// expected files, by path relative to the case directory and to
// expected/admission/v2/.
func v2Tree(t *testing.T, caseFiles, expectedFiles map[string]string, expected string) string {
	t.Helper()
	e := evalEntry("admission/v2", "ADMISSIBLE")
	if expected != "" {
		e["expected"] = "expected/admission/v2/" + expected
	}
	files := map[string]string{}
	for rel, s := range caseFiles {
		files["admission/v2/"+rel] = s
	}
	for rel, s := range expectedFiles {
		files["expected/admission/v2/"+rel] = s
	}
	// Every directory the case reads has a configuration and a native context.
	dirs := map[string]bool{"": true}
	for rel := range caseFiles {
		if d, _, ok := strings.Cut(strings.TrimPrefix(rel, "exchanges/"), "/"); ok && strings.HasPrefix(rel, "exchanges/") {
			dirs["exchanges/"+d+"/"] = true
		}
	}
	for d := range dirs {
		for name, s := range map[string]string{"config.json": validatorConfig, "native_context.json": `{}`} {
			if _, ok := files["admission/v2/"+d+name]; !ok {
				files["admission/v2/"+d+name] = s
			}
		}
	}
	return evalTree(t, []entry{e}, files)
}

// runLines runs the case of root with a command that prints lines.
func runLines(t *testing.T, root string, lines ...string) Result {
	t.Helper()
	out := filepath.Join(t.TempDir(), "stdout")
	writeFile(t, out, strings.Join(lines, "\n"))
	rep, err := Run(Config{FixturesRoot: root, EvaluateCmd: script(t, "cat "+out) + " {dir}"})
	if err != nil {
		t.Fatal(err)
	}
	return result(t, rep, "admission/v2")
}

func v2Lines(t *testing.T) (receipt, deferred, replay string) {
	t.Helper()
	read := func(id string) string {
		b, err := os.ReadFile(filepath.Join("testdata", "fakeimpl", "golden", filepath.FromSlash(id), "evaluate.out"))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	return read("admission/valid"), read("approval/pending-established-request"),
		`{"type":"about:blank","title":"Rejected","status":409,"code":"REPLAY","request_id":"r-1"}`
}

func TestV2Lines(t *testing.T) {
	receipt, deferred, replay := v2Lines(t)
	two := map[string]string{"exchange.json": `{"presentations":[{"signed":"signed/presentation.jws","jti":"a"},{"signed":"signed/presentation.jws","jti":"a"}]}`}
	twoWant := map[string]string{"decision.json": `{"responses":[{"decision":"ADMISSIBLE","transport_code":null},{"transport_code":"REPLAY"}],"subject":"/responses/1"}`}
	handoff := map[string]string{"exchange.json": `{"handoff":[{}]}`}
	handoffWant := map[string]string{"decision.json": `{"decision":"ADMISSIBLE","transport_code":null,"handoff":[{"transport_code":null}]}`}
	handoffReplay := map[string]string{"decision.json": `{"decision":"ADMISSIBLE","transport_code":null,"handoff":[{"transport_code":"REPLAY"}]}`}
	invalid := `{"type":"about:blank","title":"Rejected","status":401,"code":"INVALID_PROOF","request_id":"r-1"}`
	tests := []struct {
		name          string
		caseFiles     map[string]string
		expectedFiles map[string]string
		lines         []string
		want          Status
		detail        []string
	}{
		{"two responses", two, twoWant, []string{receipt, replay}, StatusPass, nil},
		{"two responses, CRLF", two, twoWant, []string{receipt + "\r", replay + "\r", ""}, StatusPass, nil},
		{"one line short", two, twoWant, []string{receipt}, StatusFail, []string{"1 line", "want 2"}},
		{"one line too many", two, twoWant, []string{receipt, replay, replay}, StatusFail, []string{"3 lines", "want 2"}},
		{"blank line between", two, twoWant, []string{receipt, "", replay}, StatusFail, []string{"3 lines", "want 2"}},
		{"second is a receipt", two, twoWant, []string{receipt, deferred}, StatusFail, []string{"response 2", "REPLAY"}},
		{"handoff accepted", handoff, handoffWant, []string{receipt, `{"handoff":"accepted"}`}, StatusPass, nil},
		{"handoff rejected", handoff, handoffWant, []string{receipt, replay}, StatusFail, []string{"handoff 1", "REPLAY", "accepted"}},
		{"handoff line is a receipt", handoff, handoffWant, []string{receipt, receipt}, StatusFail, []string{"handoff 1"}},
		{"handoff line with more members", handoff, handoffWant, []string{receipt, `{"handoff":"accepted","x":1}`}, StatusFail, []string{"handoff 1"}},
		{"handoff in a response slot", handoff, handoffWant, []string{`{"handoff":"accepted"}`, `{"handoff":"accepted"}`}, StatusFail, []string{"response 1"}},
		{"handoff rejected as expected", handoff, handoffReplay, []string{receipt, replay}, StatusPass, nil},
		{"handoff rejected with another code", handoff, handoffReplay, []string{receipt, invalid}, StatusFail, []string{"handoff 1", "INVALID_PROOF", "REPLAY"}},
		{"handoff accepted, rejection expected", handoff, handoffReplay, []string{receipt, `{"handoff":"accepted"}`}, StatusFail, []string{"handoff 1", "accepted", "REPLAY"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := runLines(t, v2Tree(t, tt.caseFiles, tt.expectedFiles, ""), tt.lines...)
			if r.Status != tt.want {
				t.Fatalf("= %+v, want %s", r, tt.want)
			}
			if tt.detail != nil && !detailsContain(r.Details, tt.detail...) {
				t.Errorf("details %q do not name %q", r.Details, tt.detail)
			}
		})
	}
}

// TestV2ConcurrentBatch: the responses of the submissions whose concurrent is
// true match the expected entries in any order, at the place of the first of
// them; the other responses keep their order.
func TestV2ConcurrentBatch(t *testing.T) {
	receipt, deferred, replay := v2Lines(t)
	sub := func(concurrent bool) string {
		if concurrent {
			return `{"signed":"signed/presentation.jws","jti":"a","concurrent":true}`
		}
		return `{"signed":"signed/presentation.jws","jti":"b"}`
	}
	caseFiles := map[string]string{"exchange.json": `{"presentations":[` + sub(true) + `,` + sub(false) + `,` + sub(true) + `]}`}
	want := map[string]string{"decision.json": `{"responses":[{"decision":"ADMISSIBLE","transport_code":null},{"decision":"DEFERRED","transport_code":null},{"transport_code":"REPLAY"}],"subject":"/responses/2"}`}
	root := v2Tree(t, caseFiles, want, "")
	for _, tt := range []struct {
		name  string
		lines []string
		want  Status
	}{
		{"batch in order", []string{receipt, replay, deferred}, StatusPass},
		{"batch swapped", []string{replay, receipt, deferred}, StatusPass},
		{"sequential before the batch", []string{deferred, receipt, replay}, StatusFail},
		{"batch twice admitted", []string{receipt, receipt, deferred}, StatusFail},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if r := runLines(t, root, tt.lines...); r.Status != tt.want {
				t.Errorf("= %+v, want %s", r, tt.want)
			}
		})
	}
}

// TestV2BadCaseFails: an expected file or a case file that format v2 does
// not allow fails the entry, naming the file, before the command runs.
func TestV2BadCaseFails(t *testing.T) {
	one := `{"decision":"ADMISSIBLE","transport_code":null}`
	two := `{"presentations":[{"signed":"signed/presentation.jws","jti":"a"},{"signed":"signed/presentation.jws","jti":"a"}]}`
	seq := `{"exchanges":["exchanges/1","exchanges/2"],"subject":"exchanges/2"}`
	tests := []struct {
		name          string
		caseFiles     map[string]string
		expectedFiles map[string]string
		expected      string
		detail        string
	}{
		{"responses beside a top-level decision", map[string]string{"exchange.json": two},
			map[string]string{"decision.json": `{"decision":"ADMISSIBLE","transport_code":null,"responses":[` + one + `,` + one + `]}`}, "", "decision.json"},
		{"fewer responses than submissions", map[string]string{"exchange.json": two},
			map[string]string{"decision.json": `{"responses":[` + one + `]}`}, "", "decision.json"},
		{"two submissions, no responses", map[string]string{"exchange.json": two},
			map[string]string{"decision.json": one}, "", "decision.json"},
		{"unknown member in a response", map[string]string{"exchange.json": two},
			map[string]string{"decision.json": `{"responses":[` + one + `,{"decision":"ADMISSIBLE","transport_code":null,"verdict":1}]}`}, "", "decision.json"},
		{"response with neither", map[string]string{"exchange.json": two},
			map[string]string{"decision.json": `{"responses":[` + one + `,{"transport_code":null}]}`}, "", "decision.json"},
		{"subject out of range", nil,
			map[string]string{"decision.json": `{"decision":"ADMISSIBLE","transport_code":null,"subject":"/responses/0"}`}, "", "subject"},
		{"subject past the handoffs", map[string]string{"exchange.json": `{"handoff":[{}]}`},
			map[string]string{"decision.json": `{"decision":"ADMISSIBLE","transport_code":null,"handoff":[{"transport_code":null}],"subject":"/handoff/1"}`}, "", "subject"},
		{"handoff count differs", map[string]string{"exchange.json": `{"handoff":[{},{}]}`},
			map[string]string{"decision.json": `{"decision":"ADMISSIBLE","transport_code":null,"handoff":[{"transport_code":null}]}`}, "", "handoff"},
		{"unknown member in exchange.json", map[string]string{"exchange.json": `{"presentation":[]}`},
			map[string]string{"decision.json": one}, "", "exchange.json"},
		{"empty presentations", map[string]string{"exchange.json": `{"presentations":[]}`},
			map[string]string{"decision.json": one}, "", "exchange.json"},
		{"sequence subject not an exchange", map[string]string{"sequence.json": `{"exchanges":["exchanges/1"],"subject":"exchanges/2"}`, "exchanges/1/config.json": "{}"},
			map[string]string{"exchanges/1/decision.json": one}, "exchanges/1/decision.json", "sequence.json"},
		{"expected is not the subject exchange's", map[string]string{"sequence.json": seq, "exchanges/1/config.json": "{}", "exchanges/2/config.json": "{}"},
			map[string]string{"exchanges/1/decision.json": one, "exchanges/2/decision.json": one}, "exchanges/1/decision.json", "exchanges/2/decision.json"},
		{"exchange without its expected file", map[string]string{"sequence.json": seq, "exchanges/1/config.json": "{}", "exchanges/2/config.json": "{}"},
			map[string]string{"exchanges/2/decision.json": one}, "exchanges/2/decision.json", "exchanges/1/decision.json"},
		{"exchange directory missing", map[string]string{"sequence.json": seq, "exchanges/1/config.json": "{}"},
			map[string]string{"exchanges/1/decision.json": one, "exchanges/2/decision.json": one}, "exchanges/2/decision.json", "exchanges/2"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := v2Tree(t, tt.caseFiles, tt.expectedFiles, tt.expected)
			marker := filepath.Join(t.TempDir(), "ran")
			rep, err := Run(Config{FixturesRoot: root, EvaluateCmd: script(t, "touch "+marker) + " {dir}"})
			if err != nil {
				t.Fatal(err)
			}
			if r := result(t, rep, "admission/v2"); r.Status != StatusFail || !detailsContain(r.Details, tt.detail) {
				t.Errorf("= %+v, want FAIL naming %q", r, tt.detail)
			}
			if _, err := os.Stat(marker); err == nil {
				t.Error("the command ran on a malformed case")
			}
		})
	}
}

// TestV2SequenceChecksEveryExchange: a multi-exchange case prints the lines
// of each exchange in turn, and each exchange is judged, not only the subject.
func TestV2SequenceChecksEveryExchange(t *testing.T) {
	receipt, deferred, replay := v2Lines(t)
	caseFiles := map[string]string{
		"sequence.json":             `{"exchanges":["exchanges/1","exchanges/2"],"subject":"exchanges/2"}`,
		"exchanges/1/config.json":   validatorConfig,
		"exchanges/2/exchange.json": `{"handoff":[{}]}`,
	}
	want := map[string]string{
		"exchanges/1/decision.json": `{"decision":"DEFERRED","transport_code":null}`,
		"exchanges/2/decision.json": `{"decision":"ADMISSIBLE","transport_code":null,"handoff":[{"transport_code":"REPLAY"}]}`,
	}
	root := v2Tree(t, caseFiles, want, "exchanges/2/decision.json")
	for _, tt := range []struct {
		name   string
		lines  []string
		want   Status
		detail []string
	}{
		{"both right", []string{deferred, receipt, replay}, StatusPass, nil},
		{"first exchange wrong", []string{receipt, receipt, replay}, StatusFail, []string{"exchanges/1", "ADMISSIBLE", "DEFERRED"}},
		{"second exchange's handoff wrong", []string{deferred, receipt, `{"handoff":"accepted"}`}, StatusFail, []string{"exchanges/2", "handoff 1"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := runLines(t, root, tt.lines...)
			if r.Status != tt.want || (tt.detail != nil && !detailsContain(r.Details, tt.detail...)) {
				t.Errorf("= %+v, want %s naming %q", r, tt.want, tt.detail)
			}
		})
	}
}

// TestV2EveryDifferenceIsReported: the details list every difference of
// every response and exchange, not only the first.
func TestV2EveryDifferenceIsReported(t *testing.T) {
	receipt, deferred, _ := v2Lines(t)
	want := func(r Result, subs ...string) {
		t.Helper()
		if r.Status != StatusFail {
			t.Fatalf("= %+v, want FAIL", r)
		}
		for _, s := range subs {
			if !detailsContain(r.Details, s) {
				t.Errorf("details %q do not name %q", r.Details, s)
			}
		}
	}

	two := map[string]string{"exchange.json": `{"presentations":[{"signed":"signed/presentation.jws","jti":"a"},{"signed":"signed/presentation.jws","jti":"a"}]}`}
	twoWant := map[string]string{"decision.json": `{"responses":[{"decision":"ADMISSIBLE","transport_code":null},{"transport_code":"REPLAY"}],"subject":"/responses/1"}`}
	want(runLines(t, v2Tree(t, two, twoWant, ""), deferred, receipt), "response 1", "response 2")

	seq := map[string]string{
		"sequence.json":             `{"exchanges":["exchanges/1","exchanges/2"],"subject":"exchanges/2"}`,
		"exchanges/1/config.json":   validatorConfig,
		"exchanges/2/exchange.json": `{"handoff":[{}]}`,
	}
	seqWant := map[string]string{
		"exchanges/1/decision.json": `{"decision":"DEFERRED","transport_code":null}`,
		"exchanges/2/decision.json": `{"decision":"ADMISSIBLE","transport_code":null,"handoff":[{"transport_code":"REPLAY"}]}`,
	}
	want(runLines(t, v2Tree(t, seq, seqWant, "exchanges/2/decision.json"), receipt, receipt, `{"handoff":"accepted"}`), "exchanges/1", "exchanges/2: handoff 1")
}

// TestV2BatchNoAssignment: two printed receipts that each match the first
// expected response of their kind but not both expected responses (the
// second expects another aud) are not a match: the batch names the expected
// kinds.
func TestV2BatchNoAssignment(t *testing.T) {
	receipt, _, _ := v2Lines(t)
	sub := `{"signed":"signed/presentation.jws","jti":"a","concurrent":true}`
	caseFiles := map[string]string{"exchange.json": `{"presentations":[` + sub + `,` + sub + `]}`}
	want := map[string]string{"decision.json": `{"responses":[
		{"decision":"ADMISSIBLE","transport_code":null},
		{"decision":"ADMISSIBLE","transport_code":null,"receipt":{"typ":"pact-admission+jwt","claims":{"aud":"https://gateway.example/other"}}}
	],"subject":"/responses/1"}`}
	r := runLines(t, v2Tree(t, caseFiles, want, ""), receipt, receipt)
	if r.Status != StatusFail || !detailsContain(r.Details, "concurrent batch", "decision ADMISSIBLE, decision ADMISSIBLE", "any order") {
		t.Errorf("= %+v, want FAIL naming the batch", r)
	}
}
