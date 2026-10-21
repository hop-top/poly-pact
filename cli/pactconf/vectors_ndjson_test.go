package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// resultGrammar is the result grammar of the parity orchestrator:
// pass, fail, or skipped: and a reason.
var resultGrammar = regexp.MustCompile(`^(pass|fail|skipped:(out-of-scope|spec-defect|os-layer|capability))$`)

// parsedLine is one line of vectors verify --ndjson as a test reads it.
type parsedLine struct {
	ID          string `json:"id"`
	Kind        string `json:"kind"`
	Result      string `json:"result"`
	SpecDefects []struct {
		Vector         string `json:"vector"`
		AppendixValue  string `json:"appendix_value"`
		ExpectedDigest string `json:"expected_digest"`
	} `json:"spec_defects"`
	MissingCapabilities []string `json:"missing_capabilities"`
}

// parseNDJSON checks that every line of out is one JSON object with the
// members id, kind and result, spec_defects only on a skipped:spec-defect
// line and missing_capabilities only on a skipped:capability line, whose
// result follows the grammar, and returns the lines.
func parseNDJSON(t *testing.T, out string) []parsedLine {
	t.Helper()
	if out != "" && !strings.HasSuffix(out, "\n") {
		t.Errorf("stdout does not end with a newline: %q", out)
	}
	var lines []parsedLine
	for raw := range strings.Lines(out) {
		raw = strings.TrimSuffix(raw, "\n")
		var members map[string]json.RawMessage
		if err := json.Unmarshal([]byte(raw), &members); err != nil {
			t.Errorf("stdout line is not a JSON object: %q", raw)
			continue
		}
		var l parsedLine
		if err := json.Unmarshal([]byte(raw), &l); err != nil {
			t.Errorf("stdout line %q: %v", raw, err)
			continue
		}
		want := []string{"id", "kind", "result"}
		switch l.Result {
		case "skipped:spec-defect":
			want = append(want, "spec_defects")
		case "skipped:capability":
			want = append(want, "missing_capabilities")
		}
		got := make([]string, 0, len(members))
		for k := range members {
			got = append(got, k)
		}
		slices.Sort(got)
		slices.Sort(want)
		if !slices.Equal(got, want) {
			t.Errorf("stdout line %q: members %v, want %v", raw, got, want)
		}
		if !resultGrammar.MatchString(l.Result) {
			t.Errorf("stdout line %q: result outside the grammar", raw)
		}
		lines = append(lines, l)
	}
	return lines
}

func results(lines []parsedLine) map[string][]string {
	m := map[string][]string{}
	for _, l := range lines {
		m[l.ID] = append(m[l.ID], l.Kind+" "+l.Result)
	}
	return m
}

// TestVectorsVerifyNDJSONRealTree: on the real tree, one line per vector and
// key entry and per schema entry of scope core, in manifest order, and nothing else on stdout. Entries of scope
// runner are skipped:out-of-scope, keys/ed25519 is skipped:out-of-scope
// (Ed25519 is optional, draft section 7.2), every other entry passes.
func TestVectorsVerifyNDJSONRealTree(t *testing.T) {
	code, out, errOut := runVerify(t, "--ndjson", realManifest)
	if code != 0 {
		t.Fatalf("exit %d\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
	}
	lines := parseNDJSON(t, out)
	var m struct {
		Entries []struct{ ID, Kind, Scope string } `json:"entries"`
	}
	b, err := os.ReadFile(realManifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	var want []parsedLine
	for _, e := range m.Entries {
		if e.Kind != "vector" && e.Kind != "key" && (e.Kind != "schema" || e.Scope == "runner") {
			continue
		}
		r := "pass"
		if e.Scope == "runner" || e.ID == "keys/ed25519" {
			r = "skipped:out-of-scope"
		}
		want = append(want, parsedLine{ID: e.ID, Kind: e.Kind, Result: r})
	}
	if len(lines) != len(want) {
		t.Errorf("%d lines, want %d", len(lines), len(want))
	}
	for i := range min(len(lines), len(want)) {
		g, w := lines[i], want[i]
		if g.ID != w.ID || g.Kind != w.Kind || g.Result != w.Result {
			t.Errorf("line %d: %s %s %s, want %s %s %s", i, g.ID, g.Kind, g.Result, w.ID, w.Kind, w.Result)
		}
	}
	for _, kind := range []string{"vector", "key", "schema"} {
		if !slices.ContainsFunc(lines, func(l parsedLine) bool { return l.Kind == kind && l.Result == "pass" }) {
			t.Errorf("no %s line passes", kind)
		}
	}
	if !slices.ContainsFunc(lines, func(l parsedLine) bool { return l.Kind == "vector" && l.Result == "skipped:out-of-scope" }) {
		t.Error("no scope runner vector line")
	}
}

// TestVectorsVerifyNDJSONSpecDefect: a digest vector whose appendix_value
// differs from its digest, flagged spec_defect, makes its entry
// skipped:spec-defect, carrying the value the draft prints and the digest,
// and the run exits 0.
func TestVectorsVerifyNDJSONSpecDefect(t *testing.T) {
	manifest := fixtureTree(t)
	root := filepath.Dir(manifest)
	const draftValue = "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"
	var digestValue string
	edit(t, filepath.Join(root, "vectors/digest/appendix-b.json"), func(v any) any {
		for _, x := range v.([]any) {
			vec := obj(x)
			if vec["id"] == "intent-b2" {
				digestValue = vec["expected_digest"].(string)
				vec["appendix_value"] = draftValue
				vec["spec_defect"] = true
			}
		}
		return v
	})
	if digestValue == "" || digestValue == draftValue {
		t.Fatalf("vector intent-b2 not found, or its digest is %q", digestValue)
	}
	code, out, errOut := runVerify(t, "--ndjson", manifest)
	if code != 0 {
		t.Fatalf("exit %d, want 0\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
	}
	for _, l := range parseNDJSON(t, out) {
		if l.ID != "vectors/digest/appendix-b" {
			if l.Result != "pass" {
				t.Errorf("%s: %s, want pass", l.ID, l.Result)
			}
			continue
		}
		if l.Result != "skipped:spec-defect" {
			t.Errorf("%s: %s, want skipped:spec-defect", l.ID, l.Result)
		}
		if len(l.SpecDefects) != 1 {
			t.Fatalf("%s: spec_defects %+v, want one", l.ID, l.SpecDefects)
		}
		d := l.SpecDefects[0]
		if d.Vector != "intent-b2" || d.AppendixValue != draftValue || d.ExpectedDigest != digestValue {
			t.Errorf("spec defect %+v, want vector intent-b2, appendix_value %s, expected_digest %s", d, draftValue, digestValue)
		}
	}
	if !strings.Contains(errOut, "vectors/digest/appendix-b") {
		t.Errorf("stderr does not name the skipped entry:\n%s", errOut)
	}
}

// TestVectorsVerifyNDJSONForcedFail: a vector forced to fail prints fail,
// names the failure on stderr, leaves the other lines alone, and exits 1.
func TestVectorsVerifyNDJSONForcedFail(t *testing.T) {
	manifest := fixtureTree(t)
	edit(t, filepath.Join(filepath.Dir(manifest), "vectors/jws/es256-valid.json"), func(v any) any {
		obj(v)["expected_payload"] = "{}"
		return v
	})
	code, out, errOut := runVerify(t, "--ndjson", manifest)
	if code != 1 {
		t.Fatalf("exit %d, want 1\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
	}
	lines := parseNDJSON(t, out)
	if len(lines) != 7 {
		t.Errorf("%d lines, want 7:\n%s", len(lines), out)
	}
	for _, l := range lines {
		want := "pass"
		if l.ID == "vectors/jws/es256-valid" {
			want = "fail"
		}
		if l.Kind != "vector" || l.Result != want {
			t.Errorf("%s: %s %s, want vector %s", l.ID, l.Kind, l.Result, want)
		}
	}
	if !regexp.MustCompile(`(?m)^FAIL vectors/jws/es256-valid: .*payload`).MatchString(errOut) {
		t.Errorf("stderr lacks the failure of vectors/jws/es256-valid:\n%s", errOut)
	}
}

// TestVectorsVerifyNDJSONScopeRunner: an entry of scope runner is
// skipped:out-of-scope whether or not its group has a runner here. One with
// a runner still runs, so its failure is reported on stderr and exits 1, as
// the table does.
func TestVectorsVerifyNDJSONScopeRunner(t *testing.T) {
	manifest := fixtureTree(t)
	root := filepath.Dir(manifest)
	writeJSON(t, filepath.Join(root, "reputation/x/vectors.json"), []any{})
	edit(t, manifest, func(v any) any {
		obj(v)["entries"] = append(entries(v), map[string]any{
			"id": "reputation/x", "kind": "vector", "scope": "runner",
			"path": "reputation/x/vectors.json", "expected": "reputation/x/vectors.json",
			"outcome": "MATCH", "spec_map_row": "CL-15.3", "draft_section": "15.3",
		})
		obj(entries(v)[3])["scope"] = "runner"
		return v
	})
	code, out, errOut := runVerify(t, "--ndjson", manifest)
	if code != 0 {
		t.Fatalf("exit %d, want 0\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
	}
	got := results(parseNDJSON(t, out))
	for _, id := range []string{"reputation/x", "vectors/jcs/arrays"} {
		if r := got[id]; !slices.Equal(r, []string{"vector skipped:out-of-scope"}) {
			t.Errorf("%s: %v, want one vector skipped:out-of-scope", id, r)
		}
	}

	if err := os.WriteFile(filepath.Join(root, "vectors/jcs/output/arrays.json"), []byte(`[1,2]`), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, errOut = runVerify(t, "--ndjson", manifest)
	if code != 1 {
		t.Fatalf("exit %d, want 1\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
	}
	if r := results(parseNDJSON(t, out))["vectors/jcs/arrays"]; !slices.Equal(r, []string{"vector skipped:out-of-scope"}) {
		t.Errorf("vectors/jcs/arrays: %v, want one vector skipped:out-of-scope", r)
	}
	if !regexp.MustCompile(`(?m)^FAIL vectors/jcs/arrays: .*canonical`).MatchString(errOut) {
		t.Errorf("stderr lacks the failure of vectors/jcs/arrays:\n%s", errOut)
	}
}

// TestVectorsVerifyNDJSONOtherKinds: entries of a kind other than vector and
// key print no line.
func TestVectorsVerifyNDJSONOtherKinds(t *testing.T) {
	manifest := fixtureTree(t, "adapters/_common/common-01.credential-wins")
	code, out, errOut := runVerify(t, "--ndjson", manifest)
	if code != 0 {
		t.Fatalf("exit %d\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
	}
	if r := results(parseNDJSON(t, out)); len(r) != 7 || r["adapters/_common/common-01.credential-wins"] != nil {
		t.Errorf("lines %v, want the 7 vector entries only", r)
	}
}

// TestVectorsVerifyUnknownKindOrScope: an entry whose kind or scope is not
// one of the manifest's closed sets is a harness error in both renderings:
// exit 2, nothing on stdout.
func TestVectorsVerifyUnknownKindOrScope(t *testing.T) {
	for _, tc := range []struct{ name, member, value string }{
		{"kind", "kind", "vectorr"},
		{"scope", "scope", "everywhere"},
	} {
		for _, args := range [][]string{nil, {"--ndjson"}} {
			t.Run(tc.name+strings.Join(args, ""), func(t *testing.T) {
				manifest := fixtureTree(t)
				edit(t, manifest, func(v any) any {
					obj(entries(v)[4])[tc.member] = tc.value
					return v
				})
				code, out, errOut := runVerify(t, append(args, manifest)...)
				if code != 2 {
					t.Errorf("exit %d, want 2\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
				}
				if out != "" {
					t.Errorf("stdout %q, want empty", out)
				}
				if !strings.Contains(errOut, "vectors/jws/es256-valid") || !strings.Contains(errOut, tc.value) {
					t.Errorf("stderr does not name the entry and %q:\n%s", tc.value, errOut)
				}
			})
		}
	}
}
