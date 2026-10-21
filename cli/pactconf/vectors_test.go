package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// realManifest is spec/v1.0/fixtures/manifest.json seen from this directory.
var realManifest = filepath.Join("..", "..", "spec", "v1.0", "fixtures", "manifest.json")

func runVerify(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run(append([]string{"vectors", "verify"}, args...), &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

var resultRow = regexp.MustCompile(`(?m)^(PASS|FAIL|SKIP) +(\S+)`)

// rows returns the result of every table row by its id column.
func rows(out string) map[string][]string {
	m := map[string][]string{}
	for _, r := range resultRow.FindAllStringSubmatch(out, -1) {
		m[r[2]] = append(m[r[2]], r[1])
	}
	return m
}

// scopeRunnerSkip is the detail of the SKIP row of a scope runner vector
// entry whose group pactconf has no runner for.
const scopeRunnerSkip = "scope runner: run by the Go conformance runner, not by pactconf"

// checkRealTree checks the output of vectors verify on manifest, the real
// tree: no FAIL row; one PASS row per vector entry of the five groups and
// per schema entry of scope core; one
// SKIP row naming the Go conformance runner per scope runner vector entry
// outside them; one PASS row per key entry but keys/ed25519, which is one
// SKIP row (Ed25519 is optional, draft section 7.2).
func checkRealTree(t *testing.T, manifest, out string) {
	t.Helper()
	if strings.Contains(out, "\nFAIL") {
		t.Errorf("a FAIL row on the real tree:\n%s", out)
	}
	var m struct {
		Entries []struct {
			ID    string `json:"id"`
			Kind  string `json:"kind"`
			Scope string `json:"scope"`
		} `json:"entries"`
	}
	b, err := os.ReadFile(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	got := rows(out)
	groups := map[string]int{}
	skips := 0
	keys, keySkips, schemas := 0, 0, 0
	for _, e := range m.Entries {
		if e.Kind == "key" {
			want := "PASS"
			if e.ID == "keys/ed25519" {
				want = "SKIP"
				keySkips++
			}
			if r := got[e.ID]; len(r) != 1 || r[0] != want {
				t.Errorf("%s: rows %v, want one %s", e.ID, r, want)
			}
			keys++
			continue
		}
		if e.Kind == "schema" {
			if r := got[e.ID]; e.Scope != "runner" && (len(r) != 1 || r[0] != "PASS") {
				t.Errorf("%s: rows %v, want one PASS", e.ID, r)
			}
			schemas++
			continue
		}
		if e.Kind != "vector" {
			continue
		}
		parts := strings.Split(e.ID, "/")
		if parts[0] != "vectors" {
			if e.Scope != "runner" {
				t.Errorf("%s: scope %q outside vectors/, want runner", e.ID, e.Scope)
				continue
			}
			if r := got[e.ID]; len(r) != 1 || r[0] != "SKIP" {
				t.Errorf("%s: rows %v, want one SKIP", e.ID, r)
			}
			if !regexp.MustCompile(`(?m)^SKIP +` + regexp.QuoteMeta(e.ID) + ` +` + regexp.QuoteMeta(scopeRunnerSkip) + `$`).MatchString(out) {
				t.Errorf("%s: no SKIP row with detail %q:\n%s", e.ID, scopeRunnerSkip, out)
			}
			skips++
			continue
		}
		if r := got[e.ID]; len(r) != 1 || r[0] != "PASS" {
			t.Errorf("%s: rows %v, want one PASS", e.ID, r)
		}
		groups[parts[1]]++
	}
	for _, g := range []string{"binding", "digest", "jcs", "jws", "schema", "strictjson"} {
		if groups[g] == 0 {
			t.Errorf("no vector of group %s ran", g)
		}
	}
	if skips == 0 {
		t.Errorf("no scope runner vector entry outside vectors/ in the manifest")
	}
	if keys == 0 {
		t.Errorf("no key entry in the manifest")
	}
	if schemas == 0 {
		t.Errorf("no schema entry in the manifest")
	}
	if n := strings.Count(out, "\nSKIP"); n != skips+keySkips {
		t.Errorf("%d SKIP rows, want %d:\n%s", n, skips+keySkips, out)
	}
}

// TestVectorsVerifyRealTree: every vector entry of the five groups passes,
// with one PASS row per entry; every scope runner vector entry of another
// group is one SKIP row; and the tree checks pass.
func TestVectorsVerifyRealTree(t *testing.T) {
	code, out, errOut := runVerify(t, realManifest)
	if code != 0 {
		t.Fatalf("exit %d\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
	}
	checkRealTree(t, realManifest, out)
}

// TestVectorsVerifyDefaultManifest: without an argument, run from cli/, the
// manifest is ../spec/v1.0/fixtures/manifest.json.
func TestVectorsVerifyDefaultManifest(t *testing.T) {
	t.Chdir("..")
	code, out, errOut := runVerify(t)
	if code != 0 {
		t.Fatalf("exit %d\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
	}
	checkRealTree(t, defaultManifest, out)
}

// fixtureTree copies a few real vectors of every group, and the real
// entries named by extra, into a temporary spec/v1.0/fixtures with a manifest of
// their entries, and returns the manifest path.
func fixtureTree(t *testing.T, extra ...string) string {
	t.Helper()
	ids := []string{
		"vectors/binding/bind-01-appendix-b3",
		"vectors/binding/bind-05-fragment",
		"vectors/digest/appendix-b",
		"vectors/jcs/arrays",
		"vectors/jws/es256-valid",
		"vectors/jws/thumbprint",
		"vectors/strictjson/duplicate-key-top-level",
	}
	ids = append(ids, extra...)
	src := filepath.Dir(realManifest)
	var m struct {
		ManifestVersion int               `json:"manifest_version"`
		Entries         []json.RawMessage `json:"entries"`
	}
	b, err := os.ReadFile(realManifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), "spec", "v1.0", "fixtures")
	var keep []json.RawMessage
	for _, raw := range m.Entries {
		var e struct{ ID, Path, Expected string }
		if err := json.Unmarshal(raw, &e); err != nil {
			t.Fatal(err)
		}
		for _, id := range ids {
			if e.ID == id {
				keep = append(keep, raw)
				copyFile(t, filepath.Join(src, e.Path), filepath.Join(dst, e.Path))
				if e.Expected != "" {
					copyFile(t, filepath.Join(src, e.Expected), filepath.Join(dst, e.Expected))
				}
			}
		}
	}
	if len(keep) != len(ids) {
		t.Fatalf("found %d of %d entries", len(keep), len(ids))
	}
	m.Entries = keep
	writeJSON(t, filepath.Join(dst, "manifest.json"), m)
	if err := os.MkdirAll(filepath.Join(dst, "..", "profiles", "basic"), 0o755); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(dst, "manifest.json")
}

func copyFile(t *testing.T, from, to string) {
	t.Helper()
	b, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(to), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

// edit rewrites the JSON file at path through f.
func edit(t *testing.T, path string, f func(any) any) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	writeJSON(t, path, f(v))
}

func entries(v any) []any { return obj(v)["entries"].([]any) }

// TestVectorsVerifyBindingConfigError: a config_error vector passes when
// its configuration fails Config.Validate, and fails when the configuration
// is usable or the vector's expectation does not agree.
func TestVectorsVerifyBindingConfigError(t *testing.T) {
	const id = "vectors/binding/bind-22-host-allowlisted"
	code, out, errOut := runVerify(t, fixtureTree(t, id))
	if code != 0 {
		t.Fatalf("exit %d\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
	}
	for _, tc := range []struct {
		name   string
		change func(v map[string]any)
		detail string
	}{
		{"usable configuration", func(v map[string]any) {
			obj(v["config"])["header_allowlist"] = []any{"if-match", "x-dry-run"}
		}, "configuration"},
		{"config_error false", func(v map[string]any) {
			v["expect"] = map[string]any{"config_error": false}
		}, "do not agree"},
		{"digest set", func(v map[string]any) {
			v["expect_operation_digest"] = "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"
		}, "do not agree"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			manifest := fixtureTree(t, id)
			edit(t, filepath.Join(filepath.Dir(manifest), "vectors/binding/bind-22-host-allowlisted.json"), func(v any) any {
				tc.change(obj(v))
				return v
			})
			code, out, errOut := runVerify(t, manifest)
			if code != 1 {
				t.Fatalf("exit %d, want 1\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
			}
			if !regexp.MustCompile(`(?m)^FAIL\s+` + regexp.QuoteMeta(id) + `\s.*` + regexp.QuoteMeta(tc.detail)).MatchString(out) {
				t.Errorf("no FAIL row for %s mentioning %q:\n%s", id, tc.detail, out)
			}
		})
	}
}

func TestVectorsVerifyFixtureTreePasses(t *testing.T) {
	code, out, errOut := runVerify(t, fixtureTree(t))
	if code != 0 {
		t.Fatalf("exit %d\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
	}
	if n := strings.Count(out, "\nPASS"); n != 7 {
		t.Errorf("%d PASS rows, want 7:\n%s", n, out)
	}
}

// TestVectorsVerifyFails: each change makes the command exit 1 and print a
// FAIL row whose id and detail name the problem.
func TestVectorsVerifyFails(t *testing.T) {
	tests := []struct {
		name   string
		change func(t *testing.T, root string)
		row    string // id column of the FAIL row
		detail string // text the FAIL row carries
	}{
		{"missing path", func(t *testing.T, root string) {
			edit(t, filepath.Join(root, "manifest.json"), func(v any) any {
				e := obj(entries(v)[0])
				e["path"] = "vectors/binding/nowhere.json"
				return v
			})
		}, "vectors/binding/bind-01-appendix-b3", "nowhere.json"},
		{"missing path of an entry that is not a vector", func(t *testing.T, root string) {
			edit(t, filepath.Join(root, "manifest.json"), func(v any) any {
				obj(v)["entries"] = append([]any{map[string]any{
					"id": "adapters/_common/common-99.gone", "kind": "adapter-case", "scope": "adapter",
					"path": "adapters/_common/common-99.gone.json", "expected": "adapters/_common/common-99.gone.json",
					"outcome": "REJECTED", "spec_map_row": "COMMON-99", "draft_section": "10.2",
				}}, entries(v)...)
				return v
			})
		}, "adapters/_common/common-99.gone", "does not exist"},
		{"missing expected", func(t *testing.T, root string) {
			edit(t, filepath.Join(root, "manifest.json"), func(v any) any {
				obj(entries(v)[2])["expected"] = "vectors/digest/gone.json"
				return v
			})
		}, "vectors/digest/appendix-b", "gone.json"},
		{"repeated id", func(t *testing.T, root string) {
			edit(t, filepath.Join(root, "manifest.json"), func(v any) any {
				m := obj(v)
				m["entries"] = append(entries(v), entries(v)[3])
				return v
			})
		}, "vectors/jcs/arrays", "repeated"},
		{"unregistered vector file", func(t *testing.T, root string) {
			copyFile(t, filepath.Join(root, "vectors/binding/bind-05-fragment.json"), filepath.Join(root, "vectors/binding/extra.json"))
		}, "fixtures/vectors/binding/extra.json", "not registered"},
		{"unregistered vector file in a new group", func(t *testing.T, root string) {
			writeJSON(t, filepath.Join(root, "vectors/other/x.json"), map[string]any{})
		}, "fixtures/vectors/other/x.json", "not registered"},
		{"Go file under fixtures", func(t *testing.T, root string) {
			if err := os.WriteFile(filepath.Join(root, "vectors", "gen.go"), []byte("package x\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}, "fixtures/vectors/gen.go", "Go source"},
		{"Go file under profiles", func(t *testing.T, root string) {
			if err := os.WriteFile(filepath.Join(root, "..", "profiles", "basic", "lint.go"), []byte("package x\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}, "profiles/basic/lint.go", "Go source"},
		{"binding digest", func(t *testing.T, root string) {
			edit(t, filepath.Join(root, "vectors/binding/bind-01-appendix-b3.json"), func(v any) any {
				obj(v)["expect_operation_digest"] = "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"
				return v
			})
		}, "vectors/binding/bind-01-appendix-b3", "object_digest"},
		{"binding context", func(t *testing.T, root string) {
			edit(t, filepath.Join(root, "vectors/binding/bind-01-appendix-b3.json"), func(v any) any {
				ctx := obj(obj(obj(v)["expect"])["operation_context"])
				ctx["target_uri"] = "https://gateway.example/invoices/INV-1043"
				return v
			})
		}, "vectors/binding/bind-01-appendix-b3", "operation context"},
		{"binding refusal not met", func(t *testing.T, root string) {
			edit(t, filepath.Join(root, "vectors/binding/bind-05-fragment.json"), func(v any) any {
				obj(obj(v)["request"])["raw_request_uri"] = "/invoices/INV-1042"
				return v
			})
		}, "vectors/binding/bind-05-fragment", "INVALID_MESSAGE"},
		{"binding unknown member", func(t *testing.T, root string) {
			edit(t, filepath.Join(root, "vectors/binding/bind-05-fragment.json"), func(v any) any {
				obj(v)["go_rule"] = "fragment"
				return v
			})
		}, "vectors/binding/bind-05-fragment", "go_rule"},
		{"binding missing member", func(t *testing.T, root string) {
			edit(t, filepath.Join(root, "vectors/binding/bind-05-fragment.json"), func(v any) any {
				delete(obj(v), "expect_operation_digest")
				return v
			})
		}, "vectors/binding/bind-05-fragment", "expect_operation_digest"},
		{"digest", func(t *testing.T, root string) {
			edit(t, filepath.Join(root, "vectors/digest/appendix-b.json"), func(v any) any {
				obj(v.([]any)[0])["expected_digest"] = "R5nfhv7g_o93VPHK6a2o56-MyyGy75GQwXxDM4M3cn0"
				return v
			})
		}, "vectors/digest/appendix-b", "empty-body"},
		{"jcs", func(t *testing.T, root string) {
			if err := os.WriteFile(filepath.Join(root, "vectors/jcs/output/arrays.json"), []byte(`[1,2]`), 0o644); err != nil {
				t.Fatal(err)
			}
		}, "vectors/jcs/arrays", "canonical"},
		{"jws", func(t *testing.T, root string) {
			edit(t, filepath.Join(root, "vectors/jws/es256-valid.json"), func(v any) any {
				obj(v)["expected_payload"] = "{}"
				return v
			})
		}, "vectors/jws/es256-valid", "payload"},
		{"jws thumbprint", func(t *testing.T, root string) {
			edit(t, filepath.Join(root, "vectors/jws/thumbprint.json"), func(v any) any {
				obj(v.([]any)[0])["expected_thumbprint"] = "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"
				return v
			})
		}, "vectors/jws/thumbprint", "thumbprint"},
		{"strictjson", func(t *testing.T, root string) {
			edit(t, filepath.Join(root, "vectors/strictjson/duplicate-key-top-level.json"), func(v any) any {
				obj(v)["expect"] = "accept"
				return v
			})
			edit(t, filepath.Join(root, "manifest.json"), func(v any) any {
				obj(entries(v)[6])["outcome"] = "ACCEPTED"
				return v
			})
		}, "vectors/strictjson/duplicate-key-top-level", "accept"},
		{"group without a runner", func(t *testing.T, root string) {
			writeJSON(t, filepath.Join(root, "vectors/other/x.json"), map[string]any{})
			edit(t, filepath.Join(root, "manifest.json"), func(v any) any {
				obj(v)["entries"] = append(entries(v), map[string]any{
					"id": "vectors/other/x", "kind": "vector", "scope": "core",
					"path": "vectors/other/x.json", "expected": "vectors/other/x.json",
					"outcome": "ACCEPTED", "spec_map_row": "CL-7.4", "draft_section": "7.4",
				})
				return v
			})
		}, "vectors/other/x", "no runner"},
		{"adapter scope without a runner", func(t *testing.T, root string) {
			writeJSON(t, filepath.Join(root, "other/x.json"), map[string]any{})
			edit(t, filepath.Join(root, "manifest.json"), func(v any) any {
				obj(v)["entries"] = append(entries(v), map[string]any{
					"id": "other/x", "kind": "vector", "scope": "adapter",
					"path": "other/x.json", "expected": "other/x.json",
					"outcome": "MATCH", "spec_map_row": "CL-15.3", "draft_section": "15.3",
				})
				return v
			})
		}, "other/x", "no runner"},
		{"runner scope with a runner still runs", func(t *testing.T, root string) {
			edit(t, filepath.Join(root, "vectors/strictjson/duplicate-key-top-level.json"), func(v any) any {
				obj(v)["expect"] = "accept"
				return v
			})
			edit(t, filepath.Join(root, "manifest.json"), func(v any) any {
				obj(entries(v)[6])["outcome"] = "ACCEPTED"
				obj(entries(v)[6])["scope"] = "runner"
				return v
			})
		}, "vectors/strictjson/duplicate-key-top-level", "accept"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			manifest := fixtureTree(t)
			tc.change(t, filepath.Dir(manifest))
			code, out, errOut := runVerify(t, manifest)
			if code != 1 {
				t.Fatalf("exit %d, want 1\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
			}
			found := false
			for _, line := range strings.Split(out, "\n") {
				f := strings.Fields(line)
				if len(f) >= 2 && f[0] == "FAIL" && f[1] == tc.row && strings.Contains(line, tc.detail) {
					found = true
				}
			}
			if !found {
				t.Errorf("no FAIL row for %s mentioning %q:\n%s", tc.row, tc.detail, out)
			}

			code, out, errOut = runVerify(t, "--ndjson", manifest)
			if code != 1 {
				t.Fatalf("--ndjson: exit %d, want 1\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
			}
			parseNDJSON(t, out)
			if !regexp.MustCompile(`(?m)^FAIL ` + regexp.QuoteMeta(tc.row) + `: .*` + regexp.QuoteMeta(tc.detail)).MatchString(errOut) {
				t.Errorf("--ndjson: no FAIL line on stderr for %s mentioning %q:\n%s", tc.row, tc.detail, errOut)
			}
		})
	}
}

// TestVectorsVerifyScopeRunnerSkips: a vector entry of scope runner whose
// group has no runner in pactconf is one SKIP row naming the Go conformance
// runner, inside or outside vectors/, and the run exits 0.
func TestVectorsVerifyScopeRunnerSkips(t *testing.T) {
	manifest := fixtureTree(t)
	root := filepath.Dir(manifest)
	writeJSON(t, filepath.Join(root, "reputation/x/vectors.json"), []any{})
	writeJSON(t, filepath.Join(root, "vectors/other/y.json"), map[string]any{})
	edit(t, manifest, func(v any) any {
		obj(v)["entries"] = append(entries(v),
			map[string]any{
				"id": "reputation/x", "kind": "vector", "scope": "runner",
				"path": "reputation/x/vectors.json", "expected": "reputation/x/vectors.json",
				"outcome": "MATCH", "spec_map_row": "CL-15.3", "draft_section": "15.3",
			},
			map[string]any{
				"id": "vectors/other/y", "kind": "vector", "scope": "runner",
				"path": "vectors/other/y.json", "expected": "vectors/other/y.json",
				"outcome": "MATCH", "spec_map_row": "CL-7.4", "draft_section": "7.4",
			})
		return v
	})
	code, out, errOut := runVerify(t, manifest)
	if code != 0 {
		t.Fatalf("exit %d, want 0\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
	}
	for _, id := range []string{"reputation/x", "vectors/other/y"} {
		want := regexp.MustCompile(`(?m)^SKIP +` + regexp.QuoteMeta(id) + ` +` + regexp.QuoteMeta(scopeRunnerSkip) + `$`)
		if !want.MatchString(out) {
			t.Errorf("no SKIP row for %s with detail %q:\n%s", id, scopeRunnerSkip, out)
		}
	}
	if n := strings.Count(out, "\nPASS"); n != 7 {
		t.Errorf("%d PASS rows, want 7:\n%s", n, out)
	}
	if !strings.Contains(out, "7 passed, 0 failed, 2 skipped") {
		t.Errorf("summary line, want 7 passed, 0 failed, 2 skipped:\n%s", out)
	}
}

// TestVectorsVerifyUsage: a usage error or an unreadable manifest exits 2.
func TestVectorsVerifyUsage(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"no subcommand", []string{"vectors"}},
		{"unknown subcommand", []string{"vectors", "check"}},
		{"two manifests", []string{"vectors", "verify", "a.json", "b.json"}},
		{"missing manifest", []string{"vectors", "verify", filepath.Join(t.TempDir(), "manifest.json")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := run(tc.args, &stdout, &stderr); code != 2 {
				t.Errorf("exit %d, want 2\nstdout:\n%s\nstderr:\n%s", code, stdout.String(), stderr.String())
			}
			if stderr.Len() == 0 {
				t.Error("nothing on stderr")
			}
		})
	}
}

// copySchema puts the committed schema beside the fixture directory of the
// test manifest, as spec/v1.0/schemas/pact.schema.json.
func copySchema(t *testing.T, manifest string) {
	t.Helper()
	copyFile(t, filepath.Join(filepath.Dir(realManifest), "..", "schemas", "pact.schema.json"),
		filepath.Join(filepath.Dir(manifest), "..", "schemas", "pact.schema.json"))
}

// TestVectorsVerifySchemaEntries: an entry of kind schema of scope core runs
// the verdict of spec/v1.0/fixtures/schema/README.md and passes when its
// expectation holds; one whose expectation does not hold fails, naming why;
// one of scope runner prints no line; without the schema the entry fails.
func TestVectorsVerifySchemaEntries(t *testing.T) {
	ids := []string{"parse/appendix-c-wrong-version", "schema/appendix-b-valid"}
	manifest := fixtureTree(t, ids...)
	copySchema(t, manifest)
	code, out, errOut := runVerify(t, "--ndjson", manifest)
	if code != 0 {
		t.Fatalf("exit %d\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
	}
	r := results(parseNDJSON(t, out))
	for _, id := range ids {
		if got := r[id]; len(got) != 1 || got[0] != "schema pass" {
			t.Errorf("%s: lines %v, want one schema pass", id, got)
		}
	}

	// The wrong-version payload is rejected with INVALID_MESSAGE, not the
	// INVALID_PROOF of a failed signature.
	dir := filepath.Dir(manifest)
	writeJSON(t, filepath.Join(dir, "expected", "parse", "appendix-c-wrong-version", "decision.json"),
		map[string]any{"transport_code": "INVALID_PROOF"})
	code, out, errOut = runVerify(t, "--ndjson", manifest)
	if r := results(parseNDJSON(t, out)); code != 1 || len(r["parse/appendix-c-wrong-version"]) != 1 || r["parse/appendix-c-wrong-version"][0] != "schema fail" ||
		!strings.Contains(errOut, "want INVALID_PROOF") {
		t.Errorf("wrong code: exit %d, lines %v, stderr %q; want 1 and a fail", code, r, errOut)
	}

	edit(t, manifest, func(v any) any {
		for _, e := range entries(v) {
			if obj(e)["kind"] == "schema" {
				obj(e)["scope"] = "runner"
			}
		}
		return v
	})
	code, out, _ = runVerify(t, "--ndjson", manifest)
	if r := results(parseNDJSON(t, out)); code != 0 || r[ids[0]] != nil || r[ids[1]] != nil {
		t.Errorf("scope runner: exit %d, lines %v; want 0 and no schema line", code, r)
	}

	manifest = fixtureTree(t, ids[1])
	code, out, _ = runVerify(t, manifest)
	if code != 1 || !regexp.MustCompile(`(?m)^FAIL +schema/appendix-b-valid .*pact\.schema\.json`).MatchString(out) {
		t.Errorf("no schema file: exit %d, stdout %q; want 1 and a FAIL row naming the schema", code, out)
	}
}
