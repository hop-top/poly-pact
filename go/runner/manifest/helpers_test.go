package manifest_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"hop.top/pact-go/runner/manifest"
)

// repoFixtures is spec/v1.0/fixtures relative to this package directory.
var repoFixtures = filepath.Join("..", "..", "..", "spec", "v1.0", "fixtures")

// repoSpecMap is spec/v1.0/spec-map.md relative to this package directory.
var repoSpecMap = filepath.Join("..", "..", "..", "spec", "v1.0", "spec-map.md")

// entry is one manifest entry as written, so a test can break any member.
type entry map[string]any

// baseEntries is a valid manifest: one entry of each shape the tests need,
// sorted by id.
func baseEntries() []entry {
	return []entry{
		{
			"id": "adapters/db/schema", "kind": "adapter-asset", "scope": "adapter",
			"path": "adapters/db/assets", "expected": nil, "outcome": nil,
			"spec_map_row": "CL-C", "draft_section": "17.1",
		},
		{
			"id": "admission/valid", "kind": "evaluate", "scope": "runner",
			"path": "admission/valid", "expected": "expected/admission/valid/decision.json",
			"outcome": "ADMISSIBLE", "spec_map_row": "CL-11.3", "draft_section": "11.3",
		},
		{
			"id": "keys/holder", "kind": "key", "scope": "core",
			"path": "keys/holder.jwk.json", "expected": nil, "outcome": nil,
			"spec_map_row": "CL-C", "draft_section": "C",
		},
		{
			"id": "vectors/jcs/arrays", "kind": "vector", "scope": "core",
			"path": "vectors/jcs/input/arrays.json", "expected": "vectors/jcs/output/arrays.json",
			"outcome": "ACCEPTED", "spec_map_row": "CL-C", "draft_section": "7.4",
		},
	}
}

// baseFiles are the files of the base tree, other than manifest.json.
var baseFiles = []string{
	"README.md",
	"manifest.schema.json",
	"adapters/README.md",
	"adapters/db/assets/schema.sql",
	"admission/valid/config.json",
	"admission/valid/signed/contract.jws",
	"expected/admission/valid/decision.json",
	"keys/README.md",
	"keys/holder.jwk.json",
	"vectors/jcs/input/arrays.json",
	"vectors/jcs/output/arrays.json",
}

// baseSpecMap cites every base entry's row. Every group of the base entries
// and rows has a status: admission is partial (admission/valid is registered,
// admission/wrong-tenant is reserved), approval and parse are planned, and
// adapters, keys and vectors are landed.
const baseSpecMap = "# Spec map\n\n" +
	"## Fixture groups\n\n" +
	"| Group | Directory | Covers | Status |\n" +
	"|---|---|---|---|\n" +
	"| admission | `fixtures/admission/` | Positive control | partial |\n" +
	"| approval | `fixtures/approval/` | Approval states | planned |\n" +
	"| parse | `fixtures/parse/` | Strict parse \\| JWS | planned |\n" +
	"| adapters | `fixtures/adapters/` | Adapter cases | landed |\n" +
	"| keys | `fixtures/keys/` | Test keys | landed |\n" +
	"| vectors | `fixtures/vectors/` | Vectors | landed |\n\n" +
	"## Conformance map\n\n" +
	"| ID | Check | Draft section | Finding | Fixture(s) |\n" +
	"|----|-------|---------------|---------|------------|\n" +
	"| CL-11.3 | Positive control | 11.3 | G13 | admission/valid, admission/wrong-tenant |\n" +
	"| CL-C | Test keys | C | G13 | keys/holder |\n" +
	"| CL-17.3.1 | Approval | 17.3 | G06 | approval/pending, parse/alg-none |\n\n" +
	"```\n## Not a section\n```\n"

// encode writes entries as a manifest document.
func encode(t testing.TB, entries []entry) []byte {
	t.Helper()
	b, err := json.MarshalIndent(map[string]any{"manifest_version": 1, "entries": entries}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func parse(t testing.TB, data []byte) *manifest.Manifest {
	t.Helper()
	m, err := manifest.Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return m
}

// tree is a temporary fixtures directory with a spec map beside it.
type tree struct {
	t       testing.TB
	dir     string // parent of fixtures/ and spec-map.md
	root    string // the fixtures directory
	specMap string
}

func newTree(t testing.TB, entries []entry) *tree {
	t.Helper()
	dir := t.TempDir()
	tr := &tree{t: t, dir: dir, root: filepath.Join(dir, "fixtures"), specMap: filepath.Join(dir, "spec-map.md")}
	for _, f := range baseFiles {
		tr.write(f, "{}")
	}
	tr.write("manifest.json", string(encode(t, entries)))
	if err := os.WriteFile(tr.specMap, []byte(baseSpecMap), 0o644); err != nil {
		t.Fatal(err)
	}
	return tr
}

func (tr *tree) write(rel, content string) {
	tr.t.Helper()
	full := filepath.Join(tr.root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		tr.t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		tr.t.Fatal(err)
	}
}

func (tr *tree) remove(rel string) {
	tr.t.Helper()
	if err := os.RemoveAll(filepath.Join(tr.root, filepath.FromSlash(rel))); err != nil {
		tr.t.Fatal(err)
	}
}

func (tr *tree) setSpecMap(text string) {
	tr.t.Helper()
	if err := os.WriteFile(tr.specMap, []byte(text), 0o644); err != nil {
		tr.t.Fatal(err)
	}
}

func (tr *tree) manifest() *manifest.Manifest {
	tr.t.Helper()
	m, err := manifest.Load(tr.root)
	if err != nil {
		tr.t.Fatalf("Load: %v", err)
	}
	return m
}

// rules lists the distinct rules of ps, sorted.
func rules(ps manifest.Problems) []string {
	var out []string
	for _, p := range ps {
		if !slices.Contains(out, p.Rule) {
			out = append(out, p.Rule)
		}
	}
	slices.Sort(out)
	return out
}

// wantRule fails unless ps has a problem of rule whose Where is where (any
// where when where is empty), and no problem of another rule.
func wantRule(t testing.TB, ps manifest.Problems, rule, where string) {
	t.Helper()
	found := false
	for _, p := range ps {
		if p.Rule != rule {
			t.Errorf("unexpected problem %s", p)
			continue
		}
		if where == "" || p.Where == where {
			found = true
		}
	}
	if !found {
		t.Errorf("no %s problem at %q; got:\n%s", rule, where, ps)
	}
}

func wantClean(t testing.TB, ps manifest.Problems) {
	t.Helper()
	if len(ps) > 0 {
		t.Errorf("want no problems, got:\n%s", ps)
	}
}

// mustContain fails unless s contains every part.
func mustContain(t testing.TB, s string, parts ...string) {
	t.Helper()
	for _, p := range parts {
		if !strings.Contains(s, p) {
			t.Errorf("%q does not contain %q", s, p)
		}
	}
}
