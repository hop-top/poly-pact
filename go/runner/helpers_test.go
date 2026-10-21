package runner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"hop.top/pact-go/runner/evalcase"
	"hop.top/pact-go/runner/manifest"
)

// repoFixtures is spec/v1.0/fixtures relative to this package directory.
var repoFixtures = filepath.Join("..", "..", "spec", "v1.0", "fixtures")

// entry is one manifest entry as written.
type entry map[string]any

// fakeImpl returns the path of testdata/fakeimpl/impl.sh and sets its mode.
// The fake implementation is a POSIX shell script.
func fakeImpl(t *testing.T, mode string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fake implementation is a POSIX shell script")
	}
	impl, err := filepath.Abs(filepath.Join("testdata", "fakeimpl", "impl.sh"))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("FAKEIMPL_MODE", mode)
	return impl
}

// fakeImplCfg runs every verb through the fake implementation in mode over
// the fixture directory root.
func fakeImplCfg(t *testing.T, mode, root string) Config {
	t.Helper()
	impl := fakeImpl(t, mode)
	return Config{
		FixturesRoot: root,
		EvaluateCmd:  impl + " evaluate {dir} {state}",
		ReceiptCmd:   impl + " receipt {state} {id}",
		OutcomesCmd:  impl + " outcomes {dir} {state}",
		LearningCmd:  impl + " learning {dir} {state}",
		SchemaCmd:    impl + " schema {dir}",
		// The fake implementation implements every optional capability.
		Capabilities: manifest.Capabilities(),
	}
}

// repoEntries reads the entries of the committed manifest, as written.
func repoEntries(t *testing.T) []entry {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoFixtures, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		Entries []entry `json:"entries"`
	}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m.Entries
}

// subsetRoot builds a fixture directory that holds the committed entries
// with the given ids, copied from spec/v1.0/fixtures with their files, and a
// manifest of exactly those entries. The runner tests then use real fixture
// content without depending on the state of unrelated groups.
func subsetRoot(t *testing.T, ids ...string) string {
	t.Helper()
	want := map[string]bool{}
	for _, id := range ids {
		want[id] = true
	}
	root := t.TempDir()
	var picked []entry
	needKey := false
	for _, e := range repoEntries(t) {
		id, _ := e["id"].(string)
		if !want[id] {
			continue
		}
		delete(want, id)
		picked = append(picked, e)
		if kindOf(e) == "evaluate" {
			needKey = true
		}
		for _, member := range []string{"path", "expected"} {
			if rel, ok := e[member].(string); ok {
				copyTree(t, filepath.Join(repoFixtures, filepath.FromSlash(rel)), filepath.Join(root, filepath.FromSlash(rel)))
			}
		}
		// The expected files of every exchange of a multi-exchange case.
		if kindOf(e) == "evaluate" {
			rel := "expected/" + id
			if _, err := os.Stat(filepath.Join(repoFixtures, filepath.FromSlash(rel))); err == nil {
				copyTree(t, filepath.Join(repoFixtures, filepath.FromSlash(rel)), filepath.Join(root, filepath.FromSlash(rel)))
			}
		}
	}
	for id := range want {
		t.Fatalf("no committed manifest entry %s", id)
	}
	if needKey {
		picked = withValidatorKey(t, root, picked)
	}
	writeManifest(t, root, picked)
	return root
}

// tree builds a fixture directory from a manifest and files, by path
// relative to the directory.
func tree(t *testing.T, entries []entry, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	writeManifest(t, root, entries)
	for rel, content := range files {
		writeFile(t, filepath.Join(root, filepath.FromSlash(rel)), content)
	}
	return root
}

func writeManifest(t *testing.T, root string, entries []entry) {
	t.Helper()
	if entries == nil {
		entries = []entry{}
	}
	b, err := json.MarshalIndent(map[string]any{"manifest_version": 1, "entries": entries}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(root, "manifest.json"), string(b))
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		writeFile(t, filepath.Join(dst, rel), string(b))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// evalEntry is a manifest entry of kind evaluate for the case <id>.
func evalEntry(id, outcome string) entry {
	return entry{
		"id": id, "kind": "evaluate", "scope": "runner", "path": id,
		"expected": "expected/" + id + "/decision.json", "outcome": outcome,
		"spec_map_row": "CL-11.3", "draft_section": "11.3",
	}
}

// evalFiles are the files of an evaluation case: its configuration, which
// names the public validator test key, the native context and the expected
// decision. A tree that runs it needs the key: see evalTree.
func evalFiles(id, decision string) map[string]string {
	return map[string]string{
		id + "/config.json":                 validatorConfig,
		id + "/native_context.json":         `{}`,
		"expected/" + id + "/decision.json": decision,
	}
}

// merge returns the union of file maps.
func merge(ms ...map[string]string) map[string]string {
	out := map[string]string{}
	for _, m := range ms {
		for k, v := range m {
			out[k] = v
		}
	}
	return out
}

// script writes an executable shell script that runs body and returns its
// path. The runner splits templates on white space, so the path must have
// none.
func script(t *testing.T, body string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("test commands are POSIX shell scripts")
	}
	p := filepath.Join(t.TempDir(), "cmd.sh")
	if strings.ContainsAny(p, " \t") {
		t.Skipf("temporary path %q has white space", p)
	}
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// result returns the result for id, failing the test when there is none or
// more than one.
func result(t *testing.T, rep *Report, id string) Result {
	t.Helper()
	var found []Result
	for _, r := range rep.Fixtures {
		if r.ID == id {
			found = append(found, r)
		}
	}
	if len(found) != 1 {
		t.Fatalf("%d results for %s in %+v", len(found), id, rep.Fixtures)
	}
	return found[0]
}

func ids(rep *Report) []string {
	out := []string{}
	for _, r := range rep.Fixtures {
		out = append(out, r.ID)
	}
	return out
}

// detailsContain reports whether some detail contains every one of subs.
func detailsContain(details []string, subs ...string) bool {
	for _, d := range details {
		all := true
		for _, s := range subs {
			if !strings.Contains(d, s) {
				all = false
				break
			}
		}
		if all {
			return true
		}
	}
	return false
}

// withValidatorKey adds the manifest entry of the public validator test key
// to entries, in id order, and its file to root. The evaluate check verifies
// a receipt under the key a case names (config.json validator.key).
func withValidatorKey(t *testing.T, root string, entries []entry) []entry {
	t.Helper()
	for _, e := range repoEntries(t) {
		if e["id"] != "keys/validator" {
			continue
		}
		key, err := os.ReadFile(filepath.Join(repoFixtures, "keys", "validator.jwk.json"))
		if err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(root, "keys", "validator.jwk.json"), string(key))
		out := append(slices.Clone(entries), e)
		slices.SortStableFunc(out, func(a, b entry) int { return strings.Compare(a["id"].(string), b["id"].(string)) })
		return out
	}
	t.Fatal("no committed manifest entry keys/validator")
	return nil
}

// validatorConfig is a config.json that names the public validator test
// key of the fixtures, as the committed cases do.
const validatorConfig = `{"validator":{"key":"keys/validator.jwk.json"}}`

// evalTree is tree with the public validator test key, as the committed
// manifest lists it.
func evalTree(t *testing.T, entries []entry, files map[string]string) string {
	t.Helper()
	root := tree(t, nil, files)
	writeManifest(t, root, withValidatorKey(t, root, entries))
	return root
}

// loadMutator returns the mutator of the committed test keys.
func loadMutator(t *testing.T) mutator {
	t.Helper()
	keys, err := evalcase.LoadKeys(repoFixtures)
	if err != nil {
		t.Fatal(err)
	}
	return mutator{keys: keys}
}
