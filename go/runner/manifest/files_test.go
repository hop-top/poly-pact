package manifest_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"hop.top/pact-go/runner/manifest"
)

func TestCompletenessAcceptsBase(t *testing.T) {
	tr := newTree(t, baseEntries())
	wantClean(t, manifest.Completeness(tr.root, tr.manifest()))
}

func TestCompletenessPathMissing(t *testing.T) {
	tr := newTree(t, baseEntries())
	tr.remove("keys/holder.jwk.json")
	wantRule(t, manifest.Completeness(tr.root, tr.manifest()), manifest.RulePathMissing, "keys/holder")
}

func TestCompletenessExpectedMissing(t *testing.T) {
	tr := newTree(t, baseEntries())
	tr.remove("expected/admission/valid/decision.json")
	wantRule(t, manifest.Completeness(tr.root, tr.manifest()), manifest.RuleExpectedMissing, "admission/valid")
}

// TestCompletenessExpectedIsAFile: an expected result is a file, never a
// directory.
func TestCompletenessExpectedIsAFile(t *testing.T) {
	es := baseEntries()
	es[1]["expected"] = "expected/admission/valid"
	tr := newTree(t, es)
	ps := manifest.Completeness(tr.root, tr.manifest())
	wantWhere(t, ps, manifest.RuleExpectedMissing, "admission/valid")

	// A directory named as expected covers nothing inside it. (A file under
	// expected/<id>/ is covered by the entry <id> whatever its expected
	// names, so the directory here is outside that tree.)
	es = baseEntries()
	es[1]["expected"] = "admission/valid-results"
	tr = newTree(t, es)
	tr.write("admission/valid-results/decision.json", "{}")
	ps = manifest.Completeness(tr.root, tr.manifest())
	wantWhere(t, ps, manifest.RuleExpectedMissing, "admission/valid")
	wantWhere(t, ps, manifest.RuleUncovered, "admission/valid-results/decision.json")
}

func TestCompletenessSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symbolic links need privileges on windows")
	}
	t.Run("escapes the fixtures directory", func(t *testing.T) {
		tr := newTree(t, baseEntries())
		outside := filepath.Join(tr.dir, "outside.json")
		if err := os.WriteFile(outside, []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
		tr.remove("keys/holder.jwk.json")
		if err := os.Symlink(outside, filepath.Join(tr.root, "keys", "holder.jwk.json")); err != nil {
			t.Fatal(err)
		}
		wantRule(t, manifest.Completeness(tr.root, tr.manifest()), manifest.RulePathMissing, "keys/holder")
	})
	t.Run("dangling", func(t *testing.T) {
		tr := newTree(t, baseEntries())
		tr.remove("keys/holder.jwk.json")
		if err := os.Symlink("nowhere.json", filepath.Join(tr.root, "keys", "holder.jwk.json")); err != nil {
			t.Fatal(err)
		}
		wantRule(t, manifest.Completeness(tr.root, tr.manifest()), manifest.RulePathMissing, "keys/holder")
	})
}

// TestCompletenessSymlinkedRoot: a fixture directory given as a symbolic link
// to a directory is followed, as a POSIX utility follows a link named on its
// command line (find -H): the walk covers the files of the directory it
// resolves to, so the result is the one for the directory itself. Links inside
// the tree are not followed.
func TestCompletenessSymlinkedRoot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symbolic links need privileges on windows")
	}
	link := func(tr *tree) string {
		t.Helper()
		l := filepath.Join(tr.dir, "fixtures-link")
		if err := os.Symlink(tr.root, l); err != nil {
			t.Fatal(err)
		}
		return l
	}
	t.Run("clean tree", func(t *testing.T) {
		tr := newTree(t, baseEntries())
		wantClean(t, manifest.Completeness(link(tr), tr.manifest()))
	})
	t.Run("uncovered file", func(t *testing.T) {
		tr := newTree(t, baseEntries())
		tr.write("keys/issuer.jwk.json", "{}")
		wantRule(t, manifest.Completeness(link(tr), tr.manifest()), manifest.RuleUncovered, "keys/issuer.jwk.json")
	})
	t.Run("extension", func(t *testing.T) {
		tr := newTree(t, baseEntries())
		tr.write("admission/valid/run.sh", "x")
		wantRule(t, manifest.Completeness(link(tr), tr.manifest()), manifest.RuleExtension, "admission/valid/run.sh")
	})
	t.Run("missing path", func(t *testing.T) {
		tr := newTree(t, baseEntries())
		tr.remove("keys/holder.jwk.json")
		wantRule(t, manifest.Completeness(link(tr), tr.manifest()), manifest.RulePathMissing, "keys/holder")
	})
}

func TestCompletenessUncovered(t *testing.T) {
	cases := map[string]string{
		"file in no entry":            "keys/issuer.jwk.json",
		"file beside a file path":     "vectors/jcs/input/french.json",
		"expected tree of no entry":   "expected/admission/other/decision.json",
		"expected tree of a group":    "expected/admission/decision.json",
		"beside an expected tree":     "expected/admission/valid-2/decision.json",
		"nested manifest.json":        "keys/manifest.json",
		"nested manifest.schema.json": "vectors/manifest.schema.json",
		"other markdown":              "vectors/jcs/NOTES.md",
		"LICENSE inside a name":       "vectors/jcs/MY-LICENSE.md",
		"lower-case license":          "vectors/jcs/license.md",
		"directory named LICENSE":     "vectors/LICENSE/notes.json",
		"prefix but not inside":       "admission/valid-2/config.json",
	}
	for name, file := range cases {
		t.Run(name, func(t *testing.T) {
			tr := newTree(t, baseEntries())
			tr.write(file, "{}")
			wantRule(t, manifest.Completeness(tr.root, tr.manifest()), manifest.RuleUncovered, file)
		})
	}
}

// TestCompletenessCovered: a file inside a directory path, a single-file path,
// an expected file, a file under expected/<id>/ of an entry <id>, a README.md
// anywhere and a file whose name starts with LICENSE are covered.
func TestCompletenessCovered(t *testing.T) {
	tr := newTree(t, baseEntries())
	tr.write("expected/admission/valid/snapshot.json", "{}")
	tr.write("expected/admission/valid/exchanges/1/decision.json", "{}")
	tr.write("expected/vectors/jcs/arrays/extra.json", "{}")
	tr.write("admission/valid/evidence/runtime.json", "{}")
	tr.write("admission/valid/signed/evidence/runtime.jws", "e30.e30.e30")
	tr.write("vectors/jcs/README.md", "# x")
	tr.write("expected/README.md", "# x")
	tr.write("vectors/jcs/LICENSE-NOTE.md", "# x")
	tr.write("LICENSE.md", "# x")
	tr.write("keys/LICENSE.json", "{}")
	wantClean(t, manifest.Completeness(tr.root, tr.manifest()))
}

func TestCompletenessExtensions(t *testing.T) {
	cases := map[string]struct {
		file  string
		rules []string
	}{
		"go source inside a case":        {"admission/valid/gen.go", []string{manifest.RuleExtension}},
		"shell script inside a case":     {"admission/valid/run.sh", []string{manifest.RuleExtension}},
		"no extension":                   {"admission/valid/LICENSE", []string{manifest.RuleExtension}},
		"LICENSE outside every entry":    {"vectors/LICENSE", []string{manifest.RuleExtension}},
		"yml is not in the neutral list": {"admission/valid/case.yml", []string{manifest.RuleExtension}},
		"txt is not in the neutral list": {"admission/valid/notes.txt", []string{manifest.RuleExtension}},
		"sql outside an asset entry":     {"admission/valid/seed.sql", []string{manifest.RuleExtension}},
		"rego outside an asset entry":    {"admission/valid/policy.rego", []string{manifest.RuleExtension}},
		"fga outside an asset entry":     {"admission/valid/model.fga", []string{manifest.RuleExtension}},
		"ldif outside an asset entry":    {"admission/valid/tree.ldif", []string{manifest.RuleExtension}},
		"uncovered sql":                  {"adapters/db/other.sql", []string{manifest.RuleExtension, manifest.RuleUncovered}},
		// Extensions are lowercase, as listed.
		"upper-case json":                {"admission/valid/E.JSON", []string{manifest.RuleExtension}},
		"mixed-case yaml":                {"admission/valid/case.Yaml", []string{manifest.RuleExtension}},
		"upper-case jws":                 {"admission/valid/signed/x.JWS", []string{manifest.RuleExtension}},
		"upper-case md":                  {"admission/valid/NOTES.MD", []string{manifest.RuleExtension}},
		"upper-case sql inside an asset": {"adapters/db/assets/seed.SQL", []string{manifest.RuleExtension}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			tr := newTree(t, baseEntries())
			tr.write(c.file, "x")
			ps := manifest.Completeness(tr.root, tr.manifest())
			got := rules(ps)
			if len(got) != len(c.rules) {
				t.Fatalf("rules %v, want %v:\n%s", got, c.rules, ps)
			}
			for _, r := range c.rules {
				wantWhere(t, ps, r, c.file)
			}
		})
	}
}

func TestCompletenessAllowedExtensions(t *testing.T) {
	tr := newTree(t, baseEntries())
	for _, f := range []string{
		"admission/valid/a.json", "admission/valid/b.yaml", "admission/valid/c.md",
		"admission/valid/d.jws", "admission/valid/E.json",
		"adapters/db/assets/policy.rego", "adapters/db/assets/model.fga", "adapters/db/assets/tree.ldif",
	} {
		tr.write(f, "x")
	}
	wantClean(t, manifest.Completeness(tr.root, tr.manifest()))
}

// TestCompletenessSkipsMalformedEntries: an entry whose path breaks a field
// rule is reported by Validate, not looked up on disk.
func TestCompletenessSkipsMalformedEntries(t *testing.T) {
	es := baseEntries()
	es[2]["path"] = "../outside.json"
	tr := newTree(t, es)
	for _, p := range manifest.Completeness(tr.root, tr.manifest()) {
		if p.Rule != manifest.RuleUncovered || p.Where != "keys/holder.jwk.json" {
			t.Errorf("unexpected problem %s", p)
		}
	}
}

func wantWhere(t testing.TB, ps manifest.Problems, rule, where string) {
	t.Helper()
	for _, p := range ps {
		if p.Rule == rule && p.Where == where {
			return
		}
	}
	t.Errorf("no %s problem at %s:\n%s", rule, where, ps)
}
