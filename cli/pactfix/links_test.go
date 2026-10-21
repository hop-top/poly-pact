package main

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"

	"hop.top/pact-go/runner/manifest"
)

// specTree is a repository root with spec/ and docs/, as the source
// repository has them. files maps a repository-relative path to its content.
func specTree(t testing.TB, files map[string]string) (root, spec string) {
	t.Helper()
	root = t.TempDir()
	base := map[string]string{
		"spec/README.md":               "# spec\n\nSee [the draft](draft.md) and [fixtures](fixtures/README.md).\n",
		"spec/draft.md":                "# Draft\n\n## 1. Abstract\n",
		"spec/fixtures/README.md":      "# Fixtures\n\n[Keys](keys/README.md), [map](../spec-map.md#fixture-groups).\n",
		"spec/fixtures/keys/README.md": "# Keys\n",
		"spec/spec-map.md":             "# Map\n\n[draft](draft.md)\n",
		"docs/notes.md":                "# Notes\n",
	}
	for k, v := range files {
		base[k] = v
	}
	for k, v := range base {
		writeFile(t, filepath.Join(root, filepath.FromSlash(k)), []byte(v))
	}
	return root, filepath.Join(root, "spec")
}

func linkRules(t testing.TB, spec string) manifest.Problems {
	t.Helper()
	ps, _, err := checkLinks(spec)
	if err != nil {
		t.Fatalf("checkLinks: %v", err)
	}
	return ps
}

func wantLinkProblem(t testing.TB, ps manifest.Problems, rule, where string) {
	t.Helper()
	found := false
	for _, p := range ps {
		if p.Rule == rule && p.Where == where {
			found = true
		} else {
			t.Errorf("unexpected problem %s", p)
		}
	}
	if !found {
		t.Errorf("no %s problem at %s; got:\n%s", rule, where, ps)
	}
}

func TestCheckLinksAcceptsBase(t *testing.T) {
	_, spec := specTree(t, nil)
	ps, st, err := checkLinks(spec)
	if err != nil || len(ps) > 0 {
		t.Fatalf("problems %v, error %v", ps, err)
	}
	if st.files != 5 || st.links != 5 {
		t.Errorf("stats %+v", st)
	}
}

// TestCheckLinksOutside: a link from the spec map to docs/notes.md outside
// spec/ fails although the file exists in the source repository.
func TestCheckLinksOutside(t *testing.T) {
	_, spec := specTree(t, map[string]string{
		"spec/spec-map.md": "# Map\n\nSee [notes](../docs/notes.md).\n",
	})
	wantLinkProblem(t, linkRules(t, spec), ruleLinkOutside, "spec/spec-map.md:3")
}

func TestCheckLinksRules(t *testing.T) {
	cases := map[string]struct {
		file, text, rule, where string
	}{
		"leaves and re-enters spec": {"spec/README.md", "[d](../spec/draft.md)\n", ruleLinkOutside, "spec/README.md:1"},
		"root-absolute":             {"spec/README.md", "[d](/spec/draft.md)\n", ruleLinkOutside, "spec/README.md:1"},
		"nested escape":             {"spec/fixtures/README.md", "x\n\n[g](../../go/README.md)\n", ruleLinkOutside, "spec/fixtures/README.md:3"},
		"reference definition":      {"spec/README.md", "[x][h]\n\n[h]: ../docs/notes.md\n", ruleLinkOutside, "spec/README.md:3"},
		"angle destination":         {"spec/README.md", "[h](<../docs/notes.md>)\n", ruleLinkOutside, "spec/README.md:1"},
		"html href":                 {"spec/README.md", "<a href=\"../docs/notes.md\">h</a>\n", ruleLinkOutside, "spec/README.md:1"},
		"image":                     {"spec/README.md", "![i](../docs/x.png)\n", ruleLinkOutside, "spec/README.md:1"},
		"percent-encoded escape":    {"spec/README.md", "[h](%2E%2E/docs/notes.md)\n", ruleLinkOutside, "spec/README.md:1"},
		"missing target":            {"spec/README.md", "[x](nope.md)\n", ruleLinkMissing, "spec/README.md:1"},
		"missing with fragment":     {"spec/README.md", "[x](nope.md#a)\n", ruleLinkMissing, "spec/README.md:1"},
		"missing nested":            {"spec/fixtures/README.md", "[x](keys/holder.jwk.json)\n", ruleLinkMissing, "spec/fixtures/README.md:1"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, spec := specTree(t, map[string]string{c.file: c.text})
			wantLinkProblem(t, linkRules(t, spec), c.rule, c.where)
		})
	}
}

// TestCheckLinksIgnores: code, comments, URLs and fragments are not local
// links.
func TestCheckLinksIgnores(t *testing.T) {
	text := "# x\n\n" +
		"```\n[h](../docs/notes.md)\n```\n\n" +
		"~~~md\n[h](../docs/notes.md)\n~~~\n\n" +
		"Code `[h](../docs/notes.md)` span.\n\n" +
		"<!-- [h](../docs/notes.md) -->\n\n" +
		"[web](https://example.com/x) [mail](mailto:a@example.com) [top](#x) [q](?a=b) [proto](//host/x)\n\n" +
		"\\[not](../docs/notes.md)\n"
	_, spec := specTree(t, map[string]string{"spec/README.md": text})
	if ps := linkRules(t, spec); len(ps) > 0 {
		t.Errorf("problems:\n%s", ps)
	}
}

func TestCheckLinksAllowList(t *testing.T) {
	allow := "# comment\n\nspec/README.md -> docs/notes.md\n"
	t.Run("allowed", func(t *testing.T) {
		_, spec := specTree(t, map[string]string{
			"spec/README.md":    "[h](../docs/notes.md)\n",
			"spec/.links-allow": allow,
		})
		ps, st, err := checkLinks(spec)
		if err != nil || len(ps) > 0 || st.allowed != 1 {
			t.Fatalf("problems %v, stats %+v, error %v", ps, st, err)
		}
	})
	t.Run("allowed only for its source", func(t *testing.T) {
		_, spec := specTree(t, map[string]string{
			"spec/README.md":    "[h](../docs/notes.md)\n",
			"spec/draft.md":     "[h](../docs/notes.md)\n",
			"spec/.links-allow": allow,
		})
		wantLinkProblem(t, linkRules(t, spec), ruleLinkOutside, "spec/draft.md:1")
	})
	t.Run("stale entry", func(t *testing.T) {
		_, spec := specTree(t, map[string]string{"spec/.links-allow": allow})
		wantLinkProblem(t, linkRules(t, spec), ruleAllowList, "spec/.links-allow:3")
	})
	t.Run("malformed entry", func(t *testing.T) {
		_, spec := specTree(t, map[string]string{"spec/.links-allow": "docs/notes.md\n"})
		if _, _, err := checkLinks(spec); err == nil {
			t.Error("a malformed allow-list was accepted")
		}
	})
}

// TestCheckLinksMirror: a link that resolves in place through a symbolic link
// out of spec/ is dead in the copy laid out as the mirror, spec/ at its root.
func TestCheckLinksMirror(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symbolic links need privileges on windows")
	}
	_, spec := specTree(t, map[string]string{"spec/README.md": "[h](notes/notes.md)\n"})
	if err := os.Symlink(filepath.Join("..", "docs"), filepath.Join(spec, "notes")); err != nil {
		t.Fatal(err)
	}
	ps := linkRules(t, spec)
	wantLinkProblem(t, ps, ruleLinkMirror, "spec/README.md:1")
}

// TestCheckLinksRepo: the committed spec/ tree passes.
func TestCheckLinksRepo(t *testing.T) {
	ps, st, err := checkLinks(repoSpecRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) > 0 {
		t.Errorf("problems:\n%s", ps)
	}
	if st.files < 40 || st.links < 100 || st.allowed != 0 {
		t.Errorf("stats %+v", st)
	}
}

func TestExtractLinks(t *testing.T) {
	text := "Intro [a](a.md \"title\") and [b](<b c.md>).\n" +
		"[c](c.md 'single') [d](d.md (paren))\n" +
		"[e](path/(x).md)\n" +
		"  [ref]: ref.md\n" +
		"[ref2]: <ref two.md>\n" +
		"<img src='img.png'> <a href=x.md>x</a>\n" +
		"| table `[no](no.md)` | [yes](yes.md) |\n"
	var got []string
	for _, l := range extractLinks(text) {
		got = append(got, l.dest)
	}
	want := []string{"a.md", "b c.md", "c.md", "d.md", "path/(x).md", "ref.md", "ref two.md", "img.png", "x.md", "yes.md"}
	if !slices.Equal(got, want) {
		t.Errorf("links\n got %q\nwant %q", got, want)
	}
}
