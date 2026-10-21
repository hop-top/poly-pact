package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func runPactfix(args ...string) (code int, stdout, stderr string) {
	var out, errOut bytes.Buffer
	code = run(args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestUsage(t *testing.T) {
	for _, args := range [][]string{nil, {"nope"}, {"check"}, {"check", "nope"}, {"generate", "-nope"}} {
		if code, _, stderr := runPactfix(args...); code != 2 || !strings.Contains(stderr, "USAGE: ") || !strings.Contains(stderr, "--help' for usage") {
			t.Errorf("%v: exit %d, stderr %q", args, code, stderr)
		}
	}
	for _, args := range [][]string{{"-h"}, {"help"}} {
		code, stdout, _ := runPactfix(args...)
		if code != 0 || !strings.Contains(stdout, "check manifest") || !strings.Contains(stdout, "generate") {
			t.Errorf("%v: exit %d, stdout %q", args, code, stdout)
		}
	}
}

func TestCheckManifestCommand(t *testing.T) {
	_, spec := specTree(t, map[string]string{
		"spec/fixtures/manifest.json": `{"manifest_version":1,"entries":[]}`,
		"spec/spec-map.md": "# Map\n\n## Fixture groups\n\n| Group | Status |\n|---|---|\n| admission | planned |\n\n" +
			"## Conformance map\n\n| ID | Fixture(s) |\n|---|---|\n| R01 | admission/valid |\n",
	})
	code, stdout, stderr := runPactfix("check", "manifest", "-spec", spec)
	if code != 0 || !strings.Contains(stdout, "ok") {
		t.Fatalf("exit %d\nstdout %s\nstderr %s", code, stdout, stderr)
	}
	writeFile(t, filepath.Join(spec, "fixtures", "keys", "holder.jwk.json"), []byte("{}"))
	code, _, stderr = runPactfix("check", "manifest", "-spec", spec)
	if code != 1 || !strings.Contains(stderr, "[file-uncovered] keys/holder.jwk.json") {
		t.Fatalf("exit %d, stderr %s", code, stderr)
	}
}

func TestCheckLinksCommand(t *testing.T) {
	_, spec := specTree(t, nil)
	if code, stdout, stderr := runPactfix("check", "links", "-spec", spec); code != 0 || !strings.Contains(stdout, "ok") {
		t.Fatalf("exit %d\nstdout %s\nstderr %s", code, stdout, stderr)
	}
	writeFile(t, filepath.Join(spec, "README.md"), []byte("[h](../docs/notes.md)\n"))
	if code, _, stderr := runPactfix("check", "links", "-spec", spec); code != 1 || !strings.Contains(stderr, "[link-outside] spec/README.md:1") {
		t.Fatalf("exit %d, stderr %s", code, stderr)
	}
	writeFile(t, filepath.Join(spec, ".links-allow"), []byte("nonsense\n"))
	if code, _, _ := runPactfix("check", "links", "-spec", spec); code != 2 {
		t.Fatalf("malformed allow-list: exit %d, want 2", code)
	}
}

func TestGenerateCommand(t *testing.T) {
	spec := t.TempDir()
	copyDir(t, unsignedTree(t), filepath.Join(spec, "fixtures"))
	if code, _, _ := runPactfix("generate", "-check", "-spec", spec, validCase); code != 1 {
		t.Errorf("check on an unsigned tree: exit %d, want 1", code)
	}
	if code, stdout, stderr := runPactfix("generate", "-spec", spec, validCase); code != 0 || !strings.Contains(stdout, "4 written") {
		t.Fatalf("generate: exit %d\nstdout %s\nstderr %s", code, stdout, stderr)
	}
	if code, stdout, stderr := runPactfix("generate", "-check", "-spec", spec, validCase); code != 0 || !strings.Contains(stdout, "0 stale") {
		t.Fatalf("check: exit %d\nstdout %s\nstderr %s", code, stdout, stderr)
	}
	if code, _, _ := runPactfix("generate", "-spec", spec, "admission/nope"); code != 2 {
		t.Errorf("unknown case: exit %d, want 2", code)
	}
}

// TestRepoChecks runs the commands over the committed tree.
func TestRepoChecks(t *testing.T) {
	if code, _, stderr := runPactfix("check", "links", "-spec", repoSpecRoot); code != 0 {
		t.Errorf("check links: exit %d\n%s", code, stderr)
	}
	if code, _, stderr := runPactfix("generate", "-check", "-spec", repoSpec); code != 0 {
		t.Errorf("generate -check: exit %d\n%s", code, stderr)
	}
	if code, _, stderr := runPactfix("check", "manifest", "-spec", repoSpec); code != 0 {
		t.Errorf("check manifest: exit %d\n%s", code, stderr)
	}
}

// TestKitValidate: the command tree passes the kit validation that Execute
// runs before every command (annotations, help text, shape).
func TestKitValidate(t *testing.T) {
	if err := newCLI().Root.Validate(); err != nil {
		t.Fatal(err)
	}
}

// TestSpecDirDefaults: without --spec, generate and check manifest read the
// spec version directory spec/v1.0 and check links reads the spec tree spec/,
// from the repository root or from cli/.
func TestSpecDirDefaults(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "spec", "v1.0"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "cli"), 0o755); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		cwd, dir, root string
	}{
		{root, filepath.Join("spec", "v1.0"), "spec"},
		{filepath.Join(root, "cli"), filepath.Join("..", "spec", "v1.0"), filepath.Join("..", "spec")},
	}
	for _, c := range cases {
		t.Chdir(c.cwd)
		if got := specDir(""); got != c.dir {
			t.Errorf("in %s: specDir = %q, want %q", c.cwd, got, c.dir)
		}
		if got := specRoot(""); got != c.root {
			t.Errorf("in %s: specRoot = %q, want %q", c.cwd, got, c.root)
		}
		if got := specDir("x"); got != "x" {
			t.Errorf("specDir(x) = %q", got)
		}
		if got := specRoot("x"); got != "x" {
			t.Errorf("specRoot(x) = %q", got)
		}
	}
}
