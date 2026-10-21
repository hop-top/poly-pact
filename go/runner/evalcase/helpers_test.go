package evalcase_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"hop.top/pact-go/core/jcs"
)

// repoFixtures is spec/v1.0/fixtures relative to this package directory.
var repoFixtures = filepath.Join("..", "..", "..", "spec", "v1.0", "fixtures")

func readFile(t testing.TB, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func writeFile(t testing.TB, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

// copyTree copies the regular files under the fixture paths rels (files or
// directories, slash-separated) into a fresh directory and returns it.
func copyTree(t testing.TB, rels ...string) string {
	t.Helper()
	root := t.TempDir()
	for _, rel := range rels {
		src := filepath.Join(repoFixtures, filepath.FromSlash(rel))
		err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			r, err := filepath.Rel(repoFixtures, p)
			if err != nil {
				return err
			}
			writeFile(t, filepath.Join(root, r), readFile(t, p))
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// caseTree copies the manifest, the test keys, and the case and expected
// directories of the manifest ids.
func caseTree(t testing.TB, ids ...string) string {
	t.Helper()
	rels := []string{"manifest.json", "keys"}
	for _, id := range ids {
		rels = append(rels, id, "expected/"+id)
	}
	return copyTree(t, rels...)
}

// edit replaces old by repl, once, in the file rel of the tree root.
func edit(t testing.TB, root, rel, old, repl string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	b := readFile(t, p)
	if n := bytes.Count(b, []byte(old)); n != 1 {
		t.Fatalf("%s holds %q %d times, want once", rel, old, n)
	}
	writeFile(t, p, bytes.Replace(b, []byte(old), []byte(repl), 1))
}

// editJSON rewrites the JSON file rel of the tree root through f, in RFC
// 8785 canonical form.
func editJSON(t testing.TB, root, rel string, f func(map[string]any)) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	var v map[string]any
	if err := json.Unmarshal(readFile(t, p), &v); err != nil {
		t.Fatal(err)
	}
	f(v)
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	// The manifest is no signed artifact, and it outgrows the 256 KiB input
	// limit of package jcs; it is written as encoded.
	if rel != "manifest.json" {
		if b, err = jcs.Canonicalize(b); err != nil {
			t.Fatal(err)
		}
	}
	writeFile(t, p, b)
}

// flipSignature changes one octet of the signature of the compact JWS file
// rel of the tree root, keeping it canonical base64url.
func flipSignature(t testing.TB, root, rel string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	seg := strings.Split(string(readFile(t, p)), ".")
	sig, err := base64.RawURLEncoding.DecodeString(seg[2])
	if err != nil {
		t.Fatal(err)
	}
	sig[10] ^= 0x01
	seg[2] = base64.RawURLEncoding.EncodeToString(sig)
	writeFile(t, p, []byte(strings.Join(seg, ".")))
}

func wantErr(t testing.TB, err error, parts ...string) {
	t.Helper()
	if err == nil {
		t.Fatalf("no error, want one mentioning %q", parts)
	}
	for _, s := range parts {
		if !strings.Contains(err.Error(), s) {
			t.Fatalf("error %q, want one mentioning %q", err, s)
		}
	}
}

func removeFile(t testing.TB, path string) {
	t.Helper()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
}
