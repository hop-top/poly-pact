package main

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"hop.top/pact-go/core/jws"
	"hop.top/pact-go/core/strictjson"
	"hop.top/pact-go/runner/evalcase"
)

// repoSpecRoot is spec/, the spec tree, relative to this package directory.
var repoSpecRoot = filepath.Join("..", "..", "spec")

// repoSpec is spec/v1.0/, the spec version directory.
var repoSpec = filepath.Join(repoSpecRoot, specVersion)

var repoFixtures = filepath.Join(repoSpec, "fixtures")

const validCase = "admission/valid"

// signedFiles are the files generate writes for admission/valid.
var signedFiles = []string{
	"signed/contract.jws", "signed/evidence/runtime.jws", "signed/reputation.jws", "signed/presentation.jws",
}

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

// copyDir copies the regular files under src to dst.
func copyDir(t testing.TB, src, dst string) {
	t.Helper()
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		writeFile(t, filepath.Join(dst, rel), readFile(t, p))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// unsignedTree is a copy of the committed fixture directory without its
// signed files: the manifest, the test keys and every decoded and
// signing.json file.
func unsignedTree(t testing.TB) string {
	t.Helper()
	root := t.TempDir()
	err := filepath.WalkDir(repoFixtures, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || strings.HasSuffix(p, ".jws") {
			return err
		}
		rel, err := filepath.Rel(repoFixtures, p)
		if err != nil {
			return err
		}
		writeFile(t, filepath.Join(root, rel), readFile(t, p))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return root
}

// repoRuns returns the committed cases generate signs whose manifest ids
// start with prefix.
func repoRuns(t testing.TB, prefix string) []evalcase.Dir {
	t.Helper()
	runs, err := evalcase.Dirs(repoFixtures)
	if err != nil {
		t.Fatal(err)
	}
	var out []evalcase.Dir
	for _, r := range runs {
		if strings.HasPrefix(r.Entry, prefix) {
			out = append(out, r)
		}
	}
	if len(out) == 0 {
		t.Fatalf("no committed case under %s", prefix)
	}
	return out
}

// mustGenerate runs generate on every case of the tree root.
func mustGenerate(t testing.TB, root string, check bool) []genResult {
	t.Helper()
	res, err := generate(root, check, nil)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	return res
}

func readCase(t testing.TB, root, rel string) []byte {
	t.Helper()
	return readFile(t, filepath.Join(root, validCase, filepath.FromSlash(rel)))
}

// segments splits a compact JWS.
func segments(t testing.TB, compact string) [3]string {
	t.Helper()
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		t.Fatalf("not a compact JWS: %q", compact)
	}
	return [3]string{parts[0], parts[1], parts[2]}
}

func fixtureJWK(t testing.TB, name string) jws.JWK {
	t.Helper()
	k, err := jws.ParseJWK(readFile(t, filepath.Join(repoFixtures, "keys", name+".jwk.json")))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// verifyAs verifies compact as typ under the public test key file name,
// from the key set of the typ's role, or as the embedded holder key.
func verifyAs(t testing.TB, compact, typ, name string) jws.ParsedJWS {
	t.Helper()
	k := fixtureJWK(t, name)
	role, _ := jws.TypRole(typ)
	var res jws.StaticResolver
	if role == jws.RoleHolder {
		tp, err := jws.Thumbprint(k)
		if err != nil {
			t.Fatal(err)
		}
		res.ExpectedHolderJKT = tp
	} else {
		set, err := jws.NewKeySet(k)
		if err != nil {
			t.Fatal(err)
		}
		res.KeySets = map[jws.Role]*jws.KeySet{role: set}
	}
	p, err := jws.Verifier{Keys: res, Typ: typ}.Verify(compact)
	if err != nil {
		t.Fatalf("verify %s as %s under %s: %v", compact[:24], typ, name, err)
	}
	return p
}

func strictObject(t testing.TB, b []byte) map[string]json.RawMessage {
	t.Helper()
	var m map[string]json.RawMessage
	if err := strictjson.Unmarshal(b, strictjson.Limits{}, &m); err != nil {
		t.Fatalf("strict JSON: %v", err)
	}
	return m
}

// appendixB returns the JSON blocks of draft Appendix B by subsection, such
// as "B.4", as written in the draft.
func appendixB(t testing.TB) map[string][]byte {
	t.Helper()
	draft := string(readFile(t, filepath.Join(repoSpec, "draft.md")))
	start := strings.Index(draft, "\n## Appendix B.")
	end := strings.Index(draft, "\n## Appendix C.")
	if start < 0 || end < start {
		t.Fatal("draft has no Appendix B")
	}
	out := map[string][]byte{}
	heading := regexp.MustCompile(`(?m)^### (B\.[0-9]+) `)
	block := regexp.MustCompile("(?s)```json\n(.*?)\n```")
	text := draft[start:end]
	locs := heading.FindAllStringSubmatchIndex(text, -1)
	for i, loc := range locs {
		stop := len(text)
		if i+1 < len(locs) {
			stop = locs[i+1][0]
		}
		if m := block.FindStringSubmatch(text[loc[1]:stop]); m != nil {
			out[text[loc[2]:loc[3]]] = []byte(m[1])
		}
	}
	return out
}

func removeFile(t testing.TB, path string) {
	t.Helper()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
}

// readFileMaybe returns nil when path does not exist.
func readFileMaybe(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	return b, err
}
