package main

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// keyIDs are the key entries of the manifest.
var keyIDs = []string{
	"keys/adversarial", "keys/ed25519", "keys/evaluator", "keys/executor", "keys/holder", "keys/holder-2", "keys/issuer",
	"keys/learning-controller", "keys/reputation-service", "keys/security-authority", "keys/test-private-scalars", "keys/validator",
}

// scalarRecord returns the record of role in the keys of the
// test-private-scalars.json document v.
func scalarRecord(t *testing.T, v any, role string) map[string]any {
	t.Helper()
	for _, k := range obj(v)["keys"].([]any) {
		if obj(k)["role"] == role {
			return obj(k)
		}
	}
	t.Fatalf("no record of role %s", role)
	return nil
}

// TestVectorsVerifyKeys: every P-256 key entry passes, keys/ed25519 is
// skipped as out of scope (Ed25519 is optional, draft section 7.2), and
// keys/test-private-scalars passes, in both renderings.
func TestVectorsVerifyKeys(t *testing.T) {
	manifest := fixtureTree(t, keyIDs...)
	code, out, errOut := runVerify(t, manifest)
	if code != 0 {
		t.Fatalf("exit %d\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
	}
	got := rows(out)
	for _, id := range keyIDs {
		want := "PASS"
		if id == "keys/ed25519" {
			want = "SKIP"
		}
		if r := got[id]; len(r) != 1 || r[0] != want {
			t.Errorf("%s: rows %v, want one %s", id, r, want)
		}
	}
	if !regexp.MustCompile(`(?m)^SKIP +keys/ed25519 +.*Ed25519.*7\.2`).MatchString(out) {
		t.Errorf("the SKIP row of keys/ed25519 does not name Ed25519 and draft section 7.2:\n%s", out)
	}

	code, out, errOut = runVerify(t, "--ndjson", manifest)
	if code != 0 {
		t.Fatalf("--ndjson: exit %d\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
	}
	res := results(parseNDJSON(t, out))
	for _, id := range keyIDs {
		want := "key pass"
		if id == "keys/ed25519" {
			want = "key skipped:out-of-scope"
		}
		if r := res[id]; !slices.Equal(r, []string{want}) {
			t.Errorf("%s: %v, want [%s]", id, r, want)
		}
	}
}

// TestVectorsVerifyKeysFail: each change breaks the key rule. The named
// entries fail, with a detail naming the problem; every other key entry
// keeps its result; the run exits 1 in both renderings.
func TestVectorsVerifyKeysFail(t *testing.T) {
	scalars := func(root string) string { return filepath.Join(root, "keys", "test-private-scalars.json") }
	tests := []struct {
		name   string
		change func(t *testing.T, root string)
		fail   []string // entries that fail
		detail string   // text the FAIL row of fail[0] carries
	}{
		{"public point is not scalar times G", func(t *testing.T, root string) {
			edit(t, filepath.Join(root, "keys", "holder.jwk.json"), func(v any) any {
				// The public point of scalar 2, the issuer key.
				obj(v)["x"] = "fPJ7GI0DT36KUjgDBLUaw8CJaeJ38hs1pgtI_EdmmXg"
				obj(v)["y"] = "B3dVENuO0EApPZrGn3Qw27p9reY86YIpngS3nSJ4c9E"
				return v
			})
		}, []string{"keys/holder", "keys/test-private-scalars"}, "public point"},
		{"d is not the scalar", func(t *testing.T, root string) {
			edit(t, scalars(root), func(v any) any {
				scalarRecord(t, v, "validator")["scalar"] = "7"
				return v
			})
		}, []string{"keys/validator", "keys/test-private-scalars"}, "scalar 7"},
		{"holder thumbprint is not holder_jkt", func(t *testing.T, root string) {
			edit(t, scalars(root), func(v any) any {
				h, i := scalarRecord(t, v, "holder"), scalarRecord(t, v, "issuer")
				h["role"], i["role"] = "issuer", "holder"
				return v
			})
		}, []string{"keys/issuer", "keys/test-private-scalars"}, "holder_jkt"},
		{"no holder record", func(t *testing.T, root string) {
			edit(t, scalars(root), func(v any) any {
				scalarRecord(t, v, "holder")["role"] = "holder-1"
				return v
			})
		}, []string{"keys/test-private-scalars"}, "holder"},
		{"no scalar for a key", func(t *testing.T, root string) {
			edit(t, scalars(root), func(v any) any {
				m := obj(v)
				m["keys"] = slices.DeleteFunc(m["keys"].([]any), func(k any) bool { return obj(k)["role"] == "adversarial" })
				return v
			})
		}, []string{"keys/adversarial"}, "adversarial.jwk.json"},
		{"private member in a public key", func(t *testing.T, root string) {
			edit(t, filepath.Join(root, "keys", "issuer.jwk.json"), func(v any) any {
				obj(v)["d"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAI"
				return v
			})
		}, []string{"keys/issuer", "keys/test-private-scalars"}, "private"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			manifest := fixtureTree(t, keyIDs...)
			tc.change(t, filepath.Dir(manifest))

			code, out, errOut := runVerify(t, manifest)
			if code != 1 {
				t.Fatalf("exit %d, want 1\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
			}
			if !regexp.MustCompile(`(?m)^FAIL +` + regexp.QuoteMeta(tc.fail[0]) + ` +.*` + regexp.QuoteMeta(tc.detail)).MatchString(out) {
				t.Errorf("no FAIL row for %s mentioning %q:\n%s", tc.fail[0], tc.detail, out)
			}

			code, out, errOut = runVerify(t, "--ndjson", manifest)
			if code != 1 {
				t.Fatalf("--ndjson: exit %d, want 1\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
			}
			res := results(parseNDJSON(t, out))
			for _, id := range keyIDs {
				want := "key pass"
				switch {
				case slices.Contains(tc.fail, id):
					want = "key fail"
				case id == "keys/ed25519":
					want = "key skipped:out-of-scope"
				}
				if r := res[id]; !slices.Equal(r, []string{want}) {
					t.Errorf("%s: %v, want [%s]", id, r, want)
				}
			}
		})
	}
}

// TestAppendixCHolderJKT: the holder thumbprint the key rule requires is the
// holder_jkt that draft Appendix C prints.
func TestAppendixCHolderJKT(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "spec", "v1.0", "draft.md"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	start := strings.Index(text, "\n## Appendix C.")
	if start < 0 {
		t.Fatal("no Appendix C in the draft")
	}
	section := text[start+1:]
	if end := strings.Index(section, "\n## "); end >= 0 {
		section = section[:end]
	}
	m := regexp.MustCompile(`"holder_jkt": "([A-Za-z0-9_-]{43})"`).FindAllStringSubmatch(section, -1)
	if len(m) != 1 {
		t.Fatalf("Appendix C prints %d holder_jkt values, want 1", len(m))
	}
	if m[0][1] != string(appendixCHolderJKT) {
		t.Errorf("appendixCHolderJKT %s, Appendix C prints %s", appendixCHolderJKT, m[0][1])
	}
}
