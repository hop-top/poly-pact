package main

import (
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The capability-marked vector of these tests, testdata/capability/
// ed25519-valid.json: an Ed25519 evidence JWS that verifies only where
// Ed25519 is negotiated. Its manifest entry lists capabilities
// [jws-ed25519] (spec/v1.0/fixtures/README.md, Optional capabilities).
const ed25519VectorID = "vectors/jws/ed25519-valid"

// capabilityTree is fixtureTree plus the Ed25519 vector, registered with
// capabilities [jws-ed25519]. edit, when not nil, rewrites the vector file.
func capabilityTree(t *testing.T, edit1 func(map[string]any)) string {
	t.Helper()
	manifest := fixtureTree(t)
	root := filepath.Dir(manifest)
	dst := filepath.Join(root, "vectors", "jws", "ed25519-valid.json")
	copyFile(t, filepath.Join("testdata", "capability", "ed25519-valid.json"), dst)
	if edit1 != nil {
		edit(t, dst, func(v any) any { edit1(obj(v)); return v })
	}
	edit(t, manifest, func(v any) any {
		obj(v)["entries"] = append(entries(v), map[string]any{
			"id": ed25519VectorID, "kind": "vector", "scope": "core",
			"path": "vectors/jws/ed25519-valid.json", "expected": "vectors/jws/ed25519-valid.json",
			"outcome": "ACCEPTED", "spec_map_row": "CL-7.2", "draft_section": "7.2",
			"capabilities": []any{"jws-ed25519"},
		})
		return v
	})
	return manifest
}

// skipRow is the table row of the Ed25519 vector when jws-ed25519 is not
// declared: SKIP, naming the missing capability.
var skipRow = regexp.MustCompile(`(?m)^SKIP +` + regexp.QuoteMeta(ed25519VectorID) + ` +.*optional capability jws-ed25519 not declared`)

// TestVectorsVerifyCapabilitySkipped: without --capability jws-ed25519 the
// vector is not run: a SKIP row naming jws-ed25519, never a PASS, in the
// table, and skipped:capability with missing_capabilities [jws-ed25519] in
// NDJSON; the run exits 0.
func TestVectorsVerifyCapabilitySkipped(t *testing.T) {
	manifest := capabilityTree(t, nil)
	code, out, errOut := runVerify(t, manifest)
	if code != 0 {
		t.Fatalf("exit %d, want 0\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
	}
	if r := rows(out)[ed25519VectorID]; !slices.Equal(r, []string{"SKIP"}) || !skipRow.MatchString(out) {
		t.Errorf("rows %v, want one SKIP naming jws-ed25519:\n%s", r, out)
	}
	if !strings.Contains(out, "7 passed, 0 failed, 1 skipped") {
		t.Errorf("summary, want 7 passed, 0 failed, 1 skipped:\n%s", out)
	}

	code, out, errOut = runVerify(t, "--ndjson", manifest)
	if code != 0 {
		t.Fatalf("ndjson: exit %d, want 0\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
	}
	lines := parseNDJSON(t, out)
	if len(lines) != 8 {
		t.Errorf("%d lines, want 8:\n%s", len(lines), out)
	}
	for _, l := range lines {
		if l.ID == ed25519VectorID {
			if l.Result != "skipped:capability" || !slices.Equal(l.MissingCapabilities, []string{"jws-ed25519"}) {
				t.Errorf("%s: %s %v, want skipped:capability [jws-ed25519]", l.ID, l.Result, l.MissingCapabilities)
			}
		} else if l.Result != "pass" {
			t.Errorf("%s: %s, want pass", l.ID, l.Result)
		}
	}
	if !regexp.MustCompile(`(?m)^SKIP ` + regexp.QuoteMeta(ed25519VectorID) + `: .*jws-ed25519`).MatchString(errOut) {
		t.Errorf("stderr does not name the skipped entry and jws-ed25519:\n%s", errOut)
	}
}

// TestVectorsVerifyCapabilityDeclared: with --capability jws-ed25519 the
// vector runs, with Ed25519 negotiated, and passes; repeating the flag is
// the same.
func TestVectorsVerifyCapabilityDeclared(t *testing.T) {
	manifest := capabilityTree(t, nil)
	for _, flags := range [][]string{
		{"--capability", "jws-ed25519"},
		{"--capability", "jws-ed25519", "--capability=jws-ed25519"},
	} {
		code, out, errOut := runVerify(t, append(slices.Clone(flags), manifest)...)
		if code != 0 {
			t.Fatalf("%v: exit %d, want 0\nstdout:\n%s\nstderr:\n%s", flags, code, out, errOut)
		}
		if r := rows(out)[ed25519VectorID]; !slices.Equal(r, []string{"PASS"}) {
			t.Errorf("%v: rows %v, want one PASS:\n%s", flags, r, out)
		}
		if !strings.Contains(out, "8 passed, 0 failed, 0 skipped") {
			t.Errorf("%v: summary, want 8 passed, 0 failed, 0 skipped:\n%s", flags, out)
		}
	}
	code, out, errOut := runVerify(t, "--ndjson", "--capability", "jws-ed25519", manifest)
	if code != 0 {
		t.Fatalf("ndjson: exit %d, want 0\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
	}
	lines := parseNDJSON(t, out)
	if len(lines) != 8 {
		t.Errorf("%d lines, want 8:\n%s", len(lines), out)
	}
	for _, l := range lines {
		if l.Result != "pass" {
			t.Errorf("%s: %s, want pass", l.ID, l.Result)
		}
	}
}

// TestVectorsVerifyCapabilityNotRun: a capability-marked vector that would
// fail is not run when its capability is not declared, so the run still
// exits 0 with a SKIP; declared, it runs and fails.
func TestVectorsVerifyCapabilityNotRun(t *testing.T) {
	manifest := capabilityTree(t, func(v map[string]any) { v["expected_payload"] = "{}" })
	for _, mode := range [][]string{nil, {"--ndjson"}} {
		code, out, errOut := runVerify(t, append(slices.Clone(mode), manifest)...)
		if code != 0 {
			t.Errorf("%v undeclared: exit %d, want 0\nstdout:\n%s\nstderr:\n%s", mode, code, out, errOut)
		}
		code, out, errOut = runVerify(t, append(slices.Clone(mode), "--capability", "jws-ed25519", manifest)...)
		if code != 1 {
			t.Errorf("%v declared: exit %d, want 1\nstdout:\n%s\nstderr:\n%s", mode, code, out, errOut)
		}
		if !strings.Contains(out+errOut, "FAIL") || !strings.Contains(out+errOut, ed25519VectorID) {
			t.Errorf("%v declared: no FAIL for %s:\n%s\n%s", mode, ed25519VectorID, out, errOut)
		}
	}
}

// TestVectorsVerifyCapabilityUnknown: --capability with a name that is not
// a capability token of the manifest format, or an entry listing one, is a
// usage or harness error: exit 2, nothing on stdout, the name on stderr.
func TestVectorsVerifyCapabilityUnknown(t *testing.T) {
	for _, mode := range [][]string{nil, {"--ndjson"}} {
		manifest := capabilityTree(t, nil)
		code, out, errOut := runVerify(t, append(slices.Clone(mode), "--capability", "jws-ed448", manifest)...)
		if code != 2 || out != "" || !strings.Contains(errOut, "jws-ed448") || !strings.Contains(errOut, "jws-ed25519") {
			t.Errorf("%v flag: exit %d, stdout %q, stderr %q; want 2, empty, naming jws-ed448 and the known jws-ed25519", mode, code, out, errOut)
		}
		edit(t, manifest, func(v any) any {
			es := entries(v)
			obj(es[len(es)-1])["capabilities"] = []any{"jws-ed448"}
			return v
		})
		code, out, errOut = runVerify(t, append(slices.Clone(mode), manifest)...)
		if code != 2 || out != "" || !strings.Contains(errOut, ed25519VectorID) || !strings.Contains(errOut, "jws-ed448") {
			t.Errorf("%v entry: exit %d, stdout %q, stderr %q; want 2, empty, naming the entry and jws-ed448", mode, code, out, errOut)
		}
	}
}
