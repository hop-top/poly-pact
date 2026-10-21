package main

import (
	"slices"
	"strings"
	"testing"
)

// TestVectorsVerifyProfileFields: the optional members conformance_profile,
// transport and layer (spec/v1.0/fixtures/README.md, Manifest entry fields) are
// read, not refused as unknown, and do not change what runs: the tree still
// passes with every entry carrying them.
func TestVectorsVerifyProfileFields(t *testing.T) {
	for _, mode := range [][]string{nil, {"--ndjson"}} {
		manifest := fixtureTree(t)
		edit(t, manifest, func(v any) any {
			for _, e := range entries(v) {
				obj(e)["conformance_profile"] = []any{"full", "single-owner"}
				obj(e)["transport"] = []any{"https", "stdio-ipc"}
				obj(e)["layer"] = "transcript"
			}
			return v
		})
		code, out, errOut := runVerify(t, append(slices.Clone(mode), manifest)...)
		if code != 0 {
			t.Fatalf("%v: exit %d, want 0\nstdout:\n%s\nstderr:\n%s", mode, code, out, errOut)
		}
		if mode == nil && !strings.Contains(out, "7 passed, 0 failed, 0 skipped") {
			t.Errorf("summary, want 7 passed, 0 failed, 0 skipped:\n%s", out)
		}
	}
}

// TestVectorsVerifyProfileFieldsUnknown: an entry naming a conformance
// profile, a transport or a layer outside the closed sets of the manifest
// format is a harness error: exit 2, nothing on stdout, the entry and the
// token on stderr.
func TestVectorsVerifyProfileFieldsUnknown(t *testing.T) {
	cases := []struct {
		member string
		value  any
		token  string
	}{
		{"conformance_profile", []any{"full", "lite"}, "lite"},
		{"transport", []any{"tcp-loopback"}, "tcp-loopback"},
		{"layer", "kernel", "kernel"},
	}
	for _, c := range cases {
		for _, mode := range [][]string{nil, {"--ndjson"}} {
			manifest := fixtureTree(t)
			var id string
			edit(t, manifest, func(v any) any {
				e := obj(entries(v)[0])
				id = e["id"].(string)
				e[c.member] = c.value
				if c.member == "layer" {
					e["transport"] = []any{"stdio-ipc"}
				}
				return v
			})
			code, out, errOut := runVerify(t, append(slices.Clone(mode), manifest)...)
			if code != 2 || out != "" || !strings.Contains(errOut, id) || !strings.Contains(errOut, c.token) {
				t.Errorf("%s %v: exit %d, stdout %q, stderr %q; want 2, empty, naming %s and %s", c.member, mode, code, out, errOut, id, c.token)
			}
		}
	}
}
