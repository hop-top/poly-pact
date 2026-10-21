package digest_test

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"hop.top/pact-go/core"
	"hop.top/pact-go/core/digest"
	"hop.top/pact-go/core/strictjson"
)

// fixturesRoot is spec/v1.0/fixtures relative to this package directory.
var fixturesRoot = filepath.Join("..", "..", "..", "spec", "v1.0", "fixtures")

const (
	vectorPrefix = "vectors/digest/"
	appendixID   = vectorPrefix + "appendix-b"
)

// manifestEntry has exactly the fields every language reads. The strict
// decode fails on any other member.
type manifestEntry struct {
	ID                 string   `json:"id"`
	Kind               string   `json:"kind"`
	Scope              string   `json:"scope"`
	Path               string   `json:"path"`
	Expected           optional `json:"expected"`
	Outcome            optional `json:"outcome"`
	SpecMapRow         string   `json:"spec_map_row"`
	DraftSection       string   `json:"draft_section"`
	Capabilities       []string `json:"capabilities"`
	ConformanceProfile []string `json:"conformance_profile"`
	Transport          []string `json:"transport"`
	Layer              string   `json:"layer"`
}

// optional is an entry member that is null in key and adapter-asset entries
// (spec/v1.0/fixtures/README.md); null reads as "".
type optional string

func (o *optional) UnmarshalJSON(b []byte) error {
	if string(b) == "null" {
		*o = ""
		return nil
	}
	return json.Unmarshal(b, (*string)(o))
}

type manifest struct {
	ManifestVersion int             `json:"manifest_version"`
	Entries         []manifestEntry `json:"entries"`
}

// vector is one entry of a digest vector file. Input depends on InputKind:
// a JSON object for "object", a JSON string holding a compact JWS for
// "artifact", and a JSON string of lowercase hex for "bytes".
type vector struct {
	ID             string          `json:"id"`
	InputKind      string          `json:"input_kind"`
	Input          json.RawMessage `json:"input"`
	ExpectedDigest core.Digest     `json:"expected_digest"`
	SpecDefect     bool            `json:"spec_defect"`
	AppendixValue  *string         `json:"appendix_value"`
}

// vectorFields are the members every vector must have, and the only ones it
// may have: a language-specific member would not be consumable elsewhere.
var vectorFields = []string{"appendix_value", "expected_digest", "id", "input", "input_kind", "spec_defect"}

func readFixture(t testing.TB, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(fixturesRoot, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return b
}

func readJSON(t testing.TB, rel string, v any) {
	t.Helper()
	if err := strictjson.Unmarshal(readFixture(t, rel), strictjson.Limits{MaxBytes: 1 << 20}, v); err != nil {
		t.Fatalf("strict-parse %s: %v", rel, err)
	}
}

func digestEntries(t testing.TB) []manifestEntry {
	t.Helper()
	var m manifest
	readJSON(t, "manifest.json", &m)
	if m.ManifestVersion != 1 {
		t.Fatalf("manifest_version = %d, want 1", m.ManifestVersion)
	}
	var out []manifestEntry
	for _, e := range m.Entries {
		if strings.HasPrefix(e.ID, vectorPrefix) {
			out = append(out, e)
		}
	}
	return out
}

func TestManifestListsEveryDigestFile(t *testing.T) {
	listed := map[string]bool{}
	ids := map[string]bool{}
	for _, e := range digestEntries(t) {
		ids[e.ID] = true
		listed[e.Path] = true
		listed[string(e.Expected)] = true
	}
	if !ids[appendixID] {
		t.Errorf("manifest lacks required entry %s", appendixID)
	}

	root := filepath.Join(fixturesRoot, filepath.FromSlash(vectorPrefix))
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(fixturesRoot, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if path.Base(rel) == "README.md" {
			return nil
		}
		if !listed[rel] {
			t.Errorf("%s is not listed in manifest.json", rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestVectorsRequiredByTheDraft pins what the draft states, so deleting a
// vector or editing its input fails here and not silently: each vector below
// must carry the digest the draft prints as its appendix_value. If the draft
// value ever stops reproducing, the vector is marked spec_defect and the
// computed value stays in expected_digest; runVector then reports a named
// skip, and this test still holds.
func TestVectorsRequiredByTheDraft(t *testing.T) {
	var vs []vector
	readJSON(t, appendixPath(t), &vs)
	byID := map[string]vector{}
	kinds := map[string]bool{}
	for _, v := range vs {
		byID[v.ID] = v
		kinds[v.InputKind] = true
	}
	want := map[string]struct{ kind, digest string }{
		"empty-body":   {"bytes", bodyDigestOfEmpty},
		"operation-b3": {"object", operationDigestB3},
		"intent-b2":    {"object", intentDigestB2},
	}
	for id, w := range want {
		v, ok := byID[id]
		if !ok {
			t.Errorf("vector %q is missing", id)
			continue
		}
		if v.InputKind != w.kind {
			t.Errorf("vector %q: input_kind %q, want %q", id, v.InputKind, w.kind)
		}
		if v.AppendixValue == nil || *v.AppendixValue != w.digest {
			t.Errorf("vector %q: appendix_value is not the digest the draft prints, %q", id, w.digest)
		}
	}
	for _, k := range []string{"object", "artifact", "bytes"} {
		if !kinds[k] {
			t.Errorf("no vector has input_kind %q", k)
		}
	}
}

func appendixPath(t testing.TB) string {
	t.Helper()
	for _, e := range digestEntries(t) {
		if e.ID == appendixID {
			return e.Path
		}
	}
	t.Fatalf("manifest lacks %s", appendixID)
	return ""
}

func TestVectorsViaManifest(t *testing.T) {
	entries := digestEntries(t)
	if len(entries) == 0 {
		t.Fatal("manifest lists no digest vectors")
	}
	for _, e := range entries {
		t.Run(strings.TrimPrefix(e.ID, vectorPrefix), func(t *testing.T) {
			if e.Kind != "vector" || e.Scope != "core" || e.Outcome != "ACCEPTED" {
				t.Errorf("kind/scope/outcome = %q/%q/%q, want vector/core/ACCEPTED", e.Kind, e.Scope, e.Outcome)
			}
			if e.SpecMapRow == "" || e.DraftSection != "7.4" {
				t.Errorf("spec_map_row/draft_section = %q/%q, want a row and 7.4", e.SpecMapRow, e.DraftSection)
			}
			if path.Ext(e.Path) != ".json" || e.Path != string(e.Expected) {
				t.Errorf("path %q / expected %q: want one JSON file", e.Path, e.Expected)
			}
			runFile(t, e.Path)
		})
	}
}

func runFile(t *testing.T, rel string) {
	t.Helper()
	var vs []vector
	readJSON(t, rel, &vs)
	if len(vs) == 0 {
		t.Fatalf("%s has no vectors", rel)
	}

	// Each vector has the six members and no others.
	var raw []map[string]json.RawMessage
	readJSON(t, rel, &raw)
	if len(raw) != len(vs) {
		t.Fatalf("decoded %d vectors and %d raw members lists", len(vs), len(raw))
	}
	seen := map[string]bool{}
	for i, m := range raw {
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		if !slices.Equal(keys, vectorFields) {
			t.Errorf("vector %d members = %v, want %v", i, keys, vectorFields)
		}
		id := vs[i].ID
		if id == "" || seen[id] {
			t.Errorf("vector %d: id %q is empty or repeated", i, id)
		}
		seen[id] = true
	}

	for _, v := range vs {
		t.Run(v.ID, func(t *testing.T) { runVector(t, v) })
	}
}

// runVector computes the digest of the input the way the draft defines it and
// compares it with expected_digest, then reports the Appendix comparison.
func runVector(t *testing.T, v vector) {
	t.Helper()
	if err := v.ExpectedDigest.Validate(); err != nil {
		t.Fatalf("expected_digest: %v", err)
	}
	got := computeDigest(t, v)
	if got != v.ExpectedDigest {
		t.Errorf("digest = %q, want expected_digest %q", got, v.ExpectedDigest)
	}

	status, err := classifyAppendix(v)
	if err != nil {
		t.Fatal(err)
	}
	if status == appendixNone {
		return
	}
	t.Run("appendix", func(t *testing.T) {
		switch {
		case status == appendixDefect:
			// A spec defect is a skip that names both values, never a pass.
			t.Skipf("spec defect: draft Appendix B states %s, computed %s", *v.AppendixValue, got)
		case *v.AppendixValue != string(got):
			t.Errorf("draft states %s, computed %s", *v.AppendixValue, got)
		}
	})
}

// computeDigest applies the digest function that input_kind names to the
// input of v.
func computeDigest(t *testing.T, v vector) core.Digest {
	t.Helper()
	switch v.InputKind {
	case "object":
		// Both ways a caller can hold the object: decoded, and as the text of
		// the file, which keeps the member order of the draft.
		var decoded any
		if err := strictjson.Unmarshal(v.Input, strictjson.Limits{}, &decoded); err != nil {
			t.Fatalf("input: %v", err)
		}
		viaValue, err := digest.ObjectDigest(decoded)
		if err != nil {
			t.Fatalf("ObjectDigest(decoded): %v", err)
		}
		viaText, err := digest.ObjectDigest(v.Input)
		if err != nil {
			t.Fatalf("ObjectDigest(raw): %v", err)
		}
		if viaValue != viaText {
			t.Errorf("ObjectDigest(decoded) = %q, ObjectDigest(raw) = %q", viaValue, viaText)
		}
		return viaValue
	case "artifact":
		var s string
		if err := strictjson.Unmarshal(v.Input, strictjson.Limits{}, &s); err != nil {
			t.Fatalf("input is not a string: %v", err)
		}
		got, err := digest.ArtifactDigest(s)
		if err != nil {
			t.Fatalf("ArtifactDigest: %v", err)
		}
		return got
	case "bytes":
		var s string
		if err := strictjson.Unmarshal(v.Input, strictjson.Limits{}, &s); err != nil {
			t.Fatalf("input is not a string: %v", err)
		}
		b, err := hex.DecodeString(s)
		if err != nil || s != strings.ToLower(s) {
			t.Fatalf("input %q is not lowercase hex: %v", s, err)
		}
		return digest.BytesDigest(b)
	}
	t.Fatalf("input_kind %q is not object, artifact or bytes", v.InputKind)
	return ""
}

type appendixStatus int

const (
	appendixNone   appendixStatus = iota // the draft states no digest for this input
	appendixMatch                        // the draft value equals expected_digest
	appendixDefect                       // the draft value differs and spec_defect is set
)

// classifyAppendix reads how a vector relates to the draft. A mismatch not
// marked spec_defect, a mark on a matching value and a mark without a draft
// value are errors: each hides a failure or a stale flag.
func classifyAppendix(v vector) (appendixStatus, error) {
	switch {
	case v.AppendixValue == nil && v.SpecDefect:
		return 0, fmt.Errorf("vector %s: spec_defect is set but appendix_value is null", v.ID)
	case v.AppendixValue == nil:
		return appendixNone, nil
	case *v.AppendixValue == string(v.ExpectedDigest) && v.SpecDefect:
		return 0, fmt.Errorf("vector %s: spec_defect is set but appendix_value matches", v.ID)
	case *v.AppendixValue == string(v.ExpectedDigest):
		return appendixMatch, nil
	case v.SpecDefect:
		return appendixDefect, nil
	default:
		return 0, fmt.Errorf("vector %s: appendix_value %s differs from expected_digest %s and spec_defect is not set",
			v.ID, *v.AppendixValue, v.ExpectedDigest)
	}
}

func TestClassifyAppendix(t *testing.T) {
	str := func(s string) *string { return &s }
	const a, b = "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU", "R5nfhv7g_o93VPHK6a2o56-MyyGy75GQwXxDM4M3cn0"
	tests := []struct {
		name    string
		v       vector
		want    appendixStatus
		wantErr bool
	}{
		{"match", vector{ExpectedDigest: a, AppendixValue: str(a)}, appendixMatch, false},
		{"no draft value", vector{ExpectedDigest: a}, appendixNone, false},
		{"flagged defect", vector{ExpectedDigest: a, AppendixValue: str(b), SpecDefect: true}, appendixDefect, false},
		{"unflagged mismatch", vector{ExpectedDigest: a, AppendixValue: str(b)}, 0, true},
		{"stale flag", vector{ExpectedDigest: a, AppendixValue: str(a), SpecDefect: true}, 0, true},
		{"flag without draft value", vector{ExpectedDigest: a, SpecDefect: true}, 0, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := classifyAppendix(tc.v)
			if (err != nil) != tc.wantErr || (err == nil && got != tc.want) {
				t.Errorf("classifyAppendix = %v, %v; want %v, error %v", got, err, tc.want, tc.wantErr)
			}
		})
	}
}
