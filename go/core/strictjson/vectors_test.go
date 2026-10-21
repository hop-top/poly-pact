package strictjson_test

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"hop.top/pact-go/core"
	"hop.top/pact-go/core/strictjson"
)

// fixturesRoot is spec/v1.0/fixtures relative to this package directory.
var fixturesRoot = filepath.Join("..", "..", "..", "spec", "v1.0", "fixtures")

const vectorPrefix = "vectors/strictjson/"

type manifest struct {
	ManifestVersion int             `json:"manifest_version"`
	Entries         []manifestEntry `json:"entries"`
}

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

type vectorFile struct {
	ID        string `json:"id"`
	InputText string `json:"input_text,omitzero"`
	InputB64  string `json:"input_b64,omitzero"`
	Expect    string `json:"expect"`
	Reason    string `json:"reason"`
}

// wantErr pins the reason each reject vector fails for. A vector missing here
// is still run for accept or reject; the pin only tightens the check.
var wantErr = map[string]error{
	"duplicate-key-top-level":             strictjson.ErrDuplicateKey,
	"duplicate-key-identical-values":      strictjson.ErrDuplicateKey,
	"duplicate-key-nested":                strictjson.ErrDuplicateKey,
	"duplicate-key-in-headers":            strictjson.ErrDuplicateKey,
	"duplicate-key-escaped-form":          strictjson.ErrDuplicateKey,
	"unknown-core-field":                  strictjson.ErrUnknownField,
	"unknown-core-field-case-variant":     strictjson.ErrUnknownField,
	"nesting-depth-17-objects":            strictjson.ErrDepth,
	"nesting-depth-17-arrays":             strictjson.ErrDepth,
	"non-finite-number-1e999":             strictjson.ErrNonFinite,
	"non-finite-number-negative-1e999":    strictjson.ErrNonFinite,
	"non-finite-number-nan":               strictjson.ErrNonFinite,
	"non-finite-number-infinity":          strictjson.ErrNonFinite,
	"non-finite-number-negative-infinity": strictjson.ErrNonFinite,
	"invalid-utf8-byte-ff":                strictjson.ErrInvalidUTF8,
	"invalid-utf8-truncated-sequence":     strictjson.ErrInvalidUTF8,
	"invalid-utf8-overlong-encoding":      strictjson.ErrInvalidUTF8,
	"invalid-utf8-encoded-surrogate":      strictjson.ErrInvalidUTF8,
	"lone-surrogate-high":                 strictjson.ErrLoneSurrogate,
	"lone-surrogate-low":                  strictjson.ErrLoneSurrogate,
	"lone-surrogate-high-then-bmp":        strictjson.ErrLoneSurrogate,
	"integer-overflow-2-pow-53":           strictjson.ErrInteger,
	"integer-overflow-negative":           strictjson.ErrInteger,
	"integer-overflow-huge":               strictjson.ErrInteger,
	"trailing-garbage-text":               strictjson.ErrTrailingData,
	"trailing-garbage-second-value":       strictjson.ErrTrailingData,
	"trailing-garbage-extra-brace":        strictjson.ErrTrailingData,
}

// requiredCases are the cases the vector set must contain, whatever else a
// later change adds.
var requiredCases = []string{
	"duplicate-key-top-level", "duplicate-key-nested", "unknown-core-field",
	"nesting-depth-17-objects", "non-finite-number-1e999", "invalid-utf8-byte-ff",
	"lone-surrogate-high", "integer-overflow-2-pow-53", "trailing-garbage-text",
	"accept-valid-object", "accept-depth-16-objects", "accept-integer-max-safe",
}

func readJSON(t *testing.T, rel string, v any) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(fixturesRoot, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	if err := strictjson.Unmarshal(b, strictjson.Limits{MaxBytes: 1 << 20}, v); err != nil {
		t.Fatalf("strict-parse %s: %v", rel, err)
	}
}

func TestVectorsViaManifest(t *testing.T) {
	var m manifest
	readJSON(t, "manifest.json", &m)
	if m.ManifestVersion != 1 {
		t.Fatalf("manifest_version = %d, want 1", m.ManifestVersion)
	}

	ids := make([]string, len(m.Entries))
	for i, e := range m.Entries {
		ids[i] = e.ID
	}
	if !slices.IsSorted(ids) {
		t.Error("manifest entries are not sorted by id")
	}
	if len(slices.Compact(slices.Clone(ids))) != len(ids) {
		t.Error("manifest ids are not unique")
	}

	seen := map[string]bool{}
	ran := 0
	for _, e := range m.Entries {
		if !strings.HasPrefix(e.ID, vectorPrefix) {
			continue
		}
		ran++
		seen[strings.TrimPrefix(e.ID, vectorPrefix)] = true
		t.Run(strings.TrimPrefix(e.ID, vectorPrefix), func(t *testing.T) {
			runEntry(t, e)
		})
	}
	if ran == 0 {
		t.Fatal("manifest lists no strictjson vectors")
	}
	for _, c := range requiredCases {
		if !seen[c] {
			t.Errorf("manifest lacks required case %s", c)
		}
	}

	// Files on disk that the manifest does not list never run: flag them.
	dir := filepath.Join(fixturesRoot, filepath.FromSlash(vectorPrefix))
	files, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	for _, f := range files {
		name := strings.TrimSuffix(f.Name(), ".json")
		if !seen[name] {
			t.Errorf("%s is not listed in manifest.json", path.Join(vectorPrefix, f.Name()))
		}
	}
}

func runEntry(t *testing.T, e manifestEntry) {
	t.Helper()
	if e.Kind != "vector" || e.Scope != "core" {
		t.Errorf("kind/scope = %q/%q, want vector/core", e.Kind, e.Scope)
	}
	if e.Path != e.ID+".json" || string(e.Expected) != e.Path {
		t.Errorf("path %q / expected %q do not match id %q", e.Path, e.Expected, e.ID)
	}
	if e.SpecMapRow == "" || e.DraftSection == "" {
		t.Errorf("spec_map_row/draft_section empty: %+v", e)
	}

	var v vectorFile
	readJSON(t, e.Path, &v) // fails the entry when the file is missing
	if v.ID != e.ID {
		t.Errorf("vector id %q, manifest id %q", v.ID, e.ID)
	}
	if v.Reason == "" {
		t.Error("vector has no reason")
	}

	var input []byte
	switch {
	case v.InputText != "" && v.InputB64 != "":
		t.Fatal("vector sets both input_text and input_b64")
	case v.InputB64 != "":
		var err error
		if input, err = base64.StdEncoding.DecodeString(v.InputB64); err != nil {
			t.Fatalf("input_b64: %v", err)
		}
	case v.InputText != "":
		input = []byte(v.InputText)
	default:
		t.Fatal("vector has no input")
	}

	wantOutcome := map[string]string{"reject": "REJECTED", "accept": "ACCEPTED"}[v.Expect]
	if wantOutcome == "" || wantOutcome != string(e.Outcome) {
		t.Fatalf("expect %q does not match outcome %q", v.Expect, e.Outcome)
	}

	// Every vector is decoded as an OperationContext.
	var op core.OperationContext
	err := strictjson.Unmarshal(input, strictjson.Limits{}, &op)
	switch v.Expect {
	case "accept":
		if err != nil {
			t.Fatalf("want accepted, got %v", err)
		}
	case "reject":
		if err == nil {
			t.Fatal("want rejected, got nil")
		}
		if want, ok := wantErr[strings.TrimPrefix(e.ID, vectorPrefix)]; ok && !errors.Is(err, want) {
			t.Fatalf("rejected for the wrong reason: %v (want %v)", err, want)
		}
	}
}
