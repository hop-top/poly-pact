package jcs_test

import (
	"bytes"
	"encoding/json"
	"math"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"hop.top/pact-go/core/jcs"
	"hop.top/pact-go/core/strictjson"
)

// fixturesRoot is spec/v1.0/fixtures relative to this package directory.
var fixturesRoot = filepath.Join("..", "..", "..", "spec", "v1.0", "fixtures")

const (
	vectorPrefix = "vectors/jcs/"
	numbersID    = vectorPrefix + "numbers"
)

// manifestEntry has exactly the fields every language reads. The strict
// decode below fails on any other member, so a language-specific field in a
// jcs entry fails this test.
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

type numberVector struct {
	IEEE754Hex string `json:"ieee754_hex"`
	Expected   string `json:"expected"`
}

// requiredPairs are the RFC 8785 reference pairs the manifest must list.
var requiredPairs = []string{"arrays", "french", "structures", "unicode", "values", "weird"}

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
	if err := strictjson.Unmarshal(readFixture(t, rel), strictjson.Limits{MaxBytes: 4 << 20}, v); err != nil {
		t.Fatalf("strict-parse %s: %v", rel, err)
	}
}

// jcsEntries returns the manifest entries under vectors/jcs/.
func jcsEntries(t testing.TB) []manifestEntry {
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

// noticeFiles are the source and license notes of the vendored data: no
// manifest entry lists them, as for every file named LICENSE*.
var noticeFiles = []string{
	vectorPrefix + "LICENSE-NOTE.md",
	vectorPrefix + "LICENSE.md",
	vectorPrefix + "LICENSE-2.0.md",
}

func TestManifestListsEveryJCSFile(t *testing.T) {
	entries := jcsEntries(t)
	listed := map[string]bool{}
	ids := map[string]bool{}
	for _, e := range entries {
		ids[e.ID] = true
		listed[e.Path] = true
		listed[string(e.Expected)] = true
	}
	for _, n := range append(slices.Clone(requiredPairs), "numbers") {
		if !ids[vectorPrefix+n] {
			t.Errorf("manifest lacks required entry %s%s", vectorPrefix, n)
		}
	}

	// Files on disk that the manifest does not list never run: flag them.
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
		if slices.Contains(noticeFiles, rel) {
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

func TestVectorsViaManifest(t *testing.T) {
	entries := jcsEntries(t)
	if len(entries) == 0 {
		t.Fatal("manifest lists no jcs vectors")
	}
	for _, e := range entries {
		t.Run(strings.TrimPrefix(e.ID, vectorPrefix), func(t *testing.T) {
			if e.Kind != "vector" || e.Scope != "core" || e.Outcome != "ACCEPTED" {
				t.Errorf("kind/scope/outcome = %q/%q/%q, want vector/core/ACCEPTED", e.Kind, e.Scope, e.Outcome)
			}
			if e.SpecMapRow == "" || e.DraftSection == "" {
				t.Errorf("spec_map_row/draft_section empty: %+v", e)
			}
			if path.Ext(e.Path) != ".json" || path.Ext(string(e.Expected)) != ".json" {
				t.Errorf("path %q / expected %q are not JSON files", e.Path, e.Expected)
			}
			if e.ID == numbersID {
				if e.Path != string(e.Expected) {
					t.Errorf("numbers entry: path %q != expected %q", e.Path, e.Expected)
				}
				runNumbers(t, e.Path)
				return
			}
			runPair(t, e)
		})
	}
}

// runPair checks one input and output pair: the canonical form of the input
// bytes equals the output bytes exactly.
func runPair(t *testing.T, e manifestEntry) {
	t.Helper()
	if e.Path == string(e.Expected) {
		t.Fatalf("pair entry has the same path and expected: %s", e.Path)
	}
	want := readFixture(t, string(e.Expected))
	got, err := jcs.Canonicalize(readFixture(t, e.Path))
	if err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("canonical form\n got: %q\nwant: %q", got, want)
	}
	// The expected output is canonical, so canonicalizing it is a no-op.
	again, err := jcs.Canonicalize(want)
	if err != nil || !bytes.Equal(again, want) {
		t.Errorf("Canonicalize(expected) = %q, %v; want the same bytes", again, err)
	}
}

// runNumbers drives the whole of Canonicalize with every number of the list:
// the value is written as an exponent-form literal (valid JSON, whatever its
// magnitude), then canonicalized.
func runNumbers(t *testing.T, rel string) {
	t.Helper()
	var vectors []numberVector
	readJSON(t, rel, &vectors)
	if len(vectors) < 1000 {
		t.Fatalf("only %d numbers, want at least 1000", len(vectors))
	}
	failed := 0
	for i, v := range vectors {
		if len(v.IEEE754Hex) != 16 || v.Expected == "" {
			t.Fatalf("entry %d malformed: %+v", i, v)
		}
		bits, err := strconv.ParseUint(v.IEEE754Hex, 16, 64)
		if err != nil {
			t.Fatalf("entry %d: %v", i, err)
		}
		literal := strconv.FormatFloat(math.Float64frombits(bits), 'e', -1, 64)
		got, err := jcs.Canonicalize([]byte(literal))
		if err != nil || string(got) != v.Expected {
			t.Errorf("%s: Canonicalize(%s) = %q, %v; want %q", v.IEEE754Hex, literal, got, err, v.Expected)
			if failed++; failed >= 20 {
				t.Fatal("too many failures; stopping")
			}
		}
	}
}
