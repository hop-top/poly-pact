package adaptertest

import (
	"encoding/json"
	"io/fs"
	"maps"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	"hop.top/pact-go/core/strictjson"
)

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

func readManifest(t *testing.T, fsys fs.FS) manifest {
	t.Helper()
	data, err := fs.ReadFile(fsys, "manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	var m manifest
	if err := strictjson.Unmarshal(data, strictjson.Limits{MaxBytes: 4 << 20}, &m); err != nil {
		t.Fatalf("manifest.json: %v", err)
	}
	return m
}

// requiredGroups are the common case groups of the suite, by id.
var requiredGroups = []string{
	"COMMON-01", "COMMON-02", "COMMON-03", "COMMON-04", "COMMON-05",
	"COMMON-06", "COMMON-07", "COMMON-08", "COMMON-09", "COMMON-10",
	"COMMON-11", "COMMON-12",
	"IDENT-01", "IDENT-02", "IDENT-03", "IDENT-04", "IDENT-05",
	"IDENT-06", "IDENT-07", "IDENT-08", "IDENT-09", "IDENT-10",
	"FRESH-01", "FRESH-02", "FRESH-03", "FRESH-04", "FRESH-05", "FRESH-06",
}

// TestCommonCaseFiles checks the shipped common case files: each loads under
// the strict format, its file name is its lowercase id, and every group of the
// task is present with at least one case.
func TestCommonCaseFiles(t *testing.T) {
	fsys, err := DefaultFixtures()
	if err != nil {
		t.Fatal(err)
	}
	cases, err := Load(fsys, "")
	if err != nil {
		t.Fatal(err)
	}
	files, err := fs.ReadDir(fsys, commonDir)
	if err != nil {
		t.Fatal(err)
	}
	var nFiles int
	for _, f := range files {
		if strings.HasSuffix(f.Name(), ".json") {
			nFiles++
		} else {
			t.Errorf("%s/%s is not a case file", commonDir, f.Name())
		}
	}
	if nFiles != len(cases) {
		t.Errorf("%d case files, %d cases", nFiles, len(cases))
	}

	groups := map[string]int{}
	for _, c := range cases {
		group, _, _ := strings.Cut(c.ID, ".")
		groups[group]++
		if _, err := fs.Stat(fsys, path.Join(commonDir, strings.ToLower(c.ID)+".json")); err != nil {
			t.Errorf("case %s is not in a file named after its lowercase id: %v", c.ID, err)
		}
		if len(c.Draft) == 0 {
			t.Errorf("case %s cites no draft section", c.ID)
		}
	}
	for _, g := range requiredGroups {
		if groups[g] == 0 {
			t.Errorf("no case of group %s", g)
		}
	}
}

// TestCaseFilesAreRegistered: manifest.json lists every common case file, as
// an adapter-case entry that cites the group of the case, and lists no other.
func TestCaseFilesAreRegistered(t *testing.T) {
	fsys, err := DefaultFixtures()
	if err != nil {
		t.Fatal(err)
	}
	cases, err := Load(fsys, "")
	if err != nil {
		t.Fatal(err)
	}
	m := readManifest(t, fsys)
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

	byPath := map[string]manifestEntry{}
	for _, e := range m.Entries {
		if e.Kind == "adapter-case" && strings.HasPrefix(e.Path, commonDir+"/") {
			byPath[e.Path] = e
		}
	}
	for _, c := range cases {
		file := path.Join(commonDir, strings.ToLower(c.ID)+".json")
		e, ok := byPath[file]
		if !ok {
			t.Errorf("manifest.json does not list %s", file)
			continue
		}
		delete(byPath, file)
		group, _, _ := strings.Cut(c.ID, ".")
		want := manifestEntry{
			ID: strings.TrimSuffix(file, ".json"), Kind: "adapter-case", Scope: "adapter",
			Path: file, Expected: optional(file), Outcome: optional(manifestOutcome(c)), SpecMapRow: group, DraftSection: e.DraftSection,
		}
		if !reflect.DeepEqual(e, want) {
			t.Errorf("manifest entry of %s\n got %+v\nwant %+v", c.ID, e, want)
		}
		if !slices.Contains(c.Draft, e.DraftSection) {
			t.Errorf("manifest entry of %s cites draft section %q, which the case does not", c.ID, e.DraftSection)
		}
	}
	for p := range byPath {
		t.Errorf("manifest.json lists %s, which is not a case file of %s", p, commonDir)
	}
}

// manifestOutcome is ACCEPTED when the case expects the adapter to let the
// stimulus through and REJECTED when it expects a refusal or a withheld result.
func manifestOutcome(c Case) string {
	switch c.Expect.Outcome {
	case outAuthenticated, outBound, outMapped, outClaim, outSigned, outAllow, outPass:
		return "ACCEPTED"
	}
	return "REJECTED"
}

// TestWorkloadModesOfTheCommonCases: IDENT-09, selection among the agents of
// a shared workload, applies only to an adapter whose profile supports
// workloads shared by several agents, and IDENT-10, the configuration error of
// a workload with more than one enrollment in force, only to one whose profile
// does not (draft 17.1, identity mapping IM-19). Every other common case
// applies to both.
func TestWorkloadModesOfTheCommonCases(t *testing.T) {
	fsys, err := DefaultFixtures()
	if err != nil {
		t.Fatal(err)
	}
	cases, err := Load(fsys, "")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"IDENT-09": workloadsShared, "IDENT-10": workloadsDedicated}
	for _, c := range cases {
		group, _, _ := strings.Cut(c.ID, ".")
		if c.Workloads != want[group] {
			t.Errorf("case %s has workloads %q, want %q", c.ID, c.Workloads, want[group])
		}
	}
}

// TestCaseFilesCiteTheDraft: the draft section numbers of a case exist in
// spec/v1.0/draft.md as headings, so a renumbering of the draft cannot leave a case
// citing nothing.
func TestCaseFilesCiteTheDraft(t *testing.T) {
	fsys, err := DefaultFixtures()
	if err != nil {
		t.Fatal(err)
	}
	cases, err := Load(fsys, "")
	if err != nil {
		t.Fatal(err)
	}
	draft := readDraftHeadings(t)
	for _, c := range cases {
		for _, s := range c.Draft {
			if !draft[s] {
				t.Errorf("case %s cites draft section %q, which is not a heading of spec/v1.0/draft.md", c.ID, s)
			}
		}
	}
}

// readDraftHeadings returns the section numbers of the headings of the draft:
// "17.1" for "### 17.1 Required adapter capabilities", and "19" for "## 19. ...".
func readDraftHeadings(t *testing.T) map[string]bool {
	t.Helper()
	// The draft sits next to the fixture directory, in spec/. This test file
	// runs in the source repository, where spec/ is three levels up.
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "spec", "v1.0", "draft.md"))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	for line := range strings.Lines(string(data)) {
		rest, ok := strings.CutPrefix(line, "#")
		if !ok {
			continue
		}
		rest = strings.TrimLeft(rest, "#")
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			continue
		}
		out[strings.TrimSuffix(fields[0], ".")] = true
	}
	return out
}

// TestCaseFilesAreJSON: the case files are valid JSON documents for any
// reader, not only for the strict decoder, and end with a newline.
func TestCaseFilesAreJSON(t *testing.T) {
	fsys, err := DefaultFixtures()
	if err != nil {
		t.Fatal(err)
	}
	files, err := fs.ReadDir(fsys, commonDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		data, err := fs.ReadFile(fsys, path.Join(commonDir, f.Name()))
		if err != nil {
			t.Fatal(err)
		}
		var v any
		if err := json.Unmarshal(data, &v); err != nil {
			t.Errorf("%s: %v", f.Name(), err)
		}
		if !strings.HasSuffix(string(data), "}\n") {
			t.Errorf("%s does not end with a newline", f.Name())
		}
	}
}

// TestMalformedRequestCasesPinTheCode: the common cases that show a request the
// baseline HTTP mapping forbids (draft 10.2) expect map_operation to fail with
// INVALID_MESSAGE (draft 13.4), so that an adapter cannot reject them with
// another code or with none. The case files name the code string and no Go
// identifier, so an adapter in another language reads the same requirement.
func TestMalformedRequestCasesPinTheCode(t *testing.T) {
	fsys, err := DefaultFixtures()
	if err != nil {
		t.Fatal(err)
	}
	cases, err := Load(fsys, "")
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]Case{}
	for _, c := range cases {
		byID[c.ID] = c
	}
	for _, id := range []string{"COMMON-03.fragment", "COMMON-03.userinfo", "COMMON-03.content-encoding"} {
		t.Run(id, func(t *testing.T) {
			c, ok := byID[id]
			if !ok {
				t.Fatalf("no case %s", id)
			}
			if c.Expect.Function != fnMapOperation || c.Expect.Outcome != outError {
				t.Errorf("expects %s %s, want %s %s", c.Expect.Function, c.Expect.Outcome, fnMapOperation, outError)
			}
			if c.Expect.ReasonCode != "INVALID_MESSAGE" {
				t.Errorf("reason_code is %q, want INVALID_MESSAGE", c.Expect.ReasonCode)
			}
			data, err := fs.ReadFile(fsys, path.Join(commonDir, strings.ToLower(id)+".json"))
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(data), "adapter.") || strings.Contains(string(data), "ErrInvalidMessage") {
				t.Errorf("%s names a Go identifier; case files are language-neutral", id)
			}
		})
	}
}

// groupRow is a row of the common case table of adapters/README.md: the
// group id in the first column, the draft sections in the last.
var groupRow = regexp.MustCompile("^\\| `([A-Z][A-Z0-9]*-[0-9]{2,})` \\|.*\\| ([^|]+) \\|$")

// TestReadmeGroupTableCitesTheCases: the Draft column of each group row of
// the common case table in adapters/README.md lists exactly the draft sections
// the cases of that group cite, and every group has a row. The cases are the
// source; the table summarizes them.
func TestReadmeGroupTableCitesTheCases(t *testing.T) {
	fsys, err := DefaultFixtures()
	if err != nil {
		t.Fatal(err)
	}
	cases, err := Load(fsys, "")
	if err != nil {
		t.Fatal(err)
	}
	cited := map[string]map[string]bool{}
	for _, c := range cases {
		group, _, _ := strings.Cut(c.ID, ".")
		if cited[group] == nil {
			cited[group] = map[string]bool{}
		}
		for _, s := range c.Draft {
			cited[group][s] = true
		}
	}
	readme, err := fs.ReadFile(fsys, "adapters/README.md")
	if err != nil {
		t.Fatal(err)
	}
	rows := map[string]bool{}
	for _, line := range strings.Split(string(readme), "\n") {
		m := groupRow.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		group := m[1]
		rows[group] = true
		listed := map[string]bool{}
		for _, s := range strings.Split(m[2], ",") {
			listed[strings.TrimSpace(s)] = true
		}
		if !maps.Equal(listed, cited[group]) {
			t.Errorf("README row %s lists draft %v, its cases cite %v", group, slices.Sorted(maps.Keys(listed)), slices.Sorted(maps.Keys(cited[group])))
		}
	}
	for group := range cited {
		if !rows[group] {
			t.Errorf("group %s has no row in the common case table of adapters/README.md", group)
		}
	}
}
