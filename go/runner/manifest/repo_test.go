package manifest_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"hop.top/pact-go/core/strictjson"
	"hop.top/pact-go/runner/manifest"
)

// TestRepoManifestValidates: every committed entry follows the field rules.
func TestRepoManifestValidates(t *testing.T) {
	m, err := manifest.Load(repoFixtures)
	if err != nil {
		t.Fatal(err)
	}
	wantClean(t, m.Validate())
}

// TestRepoSpecMapParses: the committed spec map has the tables the checks
// read.
func TestRepoSpecMapParses(t *testing.T) {
	b, err := os.ReadFile(repoSpecMap)
	if err != nil {
		t.Fatal(err)
	}
	sm, ps := manifest.ParseSpecMap(b)
	wantClean(t, ps)
	if sm == nil || len(sm.Rows) == 0 || len(sm.Groups) == 0 {
		t.Fatalf("spec map parsed as %+v", sm)
	}
}

// TestSchemaMatchesValidator: manifest.schema.json, read by non-Go consumers,
// states the same enums and patterns as the Go validator.
func TestSchemaMatchesValidator(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(repoFixtures, manifest.SchemaFileName))
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Schema string `json:"$schema"`
		Defs   map[string]struct {
			Pattern string   `json:"pattern"`
			Enum    []string `json:"enum"`
		} `json:"$defs"`
		Properties struct {
			Version struct {
				Const int `json:"const"`
			} `json:"manifest_version"`
		} `json:"properties"`
	}
	var raw any
	if err := strictjson.Unmarshal(b, strictjson.Limits{}, &raw); err != nil {
		t.Fatalf("schema is not strict JSON: %v", err)
	}
	if err := json.Unmarshal(b, &schema); err != nil {
		t.Fatal(err)
	}
	if schema.Schema != "https://json-schema.org/draft/2020-12/schema" {
		t.Errorf("$schema %q", schema.Schema)
	}
	if schema.Properties.Version.Const != manifest.Version {
		t.Errorf("manifest_version const %d, want %d", schema.Properties.Version.Const, manifest.Version)
	}
	for def, want := range map[string]string{
		"id":              manifest.IDPattern,
		"adapter_case_id": manifest.AdapterCaseIDPattern,
		// The file of an adapter case: its id followed by .json.
		"adapter_case_path": strings.TrimSuffix(manifest.AdapterCaseIDPattern, "$") + `\.json$`,
		"source_case_id":    manifest.SourceCaseIDPattern,
		// The file of a source case: its id followed by .json.
		"source_case_path": strings.TrimSuffix(manifest.SourceCaseIDPattern, "$") + `\.json$`,
		"path":             manifest.PathPattern,
		"spec_map_row":     manifest.SpecMapRowPattern,
		"draft_section":    manifest.DraftSectionPattern,
	} {
		got := schema.Defs[def].Pattern
		if got != want {
			t.Errorf("$defs/%s pattern\n got %s\nwant %s", def, got, want)
		}
		if _, err := regexp.Compile(got); err != nil {
			t.Errorf("$defs/%s pattern does not compile: %v", def, err)
		}
	}
	for def, want := range map[string][]string{
		"kind":                   manifest.Kinds(),
		"scope":                  manifest.Scopes(),
		"outcome":                manifest.Outcomes(),
		"capability":             manifest.Capabilities(),
		"conformance_profile_id": manifest.ConformanceProfiles(),
		"transport_name":         manifest.Transports(),
		"layer":                  manifest.Layers(),
	} {
		if got := schema.Defs[def].Enum; !slices.Equal(got, want) {
			t.Errorf("$defs/%s enum %v, want %v", def, got, want)
		}
	}
}

// TestSchemaAdapterCaseLayout: manifest.schema.json applies the adapter case
// id and path patterns to adapter-case entries, the source case id and path
// patterns to source-case entries and the plain id pattern to every other
// entry, as the Go validator does. The rule that the path is the id followed
// by .json is not expressible in JSON Schema.
func TestSchemaAdapterCaseLayout(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(repoFixtures, manifest.SchemaFileName))
	if err != nil {
		t.Fatal(err)
	}
	type cond struct {
		Properties map[string]struct {
			Ref   string `json:"$ref"`
			Const string `json:"const"`
		} `json:"properties"`
		Required []string `json:"required"`
		If       *cond    `json:"if"`
		Then     *cond    `json:"then"`
		Else     *cond    `json:"else"`
	}
	var schema struct {
		Defs struct {
			Entry struct {
				Properties map[string]struct {
					AnyOf []struct {
						Ref string `json:"$ref"`
					} `json:"anyOf"`
				} `json:"properties"`
				AllOf []cond `json:"allOf"`
			} `json:"entry"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(b, &schema); err != nil {
		t.Fatal(err)
	}
	entry := schema.Defs.Entry
	var ids []string
	for _, s := range entry.Properties["id"].AnyOf {
		ids = append(ids, s.Ref)
	}
	if want := []string{"#/$defs/id", "#/$defs/adapter_case_id", "#/$defs/source_case_id"}; !slices.Equal(ids, want) {
		t.Errorf("entry id is anyOf %v, want %v", ids, want)
	}
	// layout checks that c applies to kind the id and path definitions of
	// its then branch and returns its else branch.
	layout := func(c *cond, kind manifest.Kind, id, path string) *cond {
		if c == nil || c.If == nil || c.Then == nil {
			t.Fatalf("no condition on kind %s", kind)
		}
		if got := c.If.Properties["kind"].Const; got != string(kind) {
			t.Fatalf("condition on kind %q, want %s", got, kind)
		}
		if !slices.Contains(c.If.Required, "kind") {
			t.Errorf("the %s condition does not require kind", kind)
		}
		for member, want := range map[string]string{"id": id, "path": path} {
			if got := c.Then.Properties[member].Ref; got != want {
				t.Errorf("%s %s is %q, want %q", kind, member, got, want)
			}
		}
		return c.Else
	}
	found := false
	for i := range entry.AllOf {
		c := &entry.AllOf[i]
		if c.If == nil || c.If.Properties["kind"].Const != string(manifest.KindAdapterCase) {
			continue
		}
		found = true
		other := layout(c, manifest.KindAdapterCase, "#/$defs/adapter_case_id", "#/$defs/adapter_case_path")
		other = layout(other, manifest.KindSourceCase, "#/$defs/source_case_id", "#/$defs/source_case_path")
		if other == nil || other.Properties["id"].Ref != "#/$defs/id" {
			t.Errorf("the id of other kinds is not #/$defs/id: %+v", other)
		}
	}
	if !found {
		t.Error("no allOf condition on kind adapter-case in $defs/entry")
	}
}
