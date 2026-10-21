package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// manifestSchemaCase is one case of spec/v1.0/fixtures/testdata/manifest/index.json.
// Rules are the field rules of the manifest checkers, tested in package
// hop.top/pact-go/runner/manifest.
type manifestSchemaCase struct {
	File         string       `json:"file"`
	Valid        bool         `json:"valid"`
	Reason       string       `json:"reason"`
	SchemaErrors []indexError `json:"schema_errors"`
	Rules        []string     `json:"rules"`
}

// TestManifestSchemaTestdata validates the test manifests of
// spec/v1.0/fixtures/testdata/manifest against spec/v1.0/fixtures/manifest.schema.json:
// each fails with exactly the instance locations and keywords its index case
// lists, and a case the schema cannot express passes it.
func TestManifestSchemaTestdata(t *testing.T) {
	dir := filepath.Join(specDir, "fixtures", "testdata", "manifest")
	var idx struct {
		Description string               `json:"description"`
		Schema      string               `json:"schema"`
		Cases       []manifestSchemaCase `json:"cases"`
	}
	readStrict(t, filepath.Join(dir, "index.json"), &idx)
	if got, want := filepath.Join(dir, filepath.FromSlash(idx.Schema)), filepath.Join(specDir, "fixtures", "manifest.schema.json"); got != want {
		t.Fatalf("index schema %s, want %s", got, want)
	}
	sch, err := compileSchema(filepath.Join(dir, filepath.FromSlash(idx.Schema)), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(idx.Cases) != 13 {
		t.Errorf("%d cases, want 4 valid and 9 invalid", len(idx.Cases))
	}
	for _, c := range idx.Cases {
		t.Run(c.File, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(dir, c.File))
			if err != nil {
				t.Fatal(err)
			}
			got, err := schemaFindings(sch, data)
			if err != nil {
				t.Fatal(err)
			}
			want := slices.Clone(c.SchemaErrors)
			if want == nil {
				want = []indexError{}
			}
			sortIndexErrors(want)
			if g := asIndexErrors(got); !slices.Equal(g, want) {
				t.Errorf("schema errors = %+v, want %+v (%s)", g, want, c.Reason)
			}
			if c.Valid && (len(got) > 0 || len(c.Rules) > 0) {
				t.Errorf("valid case: findings %+v, rules %v", got, c.Rules)
			}
			if !c.Valid && len(c.SchemaErrors) == 0 && len(c.Rules) == 0 {
				t.Error("invalid case lists neither a schema error nor a rule")
			}
		})
	}
}

// TestManifestSchemaKindScope: the schema gives an entry of kind transport or
// profile the scope runner and one of kind mcp the scope adapter, never core
// (spec/v1.0/fixtures/README.md, Manifest entry fields). The transport entries
// name the layer that kind requires.
func TestManifestSchemaKindScope(t *testing.T) {
	sch, err := compileSchema(filepath.Join(specDir, "fixtures", "manifest.schema.json"), "")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		kind, scope string
		ok          bool
	}{
		{"transport", "runner", true}, {"transport", "core", false}, {"transport", "adapter", false},
		{"profile", "runner", true}, {"profile", "core", false}, {"profile", "adapter", false},
		{"mcp", "adapter", true}, {"mcp", "core", false}, {"mcp", "runner", false},
		{"evaluate", "core", true},
	} {
		local := ""
		if c.kind == "transport" {
			local = `, "transport": ["stdio-ipc"], "layer": "transcript"`
		}
		data := []byte(`{"manifest_version": 1, "entries": [{"id": "zz/case", "kind": "` + c.kind + `", "scope": "` + c.scope +
			`", "path": "zz/case", "expected": "zz/case/expected.json", "outcome": "MATCH", "spec_map_row": "CL-13.3", "draft_section": "13.3"` + local + `}]}`)
		got, err := schemaFindings(sch, data)
		if err != nil {
			t.Fatal(err)
		}
		want := []indexError{}
		if !c.ok {
			want = []indexError{{InstancePointer: "/entries/0/scope", Keyword: "const"}}
		}
		if g := asIndexErrors(got); !slices.Equal(g, want) {
			t.Errorf("kind %s scope %s: errors %+v, want %+v", c.kind, c.scope, g, want)
		}
	}
}

// TestManifestSchemaSourceCase: the schema gives a source-case entry the
// scope adapter, the id and path of its case file sources/<source>/<case>.json,
// and neither an expected file nor an outcome (spec/v1.0/fixtures/README.md,
// Manifest).
func TestManifestSchemaSourceCase(t *testing.T) {
	sch, err := compileSchema(filepath.Join(specDir, "fixtures", "manifest.schema.json"), "")
	if err != nil {
		t.Fatal(err)
	}
	const good = `{"id": "sources/scim/scim-01.join", "kind": "source-case", "scope": "adapter", "path": "sources/scim/scim-01.join.json", "expected": null, "outcome": null, "spec_map_row": "CL-17.2", "draft_section": "17.2"}`
	for _, c := range []struct {
		name, old, new string
		want           []indexError
	}{
		{"valid", "", "", []indexError{}},
		{"scope core", `"scope": "adapter"`, `"scope": "core"`, []indexError{{InstancePointer: "/entries/0/scope", Keyword: "const"}}},
		{"scope runner", `"scope": "adapter"`, `"scope": "runner"`, []indexError{{InstancePointer: "/entries/0/scope", Keyword: "const"}}},
		{"expected set", `"expected": null`, `"expected": "sources/scim/scim-01.join.json"`, []indexError{{InstancePointer: "/entries/0/expected", Keyword: "type"}}},
		{"outcome set", `"outcome": null`, `"outcome": "ACCEPTED"`, []indexError{{InstancePointer: "/entries/0/outcome", Keyword: "type"}}},
		{"outside sources", `"path": "sources/scim/scim-01.join.json"`, `"path": "adapters/scim/scim-01.join.json"`, []indexError{{InstancePointer: "/entries/0/path", Keyword: "pattern"}}},
		{"dot in a plain id", `"kind": "source-case"`, `"kind": "vector"`, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := good
			if c.old != "" {
				e = strings.Replace(good, c.old, c.new, 1)
			}
			got, err := schemaFindings(sch, []byte(`{"manifest_version": 1, "entries": [`+e+`]}`))
			if err != nil {
				t.Fatal(err)
			}
			if c.want == nil {
				if len(got) == 0 {
					t.Error("the schema accepts a dotted id on an entry that is not a case file")
				}
				return
			}
			if g := asIndexErrors(got); !slices.Equal(g, c.want) {
				t.Errorf("errors %+v, want %+v", g, c.want)
			}
		})
	}
}
