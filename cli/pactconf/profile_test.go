package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"hop.top/pact-go/core/strictjson"
)

// specDir is the repository's spec directory relative to this package.
var specDir = filepath.Join("..", "..", "spec", "v1.0")

var exampleProfile = filepath.Join(specDir, "profiles", "example.profile.json")

// indexError is one expected error of an index case: the instance location
// and either the failing JSON Schema keyword or the failing lint rule.
type indexError struct {
	InstancePointer string `json:"instance_pointer"`
	Keyword         string `json:"keyword,omitzero"`
	Lint            string `json:"lint,omitzero"`
}

type indexCase struct {
	File          string       `json:"file"`
	SchemaPointer string       `json:"schema_pointer,omitzero"`
	Valid         bool         `json:"valid"`
	Reason        string       `json:"reason"`
	Errors        []indexError `json:"errors,omitzero"`
}

type caseIndex struct {
	Description   string      `json:"description"`
	Schema        string      `json:"schema"`
	SchemaPointer string      `json:"schema_pointer,omitzero"`
	Cases         []indexCase `json:"cases"`
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

type manifest struct {
	ManifestVersion int             `json:"manifest_version"`
	Entries         []manifestEntry `json:"entries"`
}

func readStrict(t *testing.T, file string, v any) {
	t.Helper()
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if err := strictjson.Unmarshal(data, strictjson.Limits{MaxBytes: 4 << 20}, v); err != nil {
		t.Fatalf("%s: %v", file, err)
	}
}

// asIndexErrors projects findings onto the index form, sorted.
func asIndexErrors(fs []finding) []indexError {
	out := make([]indexError, 0, len(fs))
	for _, f := range fs {
		e := indexError{InstancePointer: f.Pointer}
		switch f.Check {
		case checkSchema:
			e.Keyword = f.Rule
		case checkLint:
			e.Lint = f.Rule
		default:
			e.Keyword = f.Check + ":" + f.Rule
		}
		out = append(out, e)
	}
	sortIndexErrors(out)
	return out
}

func sortIndexErrors(es []indexError) {
	slices.SortFunc(es, func(a, b indexError) int {
		return strings.Compare(a.InstancePointer+"\x00"+a.Keyword+"\x00"+a.Lint,
			b.InstancePointer+"\x00"+b.Keyword+"\x00"+b.Lint)
	})
}

func TestProfileValidateExample(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"profile", "validate", exampleProfile}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr:\n%s", code, stderr.String())
	}
	if got, want := stdout.String(), exampleProfile+": ok\n"; got != want {
		t.Errorf("stdout = %q, want %q", got, want)
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr = %q, want empty", stderr.String())
	}
}

// requiredInvalid are the invalid profile fixtures the task names, with the
// one error each must produce, whatever else the index adds later.
var requiredInvalid = map[string]indexError{
	"invalid-missing-bypass-control.json":  {InstancePointer: "/bypass_paths/0", Keyword: "required"},
	"invalid-empty-unsupported-forms.json": {InstancePointer: "/unsupported_forms", Keyword: "minItems"},
	"invalid-dangling-fixture-path.json":   {InstancePointer: "/fixtures/0/path", Lint: "fixture-path"},
	"invalid-attribute-freshness.json":     {InstancePointer: "/attribute_sources/0/freshness", Lint: "attribute-freshness"},
}

// TestInvalidProfileFixtures runs every case of spec/v1.0/fixtures/profiles: each
// fails with exactly the errors its index entry lists, every invalid file is
// indexed, and every indexed file is registered in the manifest.
func TestInvalidProfileFixtures(t *testing.T) {
	dir := filepath.Join(specDir, "fixtures", "profiles")
	var idx caseIndex
	readStrict(t, filepath.Join(dir, "index.json"), &idx)
	if got, want := filepath.Join(dir, filepath.FromSlash(idx.Schema)), filepath.Join(specDir, "profiles", schemaFile); got != want {
		t.Errorf("index schema resolves to %s, want %s", got, want)
	}

	var m manifest
	readStrict(t, filepath.Join(specDir, "fixtures", "manifest.json"), &m)
	byPath := map[string]manifestEntry{}
	for _, e := range m.Entries {
		byPath[e.Path] = e
	}

	v, err := newValidator(specDir)
	if err != nil {
		t.Fatal(err)
	}
	indexed := map[string]bool{}
	for _, c := range idx.Cases {
		indexed[c.File] = true
		t.Run(c.File, func(t *testing.T) {
			if c.Valid || len(c.Errors) == 0 {
				t.Fatalf("case is not an invalid case with errors")
			}
			got, err := v.validateFile(filepath.Join(dir, c.File))
			if err != nil {
				t.Fatal(err)
			}
			want := slices.Clone(c.Errors)
			sortIndexErrors(want)
			if g := asIndexErrors(got); !slices.Equal(g, want) {
				t.Errorf("errors = %+v, want %+v (findings %+v)", g, want, got)
			}
			if req, ok := requiredInvalid[c.File]; ok && !slices.Equal(want, []indexError{req}) {
				t.Errorf("index lists %+v, the required case needs exactly %+v", want, req)
			}

			rel := "profiles/" + c.File
			e, ok := byPath[rel]
			switch {
			case !ok:
				t.Errorf("%s is not registered in manifest.json", rel)
			case e.ID != strings.TrimSuffix(rel, ".json") || e.Kind != "profile-invalid" ||
				string(e.Expected) != "profiles/index.json" || string(e.Outcome) != "REJECTED":
				t.Errorf("manifest entry %+v: want id %s, kind profile-invalid, expected profiles/index.json, outcome REJECTED",
					e, strings.TrimSuffix(rel, ".json"))
			}
		})
	}
	for name := range requiredInvalid {
		if !indexed[name] {
			t.Errorf("required case %s is not in the index", name)
		}
	}
	files, err := filepath.Glob(filepath.Join(dir, "invalid-*.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if !indexed[filepath.Base(f)] {
			t.Errorf("%s is not in index.json", f)
		}
	}
	for _, e := range m.Entries {
		if e.Kind == "profile-invalid" && !indexed[path.Base(e.Path)] {
			t.Errorf("manifest entry %s has no index case", e.ID)
		}
	}
}

// TestSchemaTestdata checks the schema step against the blocks indexed in
// spec/v1.0/profiles/testdata: each validates against its subschema with exactly
// the listed instance locations and keywords.
func TestSchemaTestdata(t *testing.T) {
	dir := filepath.Join(specDir, "profiles", "testdata")
	var idx caseIndex
	readStrict(t, filepath.Join(dir, "index.json"), &idx)
	if len(idx.Cases) == 0 {
		t.Fatal("index has no cases")
	}
	for _, c := range idx.Cases {
		t.Run(c.File, func(t *testing.T) {
			ptr := c.SchemaPointer
			if ptr == "" {
				ptr = idx.SchemaPointer
			}
			sch, err := compileSchema(filepath.Join(dir, filepath.FromSlash(idx.Schema)), ptr)
			if err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(filepath.Join(dir, c.File))
			if err != nil {
				t.Fatal(err)
			}
			got, err := schemaFindings(sch, data)
			if err != nil {
				t.Fatal(err)
			}
			want := slices.Clone(c.Errors)
			if want == nil {
				want = []indexError{}
			}
			sortIndexErrors(want)
			if g := asIndexErrors(got); !slices.Equal(g, want) {
				t.Errorf("errors = %+v, want %+v", g, want)
			}
			if c.Valid != (len(got) == 0) {
				t.Errorf("valid = %v, findings %+v", c.Valid, got)
			}
		})
	}
}

func TestProfileCommandLine(t *testing.T) {
	invalid := filepath.Join(specDir, "fixtures", "profiles", "invalid-missing-bypass-control.json")
	dangling := filepath.Join(specDir, "fixtures", "profiles", "invalid-dangling-fixture-path.json")
	outside := filepath.Join(t.TempDir(), "profile.json")
	example, err := os.ReadFile(exampleProfile)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outside, example, 0o600); err != nil {
		t.Fatal(err)
	}
	duplicate := filepath.Join(t.TempDir(), "duplicate.json")
	if err := os.WriteFile(duplicate, []byte(`{"claim": {}, "claim": {}}`), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantStdout []string
		wantStderr []string
		stdoutNone bool
		stderrNone bool
	}{
		{
			name:       "no profile subcommand",
			args:       []string{"profile"},
			wantCode:   2,
			wantStderr: []string{`missing command for "pactconf profile"`, "validate"},
			stdoutNone: true,
		},
		{
			name:       "profile help",
			args:       []string{"profile", "-h"},
			wantCode:   0,
			wantStdout: []string{"pactconf profile [command]", "validate"},
			stderrNone: true,
		},
		{
			name:       "unknown profile subcommand",
			args:       []string{"profile", "check"},
			wantCode:   2,
			wantStderr: []string{`unknown command "check" for "pactconf profile"`, "pactconf profile --help"},
			stdoutNone: true,
		},
		{
			name:       "validate without files",
			args:       []string{"profile", "validate"},
			wantCode:   2,
			wantStderr: []string{"USAGE: ", "pactconf profile validate --help"},
			stdoutNone: true,
		},
		{
			name:       "validate help",
			args:       []string{"profile", "validate", "--help"},
			wantCode:   0,
			wantStdout: []string{"pactconf profile validate FILE...", "-spec"},
			stderrNone: true,
		},
		{
			name:       "unknown flag",
			args:       []string{"profile", "validate", "-bogus", exampleProfile},
			wantCode:   2,
			wantStderr: []string{"-bogus", "pactconf profile validate --help"},
			stdoutNone: true,
		},
		{
			name:       "invalid profile",
			args:       []string{"profile", "validate", invalid},
			wantCode:   1,
			wantStderr: []string{invalid + "#/bypass_paths/0: schema required: missing property 'control'\n"},
			stdoutNone: true,
		},
		{
			name:       "lint failure",
			args:       []string{"profile", "validate", dangling},
			wantCode:   1,
			wantStderr: []string{dangling + "#/fixtures/0/path: lint fixture-path: "},
			stdoutNone: true,
		},
		{
			name:       "valid and invalid",
			args:       []string{"profile", "validate", exampleProfile, invalid},
			wantCode:   1,
			wantStdout: []string{exampleProfile + ": ok\n"},
			wantStderr: []string{invalid + "#/bypass_paths/0: "},
		},
		{
			name:       "duplicate member name",
			args:       []string{"profile", "validate", "-spec", specDir, duplicate},
			wantCode:   1,
			wantStderr: []string{duplicate + "#/claim: parse: ", "duplicate member name"},
			stdoutNone: true,
		},
		{
			name:       "spec directory not found",
			args:       []string{"profile", "validate", outside},
			wantCode:   2,
			wantStderr: []string{"no spec directory", "-spec"},
			stdoutNone: true,
		},
		{
			name:       "explicit spec directory",
			args:       []string{"profile", "validate", "-spec", specDir, outside},
			wantCode:   0,
			wantStdout: []string{outside + ": ok\n"},
			stderrNone: true,
		},
		{
			name:       "spec directory without schema",
			args:       []string{"profile", "validate", "-spec", t.TempDir(), exampleProfile},
			wantCode:   2,
			wantStderr: []string{schemaFile},
			stdoutNone: true,
		},
		{
			name:       "missing file",
			args:       []string{"profile", "validate", "-spec", specDir, filepath.Join(t.TempDir(), "absent.json")},
			wantCode:   2,
			wantStderr: []string{"absent.json"},
			stdoutNone: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(tt.args, &stdout, &stderr)
			if code != tt.wantCode {
				t.Errorf("exit code = %d, want %d; stderr:\n%s", code, tt.wantCode, stderr.String())
			}
			for _, s := range tt.wantStdout {
				if !strings.Contains(stdout.String(), s) {
					t.Errorf("stdout %q missing %q", stdout.String(), s)
				}
			}
			for _, s := range tt.wantStderr {
				if !strings.Contains(stderr.String(), s) {
					t.Errorf("stderr %q missing %q", stderr.String(), s)
				}
			}
			if tt.stdoutNone && stdout.Len() != 0 {
				t.Errorf("stdout = %q, want empty", stdout.String())
			}
			if tt.stderrNone && stderr.Len() != 0 {
				t.Errorf("stderr = %q, want empty", stderr.String())
			}
		})
	}
}

func TestPointerFragment(t *testing.T) {
	tests := []struct{ in, want string }{
		{"", ""},
		{"/fixtures/0/path", "/fixtures/0/path"},
		{"/a~1b/c~0d", "/a~1b/c~0d"},
		{"/a b", "/a%20b"},
		{"/x%y", "/x%25y"},
		{"/q#r", "/q%23r"},
		{"/café", "/caf%C3%A9"},
		{"/a:b@c!$&'()*+,;=?", "/a:b@c!$&'()*+,;=?"},
	}
	for _, tt := range tests {
		if got := pointerFragment(tt.in); got != tt.want {
			t.Errorf("pointerFragment(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestSortFindings(t *testing.T) {
	got := []finding{
		{Pointer: "/fixtures/10/id", Check: checkLint},
		{Pointer: "/fixtures/2/path", Check: checkLint},
		{Pointer: "/fixtures/2/id", Check: checkLint},
		{Pointer: "", Check: checkSchema},
		{Pointer: "/fixtures", Check: checkLint},
	}
	sortFindings(got)
	var order []string
	for _, f := range got {
		order = append(order, f.Pointer)
	}
	want := []string{"", "/fixtures", "/fixtures/2/id", "/fixtures/2/path", "/fixtures/10/id"}
	if !slices.Equal(order, want) {
		t.Errorf("order = %q, want %q", order, want)
	}
}
