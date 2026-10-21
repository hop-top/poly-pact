package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// realFixtures is spec/v1.0/fixtures seen from this directory.
var realFixtures = filepath.Join("..", "..", "spec", "v1.0", "fixtures")

const uriVectors = "vectors/schema/uri-format.json"

func uriEntry() vectorEntry {
	p := uriVectors
	outcome := "MATCH"
	return vectorEntry{
		ID: "vectors/schema/uri-format", Kind: "vector", Scope: "core",
		Path: p, Expected: &p, Outcome: &outcome, SpecMapRow: "CL-A.3", DraftSection: "A.3",
	}
}

// uriTree copies the uri-format vectors into a temporary fixture directory
// and returns its root and the copied file.
func uriTree(t *testing.T) (string, string) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "fixtures")
	dst := filepath.Join(root, filepath.FromSlash(uriVectors))
	copyFile(t, filepath.Join(realFixtures, filepath.FromSlash(uriVectors)), dst)
	return root, dst
}

// TestSchemaEntryPasses: every row of the committed file gets its expected
// verdict from the schema compiler pactconf uses.
func TestSchemaEntryPasses(t *testing.T) {
	if err := runSchemaEntry(realFixtures, uriEntry()); err != nil {
		t.Fatal(err)
	}
}

// TestSchemaEntryRows pins the shape of the committed file: the five strings
// that separate an RFC 3986 checker from a lax one, and the rows where
// ajv-formats 3.0.1 as published differs.
func TestSchemaEntryRows(t *testing.T) {
	var vs []schemaVector
	if _, err := readFixtureJSON(realFixtures, uriVectors, &vs); err != nil {
		t.Fatal(err)
	}
	byInput := map[string]schemaVector{}
	var differs []string
	for _, v := range vs {
		byInput[v.Input] = v
		if v.AJVFormatsDiffers {
			differs = append(differs, v.ID)
		}
	}
	for in, want := range map[string]string{
		"http://example.com/a b":     "reject",
		"http://example.com/é":       "reject",
		"https://example.com/%zz":    "reject",
		`http://a/b\c`:               "reject",
		"https://example.com:99999/": "accept",
		"https:":                     "accept",
		"https://example.com:80a/":   "reject",
	} {
		if v, ok := byInput[in]; !ok || v.Expect != want {
			t.Errorf("%q: row %+v, want expect %s", in, v, want)
		}
	}
	slices.Sort(differs)
	if want := []string{"ip-literal-without-authority", "port-not-digits", "scheme-only"}; !slices.Equal(differs, want) {
		t.Errorf("ajv_formats_differs rows %v, want %v", differs, want)
	}
}

// TestSchemaEntryFails: a wrong expectation, a broken file or a manifest
// entry that does not fit fails the entry and names the problem.
func TestSchemaEntryFails(t *testing.T) {
	tests := []struct {
		name   string
		change func(t *testing.T, file string, e *vectorEntry)
		detail string
	}{
		{"flipped expect", func(t *testing.T, file string, _ *vectorEntry) {
			edit(t, file, func(v any) any {
				obj(v.([]any)[0])["expect"] = "reject"
				return v
			})
		}, "authority-and-path: accepted, want reject"},
		{"unknown expect", func(t *testing.T, file string, _ *vectorEntry) {
			edit(t, file, func(v any) any {
				obj(v.([]any)[1])["expect"] = "maybe"
				return v
			})
		}, `empty-path: expect "maybe"`},
		{"repeated id", func(t *testing.T, file string, _ *vectorEntry) {
			edit(t, file, func(v any) any {
				obj(v.([]any)[1])["id"] = "authority-and-path"
				return v
			})
		}, `id "authority-and-path" is empty or repeated`},
		{"missing member", func(t *testing.T, file string, _ *vectorEntry) {
			edit(t, file, func(v any) any {
				delete(obj(v.([]any)[0]), "reason")
				return v
			})
		}, "vector 0: members"},
		{"empty file", func(t *testing.T, file string, _ *vectorEntry) {
			writeJSON(t, file, []any{})
		}, "has no vectors"},
		{"unknown file", func(t *testing.T, _ string, e *vectorEntry) {
			e.ID = "vectors/schema/email-format"
		}, "no format for vectors/schema/email-format"},
		{"outcome", func(t *testing.T, _ string, e *vectorEntry) {
			o := "ACCEPTED"
			e.Outcome = &o
		}, `outcome "ACCEPTED", want MATCH`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root, file := uriTree(t)
			e := uriEntry()
			tt.change(t, file, &e)
			err := runSchemaEntry(root, e)
			if err == nil || !strings.Contains(err.Error(), tt.detail) {
				t.Fatalf("got %v, want an error containing %q", err, tt.detail)
			}
		})
	}
}

// TestSchemaLibraryURIChecker: the JSON Schema library's own uri checker,
// with format assertion on, gets rows of the file wrong; this is why
// pactconf registers the shared expression. The rows are characters outside
// the RFC 3986 character set that net/url lets through.
func TestSchemaLibraryURIChecker(t *testing.T) {
	var vs []schemaVector
	if _, err := readFixtureJSON(realFixtures, uriVectors, &vs); err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	c.AssertFormat()
	sch, err := compileFormatSchema(c, "uri")
	if err != nil {
		t.Fatal(err)
	}
	var wrong []string
	for _, v := range vs {
		if verdict(sch, v.Input) != v.Expect {
			wrong = append(wrong, v.ID)
		}
	}
	for _, id := range []string{"space-in-path", "non-ascii-in-path", "backslash"} {
		if !slices.Contains(wrong, id) {
			t.Errorf("the library checker gets %s right; rows it gets wrong: %v", id, wrong)
		}
	}
}

// TestURIExpressionInREADME: the vectors README carries the expression the
// ports copy; it is the one pactconf registers.
func TestURIExpressionInREADME(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(realFixtures, "vectors", "schema", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	_, rest, ok := strings.Cut(string(b), "\n```text\n")
	if !ok {
		t.Fatal("no text block in the README")
	}
	got, _, ok := strings.Cut(rest, "\n```\n")
	if !ok {
		t.Fatal("unterminated text block in the README")
	}
	if got != uriExpression {
		t.Errorf("README expression differs from uriExpression:\nREADME: %s\nGo:     %s", got, uriExpression)
	}
}

// TestURIFormatOnlyStrings: the format asserts nothing about a non-string.
func TestURIFormatOnlyStrings(t *testing.T) {
	f := uriFormat()
	if f.Name != "uri" {
		t.Errorf("name %q", f.Name)
	}
	for _, v := range []any{1.5, true, nil, map[string]any{}} {
		if err := f.Validate(v); err != nil {
			t.Errorf("%v: %v", v, err)
		}
	}
	if err := f.Validate("not a uri"); err == nil {
		t.Error(`"not a uri" accepted`)
	}
}
