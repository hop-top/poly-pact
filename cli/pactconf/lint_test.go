package main

import (
	"encoding/json"
	"os"
	"slices"
	"testing"
)

// loadExample returns the example profile as a generic JSON tree to mutate.
func loadExample(t *testing.T) map[string]any {
	t.Helper()
	data, err := os.ReadFile(exampleProfile)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func list(doc map[string]any, key string) []any { return doc[key].([]any) }

func obj(v any) map[string]any { return v.(map[string]any) }

// withoutFunction drops every enforcement point that runs fn.
func withoutFunction(fn string) func(map[string]any) {
	return func(doc map[string]any) {
		doc["enforcement_points"] = slices.DeleteFunc(list(doc, "enforcement_points"), func(v any) bool {
			return obj(v)["function"] == fn
		})
	}
}

type want struct{ pointer, check, rule string }

func lintWant(pointer, rule string) want { return want{pointer, checkLint, rule} }

// TestLintRules applies one change to the example profile, which is valid,
// and expects exactly the listed findings. Every change keeps the document
// schema-valid unless a schema finding is expected.
func TestLintRules(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(doc map[string]any)
		want   []want
	}{
		{name: "example unchanged", mutate: func(map[string]any) {}},
		{
			name:   "no authenticate_native",
			mutate: withoutFunction("authenticate_native"),
			want:   []want{lintWant("/enforcement_points", "route-enforcement")},
		},
		{
			name:   "no map_operation",
			mutate: withoutFunction("map_operation"),
			want:   []want{lintWant("/enforcement_points", "route-enforcement")},
		},
		{
			name:   "no authorize_native",
			mutate: withoutFunction("authorize_native"),
			want:   []want{lintWant("/enforcement_points", "route-enforcement")},
		},
		{
			name: "only the three route functions",
			mutate: func(doc map[string]any) {
				doc["enforcement_points"] = slices.DeleteFunc(list(doc, "enforcement_points"), func(v any) bool {
					f := obj(v)["function"]
					return f != "authenticate_native" && f != "map_operation" && f != "authorize_native"
				})
			},
		},
		{
			name: "no routes and no enforcement points",
			mutate: func(doc map[string]any) {
				doc["protected_routes"] = []any{}
				doc["enforcement_points"] = []any{}
			},
		},
		{
			name: "blank bypass evidence",
			mutate: func(doc map[string]any) {
				obj(list(doc, "bypass_paths")[2])["evidence"] = " \t "
			},
			want: []want{lintWant("/bypass_paths/2/evidence", "bypass-evidence")},
		},
		{
			name:   "no adapters",
			mutate: func(doc map[string]any) { obj(doc["claim"])["adapters"] = []any{} },
			want:   []want{lintWant("/claim/adapters", "adapters")},
		},
		{
			name: "blank mapping revision",
			mutate: func(doc map[string]any) {
				obj(obj(doc["claim"])["adapters"].([]any)[0])["mapping_revision"] = " "
			},
			want: []want{lintWant("/claim/adapters/0/mapping_revision", "mapping-revision")},
		},
		{
			name:   "blank unsupported form",
			mutate: func(doc map[string]any) { list(doc, "unsupported_forms")[1] = "\n" },
			want:   []want{lintWant("/unsupported_forms/1", "unsupported-forms")},
		},
		{
			name: "registered fixture that exists",
			mutate: func(doc map[string]any) {
				doc["fixtures"] = []any{map[string]any{
					"id":   "profiles/invalid-empty-unsupported-forms",
					"path": "fixtures/profiles/invalid-empty-unsupported-forms.json",
				}}
			},
		},
		{
			name: "fixture id not registered",
			mutate: func(doc map[string]any) {
				doc["fixtures"] = []any{map[string]any{
					"id":   "profiles/not-registered",
					"path": "fixtures/profiles/index.json",
				}}
			},
			want: []want{lintWant("/fixtures/0/id", "fixture-id")},
		},
		{
			name: "fixture path names a directory",
			mutate: func(doc map[string]any) {
				doc["fixtures"] = []any{map[string]any{
					"id":   "adapters/_common/common-01.credential-wins",
					"path": "fixtures/adapters/_common",
				}}
			},
		},
		{
			name: "every fixture of the example missing",
			mutate: func(doc map[string]any) {
				doc["fixtures"] = []any{
					map[string]any{"id": "EXGW-N01", "path": "fixtures/example-invoice-gateway/exgw-n01"},
					map[string]any{"id": "EXGW-N02", "path": "fixtures/example-invoice-gateway/exgw-n02"},
				}
			},
			want: []want{
				lintWant("/fixtures/0/id", "fixture-id"),
				lintWant("/fixtures/0/path", "fixture-path"),
				lintWant("/fixtures/1/id", "fixture-id"),
				lintWant("/fixtures/1/path", "fixture-path"),
			},
		},
		{
			name:   "no freshness rows for C02 and C05",
			mutate: func(doc map[string]any) { doc["freshness"] = []any{} },
			want: []want{
				lintWant("/freshness", "freshness-coverage"),
				lintWant("/freshness", "freshness-coverage"),
			},
		},
		{
			name: "no freshness rows and no C02 or C05",
			mutate: func(doc map[string]any) {
				doc["freshness"] = []any{}
				doc["native_dependencies"] = slices.DeleteFunc(list(doc, "native_dependencies"), func(v any) bool {
					c := obj(v)["component"]
					return c == "C02" || c == "C05"
				})
			},
		},
		{
			name: "attribute source names a freshness entry",
			mutate: func(doc map[string]any) {
				doc["attribute_sources"] = []any{map[string]any{
					"source":     "Security hold store",
					"category":   "subject",
					"attributes": []any{"/subject/hold"},
					"freshness":  "Security hold store",
				}}
			},
		},
		{
			name: "attribute source freshness differs in case",
			mutate: func(doc map[string]any) {
				doc["attribute_sources"] = []any{
					map[string]any{
						"source":     "Security hold store",
						"category":   "subject",
						"attributes": []any{"/subject/hold"},
						"freshness":  "Security hold store",
					},
					map[string]any{
						"source":     "Security hold store",
						"category":   "subject",
						"attributes": []any{"/subject/hold"},
						"freshness":  "security hold store",
					},
				}
			},
			want: []want{lintWant("/attribute_sources/1/freshness", "attribute-freshness")},
		},
		{
			name: "schema failure suppresses the lint",
			mutate: func(doc map[string]any) {
				delete(obj(list(doc, "bypass_paths")[0]), "control")
				doc["fixtures"] = []any{map[string]any{"id": "nope", "path": "nope"}}
			},
			want: []want{{"/bypass_paths/0", checkSchema, "required"}},
		},
		{
			name:   "unknown top-level key",
			mutate: func(doc map[string]any) { doc["profile"] = "x" },
			want:   []want{{"", checkSchema, "additionalProperties"}},
		},
	}

	v, err := newValidator(specDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := loadExample(t)
			tt.mutate(doc)
			data, err := json.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			got, err := v.validate(data)
			if err != nil {
				t.Fatal(err)
			}
			checkFindings(t, got, tt.want)
		})
	}
}

func checkFindings(t *testing.T, got []finding, wants []want) {
	t.Helper()
	g := make([]want, len(got))
	for i, f := range got {
		g[i] = want{f.Pointer, f.Check, f.Rule}
		if f.Message == "" {
			t.Errorf("finding %+v has no message", f)
		}
	}
	if !slices.Equal(g, wants) {
		t.Errorf("findings = %+v, want %+v (full %+v)", g, wants, got)
	}
}

// TestLintDirect covers the lint rules that the schema already enforces, so
// they cannot be reached through validate with the current schema.
func TestLintDirect(t *testing.T) {
	str := func(s string) *string { return &s }
	valid := func() *profileDoc {
		p := &profileDoc{}
		p.Claim.Adapters = []adapterDoc{{MappingRevision: str("r1")}}
		p.BypassPaths = []bypassDoc{{Control: str("closed"), Evidence: str("fixture")}}
		p.UnsupportedForms = []string{"shared accounts"}
		return p
	}
	exists := func(string) bool { return true }
	tests := []struct {
		name   string
		mutate func(p *profileDoc)
		want   []want
	}{
		{name: "valid", mutate: func(*profileDoc) {}},
		{
			name:   "bypass path without control",
			mutate: func(p *profileDoc) { p.BypassPaths[0].Control = nil },
			want:   []want{lintWant("/bypass_paths/0", "bypass-control")},
		},
		{
			name:   "bypass path with empty control",
			mutate: func(p *profileDoc) { p.BypassPaths[0].Control = str("") },
			want:   []want{lintWant("/bypass_paths/0/control", "bypass-control")},
		},
		{
			name:   "bypass path without evidence",
			mutate: func(p *profileDoc) { p.BypassPaths[0].Evidence = nil },
			want:   []want{lintWant("/bypass_paths/0", "bypass-evidence")},
		},
		{
			name:   "adapter without mapping revision",
			mutate: func(p *profileDoc) { p.Claim.Adapters[0].MappingRevision = nil },
			want:   []want{lintWant("/claim/adapters/0", "mapping-revision")},
		},
		{
			name:   "no unsupported forms",
			mutate: func(p *profileDoc) { p.UnsupportedForms = nil },
			want:   []want{lintWant("/unsupported_forms", "unsupported-forms")},
		},
		{
			name: "fixture path leaves the spec directory",
			mutate: func(p *profileDoc) {
				p.Fixtures = []fixtureDoc{{ID: "a", Path: "../go/go.mod"}, {ID: "a", Path: "/etc/hosts"}}
			},
			want: []want{lintWant("/fixtures/0/path", "fixture-path"), lintWant("/fixtures/1/path", "fixture-path")},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := valid()
			tt.mutate(p)
			checkFindings(t, lintProfile(p, exists, map[string]bool{"a": true}), tt.want)
		})
	}
}
