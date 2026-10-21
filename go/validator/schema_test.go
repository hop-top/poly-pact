package validator

import (
	"errors"
	"testing"

	"hop.top/pact-go/core"
)

// TestSchema checks the restricted keyword set of Appendix A.1 against
// instances whose verdict follows from JSON Schema Draft 2020-12.
func TestSchema(t *testing.T) {
	cases := []struct {
		schema, instance string
		want             bool
	}{
		{`true`, `{"a":1}`, true},
		{`false`, `null`, false},
		{`{"type":"string"}`, `"x"`, true},
		{`{"type":"string"}`, `1`, false},
		{`{"type":"integer"}`, `9000`, true},
		{`{"type":"integer"}`, `9000.0`, true},
		{`{"type":"integer"}`, `9000.5`, false},
		{`{"type":["string","null"]}`, `null`, true},
		{`{"const":"managed"}`, `"managed"`, true},
		{`{"const":"managed"}`, `"unmanaged"`, false},
		{`{"const":{"a":1,"b":[1,2]}}`, `{"b":[1,2],"a":1.0}`, true},
		{`{"const":[1,2]}`, `[2,1]`, false},
		{`{"enum":["a","b"]}`, `"b"`, true},
		{`{"enum":["a","b"]}`, `"c"`, false},
		{`{"minimum":9000,"type":"integer"}`, `9259`, true},
		{`{"minimum":9000,"type":"integer"}`, `8800`, false},
		{`{"minimum":9000}`, `9000`, true},
		{`{"exclusiveMinimum":9000}`, `9000`, false},
		{`{"maximum":1}`, `1.0000000000000000001`, false},
		{`{"exclusiveMaximum":10}`, `9.99`, true},
		{`{"minimum":5}`, `"text"`, true},
		{`{"minLength":1,"type":"string"}`, `""`, false},
		{`{"maxLength":2}`, `"éé"`, true},
		{`{"maxLength":2}`, `"abc"`, false},
		{`{"type":"array","items":{"type":"string"},"uniqueItems":true,"contains":{"const":"finance-reader"}}`, `["finance-reader"]`, true},
		{`{"type":"array","items":{"type":"string"},"uniqueItems":true,"contains":{"const":"finance-reader"}}`, `["finance-approver"]`, false},
		{`{"uniqueItems":true}`, `[1,1.0]`, false},
		{`{"contains":{"const":1},"minContains":2}`, `[1,2,1]`, true},
		{`{"contains":{"const":1},"maxContains":1}`, `[1,2,1]`, false},
		{`{"contains":{"const":1},"minContains":0}`, `[2]`, true},
		{`{"minItems":2}`, `[1]`, false},
		{`{"maxItems":1}`, `[1]`, true},
		{`{"properties":{"a":{"type":"string"}},"required":["a"]}`, `{"a":"x"}`, true},
		{`{"properties":{"a":{"type":"string"}},"required":["a"]}`, `{}`, false},
		{`{"properties":{"a":{"type":"string"}},"additionalProperties":false}`, `{"a":"x","b":1}`, false},
		{`{"properties":{"a":{"type":"string"}},"additionalProperties":false}`, `{"a":"x"}`, true},
		{`{"allOf":[{"type":"integer"},{"minimum":1}]}`, `0`, false},
		{`{"anyOf":[{"const":1},{"const":2}]}`, `2`, true},
		{`{"oneOf":[{"type":"integer"},{"minimum":0}]}`, `5`, false},
		{`{"not":{"const":"chat"}}`, `"chat"`, false},
	}
	for _, c := range cases {
		s, err := compileSchema([]byte(c.schema))
		if err != nil {
			t.Errorf("%s: %v", c.schema, err)
			continue
		}
		v, err := decodeJSON([]byte(c.instance))
		if err != nil {
			t.Fatal(err)
		}
		if got := matches(s, v); got != c.want {
			t.Errorf("%s on %s = %v, want %v", c.schema, c.instance, got, c.want)
		}
	}
}

// TestSchemaUnsupported: a keyword outside Appendix A.1, at any depth, or a
// malformed keyword value, is never evaluated permissively (draft 22.2).
func TestSchemaUnsupported(t *testing.T) {
	for _, s := range []string{
		`{"isolationLevel":"strict","const":"managed"}`,
		`{"pattern":"^a"}`,
		`{"$ref":"#/x"}`,
		`{"format":"uri"}`,
		`{"properties":{"a":{"pattern":"x"}}}`,
		`{"allOf":[]}`,
		`{"type":"decimal"}`,
		`{"minLength":-1}`,
		`{"minItems":1.5}`,
		`{"uniqueItems":"yes"}`,
		`"string"`,
		`{"not":{"not":{"not":{"not":{"not":{"not":{"not":{"not":{"not":{"not":{"not":{"not":{"not":{"not":{"not":{"not":{"not":true}}}}}}}}}}}}}}}}}`,
	} {
		if _, err := compileSchema([]byte(s)); !errors.Is(err, errUnsupportedSchema) {
			t.Errorf("%s compiled: %v", s, err)
		}
	}
}

func TestPointer(t *testing.T) {
	doc, err := decodeJSON([]byte(`{"a":{"b/c":[10,{"~d":true}]},"":1}`))
	if err != nil {
		t.Fatal(err)
	}
	for p, want := range map[string]bool{
		"/a/b~1c/0": true, "/a/b~1c/1/~0d": true, "/": true, "/a/x": false,
		"/a/b~1c/2": false, "/a/b~1c/01": false, "a": false,
	} {
		if _, ok := pointer(doc, p); ok != want {
			t.Errorf("pointer %q found = %v, want %v", p, ok, want)
		}
	}
}

func TestCompare(t *testing.T) {
	v := func(s string) any {
		x, err := decodeJSON([]byte(s))
		if err != nil {
			t.Fatal(err)
		}
		return x
	}
	cases := []struct {
		cmp         string
		p, a        string
		want        bool
		description string
	}{
		{"equal", `["a","b"]`, `["a","b"]`, true, "equal arrays"},
		{"equal", `["a","b"]`, `["b","a"]`, false, "array order is significant (8.4)"},
		{"equal", `{"x":1,"y":2}`, `{"y":2,"x":1}`, true, "member order is ignored (8.4)"},
		{"subset", `["a"]`, `["a","b"]`, true, "presented within authoritative"},
		{"subset", `["c"]`, `["a","b"]`, false, "presented outside authoritative"},
		{"subset", `["a","a"]`, `["a","b"]`, false, "values must be unique"},
		{"subset", `[{"a":1}]`, `[{"a":1}]`, false, "values must be scalars"},
		{"other", `1`, `1`, false, "unknown comparison never matches"},
	}
	for _, c := range cases {
		if got := compare(core.Comparison(c.cmp), v(c.p), v(c.a)); got != c.want {
			t.Errorf("%s: %v, want %v", c.description, got, c.want)
		}
	}
}
