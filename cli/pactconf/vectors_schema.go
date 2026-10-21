package main

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// schemaVector is one element of a vectors/schema file
// (spec/v1.0/fixtures/vectors/schema/README.md).
type schemaVector struct {
	ID                string `json:"id"`
	Input             string `json:"input"`
	Expect            string `json:"expect"`
	Reason            string `json:"reason"`
	AJVFormatsDiffers bool   `json:"ajv_formats_differs"`
}

var schemaMembers = []string{"ajv_formats_differs", "expect", "id", "input", "reason"}

// schemaFormats maps a vectors/schema entry id to the format its strings
// test.
var schemaFormats = map[string]string{
	"vectors/schema/uri-format": "uri",
}

// compileFormatSchema compiles {"type": "string", "format": format} with c.
func compileFormatSchema(c *jsonschema.Compiler, format string) (*jsonschema.Schema, error) {
	const loc = "pactconf:///format.schema.json"
	doc := map[string]any{"type": "string", "format": format}
	if err := c.AddResource(loc, doc); err != nil {
		return nil, err
	}
	return c.Compile(loc)
}

// verdict is accept when s validates against sch, reject otherwise.
func verdict(sch *jsonschema.Schema, s string) string {
	if sch.Validate(s) != nil {
		return "reject"
	}
	return "accept"
}

// runSchemaEntry runs a vectors/schema file: each string, validated against
// a schema that asserts the entry's format, compiled as pactconf compiles
// schemas (Draft 2020-12, format assertion on, the shared uri checker),
// gets the vector's expected verdict.
func runSchemaEntry(root string, e vectorEntry) error {
	if err := singleFile(e); err != nil {
		return err
	}
	format, ok := schemaFormats[e.ID]
	if !ok {
		return fmt.Errorf("no format for %s", e.ID)
	}
	if e.outcome() != "MATCH" {
		return fmt.Errorf("outcome %q, want MATCH", e.outcome())
	}
	var vs []schemaVector
	if _, err := readFixtureJSON(root, e.Path, &vs); err != nil {
		return err
	}
	var raws []json.RawMessage
	if _, err := readFixtureJSON(root, e.Path, &raws); err != nil {
		return err
	}
	if len(vs) == 0 {
		return fmt.Errorf("%s has no vectors", e.Path)
	}
	sch, err := compileFormatSchema(newSchemaCompiler(), format)
	if err != nil {
		return err
	}
	var wrong []string
	seen := map[string]bool{}
	for i, v := range vs {
		if err := checkMembers(raws[i], schemaMembers...); err != nil {
			return fmt.Errorf("vector %d: %w", i, err)
		}
		if v.ID == "" || seen[v.ID] {
			return fmt.Errorf("vector %d: id %q is empty or repeated", i, v.ID)
		}
		seen[v.ID] = true
		if v.Expect != "accept" && v.Expect != "reject" {
			return fmt.Errorf("%s: expect %q, want accept or reject", v.ID, v.Expect)
		}
		if got := verdict(sch, v.Input); got != v.Expect {
			wrong = append(wrong, fmt.Sprintf("%s: %sed, want %s", v.ID, got, v.Expect))
		}
	}
	if len(wrong) > 0 {
		return fmt.Errorf("format %s: %s", format, strings.Join(wrong, "; "))
	}
	return nil
}
