// Package pactschema validates PACT documents against the Appendix A.3
// schema, spec/v1.0/schemas/pact.schema.json, with
// github.com/santhosh-tekuri/jsonschema/v6: JSON Schema Draft 2020-12, with
// format assertion on and the RFC 3986 "uri" checker of URIExpression. A
// Validator is the runner.SchemaValidator of the commands; the library
// module has no JSON Schema validator of its own.
package pactschema

import (
	"bytes"
	"cmp"
	"errors"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/santhosh-tekuri/jsonschema/v6/kind"

	"hop.top/pact-go/runner"
)

// Validator validates documents against the definitions of one schema file.
// Every definition is compiled when the file is loaded.
type Validator struct {
	defs map[string]*jsonschema.Schema
}

var _ runner.SchemaValidator = (*Validator)(nil)

// Load compiles every definition of $defs of the schema file. The schema is
// a single standalone file whose $ref references are all local (Appendix
// A.1); it is registered under its $id, so nothing is fetched.
func Load(file string) (*Validator, error) {
	b, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	top, ok := doc.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s: not a JSON object", file)
	}
	id, _ := top["$id"].(string)
	if id == "" {
		return nil, fmt.Errorf("%s: no $id", file)
	}
	defs, _ := top["$defs"].(map[string]any)
	if len(defs) == 0 {
		return nil, fmt.Errorf("%s: no $defs", file)
	}
	c := NewCompiler()
	if err := c.AddResource(id, doc); err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	v := &Validator{defs: map[string]*jsonschema.Schema{}}
	for name := range defs {
		s, err := c.Compile(id + "#/$defs/" + pointerToken(name))
		if err != nil {
			return nil, fmt.Errorf("%s: $defs/%s: %w", file, name, err)
		}
		v.defs[name] = s
	}
	return v, nil
}

// Defs returns the names of the definitions, sorted.
func (v *Validator) Defs() []string {
	names := make([]string, 0, len(v.defs))
	for n := range v.defs {
		names = append(names, n)
	}
	slices.Sort(names)
	return names
}

// ValidateDef validates doc, one JSON value, against #/$defs/<def>. It
// returns one violation per failing keyword, sorted by location, keyword and
// message, none when doc is valid. It does not check what only a strict
// parser sees, such as a duplicate member name: parse doc strictly first.
func (v *Validator) ValidateDef(def string, doc []byte) ([]runner.SchemaViolation, error) {
	s, ok := v.defs[def]
	if !ok {
		return nil, fmt.Errorf("the schema has no definition %q", def)
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(doc))
	if err != nil {
		return nil, err
	}
	err = s.Validate(inst)
	var ve *jsonschema.ValidationError
	switch {
	case err == nil:
		return nil, nil
	case !errors.As(err, &ve):
		return nil, err
	}
	var out []runner.SchemaViolation
	leaves(ve, &out)
	slices.SortFunc(out, func(a, b runner.SchemaViolation) int {
		return cmp.Or(strings.Compare(a.Pointer, b.Pointer), strings.Compare(a.Keyword, b.Keyword), strings.Compare(a.Message, b.Message))
	})
	return slices.Compact(out), nil
}

// leaves appends one violation per leaf of the error tree: the leaves are the
// failing keywords, and the inner nodes only say that a subschema failed.
func leaves(e *jsonschema.ValidationError, out *[]runner.SchemaViolation) {
	if len(e.Causes) > 0 {
		for _, c := range e.Causes {
			leaves(c, out)
		}
		return
	}
	ptr := jsonPointer(e.InstanceLocation)
	msg := e.Error()
	// Error prefixes the leaf message with "at '<pointer>': ", quoted as the
	// library quotes; the pointer is reported on its own.
	q := strings.ReplaceAll(strings.ReplaceAll(strconv.Quote(ptr), `\"`, `"`), `'`, `\'`)
	msg, _ = strings.CutPrefix(msg, "at '"+q[1:len(q)-1]+"': ")
	*out = append(*out, runner.SchemaViolation{Pointer: ptr, Keyword: keyword(e.ErrorKind), Message: msg})
}

// keyword names the JSON Schema keyword that failed.
func keyword(k jsonschema.ErrorKind) string {
	if p := k.KeywordPath(); len(p) > 0 {
		return p[len(p)-1]
	}
	switch k.(type) {
	case *kind.Not:
		return "not"
	case *kind.FalseSchema:
		return "false"
	}
	return ""
}

// jsonPointer joins reference tokens into an RFC 6901 JSON Pointer.
func jsonPointer(tokens []string) string {
	var b strings.Builder
	for _, t := range tokens {
		b.WriteByte('/')
		b.WriteString(pointerToken(t))
	}
	return b.String()
}

// pointerToken escapes one RFC 6901 reference token.
func pointerToken(t string) string { return strings.NewReplacer("~", "~0", "/", "~1").Replace(t) }
