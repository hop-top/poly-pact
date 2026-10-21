package main

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/santhosh-tekuri/jsonschema/v6/kind"

	"hop.top/pact-go/core/strictjson"
)

// The checks of profile validate, in the order they run.
const (
	checkParse  = "parse"
	checkSchema = "schema"
	checkLint   = "lint"
)

const (
	// schemaFile is the integration-profile schema, in the profiles directory
	// of the spec directory.
	schemaFile = "integration-profile.schema.json"
	// profileMaxBytes bounds a profile file; the largest profile is about
	// 30 KiB.
	profileMaxBytes = 1 << 20
	// manifestMaxBytes bounds fixtures/manifest.json.
	manifestMaxBytes = 16 << 20
)

const profileHelp = `Validates each integration profile FILE: strict JSON parse, then
DIR/profiles/integration-profile.schema.json, then the profile lint of
DIR/profiles/README.md. DIR is the spec directory and the base of fixture
paths. Without --spec it is the nearest directory above FILE that holds
profiles/integration-profile.schema.json.

A valid FILE prints "FILE: ok" on stdout. Each failure prints one line on
stderr, FILE#POINTER: CHECK [RULE]: MESSAGE, where POINTER is an RFC 6901
JSON Pointer in URI fragment form, CHECK is parse, schema or lint, and RULE
is the failing JSON Schema keyword or lint rule.

Exit status: 0 every FILE is valid; 1 a FILE fails; 2 usage error, or a FILE
or the spec directory cannot be read.`

// finding is one reason a profile is not valid.
type finding struct {
	// Pointer is the RFC 6901 JSON Pointer of the failing location in the
	// profile; "" is the whole document.
	Pointer string
	// Check is checkParse, checkSchema or checkLint.
	Check string
	// Rule is the failing JSON Schema keyword for checkSchema, the lint rule
	// for checkLint, and empty for checkParse.
	Rule    string
	Message string
}

// String formats f as POINTER: CHECK [RULE]: MESSAGE, with the pointer in
// URI fragment form, to follow "FILE#".
func (f finding) String() string {
	label := f.Check
	if f.Rule != "" {
		label += " " + f.Rule
	}
	return pointerFragment(f.Pointer) + ": " + label + ": " + f.Message
}

// runValidate runs profile validate on files with the spec directory spec,
// "" to find it above each file, and returns the exit status.
func runValidate(spec string, files []string, stdout, stderr io.Writer) int {
	type compiled struct {
		v   *validator
		err error
	}
	validators := map[string]compiled{}
	code := 0
	for _, file := range files {
		dir := spec
		if dir == "" {
			var err error
			if dir, err = findSpecDir(file); err != nil {
				_, _ = fmt.Fprintf(stderr, "pactconf: %v\n", err)
				code = 2
				continue
			}
		}
		c, ok := validators[dir]
		if !ok {
			c.v, c.err = newValidator(dir)
			validators[dir] = c
		}
		if c.err != nil {
			_, _ = fmt.Fprintf(stderr, "pactconf: %v\n", c.err)
			code = 2
			continue
		}
		findings, err := c.v.validateFile(file)
		switch {
		case err != nil:
			_, _ = fmt.Fprintf(stderr, "pactconf: %v\n", err)
			code = 2
		case len(findings) == 0:
			_, _ = fmt.Fprintf(stdout, "%s: ok\n", file)
		default:
			for _, f := range findings {
				_, _ = fmt.Fprintf(stderr, "%s#%s\n", file, f)
			}
			code = max(code, 1)
		}
	}
	return code
}

// findSpecDir returns the nearest directory above file that holds
// profiles/integration-profile.schema.json.
func findSpecDir(file string) (string, error) {
	abs, err := filepath.Abs(file)
	if err != nil {
		return "", err
	}
	for dir := filepath.Dir(abs); ; {
		if st, err := os.Stat(filepath.Join(dir, "profiles", schemaFile)); err == nil && st.Mode().IsRegular() {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("%s: no spec directory above it holds profiles/%s; pass -spec", file, schemaFile)
		}
		dir = parent
	}
}

// validator validates profiles against one spec directory.
type validator struct {
	dir    string
	schema *jsonschema.Schema
	ids    map[string]bool // manifest entry ids, read on first use
}

func newValidator(dir string) (*validator, error) {
	sch, err := compileSchema(filepath.Join(dir, "profiles", schemaFile), "")
	if err != nil {
		return nil, err
	}
	return &validator{dir: dir, schema: sch}, nil
}

func (v *validator) validateFile(file string) ([]finding, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	return v.validate(data)
}

// validate returns the findings for one profile document: the parse failure,
// else the schema failures, else the lint failures. An error is a problem
// with the spec directory, not with the profile.
func (v *validator) validate(data []byte) ([]finding, error) {
	findings, err := schemaFindings(v.schema, data)
	if err != nil || len(findings) > 0 {
		return findings, err
	}
	var p profileDoc
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("decode schema-valid profile: %w", err)
	}
	var ids map[string]bool
	if len(p.Fixtures) > 0 {
		if ids, err = v.manifestIDs(); err != nil {
			return nil, err
		}
	}
	return lintProfile(&p, v.exists, ids), nil
}

// exists reports whether rel, a slash-separated path inside the spec
// directory, names a file or directory.
func (v *validator) exists(rel string) bool {
	_, err := os.Stat(filepath.Join(v.dir, filepath.FromSlash(rel)))
	return err == nil
}

// manifestIDs returns the entry ids of fixtures/manifest.json, which it
// parses strictly. Other members of an entry are not read.
func (v *validator) manifestIDs() (map[string]bool, error) {
	if v.ids != nil {
		return v.ids, nil
	}
	file := filepath.Join(v.dir, "fixtures", "manifest.json")
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	var doc map[string]any
	if err := strictjson.Unmarshal(data, strictjson.Limits{MaxBytes: manifestMaxBytes}, &doc); err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	entries, ok := doc["entries"].([]any)
	if !ok {
		return nil, fmt.Errorf("%s: no entries array", file)
	}
	ids := make(map[string]bool, len(entries))
	for i, e := range entries {
		entry, _ := e.(map[string]any)
		id, _ := entry["id"].(string)
		if id == "" {
			return nil, fmt.Errorf("%s: entries[%d] has no id", file, i)
		}
		ids[id] = true
	}
	v.ids = ids
	return ids, nil
}

// compileSchema compiles the JSON Schema in file, or its subschema at the
// JSON Pointer fragment when fragment is not empty. A schema without
// $schema is read as Draft 2020-12. The library loads file: references only,
// so a remote reference fails to compile.
func compileSchema(file, fragment string) (*jsonschema.Schema, error) {
	abs, err := filepath.Abs(file)
	if err != nil {
		return nil, err
	}
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	if fragment != "" {
		abs += "#" + fragment
	}
	return c.Compile(abs)
}

// schemaFindings parses data strictly and validates it against sch. It
// returns the parse failure or the schema failures, one per failing keyword,
// sorted by location. An error means validation could not run.
func schemaFindings(sch *jsonschema.Schema, data []byte) ([]finding, error) {
	var probe any
	if err := strictjson.Unmarshal(data, strictjson.Limits{MaxBytes: profileMaxBytes}, &probe); err != nil {
		f := finding{Check: checkParse, Message: err.Error()}
		var se *strictjson.Error
		if errors.As(err, &se) {
			f.Pointer = se.Path
		}
		return []finding{f}, nil
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		return []finding{{Check: checkParse, Message: err.Error()}}, nil
	}
	err = sch.Validate(inst)
	var ve *jsonschema.ValidationError
	switch {
	case err == nil:
		return nil, nil
	case !errors.As(err, &ve):
		return nil, err
	}
	var out []finding
	leafFindings(ve, &out)
	sortFindings(out)
	return slices.Compact(out), nil
}

// leafFindings appends one finding per leaf of the error tree: the leaves are
// the failing keywords, and the inner nodes only say that a subschema
// failed.
func leafFindings(e *jsonschema.ValidationError, out *[]finding) {
	if len(e.Causes) > 0 {
		for _, c := range e.Causes {
			leafFindings(c, out)
		}
		return
	}
	ptr := jsonPointer(e.InstanceLocation)
	msg := e.Error()
	// Error prefixes the leaf message with "at '<pointer>': ", quoted as the
	// library quotes; the pointer is reported on its own.
	q := strings.ReplaceAll(strings.ReplaceAll(strconv.Quote(ptr), `\"`, `"`), `'`, `\'`)
	msg, _ = strings.CutPrefix(msg, "at '"+q[1:len(q)-1]+"': ")
	*out = append(*out, finding{Pointer: ptr, Check: checkSchema, Rule: keyword(e.ErrorKind), Message: msg})
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
		b.WriteString(strings.NewReplacer("~", "~0", "/", "~1").Replace(t))
	}
	return b.String()
}

// pointerFragment writes a JSON Pointer in URI fragment form (RFC 6901
// section 6): every byte that RFC 3986 does not allow in a fragment is
// percent-encoded.
func pointerFragment(ptr string) string {
	const allowed = "-._~!$&'()*+,;=:@/?"
	var b strings.Builder
	for i := 0; i < len(ptr); i++ {
		c := ptr[i]
		if 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || strings.IndexByte(allowed, c) >= 0 {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// sortFindings orders findings by location, comparing array indexes as
// numbers, then by check, rule and message.
func sortFindings(fs []finding) {
	slices.SortStableFunc(fs, func(a, b finding) int {
		if c := comparePointers(a.Pointer, b.Pointer); c != 0 {
			return c
		}
		return strings.Compare(a.Check+"\x00"+a.Rule+"\x00"+a.Message, b.Check+"\x00"+b.Rule+"\x00"+b.Message)
	})
}

func comparePointers(a, b string) int {
	as, bs := strings.Split(a, "/"), strings.Split(b, "/")
	for i := 0; i < len(as) && i < len(bs); i++ {
		x, errX := strconv.Atoi(as[i])
		y, errY := strconv.Atoi(bs[i])
		var c int
		if errX == nil && errY == nil {
			c = cmp.Compare(x, y)
		} else {
			c = strings.Compare(as[i], bs[i])
		}
		if c != 0 {
			return c
		}
	}
	return len(as) - len(bs)
}
