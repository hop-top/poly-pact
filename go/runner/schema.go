package runner

// The schema case verdict of spec/v1.0/fixtures/schema/README.md, which every
// harness applies to the entries of kind schema, and the schema verb, which
// judges an implementation's verdicts on them.

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"hop.top/pact-go/core"
	"hop.top/pact-go/core/jws"
	"hop.top/pact-go/core/strictjson"
	"hop.top/pact-go/runner/manifest"
)

// SchemaValidator validates a document against one definition of the $defs
// of the Appendix A.3 schema, spec/v1.0/schemas/pact.schema.json. The library
// module has no JSON Schema validator; the commands provide one.
type SchemaValidator interface {
	// ValidateDef validates doc, one strict JSON value, against
	// #/$defs/<def>. It returns the violations, none when doc is valid, and
	// an error when def is not a definition of the schema or doc cannot be
	// validated.
	ValidateDef(def string, doc []byte) ([]SchemaViolation, error)
}

// SchemaViolation is one failing keyword of a schema validation.
type SchemaViolation struct {
	// Pointer is the RFC 6901 JSON Pointer of the failing value in the
	// document, "" for the document itself.
	Pointer string
	// Keyword is the JSON Schema keyword that failed, such as const or
	// additionalProperties.
	Keyword string
	Message string
}

// String formats v as "POINTER: KEYWORD: MESSAGE", the pointer "" written
// "(document)".
func (v SchemaViolation) String() string {
	p := v.Pointer
	if p == "" {
		p = "(document)"
	}
	return p + ": " + v.Keyword + ": " + v.Message
}

// typDefs maps each typ of the draft 7.3 table to the definition of its
// artifact (Appendix A.1: the protected typ selects the definition).
var typDefs = map[string]string{
	jws.TypRequirements:     "RequirementContract",
	jws.TypEvidence:         "Evidence",
	jws.TypPresentation:     "Presentation",
	jws.TypAdmission:        "AdmissionAttestation",
	jws.TypOutcome:          "OutcomeReport",
	jws.TypReputation:       "ReputationSnapshot",
	jws.TypLearningPolicy:   "LearningPolicy",
	jws.TypLearningArtifact: "LearningArtifact",
	jws.TypLearningEvent:    "LearningEvent",
}

// TypDef returns the $defs definition that the JWS typ selects, after the
// draft 7.3 table. typ is compared exactly.
func TypDef(typ string) (string, bool) {
	d, ok := typDefs[typ]
	return d, ok
}

// Outcomes of a schema entry.
const (
	schemaAccepted = "ACCEPTED"
	schemaRejected = "REJECTED"
)

// codeInvalidMessage is the draft 13.4 code of a document rejected for its
// form.
const codeInvalidMessage = "INVALID_MESSAGE"

// objectListMaxDepth bounds the nesting of an object list file. The depth
// limit of draft 20.1 applies to each object, counted from the object, so the
// file itself may nest deeper: the file's object, the objects array and the
// element add three levels above an object that may be over the limit.
const objectListMaxDepth = 4 * strictjson.DefaultMaxDepth

// schemaDoc is one document of a schema case's input: a compact JWS, or an
// object of an object list with its definition.
type schemaDoc struct {
	compact string
	def     string
	object  json.RawMessage
}

// schemaCase is a schema entry's input and expectation.
type schemaCase struct {
	file    string
	docs    []schemaDoc
	outcome string
	// code is the expected transport_code of a REJECTED entry.
	code string
}

type objectList struct {
	Description *string      `json:"description"`
	Objects     []listObject `json:"objects"`
}

type listObject struct {
	Section *string         `json:"section"`
	Typ     *string         `json:"typ"`
	Def     *string         `json:"def"`
	Object  json.RawMessage `json:"object"`
}

type schemaDecision struct {
	TransportCode        *string `json:"transport_code"`
	RejectedBeforeCrypto *bool   `json:"rejected_before_crypto"`
	Reason               *string `json:"reason"`
}

// readSchemaCase reads the input and the expectation of the schema entry e
// (spec/v1.0/fixtures/schema/README.md, Inputs and Outcomes).
func readSchemaCase(root string, e manifest.Entry) (*schemaCase, error) {
	c := &schemaCase{file: filepath.Join(root, filepath.FromSlash(e.Path))}
	if e.Outcome != nil {
		c.outcome = *e.Outcome
	}
	switch c.outcome {
	case schemaAccepted:
		if e.Expected == nil || *e.Expected != e.Path {
			return nil, errors.New("an ACCEPTED schema case carries its expectation inline: expected must be its path")
		}
	case schemaRejected:
		if e.Expected == nil {
			return nil, errors.New("a REJECTED schema case names its decision.json as expected")
		}
		b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(*e.Expected)))
		if err != nil {
			return nil, err
		}
		var d schemaDecision
		if err := strictjson.Unmarshal(b, strictjson.Limits{}, &d); err != nil {
			return nil, fmt.Errorf("%s: %w", *e.Expected, err)
		}
		if d.TransportCode == nil || *d.TransportCode == "" {
			return nil, fmt.Errorf("%s: no transport_code", *e.Expected)
		}
		c.code = *d.TransportCode
	default:
		return nil, fmt.Errorf("outcome %q, want ACCEPTED or REJECTED", c.outcome)
	}
	b, err := os.ReadFile(c.file)
	if err != nil {
		return nil, err
	}
	switch filepath.Ext(e.Path) {
	case ".jws":
		c.docs = []schemaDoc{{compact: strings.TrimSpace(string(b))}}
	case ".json":
		c.docs, err = readObjectList(b)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", e.Path, err)
		}
	default:
		return nil, fmt.Errorf("%s: a schema case is a .jws or a .json file", e.Path)
	}
	return c, nil
}

// readObjectList reads an object list. The file is strict JSON as a whole;
// each object is checked as a document of its own by schemaVerdict.
func readObjectList(b []byte) ([]schemaDoc, error) {
	var l objectList
	if err := strictjson.Unmarshal(b, strictjson.Limits{MaxDepth: objectListMaxDepth}, &l); err != nil {
		return nil, err
	}
	if l.Description == nil || *l.Description == "" {
		return nil, errors.New("no description")
	}
	if len(l.Objects) == 0 {
		return nil, errors.New("no objects")
	}
	docs := make([]schemaDoc, len(l.Objects))
	for i, o := range l.Objects {
		where := fmt.Sprintf("objects[%d]", i)
		switch {
		case o.Section == nil || *o.Section == "":
			return nil, fmt.Errorf("%s: no section", where)
		case len(o.Object) == 0 || o.Object[0] != '{':
			return nil, fmt.Errorf("%s: object is not a JSON object", where)
		case (o.Typ == nil) == (o.Def == nil):
			return nil, fmt.Errorf("%s: exactly one of typ and def", where)
		case o.Def != nil:
			docs[i] = schemaDoc{def: *o.Def, object: o.Object}
		default:
			def, ok := TypDef(*o.Typ)
			if !ok {
				return nil, fmt.Errorf("%s: typ %q is not a typ of the draft 7.3 table", where, *o.Typ)
			}
			docs[i] = schemaDoc{def: def, object: o.Object}
		}
	}
	return docs, nil
}

// verdictResult is the verdict on one document: accepted, or rejected with a
// draft 13.4 code and why.
type verdictResult struct {
	accepted bool
	code     string
	why      string
}

func rejected(why string, a ...any) verdictResult {
	return verdictResult{code: codeInvalidMessage, why: fmt.Sprintf(why, a...)}
}

// schemaVerdict applies the steps of spec/v1.0/fixtures/schema/README.md,
// Verdict, to d: the form of a compact JWS, the typ, strict JSON, then the
// schema. The signature is never verified. err reports a validator that
// cannot run, which is no verdict.
func schemaVerdict(d schemaDoc, v SchemaValidator) (verdictResult, error) {
	def, object := d.def, []byte(d.object)
	if d.compact != "" || d.object == nil {
		seg := strings.Split(d.compact, ".")
		if len(seg) != 3 {
			return rejected("a compact JWS has three segments separated by two periods, not %d", len(seg)), nil
		}
		raw, err := base64.RawURLEncoding.Strict().DecodeString(seg[0])
		if err != nil {
			return rejected("protected header: not canonical base64url: %v", err), nil
		}
		var header map[string]json.RawMessage
		if err := strictjson.Unmarshal(raw, strictjson.Limits{}, &header); err != nil {
			return rejected("protected header: %v", err), nil
		}
		var typ string
		if t, ok := header["typ"]; !ok || json.Unmarshal(t, &typ) != nil {
			return rejected("protected header: no typ string"), nil
		}
		var ok bool
		if def, ok = TypDef(typ); !ok {
			return rejected("typ %q is not a typ of the draft 7.3 table", typ), nil
		}
		if object, err = base64.RawURLEncoding.Strict().DecodeString(seg[1]); err != nil {
			return rejected("payload: not canonical base64url: %v", err), nil
		}
	}
	var probe json.RawMessage
	if err := strictjson.Unmarshal(object, strictjson.Limits{}, &probe); err != nil {
		return rejected("%s: %v", def, err), nil
	}
	vs, err := v.ValidateDef(def, object)
	if err != nil {
		return verdictResult{}, fmt.Errorf("validate against %s: %w", def, err)
	}
	if len(vs) > 0 {
		msgs := make([]string, len(vs))
		for i, x := range vs {
			msgs[i] = x.String()
		}
		return rejected("%s: %s", def, strings.Join(msgs, "; ")), nil
	}
	return verdictResult{accepted: true}, nil
}

// CheckSchemaFixture applies the verdict of spec/v1.0/fixtures/schema/README.md
// to the input of the schema entry e with the validator v and returns how
// the entry's expectation fails: a document of an ACCEPTED entry that is
// rejected, or one of a REJECTED entry that is accepted or rejected with
// another code. A malformed case is a problem too. None means the
// expectation holds.
func CheckSchemaFixture(root string, e manifest.Entry, v SchemaValidator) []string {
	c, err := readSchemaCase(root, e)
	if err != nil {
		return []string{err.Error()}
	}
	return c.verdicts(v)
}

// verdicts applies the verdict to each document of c and returns how the
// verdicts contradict its expectation.
func (c *schemaCase) verdicts(v SchemaValidator) []string {
	var problems []string
	for i, d := range c.docs {
		where := c.where(i)
		r, err := schemaVerdict(d, v)
		if err != nil {
			problems = append(problems, where+": "+err.Error())
			continue
		}
		switch {
		case c.outcome == schemaAccepted && !r.accepted:
			problems = append(problems, fmt.Sprintf("%s: rejected with %s (%s), want accepted", where, r.code, r.why))
		case c.outcome == schemaRejected && r.accepted:
			problems = append(problems, fmt.Sprintf("%s: accepted, want rejected with %s", where, c.code))
		case c.outcome == schemaRejected && r.code != c.code:
			problems = append(problems, fmt.Sprintf("%s: rejected with %s (%s), want %s", where, r.code, r.why, c.code))
		}
	}
	return problems
}

func (c *schemaCase) where(i int) string { return fmt.Sprintf("document %d", i+1) }

// checkSchema runs the schema command on the entry's file and judges the
// line it prints for each document (spec/v1.0/fixtures/README.md, Runner
// contract, Schema): a Problem with the expected code for a REJECTED entry,
// the document's decoded object for an ACCEPTED one. With a validator, the
// case's expectation is first checked against the schema, and a case it
// contradicts fails; with cfg.SchemaCheck [SchemaCheckOff] that check is not
// run and the entry is judged on the command alone. The exit status of the command is informational.
func checkSchema(cfg Config, e manifest.Entry, tmpl string, r Result) Result {
	c, err := readSchemaCase(cfg.FixturesRoot, e)
	if err != nil {
		return r.with(StatusFail, err.Error())
	}
	var problems []string
	switch {
	case cfg.SchemaCheck == SchemaCheckOff:
		r.Skipped = append(r.Skipped, "fixture schema check: not run, --schema-check "+SchemaCheckOff+"; the entry is judged on the schema command alone")
	case cfg.Validator != nil:
		for _, p := range c.verdicts(cfg.Validator) {
			problems = append(problems, "fixture: the case's expectation does not hold under the schema: "+p)
		}
	default:
		r.Skipped = append(r.Skipped, "fixture schema check: no schema validator")
	}
	docObjects := c.decodedObjects()
	dir, err := filepath.Abs(c.file)
	if err != nil {
		return r.with(StatusFail, err.Error())
	}
	res := runCmd(BuildArgv(tmpl, map[string]string{"dir": dir}))
	if res.Err != nil {
		return r.with(StatusFail, "cannot run the schema command: "+res.summary())
	}
	var lines []string
	for _, l := range strings.Split(string(res.Stdout), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			lines = append(lines, l)
		}
	}
	switch {
	case len(lines) == 0:
		problems = append(problems, "no line on stdout: want one per document")
	case len(lines) != len(c.docs):
		problems = append(problems, fmt.Sprintf("printed %s, want %d: one per document", plural(len(lines), "line"), len(c.docs)))
	default:
		for i, l := range lines {
			if p := c.judgeLine(i, l, docObjects[i]); p != "" {
				problems = append(problems, p)
			}
		}
	}
	if len(problems) > 0 {
		return r.with(StatusFail, append(problems, res.summary())...)
	}
	return r.with(StatusPass)
}

// decodedObjects returns the decoded object of each document as far as it
// decodes: the payload of a compact JWS, or the object of an object list;
// nil for a payload that does not decode.
func (c *schemaCase) decodedObjects() []json.RawMessage {
	out := make([]json.RawMessage, len(c.docs))
	for i, d := range c.docs {
		if d.object != nil {
			out[i] = d.object
			continue
		}
		if seg := strings.Split(d.compact, "."); len(seg) == 3 {
			if b, err := base64.RawURLEncoding.Strict().DecodeString(seg[1]); err == nil {
				out[i] = b
			}
		}
	}
	return out
}

// judgeLine judges the line the command printed for document i, whose
// decoded object is want; it returns the difference, "" when there is none.
func (c *schemaCase) judgeLine(i int, line string, want json.RawMessage) string {
	where := c.where(i)
	var obj json.RawMessage
	if err := strictjson.Unmarshal([]byte(line), strictjson.Limits{}, &obj); err != nil || obj[0] != '{' {
		return where + ": the line is neither the decoded object as a JSON object nor a Problem (RFC 9457, draft 13.4)"
	}
	var p core.Problem
	isProblem := strictjson.Unmarshal(obj, strictjson.Limits{}, &p) == nil && p.Code != ""
	switch c.outcome {
	case schemaRejected:
		switch {
		case !isProblem:
			return fmt.Sprintf("%s: accepted (the line is not a Problem with a code), want rejected with %s", where, c.code)
		case p.Code != c.code:
			return fmt.Sprintf("%s: rejected with %s, want %s", where, p.Code, c.code)
		}
	default:
		if canonicalJSON(obj) == canonicalJSON(want) {
			return ""
		}
		if isProblem {
			return fmt.Sprintf("%s: rejected with %s, want accepted", where, p.Code)
		}
		return fmt.Sprintf("%s: printed object %s, want the document %s (RFC 8785)", where, truncate(canonicalJSON(obj), 300), truncate(canonicalJSON(want), 300))
	}
	return ""
}
