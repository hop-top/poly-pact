package core

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// schemaPath is the protocol schema relative to this package directory. A
// missing file fails the test: a skipped drift check would let drift through.
const schemaPath = "../../spec/v1.0/schemas/pact.schema.json"

const digestPattern = "^[A-Za-z0-9_-]{43}$"

// defTypes maps every $defs entry to its Go struct. The test fails when the
// schema gains or loses an entry that this table does not follow.
var defTypes = map[string]reflect.Type{
	"AgentProfile":         reflect.TypeFor[AgentProfile](),
	"Intent":               reflect.TypeFor[Intent](),
	"OperationContext":     reflect.TypeFor[OperationContext](),
	"FieldRule":            reflect.TypeFor[FieldRule](),
	"RequirementContract":  reflect.TypeFor[RequirementContract](),
	"Claim":                reflect.TypeFor[Claim](),
	"Evidence":             reflect.TypeFor[Evidence](),
	"Presentation":         reflect.TypeFor[Presentation](),
	"CheckResult":          reflect.TypeFor[CheckResult](),
	"AdmissionAttestation": reflect.TypeFor[AdmissionAttestation](),
	"ReputationContext":    reflect.TypeFor[ReputationContext](),
	"DimensionStats":       reflect.TypeFor[DimensionStats](),
	"ReputationValue":      reflect.TypeFor[ReputationValue](),
	"ReputationSnapshot":   reflect.TypeFor[ReputationSnapshot](),
	"Attribution":          reflect.TypeFor[Attribution](),
	"OutcomeReport":        reflect.TypeFor[OutcomeReport](),
	"AdaptiveControl":      reflect.TypeFor[AdaptiveControl](),
	"DataPolicy":           reflect.TypeFor[DataPolicy](),
	"MetricBound":          reflect.TypeFor[MetricBound](),
	"EvaluationPolicy":     reflect.TypeFor[EvaluationPolicy](),
	"LearningPolicy":       reflect.TypeFor[LearningPolicy](),
	"LearningArtifact":     reflect.TypeFor[LearningArtifact](),
	"LearningEvent":        reflect.TypeFor[LearningEvent](),
	"ContractRequest":      reflect.TypeFor[ContractRequest](),
	"EvaluationRequest":    reflect.TypeFor[EvaluationRequest](),
	"ReputationQuery":      reflect.TypeFor[ReputationQuery](),
	"ReceiptQuery":         reflect.TypeFor[ReceiptQuery](),
	"Acknowledgment":       reflect.TypeFor[Acknowledgment](),
	"NativeAdapter":        reflect.TypeFor[NativeAdapter](),
	"GatewayMetadata":      reflect.TypeFor[GatewayMetadata](),
	"Problem":              reflect.TypeFor[Problem](),
}

func values[T ~string](s []T) []string {
	out := make([]string, len(s))
	for i, v := range s {
		out[i] = string(v)
	}
	return out
}

// enumSets maps every enum type to the values Valid accepts.
var enumSets = map[reflect.Type][]string{
	reflect.TypeFor[RuleSource]():            values(ruleSourceValues),
	reflect.TypeFor[Comparison]():            values(comparisonValues),
	reflect.TypeFor[Mode]():                  values(modeValues),
	reflect.TypeFor[EvidenceKind]():          values(evidenceKindValues),
	reflect.TypeFor[CheckStatus]():           values(checkStatusValues),
	reflect.TypeFor[Decision]():              values(decisionValues),
	reflect.TypeFor[TerminalReason]():        values(terminalReasonValues),
	reflect.TypeFor[SecurityStatus]():        values(securityStatusValues),
	reflect.TypeFor[CausalAssessment]():      values(causalAssessmentValues),
	reflect.TypeFor[ReporterRole]():          values(reporterRoleValues),
	reflect.TypeFor[EventKind]():             values(eventKindValues),
	reflect.TypeFor[OutcomeResult]():         values(outcomeResultValues),
	reflect.TypeFor[Dimension]():             values(dimensionValues),
	reflect.TypeFor[Severity]():              values(severityValues),
	reflect.TypeFor[BoundDirection]():        values(boundDirectionValues),
	reflect.TypeFor[LearningMode]():          values(learningModeValues),
	reflect.TypeFor[ArtifactType]():          values(artifactTypeValues),
	reflect.TypeFor[Transition]():            values(transitionValues),
	reflect.TypeFor[LifecycleState]():        values(lifecycleStateValues),
	reflect.TypeFor[AckStatus]():             values(ackStatusValues),
	reflect.TypeFor[JWSAlgorithm]():          values(jwsAlgorithmValues),
	reflect.TypeFor[PresentationTransport](): values(presentationTransportValues),
}

var (
	rawMessageType = reflect.TypeFor[json.RawMessage]()
	objectType     = reflect.TypeFor[Object]()
	digestType     = reflect.TypeFor[Digest]()
	stringType     = reflect.TypeFor[string]()
)

// drift collects problems and the facts later checks need.
type drift struct {
	problems []string
	structs  map[string]bool     // Go struct names reached from the schema
	enums    map[string][]string // enum type name -> schema values
}

func (d *drift) failf(format string, args ...any) {
	d.problems = append(d.problems, fmt.Sprintf(format, args...))
}

func loadSchema(t *testing.T) map[string]any {
	t.Helper()
	b, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatalf("schema drift test cannot run: %v", err)
	}
	var s map[string]any
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatalf("parse %s: %v", schemaPath, err)
	}
	return s
}

func asMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

func (d *drift) checkStruct(path string, sch map[string]any, got reflect.Type) {
	if got.Kind() != reflect.Struct {
		d.failf("%s: schema object has properties, Go type is %s", path, got)
		return
	}
	d.structs[got.Name()] = true

	if sch["type"] != "object" {
		d.failf("%s: schema type is %v, want object", path, sch["type"])
	}
	if sch["additionalProperties"] != false {
		d.failf("%s: additionalProperties is %v, want false (unknown core fields must stay rejected)", path, sch["additionalProperties"])
	}
	props := asMap(sch["properties"])
	required := map[string]bool{}
	for _, r := range sch["required"].([]any) {
		required[r.(string)] = true
		if _, ok := props[r.(string)]; !ok {
			d.failf("%s: required %q is not a property", path, r)
		}
	}

	tags := map[string]reflect.StructField{}
	for i := range got.NumField() {
		f := got.Field(i)
		if !f.IsExported() {
			d.failf("%s: unexported field %s", path, f.Name)
			continue
		}
		tag, ok := f.Tag.Lookup("json")
		if !ok || tag == "-" {
			d.failf("%s: field %s has no json tag", path, f.Name)
			continue
		}
		name, opts, _ := strings.Cut(tag, ",")
		if _, dup := tags[name]; dup {
			d.failf("%s: json name %q used twice", path, name)
		}
		tags[name] = f

		switch {
		case required[name] && opts != "":
			d.failf("%s.%s: required property must have no tag options, has %q", path, name, opts)
		case !required[name] && opts != "omitzero":
			d.failf("%s.%s: optional property must be tagged omitzero, has %q", path, name, opts)
		}
	}

	for _, name := range sortedKeys(props) {
		f, ok := tags[name]
		if !ok {
			d.failf("%s: schema property %q has no Go field", path, name)
			continue
		}
		d.checkShape(path+"."+name, asMap(props[name]), f.Type)
	}
	for _, name := range sortedKeys(tags) {
		if _, ok := props[name]; !ok {
			d.failf("%s: Go field %s (json %q) is not a schema property", path, tags[name].Name, name)
		}
	}
}

func (d *drift) checkShape(path string, sch map[string]any, got reflect.Type) {
	want := func(t reflect.Type) {
		if got != t {
			d.failf("%s: Go type is %s, schema wants %s", path, got, t)
		}
	}
	switch {
	// An anyOf beside a type only constrains values of that type, as the
	// URI-or-token items of GatewayMetadata.extensions_supported do; the type
	// case below decides the Go type.
	case sch["anyOf"] != nil && sch["type"] == nil:
		opts := sch["anyOf"].([]any)
		if len(opts) == 2 && reflect.DeepEqual(opts[1], map[string]any{"type": "null"}) {
			if got.Kind() != reflect.Pointer {
				d.failf("%s: schema allows null, Go type %s is not a pointer", path, got)
				return
			}
			d.checkShape(path, asMap(opts[0]), got.Elem())
			return
		}
		// object-or-boolean: free-form JSON.
		want(rawMessageType)
	case sch["$ref"] != nil:
		name := strings.TrimPrefix(sch["$ref"].(string), "#/$defs/")
		wt, ok := defTypes[name]
		if !ok {
			d.failf("%s: $ref to unknown def %s", path, name)
			return
		}
		want(wt)
	case sch["enum"] != nil:
		var vals []string
		for _, v := range sch["enum"].([]any) {
			vals = append(vals, v.(string))
		}
		set, ok := enumSets[got]
		if !ok {
			d.failf("%s: schema enum %v needs an enum type registered in enumSets, Go type is %s", path, vals, got)
			return
		}
		a, b := slices.Sorted(slices.Values(vals)), slices.Sorted(slices.Values(set))
		if !slices.Equal(a, b) {
			d.failf("%s: enum %s accepts %v, schema lists %v", path, got.Name(), b, a)
		}
		if prev, seen := d.enums[got.Name()]; seen && !slices.Equal(slices.Sorted(slices.Values(prev)), a) {
			d.failf("%s: enum %s is used for two different schema enums", path, got.Name())
		}
		d.enums[got.Name()] = vals
	case sch["const"] != nil:
		switch sch["const"].(type) {
		case string:
			want(stringType)
		case float64:
			want(reflect.TypeFor[int64]())
		default:
			d.failf("%s: unhandled const %v", path, sch["const"])
		}
	case sch["type"] == nil:
		want(rawMessageType) // {} accepts any JSON value
	case sch["type"] == "string":
		if sch["pattern"] == digestPattern {
			want(digestType)
		} else {
			want(stringType)
		}
	case sch["type"] == "integer":
		want(reflect.TypeFor[int64]())
	case sch["type"] == "number":
		want(reflect.TypeFor[float64]())
	case sch["type"] == "boolean":
		want(reflect.TypeFor[bool]())
	case sch["type"] == "array":
		if got.Kind() != reflect.Slice {
			d.failf("%s: schema array, Go type is %s", path, got)
			return
		}
		d.checkShape(path+"[]", asMap(sch["items"]), got.Elem())
	case sch["type"] == "object":
		switch {
		case sch["properties"] != nil:
			d.checkStruct(path, sch, got)
		case asMap(sch["additionalProperties"]) != nil:
			if got.Kind() != reflect.Map || got.Key() != stringType {
				d.failf("%s: schema map, Go type is %s", path, got)
				return
			}
			d.checkShape(path+"{}", asMap(sch["additionalProperties"]), got.Elem())
		default:
			want(objectType) // open object (attributes, extensions)
		}
	default:
		d.failf("%s: unhandled schema shape %v", path, sch)
	}
}

// payloadOnly lists the $defs entries that are payload schemas of extension
// values (draft Appendix A.3): profile documents and the conformance runner
// validate an extension value against them. They are not wire objects, so
// they are not in the root oneOf, no wire object reaches them, and they have
// no Go struct.
var payloadOnly = map[string]bool{
	"ConformanceDeclaration": true,
	"TransportDeclaration":   true,
}

// refs collects the local $ref targets in v, a decoded JSON value.
func refs(v any, out map[string]bool) {
	switch x := v.(type) {
	case map[string]any:
		for k, e := range x {
			if r, ok := e.(string); ok && k == "$ref" {
				out[strings.TrimPrefix(r, "#/$defs/")] = true
				continue
			}
			refs(e, out)
		}
	case []any:
		for _, e := range x {
			refs(e, out)
		}
	}
}

// reachable returns the $defs entries reachable from the schema's root oneOf.
func reachable(schema map[string]any) map[string]bool {
	defs := asMap(schema["$defs"])
	seen := map[string]bool{}
	todo := map[string]bool{}
	refs(schema["oneOf"], todo)
	for len(todo) > 0 {
		next := map[string]bool{}
		for name := range todo {
			if seen[name] {
				continue
			}
			seen[name] = true
			refs(defs[name], next)
		}
		todo = next
	}
	return seen
}

// goOnly lists the exported structs that have no wire form and so no schema
// entry: configuration and error types of the Go implementation. Everything
// else exported must mirror a $defs entry.
var goOnly = map[string]bool{
	"Limits":     true,
	"LimitError": true,
}

// declarations lists the exported struct types and the typed string constants
// declared in the non-test files of this package.
func declarations(t *testing.T) (structs []string, consts map[string][]string) {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	consts = map[string][]string{}
	fset := token.NewFileSet()
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, e.Name(), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range file.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok {
				continue
			}
			for _, spec := range gd.Specs {
				switch s := spec.(type) {
				case *ast.TypeSpec:
					if _, ok := s.Type.(*ast.StructType); ok && s.Name.IsExported() {
						structs = append(structs, s.Name.Name)
					}
				case *ast.ValueSpec:
					id, ok := s.Type.(*ast.Ident)
					if gd.Tok != token.CONST || !ok || len(s.Values) != 1 {
						continue
					}
					if lit, ok := s.Values[0].(*ast.BasicLit); ok && lit.Kind == token.STRING {
						v, _ := strconv.Unquote(lit.Value)
						consts[id.Name] = append(consts[id.Name], v)
					}
				}
			}
		}
	}
	return structs, consts
}

func TestSchemaDrift(t *testing.T) {
	schema := loadSchema(t)
	defs := asMap(schema["$defs"])
	if len(defs) != 33 {
		t.Errorf("schema has %d $defs entries, want 33", len(defs))
	}
	if len(defTypes) != 31 {
		t.Errorf("defTypes has %d entries, want 31", len(defTypes))
	}

	wire := reachable(schema)
	d := &drift{structs: map[string]bool{}, enums: map[string][]string{}}
	for _, name := range sortedKeys(defs) {
		if payloadOnly[name] {
			if wire[name] {
				d.failf("$defs/%s is listed payload-only but a wire object reaches it", name)
			}
			continue
		}
		if !wire[name] {
			d.failf("$defs/%s is not reachable from the root oneOf and not listed payload-only", name)
		}
		gt, ok := defTypes[name]
		if !ok {
			d.failf("$defs/%s has no Go struct", name)
			continue
		}
		if gt.Name() != name {
			d.failf("$defs/%s maps to Go type %s", name, gt.Name())
		}
		d.checkStruct(name, asMap(defs[name]), gt)
	}
	for _, name := range sortedKeys(defTypes) {
		if _, ok := defs[name]; !ok {
			d.failf("Go struct %s has no $defs entry", name)
		}
	}
	for _, name := range sortedKeys(payloadOnly) {
		if _, ok := defs[name]; !ok {
			d.failf("payload-only %s has no $defs entry", name)
		}
	}

	// Source-level checks: no exported struct without a schema counterpart,
	// and the declared constants of each enum equal the schema's values.
	structs, consts := declarations(t)
	for _, s := range structs {
		if !d.structs[s] && !goOnly[s] {
			d.failf("Go struct %s is not reachable from the schema", s)
		}
	}
	for et, set := range enumSets {
		schemaVals, used := d.enums[et.Name()]
		if !used {
			d.failf("enum type %s is not used by any schema enum property", et.Name())
			continue
		}
		a := slices.Sorted(slices.Values(schemaVals))
		if c := slices.Sorted(slices.Values(consts[et.Name()])); !slices.Equal(a, c) {
			d.failf("enum %s constants are %v, schema lists %v", et.Name(), c, a)
		}
		if len(set) != len(a) {
			d.failf("enum %s value list has %d entries, schema %d", et.Name(), len(set), len(a))
		}
	}

	for _, p := range d.problems {
		t.Error(p)
	}
}
