package pactschema

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"hop.top/pact-go/runner"
	"hop.top/pact-go/runner/manifest"
)

// specDir is the spec directory relative to this package directory.
var specDir = filepath.Join("..", "..", "..", "spec", "v1.0")

var (
	fixturesDir = filepath.Join(specDir, "fixtures")
	schemaFile  = filepath.Join(specDir, "schemas", "pact.schema.json")
)

func load(t *testing.T) *Validator {
	t.Helper()
	v, err := Load(schemaFile)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// TestLoadCompilesEveryDef: every definition of $defs is available, read
// from the schema file with encoding/json.
func TestLoadCompilesEveryDef(t *testing.T) {
	b, err := os.ReadFile(schemaFile)
	if err != nil {
		t.Fatal(err)
	}
	var s struct {
		Defs map[string]json.RawMessage `json:"$defs"`
	}
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	var want []string
	for n := range s.Defs {
		want = append(want, n)
	}
	slices.Sort(want)
	if got := load(t).Defs(); !slices.Equal(got, want) || len(got) < 31 {
		t.Errorf("Defs() = %v, want %v", got, want)
	}
	if _, err := Load(filepath.Join(t.TempDir(), "none.json")); err == nil {
		t.Error("missing file: no error")
	}
	for name, text := range map[string]string{
		"not JSON": `{`, "array": `[]`, "no $id": `{"$defs":{"A":{}}}`, "no $defs": `{"$id":"urn:x"}`,
		"remote $ref": `{"$id":"urn:x","$defs":{"A":{"$ref":"https://example.com/s.json"}}}`,
	} {
		p := filepath.Join(t.TempDir(), "s.json")
		if err := os.WriteFile(p, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(p); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

// appendixB returns the objects of the committed object list
// schema/appendix-b-valid.json.
func appendixB(t *testing.T) []listObject {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(fixturesDir, "schema", "appendix-b-valid.json"))
	if err != nil {
		t.Fatal(err)
	}
	var l struct {
		Objects []listObject `json:"objects"`
	}
	if err := json.Unmarshal(b, &l); err != nil {
		t.Fatal(err)
	}
	return l.Objects
}

type listObject struct {
	Section string          `json:"section"`
	Typ     string          `json:"typ"`
	Def     string          `json:"def"`
	Object  json.RawMessage `json:"object"`
}

// object returns the Appendix B object of section sec with the members of
// set replaced, a nil value deleting the member.
func object(t *testing.T, sec string, set map[string]any) []byte {
	t.Helper()
	for _, o := range appendixB(t) {
		if o.Section != sec {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal(o.Object, &m); err != nil {
			t.Fatal(err)
		}
		for k, v := range set {
			if v == nil {
				delete(m, k)
			} else {
				m[k] = v
			}
		}
		b, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	t.Fatalf("no Appendix B object %s", sec)
	return nil
}

// TestValidateDef: violations of the Appendix A.3 schema, each with its
// pointer and keyword, and the format uri asserted as RFC 3986.
func TestValidateDef(t *testing.T) {
	v := load(t)
	tests := []struct {
		name, def, sec string
		set            map[string]any
		pointer, kw    string
	}{
		{"wrong pact_version", "Evidence", "B.5", map[string]any{"pact_version": "0.2"}, "/pact_version", "const"},
		{"unknown core field", "Evidence", "B.5", map[string]any{"unknown_core_field": 1}, "", "additionalProperties"},
		{"missing required member", "Evidence", "B.5", map[string]any{"jti": nil}, "", "required"},
		{"string where an integer is required", "AgentProfile", "B.1", map[string]any{"revision": "1"}, "/revision", "type"},
		{"integer beyond the core range", "AgentProfile", "B.1", map[string]any{"revision": 9007199254740992}, "/revision", "maximum"},
		{"agent_id with a space is not an RFC 3986 URI", "AgentProfile", "B.1", map[string]any{"agent_id": "https://identity.example/agents/invoice assistant"}, "/agent_id", "format"},
		{"agent_id with a non-digit port", "AgentProfile", "B.1", map[string]any{"agent_id": "https://identity.example:44344a/agents"}, "/agent_id", "format"},
		{"holder_jkt too short", "AgentProfile", "B.1", map[string]any{"holder_jkt": "xx0BcA"}, "/holder_jkt", "pattern"},
		{"gateway metadata with an unknown member", "GatewayMetadata", "B.13", map[string]any{"jku": "https://gateway.example/keys"}, "", "additionalProperties"},
	}
	for _, tc := range tests {
		vs, err := v.ValidateDef(tc.def, object(t, tc.sec, tc.set))
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if !slices.ContainsFunc(vs, func(x runner.SchemaViolation) bool { return x.Pointer == tc.pointer && x.Keyword == tc.kw }) {
			t.Errorf("%s: violations %v, want %s at %q", tc.name, vs, tc.kw, tc.pointer)
		}
	}
	if vs, err := v.ValidateDef("AgentProfile", object(t, "B.1", nil)); err != nil || len(vs) > 0 {
		t.Errorf("B.1 as AgentProfile: %v, %v", vs, err)
	}
	// The definition matters: the B.5 evidence is not a requirement contract.
	if vs, err := v.ValidateDef("RequirementContract", object(t, "B.5", nil)); err != nil || len(vs) == 0 {
		t.Errorf("B.5 as RequirementContract: %v, %v; want violations", vs, err)
	}
	if _, err := v.ValidateDef("NoSuchDef", []byte(`{}`)); err == nil {
		t.Error("unknown definition: no error")
	}
	if _, err := v.ValidateDef("Intent", []byte(`{`)); err == nil {
		t.Error("not JSON: no error")
	}
}

// TestRepoSchemaCases: the expectation of every committed entry of kind
// schema holds under the schema.
func TestRepoSchemaCases(t *testing.T) {
	v := load(t)
	m, err := manifest.Load(fixturesDir)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, e := range m.Entries {
		if e.Kind != manifest.KindSchema {
			continue
		}
		ids = append(ids, e.ID)
		if p := runner.CheckSchemaFixture(fixturesDir, e, v); len(p) > 0 {
			t.Errorf("%s: %q", e.ID, p)
		}
	}
	for _, id := range []string{"parse/appendix-c-wrong-version", "schema/appendix-b-valid"} {
		if !slices.Contains(ids, id) {
			t.Errorf("no schema entry %s in %v", id, ids)
		}
	}
}

// TestAppendixBObjects: schema/appendix-b-valid.json holds the JSON objects
// of Appendix B of the draft, in order, each under its section and with
// the definition of its artifact, compared as values.
func TestAppendixBObjects(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(specDir, "draft.md"))
	if err != nil {
		t.Fatal(err)
	}
	type block struct {
		section string
		value   any
	}
	var blocks []block
	in := false
	section := ""
	var body []string
	for _, line := range strings.Split(string(b), "\n") {
		switch {
		case strings.HasPrefix(line, "## "):
			in = strings.HasPrefix(line, "## Appendix B.")
		case !in:
		case strings.HasPrefix(line, "### "):
			section = strings.Fields(line)[1]
		case line == "```json":
			body = []string{}
		case line == "```" && body != nil:
			var v any
			if err := json.Unmarshal([]byte(strings.Join(body, "\n")), &v); err != nil {
				t.Fatalf("Appendix B %s: %v", section, err)
			}
			blocks = append(blocks, block{section, v})
			body = nil
		case body != nil:
			body = append(body, line)
		}
	}
	defs := map[string]string{
		"B.1": "AgentProfile", "B.2": "Intent", "B.3": "OperationContext", "B.4": "RequirementContract",
		"B.5": "Evidence", "B.6": "ReputationSnapshot", "B.7": "AdmissionAttestation", "B.8": "OutcomeReport",
		"B.9": "LearningPolicy", "B.10": "LearningArtifact", "B.11": "LearningEvent", "B.13": "GatewayMetadata",
	}
	objs := appendixB(t)
	if len(objs) != len(blocks) || len(blocks) != len(defs) {
		t.Fatalf("%d objects, %d Appendix B blocks, want %d", len(objs), len(blocks), len(defs))
	}
	for i, o := range objs {
		var got any
		if err := json.Unmarshal(o.Object, &got); err != nil {
			t.Fatal(err)
		}
		gb, _ := json.Marshal(got)
		wb, _ := json.Marshal(blocks[i].value)
		if o.Section != blocks[i].section || !bytes.Equal(gb, wb) {
			t.Errorf("object %d (%s) differs from Appendix B %s", i+1, o.Section, blocks[i].section)
		}
		def := o.Def
		if o.Typ != "" {
			def, _ = runner.TypDef(o.Typ)
		}
		if def != defs[o.Section] {
			t.Errorf("%s: definition %q, want %q", o.Section, def, defs[o.Section])
		}
	}
}

// invalidFixtures are the decoded and signed fixture files that are not
// valid on purpose, each with the pointer of the failure: their cases
// expect the rejection.
var invalidFixtures = map[string]string{
	// learning/missing-gate: a learning policy without the test-suite release
	// gate is invalid (Appendix A.2), INVALID_MESSAGE.
	"learning/missing-gate/policies/finance.json":       "/evaluation_policy/immutable_test_suite_digests",
	"learning/missing-gate/signed/policies/finance.jws": "/evaluation_policy/immutable_test_suite_digests",
}

// caseFileDefs are the definitions of the unsigned decoded files of an
// evaluation case (spec/v1.0/fixtures/README.md, Evaluation cases).
var caseFileDefs = map[string]string{
	"profile.json":          "AgentProfile",
	"intent.json":           "Intent",
	"operation.json":        "OperationContext",
	"actual_operation.json": "OperationContext",
}

// TestFixtureCorpusValidates: every signed artifact of the fixtures, every
// decoded payload that signing.json names, and every profile, intent and
// operation file of a case validates against its definition, except the
// files that invalidFixtures lists, which fail where it says. The vectors
// and the schema cases are adversarial by design and judged by their own
// entries.
func TestFixtureCorpusValidates(t *testing.T) {
	v := load(t)
	checked := 0
	validate := func(rel, def string, doc []byte) {
		t.Helper()
		checked++
		vs, err := v.ValidateDef(def, doc)
		if err != nil {
			t.Errorf("%s as %s: %v", rel, def, err)
			return
		}
		if ptr, bad := invalidFixtures[rel]; bad {
			if !slices.ContainsFunc(vs, func(x runner.SchemaViolation) bool { return x.Pointer == ptr }) {
				t.Errorf("%s as %s: %v, want a violation at %s", rel, def, vs, ptr)
			}
			return
		}
		if len(vs) > 0 {
			t.Errorf("%s as %s: %v", rel, def, vs)
		}
	}
	err := filepath.WalkDir(fixturesDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(fixturesDir, p)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			switch rel {
			case "vectors", "testdata", "parse", "schema", "expected", "keys", "profiles", "adapters":
				return filepath.SkipDir
			}
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		switch base := path.Base(rel); {
		case strings.HasSuffix(rel, ".jws"):
			seg := strings.Split(strings.TrimSpace(string(b)), ".")
			if len(seg) != 3 {
				t.Errorf("%s: not a compact JWS", rel)
				return nil
			}
			h, err1 := base64.RawURLEncoding.DecodeString(seg[0])
			pl, err2 := base64.RawURLEncoding.DecodeString(seg[1])
			var header struct {
				Typ string `json:"typ"`
			}
			if err1 != nil || err2 != nil || json.Unmarshal(h, &header) != nil {
				t.Errorf("%s: undecodable", rel)
				return nil
			}
			def, ok := runner.TypDef(header.Typ)
			if !ok {
				t.Errorf("%s: typ %q", rel, header.Typ)
				return nil
			}
			validate(rel, def, pl)
		case base == "signing.json":
			var s struct {
				Artifacts []struct {
					Decoded string `json:"decoded"`
					Typ     string `json:"typ"`
				} `json:"artifacts"`
			}
			if err := json.Unmarshal(b, &s); err != nil {
				t.Errorf("%s: %v", rel, err)
				return nil
			}
			for _, a := range s.Artifacts {
				def, ok := runner.TypDef(a.Typ)
				if !ok {
					t.Errorf("%s: typ %q", rel, a.Typ)
					continue
				}
				drel := path.Join(path.Dir(rel), a.Decoded)
				db, err := os.ReadFile(filepath.Join(fixturesDir, filepath.FromSlash(drel)))
				if err != nil {
					t.Errorf("%s: %v", rel, err)
					continue
				}
				validate(drel, def, db)
			}
		case caseFileDefs[base] != "":
			validate(rel, caseFileDefs[base], b)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked < 1000 {
		t.Errorf("checked %d documents, want the whole corpus", checked)
	}
	t.Logf("%d documents", checked)
}
