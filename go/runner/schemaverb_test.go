package runner

// Tests of the schema verb and of the schema case verdict of
// spec/v1.0/fixtures/schema/README.md. The library module has no JSON Schema
// validator, so these tests use stubValidator, which applies two rules of
// the Appendix A.3 schema by hand; cli/internal/pactschema runs the same
// checks with the real schema.

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"hop.top/pact-go/runner/manifest"
)

// stubDefs are the definitions stubValidator knows.
var stubDefs = []string{
	"AgentProfile", "Intent", "OperationContext", "RequirementContract", "Evidence", "Presentation",
	"AdmissionAttestation", "OutcomeReport", "ReputationSnapshot", "LearningPolicy", "LearningArtifact",
	"LearningEvent", "GatewayMetadata",
}

// stubValidator records the definitions it is asked for and applies two
// rules of the Appendix A.3 schema: pact_version, when present, is the
// constant "0.1", and no member is named unknown_core_field (core objects
// are closed). An unknown definition is an error.
type stubValidator struct {
	calls []string
}

func (s *stubValidator) ValidateDef(def string, doc []byte) ([]SchemaViolation, error) {
	s.calls = append(s.calls, def)
	if !slices.Contains(stubDefs, def) {
		return nil, fmt.Errorf("no definition %q", def)
	}
	var m map[string]any
	if err := json.Unmarshal(doc, &m); err != nil {
		return []SchemaViolation{{Keyword: "type", Message: "not an object"}}, nil
	}
	var out []SchemaViolation
	if v, ok := m["pact_version"]; ok && v != "0.1" {
		out = append(out, SchemaViolation{Pointer: "/pact_version", Keyword: "const", Message: "value must be '0.1'"})
	}
	if _, ok := m["unknown_core_field"]; ok {
		out = append(out, SchemaViolation{Keyword: "additionalProperties", Message: "additional property 'unknown_core_field' not allowed"})
	}
	return out, nil
}

func b64(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

// compact is a compact JWS of header and payload text. The signature
// segment is not judged by a schema case.
func compact(header, payload string) string { return b64(header) + "." + b64(payload) + ".c2ln" }

const evidenceHeader = `{"alg":"ES256","typ":"pact-evidence+jwt","kid":"k"}`

func schemaEntry(id, path, outcome, expected string) entry {
	return entry{
		"id": id, "kind": "schema", "scope": "core", "path": path, "expected": expected,
		"outcome": outcome, "spec_map_row": "CL-A", "draft_section": "A.3",
	}
}

// rejectedTree is a fixture directory with one REJECTED schema entry,
// parse/p, whose input is the compact JWS text and whose expected code is
// code.
func rejectedTree(t *testing.T, text, code string) (string, manifest.Entry) {
	t.Helper()
	root := tree(t, []entry{schemaEntry("parse/p", "parse/p.jws", "REJECTED", "expected/parse/p/decision.json")}, map[string]string{
		"parse/p.jws":                    text,
		"expected/parse/p/decision.json": `{"transport_code":"` + code + `","rejected_before_crypto":true,"reason":"test"}`,
	})
	return root, loadEntry(t, root, "parse/p")
}

// listTree is a fixture directory with one schema entry of an object list,
// schema/s, with the given outcome; a REJECTED one expects INVALID_MESSAGE.
func listTree(t *testing.T, list, outcome string) (string, manifest.Entry) {
	t.Helper()
	exp := "schema/s.json"
	files := map[string]string{"schema/s.json": list}
	if outcome == "REJECTED" {
		exp = "expected/schema/s/decision.json"
		files[exp] = `{"transport_code":"INVALID_MESSAGE"}`
	}
	root := tree(t, []entry{schemaEntry("schema/s", "schema/s.json", outcome, exp)}, files)
	return root, loadEntry(t, root, "schema/s")
}

func loadEntry(t *testing.T, root, id string) manifest.Entry {
	t.Helper()
	m, err := manifest.Load(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range m.Entries {
		if e.ID == id {
			return e
		}
	}
	t.Fatalf("no entry %s", id)
	return manifest.Entry{}
}

func repoEntry(t *testing.T, id string) manifest.Entry { return loadEntry(t, repoFixtures, id) }

// TestTypDef: the definition of each typ of the draft 7.3 table, named
// after its artifact (spec/v1.0/fixtures/schema/README.md, Definition selection).
// typ is compared exactly.
func TestTypDef(t *testing.T) {
	want := map[string]string{
		"pact-requirements+jwt":      "RequirementContract",
		"pact-evidence+jwt":          "Evidence",
		"pact-presentation+jwt":      "Presentation",
		"pact-admission+jwt":         "AdmissionAttestation",
		"pact-outcome+jwt":           "OutcomeReport",
		"pact-reputation+jwt":        "ReputationSnapshot",
		"pact-learning-policy+jwt":   "LearningPolicy",
		"pact-learning-artifact+jwt": "LearningArtifact",
		"pact-learning-event+jwt":    "LearningEvent",
	}
	for typ, def := range want {
		if got, ok := TypDef(typ); !ok || got != def {
			t.Errorf("TypDef(%q) = %q, %v; want %q", typ, got, ok, def)
		}
	}
	for _, typ := range []string{"", "JWT", "jwt", "PACT-evidence+jwt", "application/pact-evidence+jwt", "pact-evidence+jwt ", "pact-receipt+jwt"} {
		if got, ok := TypDef(typ); ok {
			t.Errorf("TypDef(%q) = %q, want no definition", typ, got)
		}
	}
}

// TestSchemaFixtureRepoCases: the committed schema cases get their expected
// verdict, each document checked against the definition its type selects.
func TestSchemaFixtureRepoCases(t *testing.T) {
	tests := []struct {
		id   string
		defs []string
	}{
		{"parse/appendix-c-wrong-version", []string{"Evidence"}},
		{"schema/appendix-b-valid", []string{
			"AgentProfile", "Intent", "OperationContext", "RequirementContract", "Evidence", "ReputationSnapshot",
			"AdmissionAttestation", "OutcomeReport", "LearningPolicy", "LearningArtifact", "LearningEvent", "GatewayMetadata",
		}},
	}
	for _, tc := range tests {
		v := &stubValidator{}
		if p := CheckSchemaFixture(repoFixtures, repoEntry(t, tc.id), v); len(p) > 0 {
			t.Errorf("%s: %q", tc.id, p)
		}
		if !slices.Equal(v.calls, tc.defs) {
			t.Errorf("%s: validated against %v, want %v", tc.id, v.calls, tc.defs)
		}
	}
}

// TestSchemaVerdictRejects: each input is rejected with INVALID_MESSAGE
// (draft 13.4). The parse steps come before the schema: an input that is not
// strict JSON, or whose typ selects no definition, never reaches the
// validator.
func TestSchemaVerdictRejects(t *testing.T) {
	deep := strings.Repeat(`{"a":`, 17) + "1" + strings.Repeat("}", 17)
	tests := []struct {
		name     string
		text     string
		validate bool
	}{
		{"two segments", b64(evidenceHeader) + "." + b64(`{}`), false},
		{"four segments", compact(evidenceHeader, `{}`) + ".x", false},
		{"padded header", b64(evidenceHeader) + "==." + b64(`{}`) + ".c2ln", false},
		{"standard base64 payload", b64(evidenceHeader) + "." + base64.RawStdEncoding.EncodeToString([]byte("\xfb\xff\xfe")) + ".c2ln", false},
		{"header not JSON", compact(`{"typ":`, `{}`), false},
		{"header duplicate member", compact(`{"alg":"ES256","typ":"pact-evidence+jwt","typ":"pact-evidence+jwt"}`, `{}`), false},
		{"header array", compact(`["pact-evidence+jwt"]`, `{}`), false},
		{"header without typ", compact(`{"alg":"ES256"}`, `{}`), false},
		{"typ not a string", compact(`{"typ":7}`, `{}`), false},
		{"typ JWT", compact(`{"typ":"JWT"}`, `{}`), false},
		{"typ with media type prefix", compact(`{"typ":"application/pact-evidence+jwt"}`, `{}`), false},
		{"payload duplicate member", compact(evidenceHeader, `{"pact_version":"0.1","pact_version":"0.1"}`), false},
		{"payload non-finite number", compact(evidenceHeader, `{"iat":1e999}`), false},
		{"payload integer beyond 2^53-1", compact(evidenceHeader, `{"iat":9007199254740992}`), false},
		{"payload invalid UTF-8", b64(evidenceHeader) + "." + base64.RawURLEncoding.EncodeToString([]byte("{\"sub\":\"\xff\"}")) + ".c2ln", false},
		{"payload lone surrogate", compact(evidenceHeader, `{"sub":"\ud800"}`), false},
		{"payload nested 17 deep", compact(evidenceHeader, deep), false},
		{"payload trailing data", compact(evidenceHeader, `{} {}`), false},
		{"payload empty", compact(evidenceHeader, ``), false},
		{"payload fails the schema", compact(evidenceHeader, `{"pact_version":"0.2"}`), true},
		{"unknown core field", compact(evidenceHeader, `{"pact_version":"0.1","unknown_core_field":1}`), true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root, e := rejectedTree(t, tc.text, "INVALID_MESSAGE")
			v := &stubValidator{}
			if p := CheckSchemaFixture(root, e, v); len(p) > 0 {
				t.Errorf("want rejected with INVALID_MESSAGE: %q", p)
			}
			if called := len(v.calls) > 0; called != tc.validate {
				t.Errorf("validator called %v (%v), want %v", called, v.calls, tc.validate)
			}
		})
	}
}

// TestSchemaVerdictNesting: a document may nest 16 levels deep, not 17
// (draft 20.1), counted from the document: in an object list, from the
// object, not from the file.
func TestSchemaVerdictNesting(t *testing.T) {
	nest := func(n int) string { return strings.Repeat(`{"a":`, n-1) + "{}" + strings.Repeat("}", n-1) }
	list := func(n int) string {
		return `{"description":"d","objects":[{"section":"B.1","def":"AgentProfile","object":` + nest(n) + `}]}`
	}
	root, e := listTree(t, list(16), "ACCEPTED")
	if p := CheckSchemaFixture(root, e, &stubValidator{}); len(p) > 0 {
		t.Errorf("an object 16 deep: %q", p)
	}
	root, e = listTree(t, list(17), "ACCEPTED")
	if p := CheckSchemaFixture(root, e, &stubValidator{}); !detailsContain(p, "rejected", "deep") {
		t.Errorf("an object 17 deep is rejected, so the ACCEPTED expectation fails: %q", p)
	}
	root, e = rejectedTree(t, compact(evidenceHeader, nest(16)), "INVALID_MESSAGE")
	if p := CheckSchemaFixture(root, e, &stubValidator{}); len(p) == 0 || !detailsContain(p, "accepted") {
		t.Errorf("a payload 16 deep is accepted, so the REJECTED expectation fails: %q", p)
	}
	root, e = rejectedTree(t, compact(evidenceHeader, nest(17)), "INVALID_MESSAGE")
	if p := CheckSchemaFixture(root, e, &stubValidator{}); len(p) > 0 {
		t.Errorf("17 deep: %q", p)
	}
}

// TestSchemaFixtureContradictions: an expectation that the verdict does not
// meet is reported.
func TestSchemaFixtureContradictions(t *testing.T) {
	good := compact(evidenceHeader, `{"pact_version":"0.1"}`)
	bad := compact(evidenceHeader, `{"pact_version":"0.2"}`)
	tests := []struct {
		name string
		root string
		e    manifest.Entry
		want string
	}{}
	add := func(name, want string, root string, e manifest.Entry) {
		tests = append(tests, struct {
			name string
			root string
			e    manifest.Entry
			want string
		}{name, root, e, want})
	}
	root, e := rejectedTree(t, good, "INVALID_MESSAGE")
	add("REJECTED but accepted", "accepted", root, e)
	root, e = rejectedTree(t, bad, "INVALID_PROOF")
	add("REJECTED with another code", "INVALID_PROOF", root, e)
	root, e = listTree(t, `{"description":"d","objects":[{"section":"B.5","typ":"pact-evidence+jwt","object":{"pact_version":"0.2"}}]}`, "ACCEPTED")
	add("ACCEPTED but rejected", "/pact_version", root, e)
	root, e = listTree(t, `{"description":"d","objects":[{"section":"B.1","def":"NoSuchDef","object":{}}]}`, "ACCEPTED")
	add("unknown definition", "NoSuchDef", root, e)
	for _, tc := range tests {
		p := CheckSchemaFixture(tc.root, tc.e, &stubValidator{})
		if !detailsContain(p, tc.want) {
			t.Errorf("%s: %q, want a problem naming %q", tc.name, p, tc.want)
		}
	}
}

// TestSchemaInputForm: an input that breaks the format of
// spec/v1.0/fixtures/schema/README.md is a problem of the case, not a verdict.
func TestSchemaInputForm(t *testing.T) {
	obj := `{"pact_version":"0.1"}`
	lists := map[string]string{
		"typ and def":        `{"description":"d","objects":[{"section":"B.5","typ":"pact-evidence+jwt","def":"Evidence","object":` + obj + `}]}`,
		"neither typ or def": `{"description":"d","objects":[{"section":"B.5","object":` + obj + `}]}`,
		"unknown typ":        `{"description":"d","objects":[{"section":"B.5","typ":"pact-receipt+jwt","object":` + obj + `}]}`,
		"no objects":         `{"description":"d","objects":[]}`,
		"no description":     `{"objects":[{"section":"B.5","def":"Evidence","object":` + obj + `}]}`,
		"no section":         `{"description":"d","objects":[{"def":"Evidence","object":` + obj + `}]}`,
		"object not object":  `{"description":"d","objects":[{"section":"B.5","def":"Evidence","object":[1]}]}`,
		"object missing":     `{"description":"d","objects":[{"section":"B.5","def":"Evidence"}]}`,
		"unknown member":     `{"description":"d","objects":[{"section":"B.5","def":"Evidence","object":` + obj + `,"note":"x"}]}`,
		"duplicate member":   `{"description":"d","description":"d","objects":[{"section":"B.5","def":"Evidence","object":` + obj + `}]}`,
	}
	for name, list := range lists {
		root, e := listTree(t, list, "ACCEPTED")
		v := &stubValidator{}
		if p := CheckSchemaFixture(root, e, v); len(p) == 0 {
			t.Errorf("%s: no problem", name)
		}
		if len(v.calls) > 0 {
			t.Errorf("%s: validated %v", name, v.calls)
		}
	}
	// The expectation must fit the outcome.
	root := tree(t, []entry{
		schemaEntry("schema/a", "schema/a.json", "ACCEPTED", "expected/schema/a/decision.json"),
		schemaEntry("schema/b", "schema/b.json", "MATCH", "schema/b.json"),
		schemaEntry("schema/c", "schema/c.txt", "ACCEPTED", "schema/c.txt"),
		schemaEntry("parse/d", "parse/d.jws", "REJECTED", "expected/parse/d/decision.json"),
		schemaEntry("parse/e", "parse/e.jws", "REJECTED", "expected/parse/e/decision.json"),
	}, map[string]string{
		"schema/a.json":                   `{"description":"d","objects":[{"section":"B.5","def":"Evidence","object":` + obj + `}]}`,
		"expected/schema/a/decision.json": `{"transport_code":null}`,
		"schema/b.json":                   `{"description":"d","objects":[{"section":"B.5","def":"Evidence","object":` + obj + `}]}`,
		"schema/c.txt":                    obj,
		"parse/d.jws":                     compact(evidenceHeader, `{"pact_version":"0.2"}`),
		"expected/parse/d/decision.json":  `{"transport_code":null}`,
		"parse/e.jws":                     compact(evidenceHeader, `{"pact_version":"0.2"}`),
		"expected/parse/e/decision.json":  `{"transport_code":"INVALID_MESSAGE","decision":"INADMISSIBLE"}`,
	})
	for _, id := range []string{"schema/a", "schema/b", "schema/c", "parse/d", "parse/e"} {
		if p := CheckSchemaFixture(root, loadEntry(t, root, id), &stubValidator{}); len(p) == 0 {
			t.Errorf("%s: no problem", id)
		}
	}
}

// schemaRun runs the schema verb on the entry id of root with a command that
// prints out, and returns the result.
func schemaRun(t *testing.T, root, id, out string, v SchemaValidator) Result {
	t.Helper()
	p := filepath.Join(t.TempDir(), "out.txt")
	if err := os.WriteFile(p, []byte(out), 0o644); err != nil {
		t.Fatal(err)
	}
	rep, err := Run(Config{FixturesRoot: root, SchemaCmd: script(t, `cat `+p) + " {dir}", Validator: v})
	if err != nil {
		t.Fatal(err)
	}
	return result(t, rep, id)
}

const problemLine = `{"type":"https://pact.example/problems/invalid-message","title":"Invalid message","status":400,"code":"%s","request_id":"r-1","extensions":{}}`

// TestSchemaVerbRejected: for a REJECTED entry, every line must be a Problem
// with the expected code.
func TestSchemaVerbRejected(t *testing.T) {
	root, _ := rejectedTree(t, compact(evidenceHeader, `{"pact_version":"0.2"}`), "INVALID_MESSAGE")
	pass := fmt.Sprintf(problemLine, "INVALID_MESSAGE")
	if r := schemaRun(t, root, "parse/p", pass+"\n", &stubValidator{}); r.Status != StatusPass || len(r.Skipped) > 0 {
		t.Errorf("Problem INVALID_MESSAGE: %+v, want PASS", r)
	}
	tests := map[string]struct{ out, want string }{
		"another code":    {fmt.Sprintf(problemLine, "INVALID_PROOF") + "\n", "INVALID_PROOF"},
		"accepted":        {`{"pact_version":"0.2"}` + "\n", "accepted"},
		"nothing":         {"", "no line"},
		"two lines":       {pass + "\n" + pass + "\n", "2 lines"},
		"not JSON":        {"rejected\n", "document 1"},
		"Problem no code": {`{"type":"about:blank","title":"t","status":400,"request_id":"r","extensions":{}}` + "\n", "document 1"},
	}
	for name, tc := range tests {
		r := schemaRun(t, root, "parse/p", tc.out, &stubValidator{})
		if r.Status != StatusFail || !detailsContain(r.Details, tc.want) {
			t.Errorf("%s: %+v, want FAIL naming %q", name, r, tc.want)
		}
	}
}

// TestSchemaVerbAccepted: for an ACCEPTED entry, every line must be its
// document, compared as RFC 8785 canonical JSON.
func TestSchemaVerbAccepted(t *testing.T) {
	list := `{"description":"d","objects":[` +
		`{"section":"B.5","typ":"pact-evidence+jwt","object":{"pact_version":"0.1","iat":1792080000,"claims":[{"path":"/a","value":0.01}]}},` +
		`{"section":"B.1","def":"AgentProfile","object":{"profile_id":"p"}}]}`
	root, _ := listTree(t, list, "ACCEPTED")
	same := `{"claims":[{"value":1e-2,"path":"/a"}],"iat":1.79208e9,"pact_version":"0.1"}` + "\n" + `{ "profile_id" : "p" }` + "\n"
	if r := schemaRun(t, root, "schema/s", same, &stubValidator{}); r.Status != StatusPass {
		t.Errorf("same documents, other form: %+v, want PASS", r)
	}
	tests := map[string]struct{ out, want string }{
		"altered member": {`{"pact_version":"0.1","iat":1792080001,"claims":[{"path":"/a","value":0.01}]}` + "\n" + `{"profile_id":"p"}` + "\n", "document 1"},
		"extra member":   {`{"pact_version":"0.1","iat":1792080000,"claims":[{"path":"/a","value":0.01}]}` + "\n" + `{"profile_id":"p","x":1}` + "\n", "document 2"},
		"rejected":       {fmt.Sprintf(problemLine, "INVALID_MESSAGE") + "\n" + `{"profile_id":"p"}` + "\n", "rejected with INVALID_MESSAGE"},
		"one line":       {`{"profile_id":"p"}` + "\n", "1 line"},
		"order swapped":  {`{"profile_id":"p"}` + "\n" + `{"pact_version":"0.1","iat":1792080000,"claims":[{"path":"/a","value":0.01}]}` + "\n", "document 1"},
	}
	for name, tc := range tests {
		r := schemaRun(t, root, "schema/s", tc.out, &stubValidator{})
		if r.Status != StatusFail || !detailsContain(r.Details, tc.want) {
			t.Errorf("%s: %+v, want FAIL naming %q", name, r, tc.want)
		}
	}
}

// TestSchemaVerbFixtureCheck: with a validator the runner applies the
// verdict to the input itself, and a case whose expectation does not hold
// fails whatever the command printed; without one the sub-check is
// reported skipped.
func TestSchemaVerbFixtureCheck(t *testing.T) {
	// The input is accepted by the verdict, but the case expects REJECTED.
	root, _ := rejectedTree(t, compact(evidenceHeader, `{"pact_version":"0.1"}`), "INVALID_MESSAGE")
	out := fmt.Sprintf(problemLine, "INVALID_MESSAGE") + "\n"
	if r := schemaRun(t, root, "parse/p", out, &stubValidator{}); r.Status != StatusFail || !detailsContain(r.Details, "fixture") {
		t.Errorf("contradicted case: %+v, want FAIL naming the fixture", r)
	}
	r := schemaRun(t, root, "parse/p", out, nil)
	if r.Status != StatusPass || !detailsContain(r.Skipped, "fixture schema check", "no schema validator") {
		t.Errorf("no validator: %+v, want PASS with the fixture sub-check skipped", r)
	}
}

// TestSchemaVerbArgv: {dir} is the absolute path of the entry's file.
func TestSchemaVerbArgv(t *testing.T) {
	root, _ := rejectedTree(t, compact(evidenceHeader, `{"pact_version":"0.2"}`), "INVALID_MESSAGE")
	got := filepath.Join(t.TempDir(), "argv")
	cmd := script(t, `printf '%s' "$1" >`+got+`; printf '%s\n' '`+fmt.Sprintf(problemLine, "INVALID_MESSAGE")+`'`)
	rep, err := Run(Config{FixturesRoot: root, SchemaCmd: cmd + " {dir}"})
	if err != nil {
		t.Fatal(err)
	}
	if r := result(t, rep, "parse/p"); r.Status != StatusPass {
		t.Errorf("%+v, want PASS", r)
	}
	b, err := os.ReadFile(got)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := filepath.Abs(filepath.Join(root, "parse", "p.jws"))
	if string(b) != want {
		t.Errorf("{dir} = %q, want %q", b, want)
	}
}

// TestSchemaVerbFakeImpl runs the committed schema cases through the fake
// implementation: the good goldens pass, and each mutant mode fails the
// case it breaks for the stated reason.
func TestSchemaVerbFakeImpl(t *testing.T) {
	ids := []string{"parse/appendix-c-wrong-version", "schema/appendix-b-valid"}
	root := subsetRoot(t, ids...)
	run := func(mode string) *Report {
		t.Helper()
		cfg := fakeImplCfg(t, mode, root)
		cfg.Validator = &stubValidator{}
		rep, err := Run(cfg)
		if err != nil {
			t.Fatal(err)
		}
		return rep
	}
	rep := run("good")
	for _, id := range ids {
		if r := result(t, rep, id); r.Status != StatusPass {
			t.Errorf("good: %s = %+v, want PASS", id, r)
		}
	}
	mutants := []struct{ mode, id, want string }{
		{"schema-accepts-all", "parse/appendix-c-wrong-version", "accepted"},
		{"schema-wrong-code", "parse/appendix-c-wrong-version", "INVALID_PROOF"},
		{"schema-rejects-valid", "schema/appendix-b-valid", "document 5"},
		{"schema-altered-object", "schema/appendix-b-valid", "document 9"},
	}
	for _, m := range mutants {
		rep := run(m.mode)
		for _, id := range ids {
			r := result(t, rep, id)
			if id != m.id {
				if r.Status != StatusPass {
					t.Errorf("%s: %s = %+v, want PASS", m.mode, id, r)
				}
				continue
			}
			if r.Status != StatusFail || !detailsContain(r.Details, m.want) {
				t.Errorf("%s: %s = %+v, want FAIL naming %q", m.mode, id, r, m.want)
			}
		}
	}
}
