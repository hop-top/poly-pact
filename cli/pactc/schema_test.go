package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// repoSpec is the spec directory relative to this package directory.
var repoSpec = filepath.Join("..", "..", "spec", "v1.0")

// schemaTree writes a spec directory whose fixtures hold the committed
// schema case parse/appendix-c-wrong-version with the expected code code,
// and, when withSchema, the committed schema in schemas/. It returns the
// fixtures root.
func schemaTree(t *testing.T, code string, withSchema bool) string {
	t.Helper()
	spec := t.TempDir()
	root := filepath.Join(spec, "fixtures")
	jws, err := os.ReadFile(filepath.Join(repoSpec, "fixtures", "parse", "appendix-c-wrong-version.jws"))
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"fixtures/manifest.json": `{"manifest_version":1,"entries":[{"id":"parse/appendix-c-wrong-version","kind":"schema","scope":"core",` +
			`"path":"parse/appendix-c-wrong-version.jws","expected":"expected/parse/appendix-c-wrong-version/decision.json",` +
			`"outcome":"REJECTED","spec_map_row":"CL-21","draft_section":"21"}]}`,
		"fixtures/parse/appendix-c-wrong-version.jws":                    string(jws),
		"fixtures/expected/parse/appendix-c-wrong-version/decision.json": `{"transport_code":"` + code + `"}`,
	}
	if withSchema {
		b, err := os.ReadFile(filepath.Join(repoSpec, "schemas", "pact.schema.json"))
		if err != nil {
			t.Fatal(err)
		}
		files["schemas/pact.schema.json"] = string(b)
	}
	for rel, content := range files {
		p := filepath.Join(spec, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// problemCmd writes a schema command that prints a Problem with code.
func problemCmd(t *testing.T, code string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the test command is a POSIX shell script")
	}
	p := filepath.Join(t.TempDir(), "schema.sh")
	body := "#!/bin/sh\nprintf '%s\\n' '{\"type\":\"about:blank\",\"title\":\"t\",\"status\":400,\"code\":\"" + code + "\",\"request_id\":\"r\"}'\n"
	if err := os.WriteFile(p, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return p + " {dir}"
}

type fixtureResult struct {
	ID      string   `json:"id"`
	Status  string   `json:"status"`
	Details []string `json:"details"`
	Skipped []string `json:"skipped"`
}

func schemaResult(t *testing.T, stdout string) fixtureResult {
	t.Helper()
	var rep struct {
		Fixtures []fixtureResult `json:"fixtures"`
	}
	if err := json.Unmarshal([]byte(stdout), &rep); err != nil || len(rep.Fixtures) != 1 {
		t.Fatalf("report %q: %v", stdout, err)
	}
	return rep.Fixtures[0]
}

// TestRunSchemaVerb: the schema verb judges the command's verdict and, with
// the schema beside the fixtures root or named by --schema, the case's own
// expectation; without the schema that sub-check is reported skipped.
func TestRunSchemaVerb(t *testing.T) {
	root := schemaTree(t, "INVALID_MESSAGE", true)
	code, stdout, stderr := runPactc("run", "--json", "--fixtures-root", root, "--schema-cmd", problemCmd(t, "INVALID_MESSAGE"))
	if r := schemaResult(t, stdout); code != 0 || r.Status != "PASS" || len(r.Skipped) > 0 {
		t.Errorf("good: exit %d, %+v, stderr %q; want 0, PASS with no skipped sub-check", code, r, stderr)
	}
	code, stdout, _ = runPactc("run", "--json", "--fixtures-root", root, "--schema-cmd", problemCmd(t, "INVALID_PROOF"))
	if r := schemaResult(t, stdout); code != 1 || r.Status != "FAIL" || !strings.Contains(strings.Join(r.Details, "\n"), "INVALID_PROOF") {
		t.Errorf("wrong code: exit %d, %+v; want 1, FAIL", code, r)
	}

	// A case that expects INVALID_PROOF for a payload the schema rejects is
	// contradicted by the schema, whatever the command prints.
	bad := schemaTree(t, "INVALID_PROOF", true)
	code, stdout, _ = runPactc("run", "--json", "--fixtures-root", bad, "--schema-cmd", problemCmd(t, "INVALID_PROOF"))
	if r := schemaResult(t, stdout); code != 1 || r.Status != "FAIL" || !strings.Contains(strings.Join(r.Details, "\n"), "fixture") {
		t.Errorf("contradicted case: exit %d, %+v; want 1, FAIL naming the fixture", code, r)
	}

	// No schema beside the fixtures root: the fixture sub-check is skipped.
	plain := schemaTree(t, "INVALID_PROOF", false)
	code, stdout, _ = runPactc("run", "--json", "--fixtures-root", plain, "--schema-cmd", problemCmd(t, "INVALID_PROOF"))
	if r := schemaResult(t, stdout); code != 0 || r.Status != "PASS" || !strings.Contains(strings.Join(r.Skipped, "\n"), "no schema validator") {
		t.Errorf("no schema: exit %d, %+v; want 0, PASS with the fixture sub-check skipped", code, r)
	}
	// --schema names it explicitly.
	schema := filepath.Join(filepath.Dir(root), "schemas", "pact.schema.json")
	code, stdout, _ = runPactc("run", "--json", "--fixtures-root", plain, "--schema", schema, "--schema-cmd", problemCmd(t, "INVALID_PROOF"))
	if r := schemaResult(t, stdout); code != 1 || r.Status != "FAIL" {
		t.Errorf("--schema: exit %d, %+v; want 1, FAIL", code, r)
	}
	// A --schema that cannot be loaded is a usage error.
	for _, f := range []string{filepath.Join(t.TempDir(), "none.json"), filepath.Join(plain, "manifest.json")} {
		if code, _, stderr := runPactc("run", "--fixtures-root", plain, "--schema", f); code != 2 || !strings.Contains(stderr, "--schema") {
			t.Errorf("--schema %s: exit %d, stderr %q; want 2", f, code, stderr)
		}
	}
	// So is a schema beside the fixtures root that cannot be loaded.
	if err := os.WriteFile(schema, []byte(`{`), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := runPactc("run", "--fixtures-root", root); code != 2 || !strings.Contains(stderr, "pact.schema.json") {
		t.Errorf("broken default schema: exit %d, stderr %q; want 2", code, stderr)
	}
}

// TestRunHelpDocumentsSchema: pactc run --help states the schema verb's
// contract and the --schema flag.
func TestRunHelpDocumentsSchema(t *testing.T) {
	code, stdout, stderr := runPactc("run", "--help")
	if code != 0 {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	for _, want := range []string{
		`--schema-cmd "tool schema {dir}"`, "absolute path of the entry's file", "one line per document",
		"decoded object", "transport_code", "RFC 8785", "--schema", "pact.schema.json", "spec/v1.0/fixtures/schema/README.md",
		"fixture schema check",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("help lacks %q", want)
		}
	}
	if strings.Contains(stdout, "no check for them yet") {
		t.Error("help still says schema entries are not checked")
	}
}

// TestRunSchemaCheckMode: --schema-check gate is the default and applies the
// reference check of the schema verb; off leaves it out, judges the entry on
// the command alone and lists the skip; another value is a usage error.
func TestRunSchemaCheckMode(t *testing.T) {
	// The schema contradicts this case, whatever the command prints.
	bad := schemaTree(t, "INVALID_PROOF", true)
	cmd := problemCmd(t, "INVALID_PROOF")
	for _, args := range [][]string{nil, {"--schema-check", "gate"}, {"--schema-check=gate"}} {
		code, stdout, _ := runPactc(append([]string{"run", "--json", "--fixtures-root", bad, "--schema-cmd", cmd}, args...)...)
		if r := schemaResult(t, stdout); code != 1 || r.Status != "FAIL" || len(r.Skipped) > 0 {
			t.Errorf("%v: exit %d, %+v; want 1, FAIL, nothing skipped", args, code, r)
		}
	}
	code, stdout, stderr := runPactc("run", "--json", "--fixtures-root", bad, "--schema-cmd", cmd, "--schema-check", "off")
	if r := schemaResult(t, stdout); code != 0 || r.Status != "PASS" || len(r.Skipped) != 1 ||
		!strings.Contains(r.Skipped[0], "fixture schema check") || !strings.Contains(r.Skipped[0], "--schema-check off") {
		t.Errorf("off: exit %d, %+v, stderr %q; want 0, PASS, one skip naming the flag", code, r, stderr)
	}
	// The command is still judged.
	code, stdout, _ = runPactc("run", "--json", "--fixtures-root", bad, "--schema-cmd", problemCmd(t, "INVALID_MESSAGE"), "--schema-check", "off")
	if r := schemaResult(t, stdout); code != 1 || r.Status != "FAIL" || !strings.Contains(strings.Join(r.Details, "\n"), "INVALID_PROOF") {
		t.Errorf("off, wrong code: exit %d, %+v; want 1, FAIL naming the expected code", code, r)
	}
	// The table says so too.
	if code, stdout, _ := runPactc("run", "--fixtures-root", bad, "--schema-cmd", cmd, "--schema-check", "off"); code != 0 || !strings.Contains(stdout, "--schema-check off") {
		t.Errorf("off, table: exit %d, stdout %q; want 0 listing the skip", code, stdout)
	}
	// With the check off the schema is not consulted: a broken default file
	// is no usage error.
	if err := os.WriteFile(filepath.Join(filepath.Dir(bad), "schemas", "pact.schema.json"), []byte(`{`), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := runPactc("run", "--fixtures-root", bad, "--schema-cmd", cmd, "--schema-check", "off"); code != 0 {
		t.Errorf("off, broken default schema: exit %d, stderr %q; want 0", code, stderr)
	}
	if code, _, _ := runPactc("run", "--fixtures-root", bad, "--schema-cmd", cmd); code != 2 {
		t.Errorf("gate, broken default schema: exit %d, want 2", code)
	}
	// Restore the schema for the values below, so only the mode can be wrong.
	good, err := os.ReadFile(filepath.Join(repoSpec, "schemas", "pact.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(filepath.Dir(bad), "schemas", "pact.schema.json"), good, 0o644); err != nil {
		t.Fatal(err)
	}

	// Other values, including the unbuilt report mode, are usage errors that
	// name the flag, the value and the modes.
	for _, v := range []string{"report", "Gate", "OFF", "", "on"} {
		code, stdout, stderr := runPactc("run", "--fixtures-root", bad, "--schema-cmd", cmd, "--schema-check", v)
		if code != 2 || stdout != "" || !strings.Contains(stderr, "--schema-check") || !strings.Contains(stderr, "gate") || !strings.Contains(stderr, "off") {
			t.Errorf("--schema-check %q: exit %d, stdout %q, stderr %q; want 2 naming the flag, gate and off", v, code, stdout, stderr)
		}
	}
}

// TestRunHelpDocumentsSchemaCheck: pactc run --help states the modes, the
// default and that off is reported in skipped.
func TestRunHelpDocumentsSchemaCheck(t *testing.T) {
	code, stdout, stderr := runPactc("run", "--help")
	if code != 0 {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	for _, want := range []string{"--schema-check", "gate", "off", "default", "skipped", "local diagnostic"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("help lacks %q", want)
		}
	}
}
