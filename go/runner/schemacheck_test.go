package runner

// Tests of Config.SchemaCheck, the mode of the fixture schema check of the
// schema verb: gate (the default) applies the verdict of
// spec/v1.0/fixtures/schema/README.md to the input of each entry, off leaves that
// sub-check out and lists it in Result.Skipped.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// schemaRunMode is schemaRun with a schema check mode.
func schemaRunMode(t *testing.T, root, id, out, mode string, v SchemaValidator) (Result, error) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "out.txt")
	if err := os.WriteFile(p, []byte(out), 0o644); err != nil {
		t.Fatal(err)
	}
	rep, err := Run(Config{FixturesRoot: root, SchemaCmd: script(t, `cat `+p) + " {dir}", Validator: v, SchemaCheck: mode})
	if err != nil {
		return Result{}, err
	}
	return result(t, rep, id), nil
}

// TestSchemaCheckGate: the default and the explicit mode gate run the fixture
// sub-check, and a case the schema contradicts fails whatever the command
// printed.
func TestSchemaCheckGate(t *testing.T) {
	// The input is accepted by the verdict, but the case expects REJECTED.
	root, _ := rejectedTree(t, compact(evidenceHeader, `{"pact_version":"0.1"}`), "INVALID_MESSAGE")
	out := fmt.Sprintf(problemLine, "INVALID_MESSAGE") + "\n"
	for _, mode := range []string{"", SchemaCheckGate} {
		v := &stubValidator{}
		r, err := schemaRunMode(t, root, "parse/p", out, mode, v)
		if err != nil {
			t.Fatal(err)
		}
		if r.Status != StatusFail || !detailsContain(r.Details, "fixture") || len(v.calls) == 0 || detailsContain(r.Skipped, "fixture schema check") {
			t.Errorf("mode %q: %+v, validator calls %v; want FAIL naming the fixture, validator consulted, nothing skipped", mode, r, v.calls)
		}
	}
	// Without a validator, gate keeps today's skip reason.
	r, err := schemaRunMode(t, root, "parse/p", out, SchemaCheckGate, nil)
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != StatusPass || !detailsContain(r.Skipped, "fixture schema check", "no schema validator") || detailsContain(r.Skipped, "--schema-check") {
		t.Errorf("gate, no validator: %+v, want PASS with the no-validator skip only", r)
	}
}

// TestSchemaCheckOff: off does not run the fixture sub-check, judges the
// entry on the command alone, and lists the skip with the flag's name.
func TestSchemaCheckOff(t *testing.T) {
	root, _ := rejectedTree(t, compact(evidenceHeader, `{"pact_version":"0.1"}`), "INVALID_MESSAGE")
	out := fmt.Sprintf(problemLine, "INVALID_MESSAGE") + "\n"

	// The schema contradicts the case; off does not ask it.
	v := &stubValidator{}
	r, err := schemaRunMode(t, root, "parse/p", out, SchemaCheckOff, v)
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != StatusPass || len(v.calls) != 0 || !detailsContain(r.Skipped, "fixture schema check", "--schema-check off") {
		t.Errorf("off: %+v, validator calls %v; want PASS, validator never asked, skip naming --schema-check off", r, v.calls)
	}
	if len(r.Skipped) != 1 {
		t.Errorf("off: skipped %q, want the one fixture schema check line", r.Skipped)
	}

	// Without a validator the entry is skipped once, for the flag, not for the
	// missing validator.
	r, err = schemaRunMode(t, root, "parse/p", out, SchemaCheckOff, nil)
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != StatusPass || len(r.Skipped) != 1 || !detailsContain(r.Skipped, "--schema-check off") || detailsContain(r.Skipped, "no schema validator") {
		t.Errorf("off, no validator: %+v, want PASS with one skip naming --schema-check off", r)
	}

	// The command is still judged.
	for name, bad := range map[string]string{
		"another code": fmt.Sprintf(problemLine, "INVALID_PROOF") + "\n",
		"nothing":      "",
	} {
		r, err := schemaRunMode(t, root, "parse/p", bad, SchemaCheckOff, &stubValidator{})
		if err != nil {
			t.Fatal(err)
		}
		if r.Status != StatusFail || !detailsContain(r.Skipped, "--schema-check off") {
			t.Errorf("off, %s: %+v, want FAIL from the command with the skip still listed", name, r)
		}
	}
}

// TestSchemaCheckOffNoCommand: an entry without a schema command is SKIP for
// the missing command, whatever the mode; the mode adds no sub-check skip.
func TestSchemaCheckOffNoCommand(t *testing.T) {
	root, _ := rejectedTree(t, compact(evidenceHeader, `{"pact_version":"0.2"}`), "INVALID_MESSAGE")
	for _, mode := range []string{"", SchemaCheckGate, SchemaCheckOff} {
		rep, err := Run(Config{FixturesRoot: root, SchemaCheck: mode})
		if err != nil {
			t.Fatal(err)
		}
		if r := result(t, rep, "parse/p"); r.Status != StatusSkip || !detailsContain(r.Details, "no --schema-cmd") || len(r.Skipped) > 0 {
			t.Errorf("mode %q: %+v, want SKIP for no --schema-cmd", mode, r)
		}
	}
}

// TestSchemaCheckInvalid: a mode other than gate and off cannot start the run.
func TestSchemaCheckInvalid(t *testing.T) {
	root, _ := rejectedTree(t, compact(evidenceHeader, `{"pact_version":"0.2"}`), "INVALID_MESSAGE")
	for _, mode := range []string{"report", "Gate", "OFF", "on", " off", "gate "} {
		_, err := Run(Config{FixturesRoot: root, SchemaCheck: mode})
		if err == nil || !strings.Contains(err.Error(), "--schema-check") || !strings.Contains(err.Error(), fmt.Sprintf("%q", mode)) ||
			!strings.Contains(err.Error(), "gate") || !strings.Contains(err.Error(), "off") {
			t.Errorf("mode %q: error %v, want one naming --schema-check, the value, gate and off", mode, err)
		}
	}
	// The empty string is the zero value of Config, the default; as the
	// value of a flag it is not a mode.
	if _, err := ParseSchemaCheck(""); err == nil {
		t.Error(`ParseSchemaCheck("") is nil, want an error`)
	}
	for _, m := range []string{SchemaCheckGate, SchemaCheckOff} {
		if got, err := ParseSchemaCheck(m); err != nil || got != m {
			t.Errorf("ParseSchemaCheck(%q) = %q, %v", m, got, err)
		}
	}
}
