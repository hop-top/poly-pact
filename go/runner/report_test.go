package runner

import (
	"bytes"
	"strings"
	"testing"
)

func TestReportFailedAndSummary(t *testing.T) {
	rep := &Report{
		Manifest: Check{Status: StatusPass},
		Fixtures: []Result{
			{ID: "admission/valid", Verb: VerbEvaluate, Status: StatusPass},
			{ID: "outcomes/o", Verb: VerbOutcomes, Status: StatusSkip, Details: []string{"no --outcomes-cmd"}},
		},
	}
	if rep.Failed() {
		t.Error("PASS and SKIP only: Failed must be false")
	}
	if got, want := rep.Summary(), (Summary{Pass: 2, Skip: 1}); got != want {
		t.Errorf("summary %+v, want %+v", got, want)
	}
	rep.Manifest = Check{Status: StatusFail, Details: []string{"[manifest-incomplete] x.json: no entry"}}
	if !rep.Failed() {
		t.Error("manifest FAIL: Failed must be true")
	}
	rep.Manifest = Check{Status: StatusPass}
	rep.Fixtures[1].Status = StatusFail
	if !rep.Failed() {
		t.Error("fixture FAIL: Failed must be true")
	}
	if got, want := rep.Summary(), (Summary{Pass: 2, Fail: 1}); got != want {
		t.Errorf("summary %+v, want %+v", got, want)
	}
}

func TestReportTable(t *testing.T) {
	rep := &Report{
		Manifest: Check{Status: StatusFail, Details: []string{"[manifest-incomplete] admission/c/config.json: no entry"}},
		Fixtures: []Result{
			{ID: "admission/valid", Verb: VerbEvaluate, Status: StatusFail, Details: []string{"decision INADMISSIBLE, want ADMISSIBLE"}},
			{ID: "parse/appendix-c-wrong-version", Verb: VerbSchema, Status: StatusSkip, Details: []string{"no --schema-cmd"}},
		},
	}
	var buf bytes.Buffer
	rep.WriteTable(&buf)
	out := buf.String()
	for _, want := range []string{
		"manifest.json  FAIL",
		"FIXTURE",
		"admission/valid                 evaluate  FAIL",
		"parse/appendix-c-wrong-version  schema    SKIP",
		"manifest.json FAIL:\n  - [manifest-incomplete] admission/c/config.json: no entry",
		"admission/valid evaluate FAIL:\n  - decision INADMISSIBLE, want ADMISSIBLE",
		"pass 0, fail 2, skip 1",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("table lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "no --schema-cmd") {
		t.Errorf("table prints skip reasons:\n%s", out)
	}
}
