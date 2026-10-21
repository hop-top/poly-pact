package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"hop.top/pact-go/runner"
)

// harnessEnv makes the test binary act as the pactvalidate command, so the
// runner can drive it through the adapter contract without a separate build.
const harnessEnv = "PACTVALIDATE_AS_HARNESS"

func TestMain(m *testing.M) {
	if os.Getenv(harnessEnv) == "1" {
		os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
	}
	os.Exit(m.Run())
}

// TestConformance runs every evaluate entry of the manifest through the
// conformance runner against this harness: each must PASS, none may SKIP
// (spec/v1.0/fixtures/README.md, Runner contract).
func TestConformance(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	root, err := filepath.Abs(filepath.Join("..", "..", "spec", "v1.0", "fixtures"))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(harnessEnv, "1")
	rep, err := runner.Run(runner.Config{
		FixturesRoot: root,
		Fixtures:     []string{"admission/", "approval/", "delegation/", "selection/", "transport/"},
		EvaluateCmd:  exe + " evaluate {dir} {state}",
		ReceiptCmd:   exe + " receipt {state} {id}",
		Capabilities: []string{"jws-ed25519"},
	})
	if err != nil {
		t.Fatal(err)
	}
	evaluated := 0
	for _, r := range rep.Fixtures {
		if r.Verb != runner.VerbEvaluate {
			continue
		}
		evaluated++
		if r.Status != runner.StatusPass {
			t.Errorf("%s: %s %s", r.ID, r.Status, strings.Join(r.Details, "; "))
		}
	}
	if evaluated == 0 {
		t.Fatal("no evaluate entry ran")
	}
	t.Logf("%d evaluate entries", evaluated)
}

func TestUsage(t *testing.T) {
	for _, args := range [][]string{nil, {"evaluate"}, {"receipt", "state"}, {"schema", "x"}} {
		var out, errb bytes.Buffer
		if code := run(args, &out, &errb); code != 2 || out.Len() != 0 || !strings.Contains(errb.String(), "usage") {
			t.Errorf("%q: exit %d, stdout %q, stderr %q", args, code, out.String(), errb.String())
		}
	}
	var out, errb bytes.Buffer
	if code := run([]string{"evaluate", t.TempDir()}, &out, &errb); code != 1 || out.Len() != 0 {
		t.Errorf("a directory that is not a case: exit %d, stdout %q", code, out.String())
	}
}
