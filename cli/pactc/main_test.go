package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func runPactc(args ...string) (code int, stdout, stderr string) {
	var out, errOut bytes.Buffer
	code = run(args, &out, &errOut)
	return code, out.String(), errOut.String()
}

// fixtures writes a fixture directory with one evaluation case,
// admission/a, and the extra files given.
func fixtures(t *testing.T, extra map[string]string) string {
	t.Helper()
	root := t.TempDir()
	files := map[string]string{
		"manifest.json": `{"manifest_version":1,"entries":[{"id":"admission/a","kind":"evaluate","scope":"runner",` +
			`"path":"admission/a","expected":"expected/admission/a/decision.json","outcome":"ADMISSIBLE",` +
			`"spec_map_row":"CL-11.3","draft_section":"11.3"}]}`,
		"admission/a/config.json":            `{}`,
		"expected/admission/a/decision.json": `{"decision":"ADMISSIBLE","transport_code":null}`,
	}
	for k, v := range extra {
		files[k] = v
	}
	for rel, content := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// TestRunHelpDocumentsContract: pactc run --help states the adapter
// contract: the four command flags with their argv templates, the
// substitutions, no shell, the stdout of each verb, SKIP for a missing
// command, the exit status, fixture selection through the manifest, and
// the report format.
func TestRunHelpDocumentsContract(t *testing.T) {
	for _, args := range [][]string{{"run", "--help"}, {"run", "-h"}} {
		code, stdout, stderr := runPactc(args...)
		if code != 0 {
			t.Fatalf("%v: exit %d, stderr %q", args, code, stderr)
		}
		for _, want := range []string{
			`--evaluate-cmd "tool evaluate {dir} {state}"`,
			`--receipt-cmd "tool receipt {state} {id}"`,
			"{id}", "distinct jti", "unchanged", "evaluated twice",
			`--outcomes-cmd "tool outcomes {dir} {state}"`,
			`--learning-cmd "tool learning {dir} {state}"`,
			"--schema-cmd",
			"{dir}", "{state}", "no shell",
			"pact-admission+jwt", "RFC 9457", "ReputationSnapshot", "registry state",
			"outcomes result object", "identical retry", "within one basis point", "provenance manifest",
			"SKIP", "exit status",
			"--fixtures-root", "spec/v1.0/fixtures", "manifest.json",
			"--fixture", "id prefix", "admission/", "manifest-incomplete",
			"--json", "pactc/v1",
			"--capability", "jws-ed25519", "optional capabilities", "never counted as passed",
		} {
			if !strings.Contains(stdout, want) {
				t.Errorf("%v: help lacks %q", args, want)
			}
		}
		if strings.Contains(stdout, "kind outcomes and schema are SKIP") {
			t.Errorf("%v: help still says outcomes entries are SKIP", args)
		}
	}
}

func TestUsage(t *testing.T) {
	for _, args := range [][]string{nil, {"nope"}, {"run", "--nope"}, {"run", "extra"}} {
		if code, _, stderr := runPactc(args...); code != 2 || !strings.Contains(stderr, "USAGE: ") || !strings.Contains(stderr, "--help' for usage") {
			t.Errorf("%v: exit %d, stderr %q", args, code, stderr)
		}
	}
	for _, args := range [][]string{{"-h"}, {"--help"}, {"help"}} {
		if code, stdout, _ := runPactc(args...); code != 0 || !strings.Contains(stdout, "pactc run") {
			t.Errorf("%v: exit %d, stdout %q", args, code, stdout)
		}
	}
}

func TestRunExitStatus(t *testing.T) {
	root := fixtures(t, nil)
	code, stdout, stderr := runPactc("run", "--fixtures-root", root)
	if code != 0 || !strings.Contains(stdout, "admission/a") || !strings.Contains(stdout, "SKIP") {
		t.Errorf("no commands: exit %d, stdout %q, stderr %q; want 0 with admission/a SKIP", code, stdout, stderr)
	}

	stray := fixtures(t, map[string]string{"admission/b/config.json": `{}`})
	if code, stdout, _ := runPactc("run", "--fixtures-root", stray); code != 1 || !strings.Contains(stdout, "manifest-incomplete") {
		t.Errorf("unlisted file: exit %d, stdout %q; want 1 naming manifest-incomplete", code, stdout)
	}

	if code, _, stderr := runPactc("run", "--fixtures-root", root, "--fixture", "approval/"); code != 2 || !strings.Contains(stderr, "approval/") {
		t.Errorf("selector matching nothing: exit %d, stderr %q; want 2", code, stderr)
	}
	if code, _, _ := runPactc("run", "--fixtures-root", t.TempDir()); code != 2 {
		t.Errorf("no manifest.json: exit %d, want 2", code)
	}
}

func TestRunJSON(t *testing.T) {
	root := fixtures(t, nil)
	code, stdout, stderr := runPactc("run", "--json", "--fixtures-root", root, "--fixture", "admission/", "--fixture", "admission/a")
	if code != 0 {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	var rep struct {
		Schema   string `json:"schema"`
		Fixtures []struct {
			ID     string `json:"id"`
			Verb   string `json:"verb"`
			Status string `json:"status"`
		} `json:"fixtures"`
	}
	if err := json.Unmarshal([]byte(stdout), &rep); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, stdout)
	}
	if rep.Schema != "pactc/v1" || len(rep.Fixtures) != 1 || rep.Fixtures[0].ID != "admission/a" ||
		rep.Fixtures[0].Verb != "evaluate" || rep.Fixtures[0].Status != "SKIP" {
		t.Errorf("report %+v", rep)
	}
}

func TestDefaultFixturesRoot(t *testing.T) {
	root := fixtures(t, nil)
	t.Chdir(t.TempDir())
	if err := os.MkdirAll(filepath.Join("spec", "v1.0"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(root, filepath.Join("spec", "v1.0", "fixtures")); err != nil {
		t.Fatal(err)
	}
	if code, stdout, stderr := runPactc("run"); code != 0 || !strings.Contains(stdout, "admission/a") {
		t.Errorf("default root spec/v1.0/fixtures: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
}

// TestKitValidate: the command tree passes the kit validation that Execute
// runs before every command (annotations, help text, shape).
func TestKitValidate(t *testing.T) {
	if err := newCLI().Root.Validate(); err != nil {
		t.Fatal(err)
	}
}

// TestRunCapabilities: --capability declares an optional capability of the
// implementation; an entry that tests one not declared is SKIP with that
// reason, and an unknown capability is a usage error.
func TestRunCapabilities(t *testing.T) {
	root := fixtures(t, map[string]string{
		"manifest.json": `{"manifest_version":1,"entries":[{"id":"admission/a","kind":"evaluate","scope":"runner",` +
			`"path":"admission/a","expected":"expected/admission/a/decision.json","outcome":"ADMISSIBLE",` +
			`"spec_map_row":"CL-7.2","draft_section":"7.2","capabilities":["jws-ed25519"]}]}`,
	})
	type report struct {
		Capabilities []string `json:"capabilities"`
		Fixtures     []struct {
			Status       string   `json:"status"`
			Details      []string `json:"details"`
			Capabilities []string `json:"capabilities"`
		} `json:"fixtures"`
	}
	for _, tt := range []struct {
		args     []string
		declared []string
		reason   string
	}{
		{nil, []string{}, "optional capability jws-ed25519 not declared"},
		{[]string{"--capability", "jws-ed25519"}, []string{"jws-ed25519"}, "no --evaluate-cmd"},
	} {
		code, stdout, stderr := runPactc(append([]string{"run", "--json", "--fixtures-root", root}, tt.args...)...)
		if code != 0 {
			t.Fatalf("%v: exit %d, stderr %q", tt.args, code, stderr)
		}
		var rep report
		if err := json.Unmarshal([]byte(stdout), &rep); err != nil {
			t.Fatalf("stdout is not JSON: %v\n%s", err, stdout)
		}
		if strings.Join(rep.Capabilities, ",") != strings.Join(tt.declared, ",") || len(rep.Fixtures) != 1 ||
			rep.Fixtures[0].Status != "SKIP" || strings.Join(rep.Fixtures[0].Capabilities, ",") != "jws-ed25519" ||
			len(rep.Fixtures[0].Details) != 1 || !strings.Contains(rep.Fixtures[0].Details[0], tt.reason) {
			t.Errorf("%v: report %+v, want SKIP because %q", tt.args, rep, tt.reason)
		}
	}
	if code, _, stderr := runPactc("run", "--fixtures-root", root, "--capability", "ed25519"); code != 2 || !strings.Contains(stderr, `"ed25519"`) {
		t.Errorf("unknown capability: exit %d, stderr %q; want 2 naming it", code, stderr)
	}
}

// TestRunProfileAndTransport: --profile and --transport select the entries
// that list the conformance profile and share a transport; an unknown profile
// or transport is a usage error naming the known ones, and a run that
// selects no entry exits 3, never 0.
func TestRunProfileAndTransport(t *testing.T) {
	root := fixtures(t, map[string]string{
		"manifest.json": `{"manifest_version":1,"entries":[` +
			`{"id":"admission/a","kind":"evaluate","scope":"runner","path":"admission/a",` +
			`"expected":"expected/admission/a/decision.json","outcome":"ADMISSIBLE","spec_map_row":"CL-11.3","draft_section":"11.3"},` +
			`{"id":"admission/b","kind":"evaluate","scope":"runner","path":"admission/b",` +
			`"expected":"expected/admission/b/decision.json","outcome":"ADMISSIBLE","spec_map_row":"CL-11.3","draft_section":"11.3",` +
			`"conformance_profile":["single-owner"],"transport":["stdio-ipc"],"layer":"transcript"}]}`,
		"admission/b/config.json":            `{}`,
		"expected/admission/b/decision.json": `{"decision":"ADMISSIBLE","transport_code":null}`,
	})
	type report struct {
		Profile   string   `json:"profile"`
		Transport []string `json:"transport"`
		ByProfile map[string]struct {
			Selected             int      `json:"selected"`
			SkippedNotApplicable int      `json:"skipped_not_applicable"`
			RolesClaimed         []string `json:"roles_claimed"`
		} `json:"by_profile"`
		Fixtures []struct {
			ID string `json:"id"`
		} `json:"fixtures"`
	}
	for _, tt := range []struct {
		args      []string
		code      int
		profile   string
		transport []string
		ids       []string
	}{
		{nil, 0, "full", []string{"https"}, []string{"admission/a"}},
		{[]string{"--profile", "full", "--transport", "https"}, 0, "full", []string{"https"}, []string{"admission/a"}},
		{[]string{"--profile", "single-owner"}, 3, "single-owner", []string{"https"}, nil},
		{[]string{"--profile", "single-owner", "--transport", "stdio-ipc"}, 0, "single-owner", []string{"stdio-ipc"}, []string{"admission/b"}},
		{[]string{"--transport", "stdio-ipc"}, 3, "full", []string{"stdio-ipc"}, nil},
		{[]string{"--transport", "stdio-ipc", "--transport", "https"}, 0, "full", []string{"https", "stdio-ipc"}, []string{"admission/a"}},
	} {
		code, stdout, stderr := runPactc(append([]string{"run", "--json", "--fixtures-root", root}, tt.args...)...)
		if code != tt.code {
			t.Errorf("%v: exit %d, want %d; stderr %q", tt.args, code, tt.code, stderr)
		}
		var rep report
		if err := json.Unmarshal([]byte(stdout), &rep); err != nil {
			t.Fatalf("%v: stdout is not JSON: %v\n%s", tt.args, err, stdout)
		}
		var ids []string
		for _, f := range rep.Fixtures {
			ids = append(ids, f.ID)
		}
		if rep.Profile != tt.profile || strings.Join(rep.Transport, ",") != strings.Join(tt.transport, ",") || strings.Join(ids, ",") != strings.Join(tt.ids, ",") {
			t.Errorf("%v: profile %q transport %v fixtures %v", tt.args, rep.Profile, rep.Transport, ids)
		}
		if s := rep.ByProfile[tt.profile]; s.Selected != len(tt.ids) || s.SkippedNotApplicable != 2-len(tt.ids) {
			t.Errorf("%v: by_profile %+v", tt.args, rep.ByProfile)
		}
		// Draft Section 22.1 roles minus the declaration's omitted_roles:
		// single-owner omits Reputation and Learning, full omits none.
		roles := "Holder,Gateway,Validator,Reputation,Learning"
		if tt.profile == "single-owner" {
			roles = "Holder,Gateway,Validator"
		}
		if got := strings.Join(rep.ByProfile[tt.profile].RolesClaimed, ","); got != roles {
			t.Errorf("%v: by_profile.%s.roles_claimed %q, want %q", tt.args, tt.profile, got, roles)
		}
		if tt.code == 3 && !strings.Contains(stderr, "no entry") {
			t.Errorf("%v: stderr %q does not say that no entry was selected", tt.args, stderr)
		}
	}
	// The table run of an empty selection says so too, and still exits 3.
	if code, stdout, stderr := runPactc("run", "--fixtures-root", root, "--profile", "single-owner"); code != 3 || !strings.Contains(stdout, "selected 0") || !strings.Contains(stderr, "no entry") {
		t.Errorf("--profile single-owner: exit %d, stdout %q, stderr %q; want 3", code, stdout, stderr)
	}
	for _, tt := range []struct {
		args []string
		want []string
	}{
		{[]string{"--profile", "lite"}, []string{`"lite"`, "full, single-owner"}},
		{[]string{"--transport", "tcp"}, []string{`"tcp"`, "https, stdio-ipc"}},
		{[]string{"--transport", "stdio"}, []string{`"stdio"`, "https, stdio-ipc"}},
	} {
		if code, _, stderr := runPactc(append([]string{"run", "--fixtures-root", root}, tt.args...)...); code != 2 || !containsAll(stderr, tt.want) {
			t.Errorf("%v: exit %d, stderr %q; want 2 naming %v", tt.args, code, stderr, tt.want)
		}
	}
	// An unknown profile in the manifest fails the run.
	bad := fixtures(t, map[string]string{
		"manifest.json": `{"manifest_version":1,"entries":[{"id":"admission/a","kind":"evaluate","scope":"runner",` +
			`"path":"admission/a","expected":"expected/admission/a/decision.json","outcome":"ADMISSIBLE",` +
			`"spec_map_row":"CL-11.3","draft_section":"11.3","conformance_profile":["lite"]}]}`,
	})
	if code, stdout, _ := runPactc("run", "--fixtures-root", bad); code != 1 || !strings.Contains(stdout, "entry-conformance-profile") {
		t.Errorf("unknown profile in the manifest: exit %d, stdout %q; want 1", code, stdout)
	}
}

// TestRunHelpDocumentsProfile: pactc run --help documents --profile and
// --transport, their defaults and exit status 3.
func TestRunHelpDocumentsProfile(t *testing.T) {
	code, stdout, stderr := runPactc("run", "--help")
	if code != 0 {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	for _, want := range []string{"--profile", "--transport", "single-owner", "spec/v1.0/profiles/registry.json", "https", "stdio-ipc", "not applicable", "every layer", "3 when"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("help lacks %q", want)
		}
	}
}

func containsAll(s string, parts []string) bool {
	for _, p := range parts {
		if !strings.Contains(s, p) {
			return false
		}
	}
	return true
}
