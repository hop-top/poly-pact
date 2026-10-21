package adaptertest

import (
	"slices"
	"strings"
	"testing"

	"hop.top/pact-go/adapter"
)

// caseWith returns minimalCase, an authenticate_native case that expects a
// denial, with another id and outcome.
func caseWith(id, outcome string) string {
	s := strings.Replace(minimalCase, "COMMON-01.one", id, 1)
	return strings.Replace(s, `"denied"`, `"`+outcome+`"`, 1)
}

// bindingCaseJSON is a resolve_agent_binding case that expects UNKNOWN.
func bindingCaseJSON(id string) string {
	return `{
  "case_version": 1,
  "id": "` + id + `",
  "title": "A binding case",
  "draft": ["17.1"],
  "native_state": {"model": "common/1"},
  "call": {
    "realm": {"tenant_id": "acme", "environment_id": "https://gateway.example/environments/finance"},
    "workload": "w-1",
    "agent_id": "https://identity.example/agents/a"
  },
  "expect": {"function": "resolve_agent_binding", "outcome": "unknown"}
}`
}

// The principal and operation of the authorize_native, check_context and
// read_native_claim cases below.
const (
	callPrincipal = `"principal": {"id": "p", "realm": {"tenant_id": "t", "environment_id": "e"}, "workload": "w"}`
	callOperation = `"operation": {"operation_id": "o", "environment_id": "e", "principal_id": "p", "action": "a", "resources": [], "method": "GET", "target_uri": "https://x.example/", "body_digest": "", "headers": {}}`
)

// callCaseJSON is a case of the function fn with the call members call that
// expects outcome.
func callCaseJSON(id, fn, outcome, call string) string {
	return `{
  "case_version": 1,
  "id": "` + id + `",
  "title": "A ` + fn + ` case",
  "draft": ["17.1"],
  "native_state": {"model": "common/1"},
  "call": {` + call + `},
  "expect": {"function": "` + fn + `", "outcome": "` + outcome + `"}
}`
}

// authorizeCaseJSON is an authorize_native case that expects outcome.
func authorizeCaseJSON(id, outcome string) string {
	return callCaseJSON(id, "authorize_native", outcome, callPrincipal+", "+callOperation)
}

// replacedTree holds common cases of four functions and the cases of the
// adapter "mech": a denial, an authenticated principal, a binding, an
// error, two authorize_native decisions and a check_context verdict.
func replacedTree() map[string]string {
	return map[string]string{
		"adapters/_common/a.json":      caseWith("COMMON-01.one", "error"),
		"adapters/_common/b.json":      bindingCaseJSON("COMMON-08.one"),
		"adapters/_common/c.json":      authorizeCaseJSON("COMMON-06.one", "ALLOW"),
		"adapters/_common/d.json":      callCaseJSON("COMMON-04.one", "read_native_claim", "error", callPrincipal+`, "native_path": "/x"`),
		"adapters/mech/mech-01.json":   caseWith("MECH-01.denied", "denied"),
		"adapters/mech/mech-02.json":   caseWith("MECH-02.authenticated", "authenticated"),
		"adapters/mech/mech-03.json":   bindingCaseJSON("MECH-03.binding"),
		"adapters/mech/mech-04.json":   caseWith("MECH-04.error", "error"),
		"adapters/mech/mech-05.json":   authorizeCaseJSON("MECH-05.allow", "ALLOW"),
		"adapters/mech/mech-06.json":   authorizeCaseJSON("MECH-06.deny", "DENY"),
		"adapters/mech/mech-07.json":   callCaseJSON("MECH-07.check", "check_context", "PASS", callPrincipal+", "+callOperation+`, "check_id": "c"`),
		"adapters/mech/mech-08.json":   callCaseJSON("MECH-08.claim", "read_native_claim", "error", callPrincipal+`, "native_path": "/x"`),
		"adapters/other/other-01.json": caseWith("OTHER-01.denied", "denied"),
	}
}

func TestCheckReplaced(t *testing.T) {
	tree := replacedTree()
	// MECH-02 expects a principal, so its case needs one.
	tree["adapters/mech/mech-02.json"] = strings.Replace(tree["adapters/mech/mech-02.json"],
		`"outcome": "authenticated"}`, `"outcome": "authenticated", "principal": {"id": "p"}}`, 1)
	cases, err := Load(treeOf(tree), "mech")
	if err != nil {
		t.Fatal(err)
	}
	ok := Replacement{By: "MECH-01.denied", Reason: "the mechanism has no bearer token"}
	if err := checkReplaced(cases, Options{Adapter: "mech", Replaced: map[string]Replacement{"COMMON-01.one": ok}}); err != nil {
		t.Errorf("a valid declaration is refused: %v", err)
	}
	if err := checkReplaced(cases, Options{Adapter: "mech", Replaced: map[string]Replacement{
		"COMMON-01.one": {By: "MECH-04.error", Reason: "r"},
	}}); err != nil {
		t.Errorf("a replacement with another rejected outcome is refused: %v", err)
	}
	// An authorize_native case may be replaced as well, under the same rules
	// (spec/v1.0/fixtures/adapters/README.md, "Replaced common cases").
	if err := checkReplaced(cases, Options{Adapter: "mech", Replaced: map[string]Replacement{
		"COMMON-06.one": {By: "MECH-05.allow", Reason: "the decision answer carries no decision time"},
	}}); err != nil {
		t.Errorf("a valid authorize_native declaration is refused: %v", err)
	}
	if err := checkReplaced(cases, Options{Adapter: "mech", Replaced: map[string]Replacement{
		"COMMON-01.one": ok,
		"COMMON-06.one": {By: "MECH-05.allow", Reason: "r"},
	}}); err != nil {
		t.Errorf("declarations of both functions are refused: %v", err)
	}
	for _, tc := range []struct {
		name string
		id   string
		rep  Replacement
		want string
	}{
		{"unknown id", "COMMON-01.none", ok, "is not a common case"},
		{"adapter case as the original", "MECH-04.error", ok, "is not a common case"},
		{"original of another function", "COMMON-08.one", Replacement{By: "MECH-03.binding", Reason: "r"}, "only authenticate_native and authorize_native cases"},
		{"read_native_claim original", "COMMON-04.one", Replacement{By: "MECH-08.claim", Reason: "r"}, "only authenticate_native and authorize_native cases"},
		{"authorize_native replaced by check_context", "COMMON-06.one", Replacement{By: "MECH-07.check", Reason: "r"}, "is a check_context case"},
		{"authorize_native replaced by authenticate_native", "COMMON-06.one", Replacement{By: "MECH-02.authenticated", Reason: "r"}, "is a authenticate_native case"},
		{"authorize_native replaced by the other outcome class", "COMMON-06.one", Replacement{By: "MECH-06.deny", Reason: "r"}, "other outcome class"},
		{"authorize_native with an empty reason", "COMMON-06.one", Replacement{By: "MECH-05.allow", Reason: ""}, "gives no reason"},
		{"no replacement", "COMMON-01.one", Replacement{Reason: "r"}, "names no replacement"},
		{"unknown replacement", "COMMON-01.one", Replacement{By: "MECH-09.none", Reason: "r"}, "not a case of adapters/mech"},
		{"common case as the replacement", "COMMON-01.one", Replacement{By: "COMMON-01.one", Reason: "r"}, "not a case of adapters/mech"},
		{"replacement of another function", "COMMON-01.one", Replacement{By: "MECH-03.binding", Reason: "r"}, "is a resolve_agent_binding case"},
		{"replacement of the other outcome class", "COMMON-01.one", Replacement{By: "MECH-02.authenticated", Reason: "r"}, "other outcome class"},
		{"empty reason", "COMMON-01.one", Replacement{By: "MECH-01.denied", Reason: " "}, "gives no reason"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := checkReplaced(cases, Options{Adapter: "mech", Replaced: map[string]Replacement{tc.id: tc.rep}})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("checkReplaced = %v, want an error containing %q", err, tc.want)
			}
		})
	}
	t.Run("another adapter's case is no replacement", func(t *testing.T) {
		other, err := Load(treeOf(tree), "other")
		if err != nil {
			t.Fatal(err)
		}
		err = checkReplaced(other, Options{Adapter: "other", Replaced: map[string]Replacement{"COMMON-01.one": ok}})
		if err == nil || !strings.Contains(err.Error(), "not a case of adapters/other") {
			t.Errorf("checkReplaced = %v, want the replacement refused", err)
		}
	})
}

func TestVerdict(t *testing.T) {
	rep := Replacement{By: "MECH-01.denied", Reason: "no bearer token"}
	fails := []string{"principal id is \"x\""}

	errs, logs := verdict("COMMON-01.one", fails, Replacement{}, false)
	if !slices.Equal(errs, fails) || len(logs) != 0 {
		t.Errorf("undeclared failing case: errors %q, logs %q; want its failures as errors", errs, logs)
	}
	errs, logs = verdict("COMMON-01.one", nil, Replacement{}, false)
	if len(errs) != 0 || len(logs) != 0 {
		t.Errorf("undeclared passing case: errors %q, logs %q", errs, logs)
	}
	errs, _ = verdict("COMMON-01.one", nil, rep, true)
	if len(errs) != 1 || !strings.Contains(errs[0], "declared replaced by MECH-01.denied but passes") {
		t.Errorf("declared passing case: errors %q, want the stale declaration reported", errs)
	}
	errs, logs = verdict("COMMON-01.one", fails, rep, true)
	if len(errs) != 0 || !slices.Contains(logs, fails[0]) || !strings.Contains(logs[0], "no bearer token") {
		t.Errorf("declared failing case: errors %q, logs %q; want no error and the failures logged", errs, logs)
	}
}

func TestRunReplaced(t *testing.T) {
	denying := authFake(adapter.Principal{}, &adapter.NativeDenial{Reason: adapter.DenialNoCredential})
	tree := treeOf(map[string]string{
		"adapters/_common/a.json":    strings.Replace(caseWith("COMMON-01.one", "error"), `"outcome": "error"`, `"outcome": "error", "reason_code": "DEPENDENCY_UNAVAILABLE"`, 1),
		"adapters/mech/mech-01.json": caseWith("MECH-01.denied", "denied"),
	})
	opts := Options{Fixtures: tree, Adapter: "mech", Replaced: map[string]Replacement{
		"COMMON-01.one": {By: "MECH-01.denied", Reason: "the mechanism cannot produce this error"},
	}}

	t.Run("declared, failing, valid replacement", func(t *testing.T) {
		Run(t, factoryFor(denying), opts)
	})

	t.Run("evaluate ignores the declaration", func(t *testing.T) {
		res, err := Evaluate(t, factoryFor(denying), opts)
		if err != nil {
			t.Fatal(err)
		}
		if len(res) != 2 || res[0].ID != "COMMON-01.one" || res[0].Passed() || !res[1].Passed() {
			t.Errorf("results = %+v; want the replaced case reported as run and failed", res)
		}
	})
}
