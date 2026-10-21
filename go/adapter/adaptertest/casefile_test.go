package adaptertest

import (
	"slices"
	"strings"
	"testing"
	"testing/fstest"
)

// minimalCase is a valid authenticate_native case.
const minimalCase = `{
  "case_version": 1,
  "id": "COMMON-01.one",
  "title": "A case",
  "draft": ["17.1"],
  "native_state": {"model": "common/1"},
  "request": {"method": "GET", "url": "https://gateway.example/x"},
  "expect": {"function": "authenticate_native", "outcome": "denied"}
}`

func treeOf(files map[string]string) fstest.MapFS {
	fsys := fstest.MapFS{}
	for name, body := range files {
		fsys[name] = &fstest.MapFile{Data: []byte(body)}
	}
	return fsys
}

func TestLoad(t *testing.T) {
	t.Run("common cases", func(t *testing.T) {
		cases, err := Load(treeOf(map[string]string{
			"adapters/_common/a.json":    minimalCase,
			"adapters/_common/b.json":    strings.Replace(minimalCase, "COMMON-01.one", "COMMON-01.two", 1),
			"adapters/_common/notes.txt": "ignored",
		}), "")
		if err != nil {
			t.Fatal(err)
		}
		if len(cases) != 2 || cases[0].ID != "COMMON-01.one" || cases[1].ID != "COMMON-01.two" {
			t.Fatalf("cases = %+v", cases)
		}
	})

	t.Run("adapter cases follow the common cases", func(t *testing.T) {
		cases, err := Load(treeOf(map[string]string{
			"adapters/_common/a.json":       minimalCase,
			"adapters/basic/basic-01.json":  strings.Replace(minimalCase, "COMMON-01.one", "BASIC-01", 1),
			"adapters/basic/basic-02.json":  strings.Replace(minimalCase, "COMMON-01.one", "BASIC-02", 1),
			"adapters/other/other-01.json":  strings.Replace(minimalCase, "COMMON-01.one", "OTHER-01", 1),
			"adapters/basic/notes/x.json":   strings.Replace(minimalCase, "COMMON-01.one", "BASIC-99", 1),
			"adapters/basic/cases/old.json": strings.Replace(minimalCase, "COMMON-01.one", "BASIC-98", 1),
		}), "basic")
		if err != nil {
			t.Fatal(err)
		}
		var ids []string
		for _, c := range cases {
			ids = append(ids, c.ID)
		}
		if want := []string{"COMMON-01.one", "BASIC-01", "BASIC-02"}; !slices.Equal(ids, want) {
			t.Fatalf("ids = %v, want %v: the adapter's cases are the files of adapters/<name>, with no subdirectory", ids, want)
		}
	})

	t.Run("adapter name without cases", func(t *testing.T) {
		for name, tree := range map[string]map[string]string{
			"no directory":              {"adapters/_common/a.json": minimalCase},
			"only a cases subdirectory": {"adapters/_common/a.json": minimalCase, "adapters/basic/cases/own.json": strings.Replace(minimalCase, "COMMON-01.one", "BASIC-01", 1)},
		} {
			_, err := Load(treeOf(tree), "basic")
			if err == nil || !strings.Contains(err.Error(), "adapters/basic") || strings.Contains(err.Error(), "adapters/basic/cases") {
				t.Errorf("%s: err = %v, want no case files in adapters/basic", name, err)
			}
		}
	})

	t.Run("bad adapter name", func(t *testing.T) {
		for _, name := range []string{"../x", "Basic", "a/b", "-x"} {
			_, err := Load(treeOf(map[string]string{"adapters/_common/a.json": minimalCase}), name)
			if err == nil || !strings.Contains(err.Error(), "adapter name") {
				t.Errorf("Load(%q) = %v, want an adapter name error", name, err)
			}
		}
	})

	t.Run("no common cases", func(t *testing.T) {
		if _, err := Load(treeOf(map[string]string{"adapters/_common/readme.txt": "x"}), ""); err == nil {
			t.Error("no error for a directory without case files")
		}
		if _, err := Load(treeOf(map[string]string{"other/a.json": minimalCase}), ""); err == nil {
			t.Error("no error for a tree without adapters/_common")
		}
	})

	t.Run("duplicate id across directories", func(t *testing.T) {
		_, err := Load(treeOf(map[string]string{
			"adapters/_common/a.json":      minimalCase,
			"adapters/basic/basic-01.json": minimalCase,
		}), "basic")
		if err == nil || !strings.Contains(err.Error(), "used twice") {
			t.Errorf("err = %v, want a duplicate id error", err)
		}
	})
}

// TestCaseFileRules: each mutation of the minimal case breaks one rule of the
// format, and Load names it.
func TestCaseFileRules(t *testing.T) {
	sub := func(old, new string) string {
		if !strings.Contains(minimalCase, old) {
			t.Fatalf("minimalCase lacks %q", old)
		}
		return strings.Replace(minimalCase, old, new, 1)
	}
	tests := []struct {
		name string
		body string
		want string
	}{
		{"unknown member", sub(`"title": "A case",`, `"title": "A case", "surprise": 1,`), "surprise"},
		{"duplicate member", sub(`"title": "A case",`, `"title": "A case", "title": "B",`), "duplicate"},
		{"case version", sub(`"case_version": 1`, `"case_version": 2`), "case_version"},
		{"id shape", sub(`COMMON-01.one`, `common-01`), "does not match"},
		{"id suffix shape", sub(`COMMON-01.one`, `COMMON-01.One`), "does not match"},
		{"empty title", sub(`"A case"`, `" "`), "title is empty"},
		{"native state is not an object", sub(`{"model": "common/1"}`, `[1]`), "native_state"},
		{"native state missing", sub(`"native_state": {"model": "common/1"},`, ``), "native_state"},
		{"negative now", sub(`"title"`, `"now": -1, "title"`), "now"},
		{"unknown function", sub(`authenticate_native`, `authenticate`), "seven functions"},
		{"outcome of another function", sub(`"denied"`, `"mapped"`), "not defined for authenticate_native"},
		// A clock-ahead claim is refused (freshness profile); no outcome accepts
		// a claim with its times clamped instead.
		{"retired bounded outcome", strings.NewReplacer(
			`authenticate_native`, `read_native_claim`,
			`"denied"`, `"bounded"`,
			`"request": {"method": "GET", "url": "https://gateway.example/x"},`, `"call": {"principal": {"id": "p", "realm": {"tenant_id": "t", "environment_id": "e"}}, "native_path": "/x"},`,
		).Replace(minimalCase), `outcome "bounded" is not defined for read_native_claim`},
		{"authenticated without a principal", sub(`"denied"`, `"authenticated"`), "needs expect.principal"},
		{"missing request", sub(`"request": {"method": "GET", "url": "https://gateway.example/x"},`, ``), "needs a request"},
		{"request without a url", sub(`"url": "https://gateway.example/x"`, `"url": ""`), "method and a url"},
		{"bad arrival", sub(`"method": "GET"`, `"method": "GET", "arrival": "sideways"`), "arrival"},
		{"bad header name", sub(`"method": "GET"`, `"method": "GET", "headers": {"X Bad": "1"}`), "header name"},
		{"bad body", sub(`"method": "GET"`, `"method": "GET", "body_b64": "***"`), "base64"},
		{"call argument that does not apply", sub(`"expect"`, `"call": {"native_path": "/x"}, "expect"`), "not an argument of authenticate_native"},
		{"expectation that does not apply", sub(`"outcome": "denied"`, `"outcome": "denied", "claim": {}`), "does not apply"},
		{"empty hook name", sub(`"outcome": "denied"`, `"outcome": "denied", "must_not_call": [" "]`), "empty hook name"},
		{"unknown workload mode", sub(`"title": "A case",`, `"title": "A case", "workloads": "Shared",`), "workloads"},
		{"workload mode of no profile", sub(`"title": "A case",`, `"title": "A case", "workloads": "any",`), "workloads"},
		{"not json", `{`, "strictjson"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(treeOf(map[string]string{"adapters/_common/a.json": tc.body}), "")
			if err == nil {
				t.Fatal("Load accepted the file")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want it to mention %q", err, tc.want)
			}
			if !strings.Contains(err.Error(), "adapters/_common/a.json") {
				t.Errorf("err = %v, want it to name the file", err)
			}
		})
	}
}

// TestWorkloadsMember: a case may say which adapters it applies to, by
// whether the adapter's profile supports workloads shared by several agents.
// "shared" and "dedicated" are the two values; absent, the case applies to
// every adapter.
func TestWorkloadsMember(t *testing.T) {
	for _, tc := range []struct{ member, want string }{
		{``, ""},
		{`"workloads": "shared",`, "shared"},
		{`"workloads": "dedicated",`, "dedicated"},
	} {
		body := strings.Replace(minimalCase, `"title": "A case",`, `"title": "A case", `+tc.member, 1)
		cases, err := Load(treeOf(map[string]string{"adapters/_common/a.json": body}), "")
		if err != nil {
			t.Fatalf("%q: %v", tc.member, err)
		}
		if got := cases[0].Workloads; got != tc.want {
			t.Errorf("%q: Workloads = %q, want %q", tc.member, got, tc.want)
		}
	}
}

// TestEnrolledElsewhereExpectation: expect.binding.enrolled_elsewhere may be
// true only for the outcome unknown, which accepts no other binding member.
func TestEnrolledElsewhereExpectation(t *testing.T) {
	const record = `"agent_id": "https://a.example/a", "operator_id": "https://o.example/o", "holder_jkt": "xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M", "status": "ACTIVE"`
	tests := []struct {
		outcome, binding string
		want             string // "" when the case is valid
	}{
		{"unknown", `"enrolled_elsewhere": true`, ""},
		{"unknown", `"enrolled_elsewhere": false`, ""},
		{"unknown", `"enrolled_elsewhere": true, "agent_id": "https://a.example/a"`, "only enrolled_elsewhere"},
		{"unknown", `"status": "UNKNOWN"`, "only enrolled_elsewhere"},
		{"bound", record + `, "enrolled_elsewhere": false`, ""},
		{"bound", record + `, "enrolled_elsewhere": true`, "enrolled_elsewhere true"},
		{"unusable", record + `, "enrolled_elsewhere": true`, "enrolled_elsewhere true"},
		{"error", `"enrolled_elsewhere": true`, "enrolled_elsewhere true"},
	}
	for _, tc := range tests {
		t.Run(tc.outcome+"/"+tc.binding, func(t *testing.T) {
			body := `{"case_version": 1, "id": "CASE-01", "title": "t", "native_state": {}, ` +
				`"call": {"realm": {"tenant_id": "t", "environment_id": "e"}, "workload": "w", "agent_id": "https://a.example/a"}, ` +
				`"expect": {"function": "resolve_agent_binding", "outcome": "` + tc.outcome + `", "binding": {` + tc.binding + `}}}`
			_, err := Load(treeOf(map[string]string{"adapters/_common/a.json": body}), "")
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("Load rejected a valid case: %v", err)
			case tc.want != "" && err == nil:
				t.Fatal("Load accepted an invalid case")
			case tc.want != "" && !strings.Contains(err.Error(), tc.want):
				t.Fatalf("err = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

// TestCallArgumentsPerFunction: each function requires its arguments and
// rejects the others.
func TestCallArgumentsPerFunction(t *testing.T) {
	const (
		realm     = `"realm": {"tenant_id": "t", "environment_id": "e"}`
		prin      = `"principal": {"id": "p", "realm": {"tenant_id": "t", "environment_id": "e"}, "workload": "w"}`
		op        = `"operation": {"operation_id": "o", "environment_id": "e", "principal_id": "p", "action": "a", "resources": [], "method": "GET", "target_uri": "https://x.example/", "body_digest": "", "headers": {}}`
		binding   = `"binding": {"agent_id": "https://a.example/a", "operator_id": "https://o.example/o", "holder_jkt": "k"}`
		otherPrin = `"principal": {"id": "q", "realm": {"tenant_id": "t", "environment_id": "e"}, "workload": "w"}`
		obs       = `"observation": {"event_id": "e", "event_kind": "ADMISSION", "task_id": "t", "operation_id": "o", "observed_at": 1}`
	)
	tests := []struct {
		fn, outcome, call string
		request           bool
		want              string // "" when the case is valid
	}{
		{"resolve_agent_binding", "unknown", realm + `, "workload": "w", "agent_id": "https://a.example/a"`, false, ""},
		{"resolve_agent_binding", "unknown", realm + `, "agent_id": "https://a.example/a"`, false, "call.workload is required"},
		{"resolve_agent_binding", "unknown", realm + `, "workload": "w"`, false, "call.agent_id is required"},
		{"resolve_agent_binding", "unknown", `"workload": "w", "agent_id": "https://a.example/a"`, false, "call.realm is required"},
		{"resolve_agent_binding", "unknown", realm + `, "workload": "w", "agent_id": "https://a.example/a", "native_path": "/x"`, false, "not an argument"},
		{"resolve_agent_binding", "unusable", realm + `, "workload": "w", "agent_id": "https://a.example/a"`, false, "needs expect.binding"},
		{"map_operation", "error", prin + `, "mapping_version": "m"`, true, ""},
		{"map_operation", "error", prin, true, "call.mapping_version is required"},
		{"map_operation", "error", prin + `, "mapping_version": "m", "agent_id": "https://a.example/a"`, true, "not an argument"},
		{"map_operation", "error", prin + `, "mapping_version": "m"`, false, "needs a request"},
		{"read_native_claim", "error", prin + `, "native_path": "/x"`, false, ""},
		{"read_native_claim", "error", prin + `, "native_path": "/x"`, true, "takes no request"},
		{"read_native_claim", "error", prin + `, "native_path": "/x", ` + op, false, ""},
		{"read_native_claim", "error", prin + `, "native_path": "/x", "intent": {"intent_id": "i", "purpose_id": "p", "description": "", "task_id": "t"}`, false, ""},
		{"read_native_claim", "error", prin + `, "native_path": "/x", "intent": {"intent_id": "i", "purpose_id": "p", "description": "", "task_id": "t"}, ` + op, false, ""},
		{"read_native_claim", "error", `"native_path": "/x", ` + op, false, "call.principal is required"},
		{"read_native_claim", "error", prin + `, "native_path": "/x", "evidence_refs": ["r"]`, false, "not an argument"},
		{"read_native_claim", "error", prin + `, "native_path": "/x", "check_id": "c"`, false, "not an argument"},
		{"check_context", "UNKNOWN", prin + `, ` + op + `, "check_id": ""`, false, ""},
		{"check_context", "UNKNOWN", prin + `, ` + op, false, "call.check_id is required"},
		{"check_context", "UNKNOWN", `"check_id": "c", ` + op, false, "call.principal is required"},
		{"check_context", "UNKNOWN", `"check_id": "c", ` + prin, false, "call.operation is required"},
		{"check_context", "UNKNOWN", `"check_id": "c", ` + prin + `, ` + op + `, "evidence_refs": ["r"]`, false, ""},
		{"check_context", "UNKNOWN", `"check_id": "c", ` + prin + `, ` + op + `, ` + binding, false, ""},
		{"check_context", "UNKNOWN", `"check_id": "c", ` + prin + `, ` + op + `, "binding": {"agent_id": "https://a.example/a", "status": "ACTIVE"}`, false, ""},
		{"check_context", "UNKNOWN", `"check_id": "c", ` + prin + `, ` + op + `, "binding": {"agent_id": "https://a.example/a", "status": "LIVE"}`, false, "not a binding status"},
		{"check_context", "UNKNOWN", `"check_id": "c", ` + otherPrin + `, ` + op, false, "is not call.operation.principal_id"},
		{"read_native_claim", "error", prin + `, "native_path": "/x", ` + binding, false, "call.binding is not an argument"},
		{"authorize_native", "DENY", prin + `, ` + op + `, ` + binding, false, "call.binding is not an argument"},
		{"resolve_agent_binding", "unknown", realm + `, "workload": "w", "agent_id": "https://a.example/a", ` + binding, false, "call.binding is not an argument"},
		{"map_operation", "error", prin + `, "mapping_version": "m", ` + binding, true, "call.binding is not an argument"},
		{"authorize_native", "DENY", prin + `, ` + op, false, ""},
		{"authorize_native", "DENY", prin, false, "call.operation is required"},
		{"record_outcome", "error", obs, false, ""},
		{"record_outcome", "error", ``, false, "call.observation is required"},
	}
	for _, tc := range tests {
		name := tc.fn + "/" + tc.want
		t.Run(name, func(t *testing.T) {
			req := ""
			if tc.request {
				req = `"request": {"method": "GET", "url": "https://gateway.example/x"},`
			}
			call := ""
			if tc.call != "" {
				call = `"call": {` + tc.call + `},`
			}
			body := `{"case_version": 1, "id": "T-01", "title": "t", "native_state": {}, ` + req + call +
				`"expect": {"function": "` + tc.fn + `", "outcome": "` + tc.outcome + `"}}`
			_, err := Load(treeOf(map[string]string{"adapters/_common/a.json": body}), "")
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("Load rejected a valid case: %v", err)
			case tc.want != "" && err == nil:
				t.Fatal("Load accepted an invalid case")
			case tc.want != "" && !strings.Contains(err.Error(), tc.want):
				t.Fatalf("err = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}
