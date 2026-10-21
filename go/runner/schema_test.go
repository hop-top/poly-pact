package runner

// Lockstep test: schemas/pactc-report.v1.schema.json and the output of
// WriteJSON must agree. The assertions read the schema document's own
// constraints (required members, const and enum values, declared
// properties, closed objects) instead of using a JSON Schema validator, so
// they fail when either side drifts.

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"hop.top/pact-go/runner/manifest"
)

func loadReportSchema(t *testing.T) map[string]any {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("schemas", "pactc-report.v1.schema.json"))
	if err != nil {
		t.Fatalf("schema file: %v", err)
	}
	var s map[string]any
	if err := json.Unmarshal(data, &s); err != nil {
		t.Fatalf("schema file: %v", err)
	}
	return s
}

func node(t *testing.T, parent map[string]any, path ...string) map[string]any {
	t.Helper()
	n := parent
	for _, p := range path {
		next, ok := n[p].(map[string]any)
		if !ok {
			t.Fatalf("schema has no object at %v", path)
		}
		n = next
	}
	return n
}

func strs(v any) []string {
	var out []string
	if a, ok := v.([]any); ok {
		for _, x := range a {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}

// closed checks that the schema object n is a closed object whose required
// members are exactly want, and that every member of the emitted object out
// is declared.
func closed(t *testing.T, where string, n map[string]any, want []string, out map[string]any) {
	t.Helper()
	if n["type"] != "object" || n["additionalProperties"] != false {
		t.Errorf("%s: schema is not a closed object: type %v, additionalProperties %v", where, n["type"], n["additionalProperties"])
	}
	req := strs(n["required"])
	slices.Sort(req)
	w := slices.Clone(want)
	slices.Sort(w)
	if !slices.Equal(req, w) {
		t.Errorf("%s: required %v, want %v", where, req, w)
	}
	props, _ := n["properties"].(map[string]any)
	for k := range out {
		if _, ok := props[k]; !ok {
			t.Errorf("%s: emitted member %q is not declared", where, k)
		}
	}
	for _, k := range want {
		if _, ok := out[k]; !ok {
			t.Errorf("%s: required member %q not emitted", where, k)
		}
	}
}

func enumOf(t *testing.T, n map[string]any) []string {
	t.Helper()
	e := strs(n["enum"])
	if len(e) == 0 {
		t.Fatalf("schema node has no enum: %v", n)
	}
	return e
}

// lockstepReport has a PASS, a FAIL with details and a SKIP with details,
// and a failing manifest check with details.
func lockstepReport(t *testing.T) map[string]any {
	t.Helper()
	root := subsetRoot(t, "admission/valid")
	writeFile(t, filepath.Join(root, "admission", "stray", "config.json"), "{}")
	cfg := fakeImplCfg(t, "good", root)
	rep, err := Run(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfg.EvaluateCmd = ""
	skipped, err := Run(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfg = fakeImplCfg(t, "crash", root)
	failed, err := Run(cfg)
	if err != nil {
		t.Fatal(err)
	}
	rep.Fixtures = append(rep.Fixtures, skipped.Fixtures...)
	rep.Fixtures = append(rep.Fixtures, failed.Fixtures...)

	var buf bytes.Buffer
	if err := rep.WriteJSON(&buf); err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestReportSchemaLockstep(t *testing.T) {
	schema := loadReportSchema(t)
	if got := schema["$schema"]; got != "https://json-schema.org/draft/2020-12/schema" {
		t.Errorf("$schema = %v, want draft 2020-12", got)
	}
	out := lockstepReport(t)

	closed(t, "report", schema, []string{"schema", "summary", "manifest", "fixtures"}, out)
	if c := node(t, schema, "properties", "schema")["const"]; c != SchemaID || out["schema"] != SchemaID {
		t.Errorf("schema const %v, emitted %v, want %q", c, out["schema"], SchemaID)
	}

	sum, _ := out["summary"].(map[string]any)
	closed(t, "summary", node(t, schema, "properties", "summary"), []string{"pass", "fail", "skip"}, sum)
	for _, k := range []string{"pass", "fail", "skip"} {
		p := node(t, schema, "properties", "summary", "properties", k)
		if p["type"] != "integer" || p["minimum"] != 0.0 {
			t.Errorf("summary.%s: %v, want a non-negative integer", k, p)
		}
	}
	if sum["pass"] != 1.0 || sum["fail"] != 2.0 || sum["skip"] != 1.0 {
		t.Errorf("summary = %v, want pass 1, fail 2 (manifest and crash), skip 1", sum)
	}

	man, _ := out["manifest"].(map[string]any)
	mn := node(t, schema, "properties", "manifest")
	closed(t, "manifest", mn, []string{"status"}, man)
	if got, want := enumOf(t, node(t, mn, "properties", "status")), []string{string(StatusPass), string(StatusFail)}; !slices.Equal(got, want) {
		t.Errorf("manifest.status enum %v, want %v", got, want)
	}
	if _, ok := man["details"].([]any); !ok {
		t.Errorf("manifest details not emitted as an array: %v", man)
	}
	if d := node(t, mn, "properties", "details"); d["type"] != "array" || node(t, d, "items")["type"] != "string" {
		t.Errorf("manifest.details: %v, want an array of strings", d)
	}

	fx := node(t, schema, "properties", "fixtures")
	if fx["type"] != "array" {
		t.Errorf("fixtures: type %v, want array", fx["type"])
	}
	item := node(t, fx, "items")
	arr, _ := out["fixtures"].([]any)
	if len(arr) != 3 {
		t.Fatalf("emitted %d fixture results, want 3", len(arr))
	}
	seen := map[string]bool{}
	for _, a := range arr {
		r, _ := a.(map[string]any)
		closed(t, "fixtures[]", item, []string{"id", "verb", "status"}, r)
		seen[r["status"].(string)] = true
	}
	if len(seen) != 3 {
		t.Errorf("statuses emitted %v, want PASS, FAIL and SKIP", seen)
	}
	if got, want := enumOf(t, node(t, item, "properties", "status")), []string{string(StatusPass), string(StatusFail), string(StatusSkip)}; !slices.Equal(got, want) {
		t.Errorf("fixtures[].status enum %v, want %v", got, want)
	}
	var verbs []string
	for _, v := range Verbs() {
		verbs = append(verbs, string(v))
	}
	if got := enumOf(t, node(t, item, "properties", "verb")); !slices.Equal(got, verbs) {
		t.Errorf("fixtures[].verb enum %v, want %v", got, verbs)
	}
	if d := node(t, item, "properties", "details"); d["type"] != "array" || node(t, d, "items")["type"] != "string" {
		t.Errorf("fixtures[].details: %v, want an array of strings", d)
	}
	if id := node(t, item, "properties", "id"); id["type"] != "string" {
		t.Errorf("fixtures[].id: %v, want a string", id)
	}

	// capabilities: the declared ones at the top level, always emitted, and
	// the entry's on a result, both arrays of capability tokens.
	if _, ok := out["capabilities"].([]any); !ok {
		t.Errorf("capabilities not emitted as an array: %v", out["capabilities"])
	}
	for where, n := range map[string]map[string]any{
		"capabilities":            node(t, schema, "properties", "capabilities"),
		"fixtures[].capabilities": node(t, item, "properties", "capabilities"),
	} {
		if n["type"] != "array" || n["uniqueItems"] != true {
			t.Errorf("%s: %v, want an array of distinct items", where, n)
		}
		if got := enumOf(t, node(t, n, "items")); !slices.Equal(got, manifest.Capabilities()) {
			t.Errorf("%s items enum %v, want %v", where, got, manifest.Capabilities())
		}
	}
}

// TestReportJSONEmptyRun: a run that selects nothing still emits arrays,
// never null.
func TestReportJSONEmptyRun(t *testing.T) {
	var buf bytes.Buffer
	if err := (&Report{Manifest: Check{Status: StatusPass}}).WriteJSON(&buf); err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if _, ok := out["fixtures"].([]any); !ok {
		t.Errorf("fixtures = %v, want []", out["fixtures"])
	}
	man, _ := out["manifest"].(map[string]any)
	if _, ok := man["details"]; ok {
		t.Errorf("manifest details emitted on PASS without problems: %v", man)
	}
}

// TestReportSkippedSubChecks: a PASS entry whose sub-check was not run
// carries "skipped" in the JSON report, declared by the schema, and the
// table lists the reasons.
func TestReportSkippedSubChecks(t *testing.T) {
	rep := &Report{
		Manifest: Check{Status: StatusPass},
		Fixtures: []Result{{ID: "approval/approved-fresh-exchange", Verb: VerbEvaluate, Status: StatusPass, Skipped: []string{"receipt query: no --receipt-cmd"}}},
	}
	var buf bytes.Buffer
	if err := rep.WriteJSON(&buf); err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	r := out["fixtures"].([]any)[0].(map[string]any)
	item := node(t, loadReportSchema(t), "properties", "fixtures", "items")
	closed(t, "fixtures[]", item, []string{"id", "verb", "status"}, r)
	if d := node(t, item, "properties", "skipped"); d["type"] != "array" || node(t, d, "items")["type"] != "string" {
		t.Errorf("fixtures[].skipped: %v, want an array of strings", d)
	}
	if got, _ := r["skipped"].([]any); len(got) != 1 || got[0] != "receipt query: no --receipt-cmd" {
		t.Errorf("skipped = %v", r["skipped"])
	}
	var table bytes.Buffer
	rep.WriteTable(&table)
	if want := "approval/approved-fresh-exchange evaluate sub-checks skipped:\n  - receipt query: no --receipt-cmd"; !strings.Contains(table.String(), want) {
		t.Errorf("table lacks %q:\n%s", want, table.String())
	}
}

// TestReportSchemaProfile: the additive members profile, transport and
// by_profile (with roles_claimed) of the pactc/v1 report, emitted on every report and declared by
// the schema with the conformance profile ids and transports of package
// manifest.
func TestReportSchemaProfile(t *testing.T) {
	schema := loadReportSchema(t)
	out := lockstepReport(t)
	props := node(t, schema, "properties")

	p := node(t, props, "profile")
	if p["type"] != "string" || !slices.Equal(enumOf(t, p), manifest.ConformanceProfiles()) {
		t.Errorf("profile: %v, want a string of %v", p, manifest.ConformanceProfiles())
	}
	if out["profile"] != "full" {
		t.Errorf("profile emitted %v, want full", out["profile"])
	}

	tr := node(t, props, "transport")
	if tr["type"] != "array" || tr["uniqueItems"] != true || tr["minItems"] != 1.0 || !slices.Equal(enumOf(t, node(t, tr, "items")), manifest.Transports()) {
		t.Errorf("transport: %v, want a non-empty array of distinct %v", tr, manifest.Transports())
	}
	if got := strs(out["transport"]); !slices.Equal(got, []string{"https"}) {
		t.Errorf("transport emitted %v, want [https]", out["transport"])
	}

	bp := node(t, props, "by_profile")
	if bp["type"] != "object" || !slices.Equal(enumOf(t, node(t, bp, "propertyNames")), manifest.ConformanceProfiles()) {
		t.Errorf("by_profile: %v, want an object keyed by conformance profile id", bp)
	}
	counts := []string{"selected", "skipped_not_applicable", "skipped_unsupported", "pass", "fail"}
	emitted, _ := out["by_profile"].(map[string]any)
	full, _ := emitted["full"].(map[string]any)
	if len(emitted) != 1 || full == nil {
		t.Fatalf("by_profile emitted %v, want the run's profile full only", out["by_profile"])
	}
	item := node(t, bp, "additionalProperties")
	closed(t, "by_profile.full", item, counts, full)
	for _, k := range counts {
		c := node(t, item, "properties", k)
		if c["type"] != "integer" || c["minimum"] != 0.0 {
			t.Errorf("by_profile.*.%s: %v, want a non-negative integer", k, c)
		}
	}
	// lockstepReport runs admission/valid three times and keeps the profile
	// summary of the first run: one entry selected and PASS.
	if full["selected"] != 1.0 || full["pass"] != 1.0 || full["skipped_not_applicable"] != 0.0 {
		t.Errorf("by_profile.full emitted %v", full)
	}

	// roles_claimed: additive, so not required, but emitted on every member;
	// the roles of draft Section 22.1 the profile claims, each once, in the
	// order of its table.
	rc := node(t, item, "properties", "roles_claimed")
	if rc["type"] != "array" || rc["uniqueItems"] != true || rc["minItems"] != 3.0 || !slices.Equal(enumOf(t, node(t, rc, "items")), draftRoles(t)) {
		t.Errorf("by_profile.*.roles_claimed: %v, want an array of at least 3 distinct %v", rc, draftRoles(t))
	}
	if !slices.Equal(enumOf(t, node(t, rc, "items")), ConformanceRoles()) {
		t.Errorf("by_profile.*.roles_claimed items enum %v, want ConformanceRoles() %v", rc["items"], ConformanceRoles())
	}
	if got := strs(full["roles_claimed"]); !slices.Equal(got, []string{"Holder", "Gateway", "Validator", "Reputation", "Learning"}) {
		t.Errorf("by_profile.full.roles_claimed emitted %v, want all five roles", full["roles_claimed"])
	}
}
