package evalcase_test

import (
	"testing"

	"hop.top/pact-go/runner/evalcase"
)

// rolesSource is a declared capability for the roles mapping of
// admission/valid, whose native claim names configured-finance-validator-v1.
func rolesSource() map[string]any {
	return map[string]any{
		"source_id":                   "configured-finance-validator-v1",
		"best_max_age_seconds":        60,
		"best_status_max_age_seconds": 30,
		"live_check":                  false,
		"change_feed":                 "poll_delta",
	}
}

// withSource sets the source of the roles mapping of admission/valid,
// native_mappings[1], through f.
func withSource(t *testing.T, root string, f func(src map[string]any) any) {
	t.Helper()
	editJSON(t, root, "admission/valid/config.json", func(c map[string]any) {
		m := c["native_mappings"].([]any)[1].(map[string]any)
		m["source"] = f(rolesSource())
	})
}

// TestNativeMappingSource: native_mappings[].source is optional, null or an
// object with exactly its five members (spec/v1.0/fixtures/README.md, config.json
// additions), parsed strictly.
func TestNativeMappingSource(t *testing.T) {
	const id = "admission/valid"
	c, err := evalcase.Load(repoFixtures, id)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range c.Exchanges[0].Config.NativeMappings {
		if m.Source != nil {
			t.Errorf("%s: source %+v, want none", m.NativePath, m.Source)
		}
	}

	root := caseTree(t, id)
	withSource(t, root, func(src map[string]any) any { return src })
	c, err = evalcase.Load(root, id)
	if err != nil {
		t.Fatal(err)
	}
	got := c.Exchanges[0].Config.NativeMappings[1].Source
	want := evalcase.NativeSource{
		SourceID: "configured-finance-validator-v1", BestMaxAgeSeconds: 60,
		BestStatusMaxAgeSeconds: 30, LiveCheck: false, ChangeFeed: "poll_delta",
	}
	if got == nil || *got != want {
		t.Fatalf("source %+v, want %+v", got, want)
	}

	root = caseTree(t, id)
	withSource(t, root, func(map[string]any) any { return nil })
	if c, err = evalcase.Load(root, id); err != nil || c.Exchanges[0].Config.NativeMappings[1].Source != nil {
		t.Fatalf("null source: %v %+v", err, c)
	}

	for name, tc := range map[string]struct {
		edit func(src map[string]any) any
		want string
	}{
		"unknown member":         {func(s map[string]any) any { s["cache_seconds"] = 1; return s }, "config.json"},
		"no source_id":           {func(s map[string]any) any { delete(s, "source_id"); return s }, "source_id"},
		"empty source_id":        {func(s map[string]any) any { s["source_id"] = ""; return s }, "source_id"},
		"no best_max_age":        {func(s map[string]any) any { delete(s, "best_max_age_seconds"); return s }, "best_max_age_seconds"},
		"no best_status":         {func(s map[string]any) any { delete(s, "best_status_max_age_seconds"); return s }, "best_status_max_age_seconds"},
		"no live_check":          {func(s map[string]any) any { delete(s, "live_check"); return s }, "live_check"},
		"no change_feed":         {func(s map[string]any) any { delete(s, "change_feed"); return s }, "change_feed"},
		"negative bound":         {func(s map[string]any) any { s["best_max_age_seconds"] = -1; return s }, "best_max_age_seconds"},
		"unknown change feed":    {func(s map[string]any) any { s["change_feed"] = "webhook"; return s }, "change_feed"},
		"live_check a string":    {func(s map[string]any) any { s["live_check"] = "false"; return s }, "config.json"},
		"no live check, bound 0": {func(s map[string]any) any { s["best_status_max_age_seconds"] = 0; return s }, "at least 1"},
		"other source_id":        {func(s map[string]any) any { s["source_id"] = "scim-northstar"; return s }, "source_id"},
		"an array":               {func(s map[string]any) any { return []any{s} }, "config.json"},
	} {
		t.Run(name, func(t *testing.T) {
			root := caseTree(t, id)
			withSource(t, root, tc.edit)
			_, err := evalcase.Load(root, id)
			wantErr(t, err, tc.want)
		})
	}

	// A live source may declare a status bound of zero.
	root = caseTree(t, id)
	withSource(t, root, func(s map[string]any) any {
		s["live_check"], s["best_status_max_age_seconds"] = true, 0
		return s
	})
	if _, err := evalcase.Load(root, id); err != nil {
		t.Errorf("live source with bound 0: %v", err)
	}
}
