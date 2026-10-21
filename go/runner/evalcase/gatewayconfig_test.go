package evalcase_test

import (
	"reflect"
	"testing"

	"hop.top/pact-go/runner/evalcase"
)

// The Appendix B values the gateway configuration members default to
// (spec/v1.0/fixtures/README.md, config.json additions): the B.2/B.3 purpose
// mapping and the B.6 context mapping and scoring revision.
var (
	b3Purposes = map[string][]string{"https://policies.example/purposes/invoice-summary/v1": {"invoice.read"}}
	b6Context  = evalcase.ReputationContext{
		ResourceClasses: []evalcase.ResourceClass{{Prefix: "https://invoices.example/invoices/", Class: "department-finance-invoice"}},
		RuntimeClass:    "managed-v1",
	}
	b6Revisions = []string{"finance-scoring-1"}
)

// TestGatewayConfigDefaults: a config.json that names none of purposes,
// reputation_context and active_policy.scoring_policy_revisions has the
// Appendix B mapping, so every committed case reads unchanged.
func TestGatewayConfigDefaults(t *testing.T) {
	for _, e := range evaluateEntries(t) {
		c, err := evalcase.Read(repoFixtures, e.ID)
		if err != nil {
			t.Fatal(err)
		}
		for _, x := range c.Exchanges {
			cfg := x.Config
			if got := cfg.InstalledPurposes(); !reflect.DeepEqual(got, b3Purposes) {
				t.Errorf("%s: purposes %v", e.ID, got)
			}
			if got := cfg.ReputationContextMapping(); !reflect.DeepEqual(got, b6Context) {
				t.Errorf("%s: reputation_context %+v", e.ID, got)
			}
			if got := cfg.ActivePolicy.AcceptedScoringRevisions(); !reflect.DeepEqual(got, b6Revisions) {
				t.Errorf("%s: scoring_policy_revisions %v", e.ID, got)
			}
		}
	}
}

// TestGatewayConfigMembers: the members, when present, replace the
// defaults; an empty object or array is no default.
func TestGatewayConfigMembers(t *testing.T) {
	const id = "selection/same-snapshot"
	root := caseTree(t, id)
	editJSON(t, root, id+"/config.json", func(c map[string]any) {
		c["purposes"] = map[string]any{"https://policies.example/purposes/other/v1": []any{"invoice.export", "invoice.read"}}
		c["reputation_context"] = map[string]any{
			"resource_classes": []any{map[string]any{"prefix": "https://invoices.example/archive/", "class": "archived-invoice"}},
			"runtime_class":    "managed-v2",
		}
		c["active_policy"].(map[string]any)["scoring_policy_revisions"] = []any{}
		c["selection"].(map[string]any)["selector"].(map[string]any)["checks"] = map[string]any{"established": []any{"security-hold-v1"}}
	})
	c, err := evalcase.Load(root, id)
	if err != nil {
		t.Fatal(err)
	}
	cfg := c.Exchanges[0].Config
	if got, want := cfg.InstalledPurposes(), map[string][]string{"https://policies.example/purposes/other/v1": {"invoice.export", "invoice.read"}}; !reflect.DeepEqual(got, want) {
		t.Errorf("purposes %v, want %v", got, want)
	}
	want := evalcase.ReputationContext{
		ResourceClasses: []evalcase.ResourceClass{{Prefix: "https://invoices.example/archive/", Class: "archived-invoice"}},
		RuntimeClass:    "managed-v2",
	}
	if got := cfg.ReputationContextMapping(); !reflect.DeepEqual(got, want) {
		t.Errorf("reputation_context %+v, want %+v", got, want)
	}
	if got := cfg.ActivePolicy.AcceptedScoringRevisions(); got == nil || len(got) != 0 {
		t.Errorf("scoring_policy_revisions %v, want none", got)
	}
	if got := cfg.Selection.Selector.Checks; !reflect.DeepEqual(got, map[string][]string{"established": {"security-hold-v1"}}) {
		t.Errorf("selector checks %v", got)
	}

	editJSON(t, root, id+"/config.json", func(c map[string]any) { c["purposes"] = map[string]any{} })
	if c, err = evalcase.Load(root, id); err != nil {
		t.Fatal(err)
	}
	if got := c.Exchanges[0].Config.InstalledPurposes(); got == nil || len(got) != 0 {
		t.Errorf("purposes {} read as %v, want no purpose", got)
	}
}

// TestGatewayConfigRejects: a reputation_context needs a runtime class and
// a prefix and class in each entry, and has no other member.
func TestGatewayConfigRejects(t *testing.T) {
	const id = "admission/valid"
	for name, rc := range map[string]any{
		"no runtime class":  map[string]any{"resource_classes": []any{}, "runtime_class": ""},
		"empty prefix":      map[string]any{"resource_classes": []any{map[string]any{"prefix": "", "class": "c"}}, "runtime_class": "r"},
		"empty class":       map[string]any{"resource_classes": []any{map[string]any{"prefix": "https://x.example/", "class": ""}}, "runtime_class": "r"},
		"no resource class": map[string]any{"runtime_class": "r"},
		"unknown member":    map[string]any{"resource_classes": []any{}, "runtime_class": "r", "action_class": "a"},
	} {
		t.Run(name, func(t *testing.T) {
			root := caseTree(t, id)
			editJSON(t, root, id+"/config.json", func(c map[string]any) { c["reputation_context"] = rc })
			_, err := evalcase.Load(root, id)
			wantErr(t, err, "config.json")
		})
	}
}
