package rebac_test

import (
	"io/fs"
	"path"
	"strings"
	"testing"

	"hop.top/pact-go/adapter/adaptertest"
)

// replaced are the common authorize_native cases whose expected decision
// carries a member that an OpenFGA Check answer cannot carry, each with the
// ReBAC case that shows the same property (profile section 10, "Replaced
// common cases").
var replaced = map[string]adaptertest.Replacement{
	"COMMON-06.allow-no-execution": {
		By:     "REBAC-10",
		Reason: "expects the obligation redact-fields; a Check answer carries allowed and no obligation (profile [OF-2])",
	},
	"COMMON-06.deny-unchanged": {
		By:     "REBAC-11",
		Reason: "expects the obligation audit on the denial; a Check answer carries allowed and no obligation (profile [OF-2])",
	},
	"COMMON-06.decision-provenance": {
		By:     "REBAC-12",
		Reason: "expects a decision record and a decision time; a Check answer carries neither (profile [OF-2])",
	},
}

// TestConformance runs the conformance suite, the common cases and the ReBAC
// cases of spec/v1.0/fixtures/adapters/rebac, with the three replaced common
// cases declared. The profile does not support workloads shared by several
// agents, so the dedicated cases run.
func TestConformance(t *testing.T) {
	adaptertest.Run(t, rebacFactory, adaptertest.Options{Adapter: "rebac", Replaced: replaced})
}

// TestFixtureWorlds loads the native state of every ReBAC case and checks
// what the cases rely on: every model parses, every tuple names a relation of
// the pinned model, and the pin names a model of the store unless the case
// is about a store that does not hold it.
func TestFixtureWorlds(t *testing.T) {
	fsys, err := fixtures()
	if err != nil {
		t.Fatal(err)
	}
	cases, err := adaptertest.Load(fsys, "rebac")
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, c := range cases {
		if !strings.HasPrefix(c.ID, "REBAC-") {
			continue
		}
		seen++
		w, err := loadWorld(c.NativeState, fsys)
		if err != nil {
			t.Errorf("%s: %v", c.ID, err)
			continue
		}
		pinned, ok := w.models[w.st.Pin.AuthorizationModelID]
		if !ok {
			t.Errorf("%s: the pinned model %s is not in the store", c.ID, w.st.Pin.AuthorizationModelID)
			continue
		}
		all := w.st.Store.Tuples
		if w.st.Store.CachedTuples != nil {
			all = append(all, *w.st.Store.CachedTuples...)
		}
		for _, k := range all {
			typ, _, _ := strings.Cut(k.Object, ":")
			if _, ok := pinned.types[typ][k.Relation]; !ok {
				t.Errorf("%s: tuple %+v names no relation of the pinned model", c.ID, k)
			}
		}
		for _, r := range w.st.Relations {
			if _, ok := pinned.types[r.ObjectType][r.Relation]; !ok {
				t.Errorf("%s: relation table row %+v names no relation of the pinned model", c.ID, r)
			}
		}
	}
	if seen == 0 {
		t.Fatal("no ReBAC case loaded")
	}
	assets, err := fs.Glob(fsys, path.Join(casesDir, "assets", "*.fga"))
	if err != nil || len(assets) == 0 {
		t.Fatalf("assets: %v, %d files", err, len(assets))
	}
	for _, a := range assets {
		src, err := fs.ReadFile(fsys, a)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := parseModel(src); err != nil {
			t.Errorf("%s: %v", a, err)
		}
	}
}

// TestModelEvaluation checks the fake store's evaluator on the reference
// model: membership of the parent project and a direct share each give
// viewer, editor is direct only, and the later model adds editor to viewer.
func TestModelEvaluation(t *testing.T) {
	fsys, err := fixtures()
	if err != nil {
		t.Fatal(err)
	}
	load := func(name string) *fgaModel {
		src, err := fs.ReadFile(fsys, path.Join(casesDir, "assets", name))
		if err != nil {
			t.Fatal(err)
		}
		m, err := parseModel(src)
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	ref, next := load("model.fga"), load("model-next.fga")
	const u, doc, proj = "user:u-1", "document:d-1", "project:p-1"
	parent := tupleKey{User: proj, Relation: "parent", Object: doc}
	member := tupleKey{User: u, Relation: "member", Object: proj}
	viewer := tupleKey{User: u, Relation: "viewer", Object: doc}
	editor := tupleKey{User: u, Relation: "editor", Object: doc}
	for _, tc := range []struct {
		name     string
		m        *fgaModel
		relation string
		tuples   []tupleKey
		want     bool
	}{
		{"member of parent", ref, "viewer", []tupleKey{parent, member}, true},
		{"direct share", ref, "viewer", []tupleKey{parent, viewer}, true},
		{"no path", ref, "viewer", []tupleKey{parent}, false},
		{"member without parent", ref, "viewer", []tupleKey{member}, false},
		{"editor is not viewer", ref, "viewer", []tupleKey{editor}, false},
		{"viewer is not editor", ref, "editor", []tupleKey{parent, member, viewer}, false},
		{"editor", ref, "editor", []tupleKey{editor}, true},
		{"later model: editor is viewer", next, "viewer", []tupleKey{editor}, true},
		{"wildcard", ref, "viewer", []tupleKey{{User: "user:*", Relation: "viewer", Object: doc}}, true},
	} {
		got, err := tc.m.check(u, tc.relation, doc, tc.tuples, 0)
		if err != nil || got != tc.want {
			t.Errorf("%s: check = %v, %v; want %v", tc.name, got, err, tc.want)
		}
	}
	if _, err := ref.check(u, "owner", doc, nil, 0); err == nil {
		t.Error("an undefined relation evaluates")
	}
	for _, bad := range []string{
		"type user\n",
		"model\n  schema 1.1\ntype a\n  relations\n    define r: [user] but not s\n",
		"model\n  schema 1.1\ntype a\n  relations\n    define r [user]\n",
		"model\n  schema 1.1\ntype a\ntype a\n",
	} {
		if _, err := parseModel([]byte(bad)); err == nil {
			t.Errorf("parseModel(%q) succeeded", bad)
		}
	}
}
