package manifest_test

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"hop.top/pact-go/runner/manifest"
)

func parseSpecMap(t testing.TB, text string) *manifest.SpecMap {
	t.Helper()
	sm, ps := manifest.ParseSpecMap([]byte(text))
	if len(ps) > 0 || sm == nil {
		t.Fatalf("ParseSpecMap: %v", ps)
	}
	return sm
}

func TestParseSpecMap(t *testing.T) {
	sm := parseSpecMap(t, baseSpecMap)
	var ids []string
	for _, r := range sm.Rows {
		ids = append(ids, r.ID)
	}
	if !slices.Equal(ids, []string{"CL-11.3", "CL-C", "CL-17.3.1"}) {
		t.Errorf("rows %v", ids)
	}
	if got := sm.Rows[2].Fixtures; !slices.Equal(got, []string{"approval/pending", "parse/alg-none"}) {
		t.Errorf("fixtures of CL-17.3.1: %v", got)
	}
	want := map[string]string{
		"admission": "partial", "approval": "planned", "parse": "planned",
		"adapters": "landed", "keys": "landed", "vectors": "landed",
	}
	if len(sm.Groups) != len(want) {
		t.Errorf("groups %v", sm.Groups)
	}
	for g, s := range want {
		if sm.Groups[g] != s {
			t.Errorf("group %s: %q, want %q", g, sm.Groups[g], s)
		}
	}
}

func TestParseSpecMapProblems(t *testing.T) {
	replace := func(old, repl string) string {
		if !strings.Contains(baseSpecMap, old) {
			panic(old)
		}
		return strings.Replace(baseSpecMap, old, repl, 1)
	}
	cases := map[string]string{
		"no conformance map":    replace("## Conformance map", "## Conformance table"),
		"no fixture groups":     replace("## Fixture groups", "## Groups"),
		"no ID column":          replace("| ID | Check |", "| Row | Check |"),
		"no Fixture(s) column":  replace("| Finding | Fixture(s) |", "| Finding | Cases |"),
		"no Status column":      replace("| Covers | Status |", "| Covers | State |"),
		"bad status":            replace("| Positive control | partial |", "| Positive control | done |"),
		"status in upper case":  replace("| Positive control | partial |", "| Positive control | Partial |"),
		"duplicate group":       replace("| approval | `fixtures/approval/`", "| admission | `fixtures/approval/`"),
		"duplicate row":         replace("| CL-C | Test keys", "| CL-11.3 | Test keys"),
		"row with a cell short": replace("| CL-C | Test keys | C | G13 | keys/holder |", "| CL-C | Test keys | C | keys/holder |"),
		"row without end pipe":  replace("| CL-C | Test keys | C | G13 | keys/holder |", "| CL-C | Test keys | C | G13 | keys/holder"),
		"fenced table only":     replace("## Conformance map\n\n", "## Conformance map\n\n```\n") + "```\n",
	}
	for name, text := range cases {
		t.Run(name, func(t *testing.T) {
			_, ps := manifest.ParseSpecMap([]byte(text))
			wantRule(t, ps, manifest.RuleSpecMap, "")
		})
	}
}

func TestCheckSpecMapAcceptsBase(t *testing.T) {
	tr := newTree(t, baseEntries())
	wantClean(t, manifest.CheckSpecMap(tr.root, tr.manifest(), parseSpecMap(t, baseSpecMap)))
}

// TestCheckSpecMapRowUnknown: every spec_map_row is a row of the map.
func TestCheckSpecMapRowUnknown(t *testing.T) {
	es := baseEntries()
	es[3]["spec_map_row"] = "CL-7.4"
	tr := newTree(t, es)
	ps := manifest.CheckSpecMap(tr.root, tr.manifest(), parseSpecMap(t, baseSpecMap))
	wantRule(t, ps, manifest.RuleRowUnknown, "CL-7.4")
	mustContain(t, ps.Error(), "vectors/jcs/arrays")
}

// withFixtures replaces the Fixture(s) cell of row CL-C.
func withFixtures(fixtures string) string {
	return strings.Replace(baseSpecMap, "| CL-C | Test keys | C | G13 | keys/holder |",
		"| CL-C | Test keys | C | G13 | "+fixtures+" |", 1)
}

// withStatus sets the status of group in the Fixture groups table.
func withStatus(text, group, status string) string {
	re := regexp.MustCompile("(?m)^(\\| " + regexp.QuoteMeta(group) + " \\|.*\\| )[a-z]+( \\|)$")
	if !re.MatchString(text) {
		panic(group)
	}
	return re.ReplaceAllString(text, "${1}"+status+"${2}")
}

// withoutGroup drops the row of group from the Fixture groups table.
func withoutGroup(text, group string) string {
	re := regexp.MustCompile("(?m)^\\| " + regexp.QuoteMeta(group) + " \\|.*\n")
	if !re.MatchString(text) {
		panic(group)
	}
	return re.ReplaceAllString(text, "")
}

// TestCheckSpecMapFixtureIDs: an id a row lists is registered when its group
// is landed, and in any group once its fixture exists. A fixture exists when
// the fixture directory has a file or directory at the id, or a file at the id
// plus a neutral extension. Other ids are reserved.
func TestCheckSpecMapFixtureIDs(t *testing.T) {
	cases := map[string]struct {
		specMap string
		create  []string // files to write; a name ending in / is a directory
		want    string   // the id reported missing, "" for none
	}{
		"landed group, id absent":              {withFixtures("keys/holder, keys/issuer"), nil, "keys/issuer"},
		"landed group, id on disk":             {withFixtures("keys/holder, keys/issuer"), []string{"keys/issuer/"}, "keys/issuer"},
		"partial group, id absent":             {baseSpecMap, nil, ""},
		"partial group, case directory":        {baseSpecMap, []string{"admission/wrong-tenant/README.md"}, "admission/wrong-tenant"},
		"partial group, empty case directory":  {baseSpecMap, []string{"admission/wrong-tenant/"}, "admission/wrong-tenant"},
		"partial group, case file":             {baseSpecMap, []string{"admission/wrong-tenant.jws"}, "admission/wrong-tenant"},
		"partial group, json case file":        {baseSpecMap, []string{"admission/wrong-tenant.json"}, "admission/wrong-tenant"},
		"partial group, other extension":       {baseSpecMap, []string{"admission/wrong-tenant.txt"}, ""},
		"partial group, longer name":           {baseSpecMap, []string{"admission/wrong-tenant-2.json"}, ""},
		"planned group, no directory":          {withFixtures("keys/holder, approval/expired"), nil, ""},
		"planned group, directory exists":      {withFixtures("keys/holder, approval/expired"), []string{"approval/README.md"}, ""},
		"planned group, case directory":        {withFixtures("keys/holder, approval/expired"), []string{"approval/expired/"}, "approval/expired"},
		"planned group, three-part id on disk": {withFixtures("keys/holder, approval/expired/old"), []string{"approval/expired/old.json"}, "approval/expired/old"},
		"planned group, id with dots on disk":  {withFixtures("keys/holder, approval/_x/c-01.a"), []string{"approval/_x/c-01.a.json"}, "approval/_x/c-01.a"},
		"id that is not an id form":            {withFixtures("keys/holder, admission/../keys"), nil, ""},
		"backticked id":                        {withFixtures("keys/holder, `admission/valid`"), nil, ""},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			tr := newTree(t, baseEntries())
			for _, f := range c.create {
				if dir, ok := strings.CutSuffix(f, "/"); ok {
					if err := os.MkdirAll(filepath.Join(tr.root, filepath.FromSlash(dir)), 0o755); err != nil {
						t.Fatal(err)
					}
					continue
				}
				tr.write(f, "{}")
			}
			ps := manifest.CheckSpecMap(tr.root, tr.manifest(), parseSpecMap(t, c.specMap))
			if c.want == "" {
				wantClean(t, ps)
				return
			}
			wantWhere(t, ps, manifest.RuleFixtureMissing, c.want)
			for _, p := range ps {
				if p.Rule == manifest.RuleFixtureMissing && p.Where != c.want {
					t.Errorf("unexpected problem %s", p)
				}
			}
		})
	}
}

// TestCheckSpecMapGroupStatus: the three statuses of the Fixture groups
// table. planned: no manifest entry under the group. partial: at least one
// entry, and not every listed id exists yet. landed: at least one entry
// (and every listed id registered, TestCheckSpecMapFixtureIDs).
func TestCheckSpecMapGroupStatus(t *testing.T) {
	withEntry := func(e entry) []entry {
		es := baseEntries()
		for i, x := range es {
			if x["id"].(string) > e["id"].(string) {
				return append(es[:i:i], append([]entry{e}, es[i:]...)...)
			}
		}
		return append(es, e)
	}
	parseEntry := entry{
		"id": "parse/alg-none", "kind": "evaluate", "scope": "runner", "path": "parse/alg-none.jws",
		"expected": "expected/parse/alg-none/decision.json", "outcome": "REJECTED",
		"spec_map_row": "CL-17.3.1", "draft_section": "7.2",
	}
	onlyValid := strings.Replace(baseSpecMap, "admission/valid, admission/wrong-tenant |", "admission/valid |", 1)
	noParseID := strings.Replace(baseSpecMap, "approval/pending, parse/alg-none |", "approval/pending |", 1)
	noApprovalID := strings.Replace(baseSpecMap, "approval/pending, parse/alg-none |", "parse/alg-none |", 1)
	cases := map[string]struct {
		entries []entry
		specMap string
		create  []string
		rule    string // "" for a clean result
		where   string
	}{
		"planned group with an entry":           {withEntry(parseEntry), baseSpecMap, []string{"parse/alg-none.jws", "expected/parse/alg-none/decision.json"}, manifest.RuleGroupPlanned, "parse"},
		"planned group, entry no row lists":     {withEntry(parseEntry), noParseID, []string{"parse/alg-none.jws", "expected/parse/alg-none/decision.json"}, manifest.RuleGroupPlanned, "parse"},
		"partial group, its only id registered": {withEntry(parseEntry), withStatus(baseSpecMap, "parse", "partial"), []string{"parse/alg-none.jws", "expected/parse/alg-none/decision.json"}, manifest.RuleGroupPartialComplete, "parse"},
		"partial group without entries":         {baseEntries(), withStatus(baseSpecMap, "approval", "partial"), nil, manifest.RuleGroupPartialEmpty, "approval"},
		"partial group, every id registered":    {baseEntries(), onlyValid, nil, manifest.RuleGroupPartialComplete, "admission"},
		"partial group, no listed id":           {baseEntries(), withStatus(baseSpecMap, "adapters", "partial"), nil, manifest.RuleGroupPartialComplete, "adapters"},
		"landed group without entries":          {baseEntries(), withStatus(noApprovalID, "approval", "landed"), nil, manifest.RuleGroupLanded, "approval"},
		"landed group, no listed id":            {baseEntries(), baseSpecMap, nil, "", ""},
		"landed group, every id registered":     {baseEntries(), withStatus(onlyValid, "admission", "landed"), nil, "", ""},
		"partial group, one id reserved":        {baseEntries(), baseSpecMap, nil, "", ""},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			tr := newTree(t, c.entries)
			for _, f := range c.create {
				tr.write(f, "{}")
			}
			ps := manifest.CheckSpecMap(tr.root, tr.manifest(), parseSpecMap(t, c.specMap))
			if c.rule == "" {
				wantClean(t, ps)
				return
			}
			wantRule(t, ps, c.rule, c.where)
		})
	}

	// Every listed id of a partial group exists, one only on disk: the group
	// is complete, and the unregistered fixture is missing from the manifest.
	t.Run("partial group, last id on disk", func(t *testing.T) {
		tr := newTree(t, baseEntries())
		tr.write("admission/wrong-tenant/README.md", "# x")
		ps := manifest.CheckSpecMap(tr.root, tr.manifest(), parseSpecMap(t, baseSpecMap))
		want := []string{manifest.RuleFixtureMissing, manifest.RuleGroupPartialComplete}
		slices.Sort(want)
		if got := rules(ps); !slices.Equal(got, want) {
			t.Errorf("rules %v, want %v:\n%s", got, want, ps)
		}
		wantWhere(t, ps, manifest.RuleGroupPartialComplete, "admission")
	})
}

// TestCheckSpecMapGroupUnlisted: every group that a manifest entry or a row
// names has a status.
func TestCheckSpecMapGroupUnlisted(t *testing.T) {
	cases := map[string]struct {
		specMap string
		where   string
	}{
		"row names a group without a status":      {withFixtures("keys/holder, schema/appendix-b-valid"), "schema"},
		"manifest names a group without a status": {withoutGroup(baseSpecMap, "vectors"), "vectors"},
		"both name a group without a status":      {withoutGroup(baseSpecMap, "keys"), "keys"},
		"a group named only by a reserved id":     {withoutGroup(baseSpecMap, "approval"), "approval"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			tr := newTree(t, baseEntries())
			ps := manifest.CheckSpecMap(tr.root, tr.manifest(), parseSpecMap(t, c.specMap))
			wantRule(t, ps, manifest.RuleGroupUnlisted, c.where)
			if len(ps) != 1 {
				t.Errorf("want one problem, got:\n%s", ps)
			}
		})
	}
	t.Run("an id both registered and listed is named once", func(t *testing.T) {
		tr := newTree(t, baseEntries())
		ps := manifest.CheckSpecMap(tr.root, tr.manifest(), parseSpecMap(t, withoutGroup(baseSpecMap, "keys")))
		if n := strings.Count(ps.Error(), "keys/holder"); n != 1 {
			t.Errorf("keys/holder named %d times:\n%s", n, ps)
		}
	})
	t.Run("a listed group nothing names", func(t *testing.T) {
		text := strings.Replace(baseSpecMap, "| vectors |", "| capacity | `fixtures/capacity/` | Limits | planned |\n| vectors |", 1)
		tr := newTree(t, baseEntries())
		wantClean(t, manifest.CheckSpecMap(tr.root, tr.manifest(), parseSpecMap(t, text)))
	})
}

// TestCheck runs every rule over a tree on disk, as pactfix check manifest
// does.
func TestCheck(t *testing.T) {
	tr := newTree(t, baseEntries())
	wantClean(t, manifest.Check(tr.root, tr.specMap))

	tr.write("keys/issuer.jwk.json", "{}")
	tr.setSpecMap(strings.Replace(baseSpecMap, "| CL-C | Test keys | C | G13 | keys/holder |",
		"| CL-D | Test keys | C | G13 | keys/holder, keys/issuer |", 1))
	got := rules(manifest.Check(tr.root, tr.specMap))
	want := []string{manifest.RuleUncovered, manifest.RuleFixtureMissing, manifest.RuleRowUnknown}
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("rules %v, want %v", got, want)
	}

	tr.write("manifest.json", `{"manifest_version":1,"entries":[],"entries":[]}`)
	wantRule(t, manifest.Check(tr.root, tr.specMap), manifest.RuleJSON, "manifest.json")

	tr.remove("manifest.json")
	wantRule(t, manifest.Check(tr.root, tr.specMap), manifest.RuleJSON, "manifest.json")

	tr.write("manifest.json", string(encode(t, baseEntries())))
	tr.remove("keys/issuer.jwk.json")
	if err := os.Remove(tr.specMap); err != nil {
		t.Fatal(err)
	}
	wantRule(t, manifest.Check(tr.root, tr.specMap), manifest.RuleSpecMap, "")
}
