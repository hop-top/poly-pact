package manifest_test

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"hop.top/pact-go/core/strictjson"
	"hop.top/pact-go/runner/manifest"
)

func TestParseAcceptsBase(t *testing.T) {
	m := parse(t, encode(t, baseEntries()))
	wantClean(t, m.Validate())
	if m.Version != 1 || len(m.Entries) != 4 {
		t.Fatalf("version %d, %d entries", m.Version, len(m.Entries))
	}
	e := m.Entries[1]
	if e.ID != "admission/valid" || e.Kind != manifest.KindEvaluate || e.Scope != manifest.ScopeRunner ||
		e.Path != "admission/valid" || e.Expected == nil || *e.Expected != "expected/admission/valid/decision.json" ||
		e.Outcome == nil || *e.Outcome != "ADMISSIBLE" || e.SpecMapRow != "CL-11.3" || e.DraftSection != "11.3" {
		t.Errorf("entry decoded as %+v", e)
	}
	if k := m.Entries[2]; k.Expected != nil || k.Outcome != nil {
		t.Errorf("key entry: expected %v outcome %v, want nil", k.Expected, k.Outcome)
	}
	if got, ok := m.Lookup("keys/holder"); !ok || got.Path != "keys/holder.jwk.json" {
		t.Errorf("Lookup(keys/holder) = %+v, %v", got, ok)
	}
	if _, ok := m.Lookup("keys/nobody"); ok {
		t.Error("Lookup found an absent id")
	}
}

// TestParseIsStrict: the manifest is read with the parse rules of draft
// Section 7.1, before any field rule.
func TestParseIsStrict(t *testing.T) {
	cases := map[string]struct {
		text string
		kind error
	}{
		"duplicate member":        {`{"manifest_version":1,"entries":[],"entries":[]}`, strictjson.ErrDuplicateKey},
		"nested duplicate member": {`{"manifest_version":1,"entries":[{"id":"a/b","id":"a/c"}]}`, strictjson.ErrDuplicateKey},
		"non-finite number":       {`{"manifest_version":NaN,"entries":[]}`, strictjson.ErrNonFinite},
		"invalid UTF-8":           {"{\"manifest_version\":1,\"entries\":[\"\xff\"]}", strictjson.ErrInvalidUTF8},
		"lone surrogate":          {`{"manifest_version":1,"entries":["\ud800"]}`, strictjson.ErrLoneSurrogate},
		"byte order mark":         {"\xef\xbb\xbf{\"manifest_version\":1,\"entries\":[]}", strictjson.ErrSyntax},
		"trailing data":           {`{"manifest_version":1,"entries":[]} {}`, strictjson.ErrTrailingData},
		"not an object":           {`[]`, nil},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := manifest.Parse([]byte(c.text))
			if err == nil {
				t.Fatal("Parse accepted it")
			}
			var ps manifest.Problems
			if !errors.As(err, &ps) || len(ps) != 1 || ps[0].Rule != manifest.RuleJSON {
				t.Fatalf("error %v, want one %s problem", err, manifest.RuleJSON)
			}
			if c.kind != nil && !errors.Is(err, c.kind) {
				t.Errorf("error %v does not wrap %v", err, c.kind)
			}
		})
	}
}

// TestValidateRules breaks one rule at a time and expects exactly that rule.
func TestValidateRules(t *testing.T) {
	type mutation struct {
		rule  string
		where string
		edit  func([]entry) []entry
	}
	set := func(i int, k string, v any) func([]entry) []entry {
		return func(es []entry) []entry { es[i][k] = v; return es }
	}
	drop := func(i int, k string) func([]entry) []entry {
		return func(es []entry) []entry { delete(es[i], k); return es }
	}
	const ev = 1 // index of the evaluate entry in baseEntries
	const key = 2
	cases := map[string]mutation{
		"missing id":            {manifest.RuleShape, "entries[1]", drop(ev, "id")},
		"missing kind":          {manifest.RuleShape, "admission/valid", drop(ev, "kind")},
		"missing scope":         {manifest.RuleShape, "admission/valid", drop(ev, "scope")},
		"missing path":          {manifest.RuleShape, "admission/valid", drop(ev, "path")},
		"missing expected":      {manifest.RuleShape, "admission/valid", drop(ev, "expected")},
		"missing outcome":       {manifest.RuleShape, "admission/valid", drop(ev, "outcome")},
		"missing spec_map_row":  {manifest.RuleShape, "admission/valid", drop(ev, "spec_map_row")},
		"missing draft_section": {manifest.RuleShape, "admission/valid", drop(ev, "draft_section")},
		"unknown member":        {manifest.RuleShape, "admission/valid", set(ev, "note", "x")},
		"id not a string":       {manifest.RuleShape, "entries[1]", set(ev, "id", 7)},
		"kind not a string":     {manifest.RuleShape, "admission/valid", set(ev, "kind", true)},
		"path not a string":     {manifest.RuleShape, "admission/valid", set(ev, "path", []string{"a"})},
		"expected a number":     {manifest.RuleShape, "admission/valid", set(ev, "expected", 1)},
		"draft_section number":  {manifest.RuleShape, "admission/valid", set(ev, "draft_section", 11.3)},

		"id one segment":       {manifest.RuleID, "admission", set(ev, "id", "admission")},
		"id four segments":     {manifest.RuleID, "admission/b/c/d", set(ev, "id", "admission/b/c/d")},
		"id upper case":        {manifest.RuleID, "admission/Valid", set(ev, "id", "admission/Valid")},
		"id underscore inside": {manifest.RuleID, "admission/va_lid", set(ev, "id", "admission/va_lid")},
		"id trailing hyphen":   {manifest.RuleID, "admission/valid-", set(ev, "id", "admission/valid-")},
		"id empty segment":     {manifest.RuleID, "admission//valid", set(ev, "id", "admission//valid")},
		"id empty":             {manifest.RuleID, "entries[1]", set(ev, "id", "")},

		// Only adapter-case ids, which follow their file names, may start a
		// segment with "_" or have a "." in one.
		"id dot in a key":                   {manifest.RuleID, "keys/holder.v2", set(key, "id", "keys/holder.v2")},
		"id leading underscore in a key":    {manifest.RuleID, "keys/_holder", set(key, "id", "keys/_holder")},
		"id leading underscore in a case":   {manifest.RuleID, "admission/_valid", set(ev, "id", "admission/_valid")},
		"id dot in an adapter asset":        {manifest.RuleID, "adapters/db/schema.v2", set(0, "id", "adapters/db/schema.v2")},
		"id underscore in an adapter asset": {manifest.RuleID, "adapters/_db/schema", set(0, "id", "adapters/_db/schema")},
		// An unknown kind is reported once, by its own rule.
		"id underscore with an unknown kind": {manifest.RuleKind, "admission/_valid", func(es []entry) []entry {
			es[ev]["kind"] = "evaluation"
			es[ev]["id"] = "admission/_valid"
			return es
		}},

		"kind unknown":  {manifest.RuleKind, "admission/valid", set(ev, "kind", "evaluation")},
		"scope unknown": {manifest.RuleScope, "admission/valid", set(ev, "scope", "sdk")},

		"path absolute":       {manifest.RulePath, "admission/valid", set(ev, "path", "/admission/valid")},
		"path dot dot":        {manifest.RulePath, "admission/valid", set(ev, "path", "admission/../keys")},
		"path dot":            {manifest.RulePath, "admission/valid", set(ev, "path", "./admission/valid")},
		"path empty segment":  {manifest.RulePath, "admission/valid", set(ev, "path", "admission//valid")},
		"path trailing slash": {manifest.RulePath, "admission/valid", set(ev, "path", "admission/valid/")},
		"path backslash":      {manifest.RulePath, "admission/valid", set(ev, "path", `admission\valid`)},
		"path empty":          {manifest.RulePath, "admission/valid", set(ev, "path", "")},
		"path hidden":         {manifest.RulePath, "admission/valid", set(ev, "path", "admission/.valid")},
		"path space":          {manifest.RulePath, "admission/valid", set(ev, "path", "admission/va lid")},

		"expected null for evaluate":  {manifest.RuleExpected, "admission/valid", set(ev, "expected", nil)},
		"expected set for key":        {manifest.RuleExpected, "keys/holder", set(key, "expected", "keys/holder.jwk.json")},
		"expected absolute":           {manifest.RuleExpected, "admission/valid", set(ev, "expected", "/expected/x.json")},
		"expected dot dot":            {manifest.RuleExpected, "admission/valid", set(ev, "expected", "../x.json")},
		"outcome null for evaluate":   {manifest.RuleOutcome, "admission/valid", set(ev, "outcome", nil)},
		"outcome set for key":         {manifest.RuleOutcome, "keys/holder", set(key, "outcome", "MATCH")},
		"outcome unknown token":       {manifest.RuleOutcome, "admission/valid", set(ev, "outcome", "PASS")},
		"outcome lower case":          {manifest.RuleOutcome, "admission/valid", set(ev, "outcome", "admissible")},
		"spec_map_row empty":          {manifest.RuleSpecMapRow, "admission/valid", set(ev, "spec_map_row", "")},
		"spec_map_row lower case":     {manifest.RuleSpecMapRow, "admission/valid", set(ev, "spec_map_row", "cl-11.3")},
		"draft_section trailing dot":  {manifest.RuleDraftSection, "admission/valid", set(ev, "draft_section", "11.3.")},
		"draft_section lower letter":  {manifest.RuleDraftSection, "admission/valid", set(ev, "draft_section", "c")},
		"draft_section leading zero":  {manifest.RuleDraftSection, "admission/valid", set(ev, "draft_section", "011")},
		"draft_section empty":         {manifest.RuleDraftSection, "admission/valid", set(ev, "draft_section", "")},
		"draft_section with a prefix": {manifest.RuleDraftSection, "admission/valid", set(ev, "draft_section", "Section 11.3")},

		"capabilities a string":     {manifest.RuleShape, "admission/valid", set(ev, "capabilities", "jws-ed25519")},
		"capabilities null":         {manifest.RuleShape, "admission/valid", set(ev, "capabilities", nil)},
		"capability not a string":   {manifest.RuleShape, "admission/valid", set(ev, "capabilities", []any{1})},
		"capability null":           {manifest.RuleShape, "admission/valid", set(ev, "capabilities", []any{nil})},
		"capabilities empty":        {manifest.RuleCapabilities, "admission/valid", set(ev, "capabilities", []string{})},
		"capability unknown":        {manifest.RuleCapabilities, "admission/valid", set(ev, "capabilities", []string{"ed25519"})},
		"capability upper case":     {manifest.RuleCapabilities, "admission/valid", set(ev, "capabilities", []string{"JWS-ED25519"})},
		"capability repeated":       {manifest.RuleCapabilities, "admission/valid", set(ev, "capabilities", []string{"jws-ed25519", "jws-ed25519"})},
		"capability unknown on key": {manifest.RuleCapabilities, "keys/holder", set(key, "capabilities", []string{"ES256"})},

		"duplicate id": {manifest.RuleIDDuplicate, "keys/holder", func(es []entry) []entry {
			dup := entry{}
			for k, v := range es[key] {
				dup[k] = v
			}
			return append(es[:key+1], append([]entry{dup}, es[key+1:]...)...)
		}},
		"unsorted": {manifest.RuleOrder, "adapters/db/schema", func(es []entry) []entry {
			es[0], es[1] = es[1], es[0]
			return es
		}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			m := parse(t, encode(t, c.edit(baseEntries())))
			wantRule(t, m.Validate(), c.rule, c.where)
		})
	}
}

func TestValidateAcceptsExistingIDForms(t *testing.T) {
	for _, c := range []struct{ id, kind, path string }{
		{"admission/valid", "evaluate", "admission/valid"},
		{"outcomes/qualification/correction-recompute", "outcomes", "outcomes/qualification/correction-recompute"},
		{"vectors/jws/es256-r-equals-n", "vector", "vectors/jws/es256-r-equals-n.json"},
		{"adapters/_common/common-03.fragment", "adapter-case", "adapters/_common/common-03.fragment.json"},
		{"keys/reputation-service", "vector", "keys/reputation-service.jwk.json"},
	} {
		es := []entry{{
			"id": c.id, "kind": c.kind, "scope": "core", "path": c.path, "expected": "a.json",
			"outcome": "MATCH", "spec_map_row": "CL-17.3.1", "draft_section": "B.7",
		}}
		wantClean(t, parse(t, encode(t, es)).Validate())
	}
}

// adapterCase is an adapter-case entry with the given id and path.
func adapterCase(id, path string) entry {
	return entry{
		"id": id, "kind": "adapter-case", "scope": "adapter", "path": path, "expected": path,
		"outcome": "REJECTED", "spec_map_row": "COMMON-03", "draft_section": "10.2",
	}
}

// TestValidateAdapterCaseLayout: an adapter case is the file
// adapters/<adapter>/<case>.json with the id adapters/<adapter>/<case>, for
// adapters/_common and every adapter alike, with no cases/ subdirectory
// (spec/v1.0/fixtures/README.md, Manifest).
func TestValidateAdapterCaseLayout(t *testing.T) {
	for _, c := range []struct{ id, path string }{
		{"adapters/_common/common-03.fragment", "adapters/_common/common-03.fragment.json"},
		{"adapters/_common/fresh-02.at-limit", "adapters/_common/fresh-02.at-limit.json"},
		{"adapters/files/files-01.symlink", "adapters/files/files-01.symlink.json"},
		{"adapters/oauth/oauth-02", "adapters/oauth/oauth-02.json"},
	} {
		t.Run(c.id, func(t *testing.T) {
			wantClean(t, parse(t, encode(t, []entry{adapterCase(c.id, c.path)})).Validate())
		})
	}

	cases := map[string]struct {
		id, path, rule string
	}{
		"cases subdirectory": {"adapters/_common/common-03.fragment",
			"adapters/_common/cases/common-03.fragment.json", manifest.RuleAdapterCasePath},
		"path of another case": {"adapters/_common/common-03.fragment",
			"adapters/_common/common-03.headers.json", manifest.RuleAdapterCasePath},
		"path without .json": {"adapters/_common/common-03.fragment",
			"adapters/_common/common-03.fragment", manifest.RuleAdapterCasePath},
		"path with another extension": {"adapters/_common/common-03.fragment",
			"adapters/_common/common-03.fragment.yaml", manifest.RuleAdapterCasePath},
		"path the adapter directory": {"adapters/_common/common-03.fragment",
			"adapters/_common", manifest.RuleAdapterCasePath},
		"path in another adapter": {"adapters/_common/common-03.fragment",
			"adapters/files/common-03.fragment.json", manifest.RuleAdapterCasePath},
		"id outside adapters": {"vectors/zz-case", "vectors/zz-case.json", manifest.RuleAdapterCasePath},
		"id of two segments":  {"adapters/zz-case", "adapters/zz-case.json", manifest.RuleAdapterCasePath},
		"id with an underscore group": {"_adapters/_common/zz-case",
			"_adapters/_common/zz-case.json", manifest.RuleAdapterCasePath},
		// A malformed id or path is reported by its own rule only.
		"id upper case": {"adapters/_common/Common-03", "adapters/_common/Common-03.json", manifest.RuleID},
		"id of four segments": {"adapters/_common/cases/zz-case",
			"adapters/_common/cases/zz-case.json", manifest.RuleID},
		"path dot dot": {"adapters/_common/zz-case", "adapters/../zz-case.json", manifest.RulePath},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			e := adapterCase(c.id, c.path)
			if c.rule == manifest.RulePath {
				e["expected"] = c.id + ".json" // so that only the path rule speaks
			}
			wantRule(t, parse(t, encode(t, []entry{e})).Validate(), c.rule, c.id)
		})
	}
}

// sourceCase is a source-case entry with the given id and path: scope
// adapter, and neither an expected file nor an outcome.
func sourceCase(id, path string) entry {
	return entry{
		"id": id, "kind": "source-case", "scope": "adapter", "path": path, "expected": nil,
		"outcome": nil, "spec_map_row": "CL-17.2", "draft_section": "17.2",
	}
}

// TestValidateSourceCaseLayout: a source case is the file
// sources/<source>/<case>.json with the id sources/<source>/<case>; its case
// segment may contain "." as an adapter case's does, and it has scope adapter
// and no expected file or outcome (spec/v1.0/fixtures/README.md, Manifest).
func TestValidateSourceCaseLayout(t *testing.T) {
	for _, c := range []struct{ id, path string }{
		{"sources/scim/scim-01.join", "sources/scim/scim-01.join.json"},
		{"sources/shared-signals/ssf-02", "sources/shared-signals/ssf-02.json"},
	} {
		t.Run(c.id, func(t *testing.T) {
			wantClean(t, parse(t, encode(t, []entry{sourceCase(c.id, c.path)})).Validate())
		})
	}

	cases := map[string]struct {
		id, path, rule string
		edit           func(entry)
	}{
		"cases subdirectory":        {"sources/scim/scim-01.join", "sources/scim/cases/scim-01.join.json", manifest.RuleSourceCasePath, nil},
		"path without .json":        {"sources/scim/scim-01.join", "sources/scim/scim-01.join", manifest.RuleSourceCasePath, nil},
		"path of another case":      {"sources/scim/scim-01.join", "sources/scim/scim-02.json", manifest.RuleSourceCasePath, nil},
		"id outside sources":        {"adapters/scim/scim-01", "adapters/scim/scim-01.json", manifest.RuleSourceCasePath, nil},
		"id of two segments":        {"sources/scim-01", "sources/scim-01.json", manifest.RuleSourceCasePath, nil},
		"source with a dot":         {"sources/sc.im/scim-01", "sources/sc.im/scim-01.json", manifest.RuleSourceCasePath, nil},
		"source with an underscore": {"sources/_scim/scim-01", "sources/_scim/scim-01.json", manifest.RuleSourceCasePath, nil},
		"case with an underscore":   {"sources/scim/_scim-01", "sources/scim/_scim-01.json", manifest.RuleSourceCasePath, nil},
		"scope core":                {"sources/scim/scim-01", "sources/scim/scim-01.json", manifest.RuleScope, func(e entry) { e["scope"] = "core" }},
		"scope runner":              {"sources/scim/scim-01", "sources/scim/scim-01.json", manifest.RuleScope, func(e entry) { e["scope"] = "runner" }},
		"expected set":              {"sources/scim/scim-01", "sources/scim/scim-01.json", manifest.RuleExpected, func(e entry) { e["expected"] = "sources/scim/scim-01.json" }},
		"outcome set":               {"sources/scim/scim-01", "sources/scim/scim-01.json", manifest.RuleOutcome, func(e entry) { e["outcome"] = "ACCEPTED" }},
		// A malformed id is reported by its own rule only.
		"id of four segments": {"sources/scim/cases/scim-01", "sources/scim/cases/scim-01.json", manifest.RuleID, nil},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			e := sourceCase(c.id, c.path)
			if c.edit != nil {
				c.edit(e)
			}
			wantRule(t, parse(t, encode(t, []entry{e})).Validate(), c.rule, c.id)
		})
	}

	// Only adapter-case and source-case ids may have a "." in a segment.
	e := sourceCase("sources/scim/scim-01.join", "sources/scim/scim-01.join.json")
	e["kind"] = "vector"
	e["expected"], e["outcome"] = "sources/scim/scim-01.join.json", "MATCH"
	wantRule(t, parse(t, encode(t, []entry{e})).Validate(), manifest.RuleID, "sources/scim/scim-01.join")
}

// TestValidateAcceptsEveryOutcome: the outcome tokens of spec/v1.0/fixtures/README.md,
// the decisions of draft Section 11.4 and the qualification results of draft
// Section 14.3 among them.
func TestValidateAcceptsEveryOutcome(t *testing.T) {
	for _, outcome := range []string{
		"ADMISSIBLE", "INADMISSIBLE", "DEFERRED",
		"ACCEPTED", "REJECTED",
		"QUALIFIED", "UNQUALIFIED", "DISPUTED",
		"MATCH",
	} {
		es := baseEntries()
		es[1]["outcome"] = outcome
		wantClean(t, parse(t, encode(t, es)).Validate())
	}
}

func TestValidateTopLevel(t *testing.T) {
	cases := map[string]string{
		"version 2":         `{"manifest_version":2,"entries":[]}`,
		"version string":    `{"manifest_version":"1","entries":[]}`,
		"version missing":   `{"entries":[]}`,
		"entries missing":   `{"manifest_version":1}`,
		"entries an object": `{"manifest_version":1,"entries":{}}`,
		"entries null":      `{"manifest_version":1,"entries":null}`,
		"unknown member":    `{"manifest_version":1,"entries":[],"generated":true}`,
		"entry not object":  `{"manifest_version":1,"entries":["admission/valid"]}`,
	}
	for name, text := range cases {
		t.Run(name, func(t *testing.T) {
			wantRule(t, parse(t, []byte(text)).Validate(), manifest.RuleShape, "")
		})
	}
}

func TestProblemsFormat(t *testing.T) {
	m := parse(t, encode(t, func() []entry {
		es := baseEntries()
		es[1]["kind"] = "evaluation"
		return es
	}()))
	ps := m.Validate()
	if ps.Err() == nil {
		t.Fatal("Err() is nil")
	}
	mustContain(t, ps.Error(), "[entry-kind]", "admission/valid", "evaluation")
	if (manifest.Problems{}).Err() != nil {
		t.Error("empty Problems has an error")
	}
	if !strings.HasPrefix(ps[0].String(), "[entry-kind] admission/valid: ") {
		t.Errorf("String() = %q", ps[0].String())
	}
}

// TestValidateCapabilities: capabilities is the one optional member of an
// entry, the optional capabilities the entry tests (spec/v1.0/fixtures/README.md,
// Optional capabilities). An entry without it is mandatory.
func TestValidateCapabilities(t *testing.T) {
	if got, want := manifest.Capabilities(), []string{manifest.CapabilityJWSEd25519}; !slices.Equal(got, want) {
		t.Errorf("Capabilities() = %v, want %v", got, want)
	}
	if manifest.CapabilityJWSEd25519 != "jws-ed25519" {
		t.Errorf("CapabilityJWSEd25519 = %q", manifest.CapabilityJWSEd25519)
	}
	es := baseEntries()
	es[1]["capabilities"] = []string{"jws-ed25519"}
	m := parse(t, encode(t, es))
	wantClean(t, m.Validate())
	if got := m.Entries[1].Capabilities; !slices.Equal(got, []string{"jws-ed25519"}) {
		t.Errorf("capabilities decoded as %q", got)
	}
	for i, e := range m.Entries {
		if i != 1 && e.Capabilities != nil {
			t.Errorf("%s: capabilities %q, want nil", e.ID, e.Capabilities)
		}
	}
	// A malformed member decodes as nil, so a caller that skips Validate
	// never reads it as a capability list.
	es[1]["capabilities"] = []any{"jws-ed25519", 1}
	if got := parse(t, encode(t, es)).Entries[1].Capabilities; got != nil {
		t.Errorf("malformed capabilities decoded as %q, want nil", got)
	}
}
