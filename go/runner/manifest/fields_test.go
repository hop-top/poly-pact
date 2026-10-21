package manifest_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"hop.top/pact-go/core/strictjson"
	"hop.top/pact-go/runner/manifest"
)

// TestEntryFieldVocabulary: the tokens of the entry fields conformance_profile,
// transport and layer, and the kinds transport, mcp and profile
// (spec/v1.0/fixtures/README.md, Manifest entry fields).
func TestEntryFieldVocabulary(t *testing.T) {
	for name, c := range map[string]struct{ got, want []string }{
		"ConformanceProfiles": {manifest.ConformanceProfiles(), []string{"full", "single-owner"}},
		"Transports":          {manifest.Transports(), []string{"https", "stdio-ipc"}},
		"Layers":              {manifest.Layers(), []string{"transcript", "os"}},
	} {
		if !slices.Equal(c.got, c.want) {
			t.Errorf("%s() = %v, want %v", name, c.got, c.want)
		}
	}
	for k, want := range map[manifest.Kind]string{
		manifest.KindTransport: "transport",
		manifest.KindMCP:       "mcp",
		manifest.KindProfile:   "profile",
	} {
		if string(k) != want || !k.Known() || !k.HasExpected() {
			t.Errorf("kind %q: want %q, known, with an expected result", k, want)
		}
	}
	// A source case carries its expectations inline and has no expected
	// file or outcome, as a key or an adapter asset; its scope is adapter.
	if k := manifest.KindSourceCase; string(k) != "source-case" || !k.Known() || k.HasExpected() {
		t.Errorf("kind %q: want source-case, known, without an expected result", k)
	}
	if s, ok := manifest.KindSourceCase.RequiredScope(); !ok || s != manifest.ScopeAdapter {
		t.Errorf("source-case RequiredScope() = %q %v, want adapter", s, ok)
	}
	if manifest.DefaultConformanceProfile != "full" || manifest.DefaultTransport != "https" {
		t.Errorf("defaults %q %q, want full https", manifest.DefaultConformanceProfile, manifest.DefaultTransport)
	}
}

// TestRegistryConformanceProfiles: the conformance profile tokens are the
// entries of kind conformance in spec/v1.0/profiles/registry.json, in file order.
func TestRegistryConformanceProfiles(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(repoFixtures, "..", "profiles", "registry.json"))
	if err != nil {
		t.Fatal(err)
	}
	var reg []map[string]any
	if err := strictjson.Unmarshal(b, strictjson.Limits{}, &reg); err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, e := range reg {
		if e["kind"] == "conformance" {
			id, _ := e["id"].(string)
			ids = append(ids, id)
		}
	}
	if got := manifest.ConformanceProfiles(); !slices.Equal(got, ids) {
		t.Errorf("ConformanceProfiles() = %v, registry conformance ids %v", got, ids)
	}
}

// TestTransportProfiles: the transport tokens are the transport profile ids
// of claim.transport in spec/v1.0/profiles/integration-profile.schema.json, the
// baseline https and the entries of kind transport in
// spec/v1.0/profiles/registry.json (draft Section 21: a profile is identified by
// kind, id and version).
func TestTransportProfiles(t *testing.T) {
	profiles := filepath.Join(repoFixtures, "..", "profiles")
	b, err := os.ReadFile(filepath.Join(profiles, "integration-profile.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Defs map[string]struct {
			Properties map[string]struct {
				Enum []string `json:"enum"`
			} `json:"properties"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(b, &schema); err != nil {
		t.Fatal(err)
	}
	var claimEnum []string
	for _, d := range schema.Defs {
		if e := d.Properties["transport_profile"].Enum; e != nil {
			claimEnum = e
		}
	}
	if got := manifest.Transports(); !slices.Equal(got, claimEnum) {
		t.Errorf("Transports() = %v, integration-profile transport_profile enum %v", got, claimEnum)
	}
	b, err = os.ReadFile(filepath.Join(profiles, "registry.json"))
	if err != nil {
		t.Fatal(err)
	}
	var reg []map[string]any
	if err := strictjson.Unmarshal(b, strictjson.Limits{}, &reg); err != nil {
		t.Fatal(err)
	}
	want := []string{manifest.TransportHTTPS}
	for _, e := range reg {
		if e["kind"] == "transport" {
			id, _ := e["id"].(string)
			want = append(want, id)
		}
	}
	if got := manifest.Transports(); !slices.Equal(got, want) {
		t.Errorf("Transports() = %v, want https and the registry transport ids %v", got, want)
	}
}

// TestEntryFieldDefaults: an absent conformance_profile means ["full"] and an
// absent transport ["https"]; the members as written are kept apart from the
// values that apply.
func TestEntryFieldDefaults(t *testing.T) {
	es := baseEntries()
	es[1]["conformance_profile"] = []string{"single-owner"}
	es[1]["transport"] = []string{"stdio-ipc", "https"}
	es[1]["layer"] = "transcript"
	m := parse(t, encode(t, es))
	wantClean(t, m.Validate())

	e := m.Entries[1]
	if !slices.Equal(e.ConformanceProfile, []string{"single-owner"}) || !slices.Equal(e.Transport, []string{"stdio-ipc", "https"}) || e.Layer != "transcript" {
		t.Errorf("decoded as profile %v transport %v layer %q", e.ConformanceProfile, e.Transport, e.Layer)
	}
	if got := e.ConformanceProfiles(); !slices.Equal(got, []string{"single-owner"}) {
		t.Errorf("ConformanceProfiles() = %v", got)
	}
	if got := e.Transports(); !slices.Equal(got, []string{"stdio-ipc", "https"}) {
		t.Errorf("Transports() = %v", got)
	}

	d := m.Entries[2]
	if d.ConformanceProfile != nil || d.Transport != nil || d.Layer != "" {
		t.Errorf("absent members decoded as %v %v %q", d.ConformanceProfile, d.Transport, d.Layer)
	}
	if got := d.ConformanceProfiles(); !slices.Equal(got, []string{"full"}) {
		t.Errorf("default ConformanceProfiles() = %v, want [full]", got)
	}
	if got := d.Transports(); !slices.Equal(got, []string{"https"}) {
		t.Errorf("default Transports() = %v, want [https]", got)
	}
	// The defaults are fresh slices: a caller cannot change them.
	d.ConformanceProfiles()[0] = "x"
	d.Transports()[0] = "x"
	if d.ConformanceProfiles()[0] != "full" || d.Transports()[0] != "https" {
		t.Error("a default changed through a returned slice")
	}
}

// TestValidateEntryFields breaks one field rule of conformance_profile,
// transport, layer or the scope of the new kinds at a time.
func TestValidateEntryFields(t *testing.T) {
	const ev = 1 // the evaluate entry of baseEntries
	const key = 2
	with := func(i int, kv ...any) func([]entry) []entry {
		return func(es []entry) []entry {
			for j := 0; j < len(kv); j += 2 {
				es[i][kv[j].(string)] = kv[j+1]
			}
			return es
		}
	}
	cases := map[string]struct {
		rule string
		edit func([]entry) []entry
	}{
		"profile a string":      {manifest.RuleShape, with(ev, "conformance_profile", "full")},
		"profile null":          {manifest.RuleShape, with(ev, "conformance_profile", nil)},
		"profile item a number": {manifest.RuleShape, with(ev, "conformance_profile", []any{1})},
		"profile empty":         {manifest.RuleConformanceProfile, with(ev, "conformance_profile", []string{})},
		"profile lite":          {manifest.RuleConformanceProfile, with(ev, "conformance_profile", []string{"lite"})},
		"profile upper case":    {manifest.RuleConformanceProfile, with(ev, "conformance_profile", []string{"FULL"})},
		"profile repeated":      {manifest.RuleConformanceProfile, with(ev, "conformance_profile", []string{"full", "full"})},
		"profile on a key":      {manifest.RuleConformanceProfile, with(key, "conformance_profile", []string{"single_owner"})},

		"transport a string":  {manifest.RuleShape, with(ev, "transport", "https")},
		"transport item null": {manifest.RuleShape, with(ev, "transport", []any{nil})},
		"transport empty":     {manifest.RuleTransport, with(ev, "transport", []string{})},
		"transport tcp":       {manifest.RuleTransport, with(ev, "transport", []string{"tcp"})},
		// Channels are not transport profiles: no http, stdio or ipc.
		"transport http":           {manifest.RuleTransport, with(ev, "transport", []string{"http"})},
		"transport stdio":          {manifest.RuleTransport, with(ev, "transport", []string{"stdio"})},
		"transport ipc":            {manifest.RuleTransport, with(ev, "transport", []string{"ipc"})},
		"transport upper case":     {manifest.RuleTransport, with(ev, "transport", []string{"HTTPS"})},
		"transport with a version": {manifest.RuleTransport, with(ev, "transport", []string{"stdio-ipc/0.1"})},
		"transport repeated":       {manifest.RuleTransport, with(ev, "transport", []string{"stdio-ipc", "stdio-ipc"})},

		"layer a number":          {manifest.RuleShape, with(ev, "transport", []string{"stdio-ipc"}, "layer", 1)},
		"layer network":           {manifest.RuleLayer, with(ev, "transport", []string{"stdio-ipc"}, "layer", "network")},
		"layer empty":             {manifest.RuleLayer, with(ev, "transport", []string{"stdio-ipc"}, "layer", "")},
		"layer on https":          {manifest.RuleLayer, with(ev, "transport", []string{"https"}, "layer", "transcript")},
		"layer without transport": {manifest.RuleLayer, with(ev, "layer", "os")},
		"transport kind no layer": {manifest.RuleLayer, with(ev, "kind", "transport", "transport", []string{"stdio-ipc"})},
		"transport kind on https": {manifest.RuleLayer, with(ev, "kind", "transport")},

		"transport kind in core":   {manifest.RuleScope, with(ev, "kind", "transport", "scope", "core", "transport", []string{"stdio-ipc"}, "layer", "os")},
		"transport kind adapter":   {manifest.RuleScope, with(ev, "kind", "transport", "scope", "adapter", "transport", []string{"stdio-ipc"}, "layer", "os")},
		"profile kind in core":     {manifest.RuleScope, with(ev, "kind", "profile", "scope", "core")},
		"profile kind in adapter":  {manifest.RuleScope, with(ev, "kind", "profile", "scope", "adapter")},
		"mcp kind in core":         {manifest.RuleScope, with(ev, "kind", "mcp", "scope", "core")},
		"mcp kind in runner scope": {manifest.RuleScope, with(ev, "kind", "mcp", "scope", "runner")},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			m := parse(t, encode(t, c.edit(baseEntries())))
			where := "admission/valid"
			if name == "profile on a key" {
				where = "keys/holder"
			}
			wantRule(t, m.Validate(), c.rule, where)
		})
	}
}

// TestValidateAcceptsEntryFields: every token of each field, a layer on every
// entry whose transport has stdio-ipc, and each new kind in its scope.
func TestValidateAcceptsEntryFields(t *testing.T) {
	cases := map[string]map[string]any{
		"full":                {"conformance_profile": []string{"full"}},
		"single-owner":        {"conformance_profile": []string{"single-owner"}},
		"both profiles":       {"conformance_profile": []string{"single-owner", "full"}},
		"https":               {"transport": []string{"https"}},
		"stdio-ipc":           {"transport": []string{"stdio-ipc"}},
		"stdio-ipc os":        {"transport": []string{"stdio-ipc"}, "layer": "os"},
		"both, transcript":    {"transport": []string{"https", "stdio-ipc"}, "layer": "transcript"},
		"both, os":            {"transport": []string{"stdio-ipc", "https"}, "layer": "os"},
		"transport kind":      {"kind": "transport", "scope": "runner", "transport": []string{"stdio-ipc"}, "layer": "transcript"},
		"profile kind":        {"kind": "profile", "scope": "runner", "conformance_profile": []string{"single-owner"}},
		"mcp kind":            {"kind": "mcp", "scope": "adapter"},
		"stdio-ipc, no layer": {"transport": []string{"stdio-ipc"}},
		"every field at once": {"conformance_profile": []string{"full", "single-owner"}, "transport": []string{"stdio-ipc"}, "layer": "transcript", "capabilities": []string{"jws-ed25519"}},
	}
	for name, members := range cases {
		t.Run(name, func(t *testing.T) {
			es := baseEntries()
			for k, v := range members {
				es[1][k] = v
			}
			wantClean(t, parse(t, encode(t, es)).Validate())
		})
	}
}

// manifestCase is one case of spec/v1.0/fixtures/testdata/manifest/index.json.
type manifestCase struct {
	File   string `json:"file"`
	Valid  bool   `json:"valid"`
	Reason string `json:"reason"`
	// SchemaErrors are checked against manifest.schema.json by the schema
	// test of cli/pactconf.
	SchemaErrors []json.RawMessage `json:"schema_errors"`
	Rules        []string          `json:"rules"`
}

// TestTestdataManifests: each test manifest of spec/v1.0/fixtures/testdata/manifest
// breaks exactly the field rules its index case lists, and a valid one none.
func TestTestdataManifests(t *testing.T) {
	dir := filepath.Join(repoFixtures, "testdata", "manifest")
	b, err := os.ReadFile(filepath.Join(dir, "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	var idx struct {
		Description string         `json:"description"`
		Schema      string         `json:"schema"`
		Cases       []manifestCase `json:"cases"`
	}
	if err := strictjson.Unmarshal(b, strictjson.Limits{}, &idx); err != nil {
		t.Fatal(err)
	}
	valid, invalid := 0, 0
	for _, c := range idx.Cases {
		if c.Valid {
			valid++
		} else {
			invalid++
		}
		t.Run(c.File, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(dir, c.File))
			if err != nil {
				t.Fatal(err)
			}
			m, err := manifest.Parse(data)
			if err != nil {
				t.Fatal(err)
			}
			got := slices.Compact(slices.Sorted(slices.Values(rules(m.Validate()))))
			want := slices.Sorted(slices.Values(c.Rules))
			if !slices.Equal(got, want) {
				t.Errorf("rules %v, want %v (%s)", got, want, c.Reason)
			}
			if c.Valid != (len(want) == 0 && len(c.SchemaErrors) == 0) {
				t.Errorf("valid = %v, but the case lists rules %v and schema errors %d", c.Valid, c.Rules, len(c.SchemaErrors))
			}
		})
	}
	if valid != 4 || invalid != 9 {
		t.Errorf("%d valid and %d invalid cases, want 4 and 9", valid, invalid)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range entries {
		if f.Name() != "index.json" && !slices.ContainsFunc(idx.Cases, func(c manifestCase) bool { return c.File == f.Name() }) {
			t.Errorf("%s is not in index.json", f.Name())
		}
	}
}

// TestCompletenessTestdata: files under testdata/ at the top of the fixture
// directory are the test data of the checks, not fixtures, and need no
// entry; a testdata directory anywhere else does.
func TestCompletenessTestdata(t *testing.T) {
	tr := newTree(t, baseEntries())
	tr.write("testdata/manifest/valid-defaults.json", "{}")
	tr.write("testdata/manifest/index.json", "{}")
	wantClean(t, manifest.Completeness(tr.root, tr.manifest()))

	tr.write("keys/testdata/x.json", "{}")
	wantRule(t, manifest.Completeness(tr.root, tr.manifest()), manifest.RuleUncovered, "keys/testdata/x.json")

	tr = newTree(t, baseEntries())
	tr.write("testdata/manifest/notes.txt", "x")
	wantRule(t, manifest.Completeness(tr.root, tr.manifest()), manifest.RuleExtension, "testdata/manifest/notes.txt")
}
