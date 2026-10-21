package manifest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"hop.top/pact-go/core/strictjson"
)

// File names in the fixture directory, and the format version.
const (
	FileName       = "manifest.json"
	SchemaFileName = "manifest.schema.json"
	Version        = 1
)

// maxBytes bounds manifest.json. It is an index, not a protocol object, so
// the presentation limit of draft Section 20.1 does not apply.
const maxBytes = 16 << 20

// entryMembers are the members every entry has, all required.
var entryMembers = []string{
	"id", "kind", "scope", "path", "expected", "outcome", "spec_map_row", "draft_section",
}

// optionalMembers are the members an entry may have.
var optionalMembers = []string{"capabilities", "conformance_profile", "transport", "layer"}

// Entry is one fixture of the manifest.
type Entry struct {
	ID    string
	Kind  Kind
	Scope Scope
	// Path is the case directory or single file, relative to the fixture
	// directory.
	Path string
	// Expected is the expected-result file, nil for key, adapter-asset and
	// source-case entries.
	Expected *string
	// Outcome is the one-token result summary, nil for key, adapter-asset
	// and source-case entries.
	Outcome      *string
	SpecMapRow   string
	DraftSection string
	// Capabilities are the optional capabilities the entry tests, nil for
	// an entry without the member, which every implementation must pass. A
	// harness judges an entry only for an implementation that declares each
	// of them (spec/v1.0/fixtures/README.md, Optional capabilities).
	Capabilities []string
	// ConformanceProfile is the member conformance_profile as written, nil
	// when the entry has none; ConformanceProfiles applies the default.
	ConformanceProfile []string
	// Transport is the member transport as written, nil when the entry has
	// none; Transports applies the default.
	Transport []string
	// Layer is the member layer, "" when the entry has none, which applies
	// to every layer. It is set only on an entry whose transport has
	// stdio-ipc.
	Layer string

	// raw holds the members as read; nil when the element is not an object.
	raw map[string]json.RawMessage
}

// Manifest is a parsed manifest.json. Call Validate before relying on it:
// Parse accepts any strict JSON object, and a member that has the wrong JSON
// type reads as its zero value.
type Manifest struct {
	// Version is manifest_version, 0 when it is absent or not an integer.
	Version int
	// Entries are in file order, one per element of entries.
	Entries []Entry

	top map[string]json.RawMessage
}

// Load reads and parses manifest.json in the fixture directory root.
func Load(root string) (*Manifest, error) {
	data, err := os.ReadFile(filepath.Join(root, FileName))
	if err != nil {
		return nil, Problems{{Rule: RuleJSON, Where: FileName, Msg: err.Error(), Err: err}}
	}
	return Parse(data)
}

// Parse reads a manifest with the strict parse rules of draft Section 7.1:
// duplicate member names, non-finite numbers, invalid UTF-8, unpaired
// surrogates, a byte order mark and trailing data are errors. The error is
// Problems with one RuleJSON problem that wraps the strictjson error.
func Parse(data []byte) (*Manifest, error) {
	var top map[string]json.RawMessage
	if err := strictUnmarshal(data, &top); err != nil {
		return nil, Problems{{Rule: RuleJSON, Where: FileName, Msg: err.Error(), Err: err}}
	}
	m := &Manifest{top: top}
	if raw, ok := top["manifest_version"]; ok {
		var v int
		if json.Unmarshal(raw, &v) == nil {
			m.Version = v
		}
	}
	var elems []json.RawMessage
	if raw, ok := top["entries"]; ok && jsonType(raw) == "array" {
		_ = json.Unmarshal(raw, &elems)
	}
	for _, el := range elems {
		var e Entry
		if jsonType(el) == "object" {
			_ = json.Unmarshal(el, &e.raw)
			e.ID = e.str("id")
			e.Kind = Kind(e.str("kind"))
			e.Scope = Scope(e.str("scope"))
			e.Path = e.str("path")
			e.Expected = e.optStr("expected")
			e.Outcome = e.optStr("outcome")
			e.SpecMapRow = e.str("spec_map_row")
			e.DraftSection = e.str("draft_section")
			e.Capabilities = e.strs("capabilities")
			e.ConformanceProfile = e.strs("conformance_profile")
			e.Transport = e.strs("transport")
			e.Layer = e.str("layer")
		}
		m.Entries = append(m.Entries, e)
	}
	return m, nil
}

// ConformanceProfiles returns the conformance profiles the entry runs under:
// its conformance_profile, or [DefaultConformanceProfile] when it has none.
// A run under a profile executes only the entries that list it.
func (e Entry) ConformanceProfiles() []string {
	if e.ConformanceProfile == nil {
		return []string{DefaultConformanceProfile}
	}
	return slices.Clone(e.ConformanceProfile)
}

// Transports returns the transports the entry exercises: its transport, or
// [DefaultTransport] when it has none.
func (e Entry) Transports() []string {
	if e.Transport == nil {
		return []string{DefaultTransport}
	}
	return slices.Clone(e.Transport)
}

// Lookup returns the entry with the given id.
func (m *Manifest) Lookup(id string) (Entry, bool) {
	for _, e := range m.Entries {
		if e.ID == id {
			return e, true
		}
	}
	return Entry{}, false
}

// Validate applies the field rules of spec/v1.0/fixtures/README.md and returns
// every violation, in file order.
func (m *Manifest) Validate() Problems {
	var ps Problems
	for _, k := range sortedKeys(m.top) {
		if k != "manifest_version" && k != "entries" {
			ps.add(RuleShape, FileName, "unknown top-level member %q", k)
		}
	}
	if raw, ok := m.top["manifest_version"]; !ok {
		ps.add(RuleShape, FileName, "no manifest_version")
	} else if string(raw) != "1" {
		ps.add(RuleShape, FileName, "manifest_version is %s, want %d", raw, Version)
	}
	raw, ok := m.top["entries"]
	switch {
	case !ok:
		ps.add(RuleShape, FileName, "no entries")
		return ps
	case jsonType(raw) != "array":
		ps.add(RuleShape, FileName, "entries is %s, not an array", jsonType(raw))
		return ps
	}

	first := map[string]int{}
	for i, e := range m.Entries {
		e.validate(i, &ps)
		if e.ID == "" {
			continue
		}
		if j, dup := first[e.ID]; dup {
			ps.add(RuleIDDuplicate, e.ID, "entries[%d] repeats the id of entries[%d]", i, j)
		} else {
			first[e.ID] = i
		}
		if i > 0 && m.Entries[i-1].ID > e.ID {
			ps.add(RuleOrder, e.ID, "entries[%d] sorts before entries[%d] %s; sort the entries by id", i, i-1, m.Entries[i-1].ID)
		}
	}
	return ps
}

func (e *Entry) validate(i int, ps *Problems) {
	where := e.ID
	if where == "" {
		where = fmt.Sprintf("entries[%d]", i)
	}
	if e.raw == nil {
		ps.add(RuleShape, where, "not an object")
		return
	}
	for _, k := range sortedKeys(e.raw) {
		if !slices.Contains(entryMembers, k) && !slices.Contains(optionalMembers, k) {
			ps.add(RuleShape, where, "unknown member %q", k)
		}
	}
	for _, k := range entryMembers {
		if _, ok := e.raw[k]; !ok {
			ps.add(RuleShape, where, "no %s", k)
		}
	}

	e.check(ps, where, "id", RuleID, false, func(v string) string {
		switch {
		case !fileIDRE.MatchString(v):
			return "is not two or three id segments: lowercase letters, digits and hyphens"
		case e.Kind.Known() && e.Kind != KindAdapterCase && e.Kind != KindSourceCase && !idRE.MatchString(v):
			return fmt.Sprintf("starts a segment with _ or has a . in one; only %s and %s ids may", KindAdapterCase, KindSourceCase)
		}
		return ""
	})
	e.check(ps, where, "kind", RuleKind, false, func(v string) string {
		if !Kind(v).Known() {
			return fmt.Sprintf("is not one of %v", Kinds())
		}
		return ""
	})
	e.check(ps, where, "scope", RuleScope, false, func(v string) string {
		if !Scope(v).Known() {
			return fmt.Sprintf("is not one of %v", Scopes())
		}
		if want, ok := e.Kind.RequiredScope(); ok && Scope(v) != want {
			return fmt.Sprintf("is not %s, the scope of every %s entry", want, e.Kind)
		}
		return ""
	})
	e.check(ps, where, "path", RulePath, false, pathProblem)
	e.check(ps, where, "spec_map_row", RuleSpecMapRow, false, func(v string) string {
		if !specMapRowRE.MatchString(v) {
			return "is not a spec-map row id such as R01 or CL-11.3"
		}
		return ""
	})
	e.check(ps, where, "draft_section", RuleDraftSection, false, func(v string) string {
		if !draftSectionRE.MatchString(v) {
			return `is not a section number or appendix letter such as "11.3" or "C"`
		}
		return ""
	})

	switch e.Kind {
	case KindAdapterCase:
		e.checkAdapterCase(ps, where)
	case KindSourceCase:
		e.checkSourceCase(ps, where)
	}
	e.checkTokens(ps, where, "capabilities", RuleCapabilities, capabilities,
		"leave the member out for an entry every implementation must pass")
	e.checkTokens(ps, where, "conformance_profile", RuleConformanceProfile, conformanceProfiles,
		"leave the member out for an entry of the default profile "+DefaultConformanceProfile)
	e.checkTokens(ps, where, "transport", RuleTransport, transports,
		"leave the member out for an entry of the default transport "+DefaultTransport)
	e.checkLayer(ps, where)

	// expected and outcome are null exactly for the kinds without them.
	known := e.Kind.Known()
	needs := e.Kind.HasExpected()
	e.check(ps, where, "expected", RuleExpected, true, pathProblem)
	e.check(ps, where, "outcome", RuleOutcome, true, func(v string) string {
		if !slices.Contains(outcomes, v) {
			return fmt.Sprintf("is not one of %v", outcomes)
		}
		return ""
	})
	for _, m := range []struct {
		name, rule string
		value      *string
	}{{"expected", RuleExpected, e.Expected}, {"outcome", RuleOutcome, e.Outcome}} {
		raw, present := e.raw[m.name]
		if !known || !present || (jsonType(raw) != "null" && jsonType(raw) != "string") {
			continue
		}
		switch {
		case needs && m.value == nil:
			ps.add(m.rule, where, "%s is null, but kind %s needs one", m.name, e.Kind)
		case !needs && m.value != nil:
			ps.add(m.rule, where, "%s is %q, but kind %s has none: write null", m.name, *m.value, e.Kind)
		}
	}
}

// checkAdapterCase applies RuleAdapterCasePath: an adapter case is the file
// adapters/<adapter>/<case>.json with the id adapters/<adapter>/<case>. An id
// or path that breaks its own field rule is left to that rule.
func (e *Entry) checkAdapterCase(ps *Problems, where string) {
	if !fileIDRE.MatchString(e.ID) || !pathRE.MatchString(e.Path) {
		return
	}
	switch want := e.ID + ".json"; {
	case !adapterCaseIDRE.MatchString(e.ID):
		ps.add(RuleAdapterCasePath, where, "id %q is not adapters/<adapter>/<case>, the id of the case file adapters/<adapter>/<case>.json", e.ID)
	case e.Path != want:
		ps.add(RuleAdapterCasePath, where, "path %q is not the case file %q, the id followed by .json", e.Path, want)
	}
}

// checkSourceCase applies RuleSourceCasePath: a source case is the file
// sources/<source>/<case>.json with the id sources/<source>/<case>. An id or
// path that breaks its own field rule is left to that rule.
func (e *Entry) checkSourceCase(ps *Problems, where string) {
	if !fileIDRE.MatchString(e.ID) || !pathRE.MatchString(e.Path) {
		return
	}
	switch want := e.ID + ".json"; {
	case !sourceCaseIDRE.MatchString(e.ID):
		ps.add(RuleSourceCasePath, where, "id %q is not sources/<source>/<case>, the id of the case file sources/<source>/<case>.json", e.ID)
	case e.Path != want:
		ps.add(RuleSourceCasePath, where, "path %q is not the case file %q, the id followed by .json", e.Path, want)
	}
}

// checkTokens applies rule to the optional member name: an array of one or
// more distinct tokens of known. It serves capabilities, conformance_profile
// and transport. A member of the wrong JSON type, or an item that is not a
// string, is a RuleShape problem; empty says what to write instead of an
// empty array.
func (e *Entry) checkTokens(ps *Problems, where, name, rule string, known []string, empty string) {
	raw, ok := e.raw[name]
	if !ok {
		return
	}
	if t := jsonType(raw); t != "array" {
		ps.add(RuleShape, where, "%s is %s, not an array", name, t)
		return
	}
	var items []json.RawMessage
	_ = json.Unmarshal(raw, &items)
	if len(items) == 0 {
		ps.add(rule, where, "%s is empty: %s", name, empty)
		return
	}
	var seen []string
	for i, item := range items {
		if t := jsonType(item); t != "string" {
			ps.add(RuleShape, where, "%s[%d] is %s, not a string", name, i, t)
			continue
		}
		var c string
		_ = json.Unmarshal(item, &c)
		switch {
		case !slices.Contains(known, c):
			ps.add(rule, where, "%s[%d] %q is not one of %v", name, i, c, known)
		case slices.Contains(seen, c):
			ps.add(rule, where, "%s[%d] %q repeats a token", name, i, c)
		}
		seen = append(seen, c)
	}
}

// checkLayer applies RuleLayer to the member layer: transcript or os, only
// on an entry whose transport, as written or by default, has stdio-ipc, and
// required on an entry of kind transport, the one kind whose entries are
// executed over the local transport. A transport that breaks its own rule is
// left to that rule.
func (e *Entry) checkLayer(ps *Problems, where string) {
	if _, ok := e.raw["layer"]; !ok && e.Kind == KindTransport {
		ps.add(RuleLayer, where, "names no layer: an entry of kind %s says who executes it, %v", KindTransport, layers)
	}
	e.check(ps, where, "layer", RuleLayer, false, func(v string) string {
		if !slices.Contains(layers, v) {
			return fmt.Sprintf("is not one of %v", layers)
		}
		if _, ok := e.raw["transport"]; ok && e.Transport == nil {
			return "" // a malformed transport is reported by its own rule
		}
		if !slices.Contains(e.Transports(), TransportStdioIPC) {
			return fmt.Sprintf("is set, but transport %v has no %s: a layer applies only to the local transport profile", e.Transports(), TransportStdioIPC)
		}
		return ""
	})
}

// check applies test to the string member name. A missing member is reported
// by validate; a member of the wrong JSON type is a RuleShape problem; null is
// accepted only when nullable, and then not passed to test.
func (e *Entry) check(ps *Problems, where, name, rule string, nullable bool, test func(string) string) {
	raw, ok := e.raw[name]
	if !ok {
		return
	}
	switch t := jsonType(raw); {
	case t == "null" && nullable:
		return
	case t != "string":
		ps.add(RuleShape, where, "%s is %s, not a string", name, t)
		return
	}
	var v string
	_ = json.Unmarshal(raw, &v)
	if msg := test(v); msg != "" {
		ps.add(rule, where, "%s %q %s", name, v, msg)
	}
}

func pathProblem(v string) string {
	if !pathRE.MatchString(v) {
		return "is not a relative path: / separated ASCII segments, none empty or starting with ."
	}
	return ""
}

func (e *Entry) str(name string) string {
	var s string
	if raw, ok := e.raw[name]; ok && jsonType(raw) == "string" {
		_ = json.Unmarshal(raw, &s)
	}
	return s
}

// strs returns the member name when it is an array of strings, else nil.
func (e *Entry) strs(name string) []string {
	raw, ok := e.raw[name]
	if !ok || jsonType(raw) != "array" {
		return nil
	}
	var items []json.RawMessage
	_ = json.Unmarshal(raw, &items)
	out := make([]string, 0, len(items))
	for _, item := range items {
		if jsonType(item) != "string" {
			return nil
		}
		var s string
		_ = json.Unmarshal(item, &s)
		out = append(out, s)
	}
	return out
}

func (e *Entry) optStr(name string) *string {
	if raw, ok := e.raw[name]; ok && jsonType(raw) == "string" {
		s := e.str(name)
		return &s
	}
	return nil
}

// jsonType names the JSON type of a valid JSON value.
func jsonType(raw json.RawMessage) string {
	b := bytes.TrimLeft(raw, " \t\r\n")
	if len(b) == 0 {
		return "empty"
	}
	switch b[0] {
	case '{':
		return "object"
	case '[':
		return "array"
	case '"':
		return "string"
	case 'n':
		return "null"
	case 't', 'f':
		return "boolean"
	}
	return "number"
}

func sortedKeys(m map[string]json.RawMessage) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

func strictUnmarshal(data []byte, v any) error {
	return strictjson.Unmarshal(data, strictjson.Limits{MaxBytes: maxBytes}, v)
}
