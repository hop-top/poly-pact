package manifest

import (
	"fmt"
	"strings"
)

// Rules. A Problem names exactly one.
const (
	// RuleJSON: manifest.json is unreadable or not strict JSON (draft 7.1).
	RuleJSON = "manifest-json"
	// RuleShape: a top-level member, an entry member or a JSON type is wrong
	// or missing.
	RuleShape = "manifest-shape"
	// RuleID: an id is not two or three id segments.
	RuleID = "entry-id"
	// RuleIDDuplicate: two entries share an id.
	RuleIDDuplicate = "entry-id-duplicate"
	// RuleOrder: the entries are not sorted by id.
	RuleOrder = "entry-order"
	// RuleKind: kind is not a known kind.
	RuleKind = "entry-kind"
	// RuleScope: scope is not a known scope, or not the one scope of a kind
	// that has one (Kind.RequiredScope).
	RuleScope = "entry-scope"
	// RulePath: path is not a relative slash-separated path.
	RulePath = "entry-path"
	// RuleExpected: expected is malformed, or null where a file is needed, or
	// set where the kind has none.
	RuleExpected = "entry-expected"
	// RuleOutcome: outcome is not a known token, or null where one is needed,
	// or set where the kind has none.
	RuleOutcome = "entry-outcome"
	// RuleSpecMapRow: spec_map_row is not a row id.
	RuleSpecMapRow = "entry-spec-map-row"
	// RuleDraftSection: draft_section is not a section number or letter.
	RuleDraftSection = "entry-draft-section"
	// RuleCapabilities: capabilities is empty, or names a capability twice
	// or one that is not a capability token.
	RuleCapabilities = "entry-capabilities"
	// RuleConformanceProfile: conformance_profile is empty, or names a
	// profile twice or one that is not a conformance profile id.
	RuleConformanceProfile = "entry-conformance-profile"
	// RuleTransport: transport is empty, or names a transport profile twice
	// or one that is not https or stdio-ipc.
	RuleTransport = "entry-transport"
	// RuleLayer: layer is not transcript or os, is set on an entry whose
	// transport has no stdio-ipc, or is absent from an entry of kind
	// transport.
	RuleLayer = "entry-layer"
	// RuleAdapterCasePath: an adapter-case entry is not the file
	// adapters/<adapter>/<case>.json with the id adapters/<adapter>/<case>.
	RuleAdapterCasePath = "adapter-case-path"
	// RuleSourceCasePath: a source-case entry is not the file
	// sources/<source>/<case>.json with the id sources/<source>/<case>.
	RuleSourceCasePath = "source-case-path"
	// RulePathMissing: an entry path does not exist, is a dangling symbolic
	// link, or resolves outside the fixture directory.
	RulePathMissing = "path-missing"
	// RuleExpectedMissing: an expected file does not exist, resolves outside
	// the fixture directory, or is not a file.
	RuleExpectedMissing = "expected-missing"
	// RuleUncovered: a fixture file is in no entry's path, is no entry's
	// expected file, and is not under expected/<id>/ for an entry's id.
	RuleUncovered = "file-uncovered"
	// RuleExtension: a fixture file has an extension outside the neutral
	// list, or a native-asset extension outside an adapter-asset entry.
	RuleExtension = "file-extension"
	// RuleRowUnknown: an entry cites a spec_map_row the spec map lacks.
	RuleRowUnknown = "row-unknown"
	// RuleFixtureMissing: a fixture id named in the spec map is not in the
	// manifest, although its group is landed or its fixture exists.
	RuleFixtureMissing = "fixture-id-missing"
	// RuleGroupPlanned: a group marked planned has manifest entries.
	RuleGroupPlanned = "group-planned-has-entries"
	// RuleGroupPartialEmpty: a group marked partial has no manifest entries.
	RuleGroupPartialEmpty = "group-partial-empty"
	// RuleGroupPartialComplete: every fixture id the spec map names in a
	// group marked partial exists.
	RuleGroupPartialComplete = "group-partial-complete"
	// RuleGroupLanded: a group marked landed has no manifest entries.
	RuleGroupLanded = "group-landed-empty"
	// RuleGroupUnlisted: a manifest entry or a spec-map row names a group
	// that has no row in the Fixture groups table.
	RuleGroupUnlisted = "group-unlisted"
	// RuleSpecMap: the spec map is unreadable or lacks a table, a column or
	// a well-formed row the checks read.
	RuleSpecMap = "spec-map"
)

// Problem is one violation of a rule.
type Problem struct {
	// Rule is one of the Rule constants.
	Rule string
	// Where is the entry id (or entries[i] when the entry has no usable id),
	// the fixture file, the spec-map row, group or fixture id, or the file
	// name of manifest.json or the spec map.
	Where string
	// Msg says what is wrong.
	Msg string
	// Err is the underlying cause, or nil.
	Err error
}

func (p Problem) String() string {
	return "[" + p.Rule + "] " + p.Where + ": " + p.Msg
}

// Problems is a list of problems. As an error it prints one problem per line.
type Problems []Problem

func (ps Problems) Error() string {
	lines := make([]string, len(ps))
	for i, p := range ps {
		lines[i] = p.String()
	}
	return strings.Join(lines, "\n")
}

// Unwrap returns the underlying causes, so errors.Is sees them.
func (ps Problems) Unwrap() []error {
	var out []error
	for _, p := range ps {
		if p.Err != nil {
			out = append(out, p.Err)
		}
	}
	return out
}

// Err returns ps as an error, or nil when it is empty.
func (ps Problems) Err() error {
	if len(ps) == 0 {
		return nil
	}
	return ps
}

func (ps *Problems) add(rule, where, format string, args ...any) {
	*ps = append(*ps, Problem{Rule: rule, Where: where, Msg: fmt.Sprintf(format, args...)})
}
