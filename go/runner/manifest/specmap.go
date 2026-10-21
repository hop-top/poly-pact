package manifest

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// Group statuses of the spec map's Fixture groups table.
const (
	// StatusPlanned: no fixture of the group is committed. The ids the map
	// lists for it are reserved, and the manifest has no entry under it.
	StatusPlanned = "planned"
	// StatusPartial: some fixtures of the group are committed. A listed id
	// whose fixture exists is registered; the others stay reserved. Once
	// every listed id exists, the group is landed.
	StatusPartial = "partial"
	// StatusLanded: every id the map lists for the group exists and is
	// registered.
	StatusLanded = "landed"
)

// statuses are the values of the Status column, in the order of the map.
var statuses = []string{StatusPlanned, StatusPartial, StatusLanded}

// Row is one row of the spec map's Conformance map table.
type Row struct {
	ID string
	// Fixtures are the ids of the Fixture(s) cell, in order.
	Fixtures []string
}

// SpecMap is what the checks read from spec/v1.0/spec-map.md.
type SpecMap struct {
	Rows []Row
	// Groups maps a group of the Fixture groups table to its status.
	Groups map[string]string
}

var (
	fenceRE     = regexp.MustCompile("^ {0,3}(`{3,}|~{3,})")
	separatorRE = regexp.MustCompile(`^:?-+:?$`)
)

// ParseSpecMap reads the Conformance map and Fixture groups tables of a spec
// map, as scripts/check-spec-map.py does. A missing section, table or column
// returns a nil SpecMap; a malformed row, a duplicate row id or group, and a
// status other than planned, partial or landed are reported beside a usable
// SpecMap. Every problem has RuleSpecMap.
func ParseSpecMap(text []byte) (*SpecMap, Problems) {
	var ps Problems
	text = bytes.TrimPrefix(text, []byte("\xef\xbb\xbf"))
	normalized := strings.ReplaceAll(strings.ReplaceAll(string(text), "\r\n", "\n"), "\r", "\n")
	sections := splitSections(normalized)

	sm := &SpecMap{Groups: map[string]string{}}
	header, rows, err := table(sections, "Fixture groups")
	if err == "" {
		groupCol, e1 := column(header, "Group", false)
		statusCol, e2 := column(header, "Status", false)
		err = e1 + e2
		for _, cells := range rows {
			if err != "" {
				break
			}
			if len(cells) != len(header) {
				ps.add(RuleSpecMap, "Fixture groups", "row %q has %d cells, the header has %d", cells[0], len(cells), len(header))
				continue
			}
			group := strings.Trim(cells[groupCol], "` ")
			status := strings.Trim(cells[statusCol], "` ")
			switch _, dup := sm.Groups[group]; {
			case dup:
				ps.add(RuleSpecMap, group, "duplicate group in the Fixture groups table")
			case !slices.Contains(statuses, status):
				ps.add(RuleSpecMap, group, "status %q is not one of %s", status, strings.Join(statuses, ", "))
			default:
				sm.Groups[group] = status
			}
		}
	}
	if err != "" {
		ps.add(RuleSpecMap, "Fixture groups", "%s", err)
		return nil, ps
	}

	header, rows, err = table(sections, "Conformance map")
	if err == "" {
		idCol, e1 := column(header, "ID", false)
		fixCol, e2 := column(header, "Fixture(s)", true)
		err = e1 + e2
		seen := map[string]bool{}
		for _, cells := range rows {
			if err != "" {
				break
			}
			if len(cells) != len(header) {
				ps.add(RuleSpecMap, cells[0], "row has %d cells, the header has %d", len(cells), len(header))
				continue
			}
			row := Row{ID: strings.Trim(cells[idCol], "` ")}
			if seen[row.ID] {
				ps.add(RuleSpecMap, row.ID, "duplicate row id")
			}
			seen[row.ID] = true
			for _, f := range strings.Split(cells[fixCol], ",") {
				if f = strings.Trim(f, " `"); f != "" {
					row.Fixtures = append(row.Fixtures, f)
				}
			}
			sm.Rows = append(sm.Rows, row)
		}
	}
	if err != "" {
		ps.add(RuleSpecMap, "Conformance map", "%s", err)
		return nil, ps
	}
	return sm, ps
}

// CheckSpecMap checks the cross-references between m and sm. root is the
// fixture directory, where FixtureExists looks for the fixture of a listed
// id that has no entry.
//
//   - RuleRowUnknown: an entry's spec_map_row is not a row of sm;
//   - RuleGroupUnlisted: an entry or a row names a group that the Fixture
//     groups table does not list. The ids of such a group are not checked
//     further;
//   - RuleFixtureMissing: a fixture id of a row is not a manifest id, and its
//     group is landed or its fixture exists;
//   - RuleGroupPlanned: a planned group has manifest entries;
//   - RuleGroupPartialEmpty: a partial group has none;
//   - RuleGroupPartialComplete: the fixture of every id the rows list for a
//     partial group exists, registered or not;
//   - RuleGroupLanded: a landed group has no manifest entries.
func CheckSpecMap(root string, m *Manifest, sm *SpecMap) Problems {
	var ps Problems
	rowIDs := map[string]bool{}
	for _, r := range sm.Rows {
		rowIDs[r.ID] = true
	}
	ids := map[string]bool{}
	byGroup := map[string][]string{}
	uncited := map[string][]string{}
	for _, e := range m.Entries {
		if e.ID == "" {
			continue
		}
		ids[e.ID] = true
		g := groupOf(e.ID)
		byGroup[g] = append(byGroup[g], e.ID)
		if e.SpecMapRow != "" && !rowIDs[e.SpecMapRow] {
			uncited[e.SpecMapRow] = append(uncited[e.SpecMapRow], e.ID)
		}
	}
	for _, row := range sortedMapKeys(uncited) {
		ps.add(RuleRowUnknown, row, "not a row of the spec map, but cited by %s", list(uncited[row]))
	}

	var order []string
	citedBy := map[string][]string{}
	listed := map[string][]string{}
	for _, r := range sm.Rows {
		for _, f := range r.Fixtures {
			if _, ok := citedBy[f]; !ok {
				order = append(order, f)
				g := groupOf(f)
				listed[g] = append(listed[g], f)
			}
			if !slices.Contains(citedBy[f], r.ID) {
				citedBy[f] = append(citedBy[f], r.ID)
			}
		}
	}

	unlisted := map[string]bool{}
	for g := range byGroup {
		if _, ok := sm.Groups[g]; !ok {
			unlisted[g] = true
		}
	}
	for g := range listed {
		if _, ok := sm.Groups[g]; !ok {
			unlisted[g] = true
		}
	}
	for _, g := range sortedMapKeys(unlisted) {
		names := slices.Clone(byGroup[g])
		for _, f := range listed[g] {
			if !slices.Contains(names, f) {
				names = append(names, f)
			}
		}
		ps.add(RuleGroupUnlisted, g, "named by %s, but the Fixture groups table has no row for it", list(names))
	}

	exists := map[string]bool{}
	for _, f := range order {
		status, ok := sm.Groups[groupOf(f)]
		if !ok {
			continue
		}
		exists[f] = ids[f] || FixtureExists(root, f)
		switch {
		case ids[f]:
		case status == StatusLanded:
			ps.add(RuleFixtureMissing, f, "named by %s but not in the manifest: group %s is landed, so every id it lists is registered",
				strings.Join(citedBy[f], ", "), groupOf(f))
		case exists[f]:
			ps.add(RuleFixtureMissing, f, "named by %s and present in the fixture directory, but not in the manifest: register it",
				strings.Join(citedBy[f], ", "))
		}
	}

	for _, g := range sortedMapKeys(sm.Groups) {
		found := byGroup[g]
		switch sm.Groups[g] {
		case StatusPlanned:
			if len(found) > 0 {
				ps.add(RuleGroupPlanned, g, "marked planned, but the manifest has entries: %s; mark it partial", list(found))
			}
		case StatusPartial:
			switch {
			case len(found) == 0:
				ps.add(RuleGroupPartialEmpty, g, "marked partial, but the manifest has no entries under it; mark it planned")
			case !slices.ContainsFunc(listed[g], func(f string) bool { return !exists[f] }):
				ps.add(RuleGroupPartialComplete, g, "marked partial, but every id the spec map lists for it exists (%d); mark it landed", len(listed[g]))
			}
		case StatusLanded:
			if len(found) == 0 {
				ps.add(RuleGroupLanded, g, "marked landed, but the manifest has no entries under it")
			}
		}
	}
	return ps
}

// FixtureExists reports whether the fixture of id is in the fixture
// directory root: root/<id> is a file or a directory, or root/<id> followed
// by a neutral extension (.json, .yaml, .md, .jws) is a file. A case
// directory such as admission/valid, a single-file case such as
// parse/appendix-c-wrong-version.jws and an adapter case such as
// adapters/_common/common-03.fragment.json all exist this way. An id that
// does not have the id form exists only through its manifest entry, which
// this function does not consult.
func FixtureExists(root, id string) bool {
	if !fileIDRE.MatchString(id) {
		return false
	}
	full := filepath.Join(root, filepath.FromSlash(id))
	if _, err := os.Stat(full); err == nil {
		return true
	}
	for _, ext := range neutralExtensions {
		if info, err := os.Stat(full + ext); err == nil && info.Mode().IsRegular() {
			return true
		}
	}
	return false
}

func groupOf(id string) string {
	g, _, _ := strings.Cut(id, "/")
	return g
}

// list shortens a list of ids for a message.
func list(ids []string) string {
	if len(ids) > 5 {
		return strings.Join(ids[:5], ", ") + ", ..."
	}
	return strings.Join(ids, ", ")
}

func sortedMapKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// splitSections maps each H2 title to the lines under it that are outside
// fenced code blocks. An H2 inside a fence starts no section.
func splitSections(text string) map[string][]string {
	sections := map[string][]string{}
	current := ""
	fence := ""
	for line := range strings.SplitSeq(text, "\n") {
		if mark := fenceRE.FindStringSubmatch(line); mark != nil {
			switch {
			case fence == "":
				fence = mark[1]
			case mark[1][0] == fence[0] && len(mark[1]) >= len(fence):
				fence = ""
			}
			continue
		}
		if fence != "" {
			continue
		}
		if title, ok := strings.CutPrefix(line, "## "); ok {
			current = strings.TrimSpace(title)
			sections[current] = nil
			continue
		}
		if current != "" {
			sections[current] = append(sections[current], line)
		}
	}
	return sections
}

// table returns the header and rows of the first pipe table of a section,
// or why there is none.
func table(sections map[string][]string, name string) (header []string, rows [][]string, problem string) {
	lines, ok := sections[name]
	if !ok {
		return nil, nil, "the spec map has no '" + name + "' section"
	}
	for _, line := range lines {
		if !strings.HasPrefix(strings.TrimLeft(line, " \t"), "|") {
			if header != nil {
				break
			}
			continue
		}
		cells := splitRow(line)
		if cells == nil {
			return nil, nil, "malformed table line: " + line
		}
		switch {
		case header == nil:
			header = cells
		case allSeparators(cells):
		default:
			rows = append(rows, cells)
		}
	}
	if header == nil {
		return nil, nil, "the '" + name + "' section has no table"
	}
	return header, rows, ""
}

// splitRow splits a table line on pipes not escaped with a backslash. The
// line must start and end with a pipe.
func splitRow(line string) []string {
	line = strings.TrimSpace(line)
	var cells []string
	var cell strings.Builder
	for i := 0; i < len(line); i++ {
		switch {
		case line[i] == '\\' && i+1 < len(line) && line[i+1] == '|':
			cell.WriteByte('|')
			i++
		case line[i] == '|':
			cells = append(cells, cell.String())
			cell.Reset()
		default:
			cell.WriteByte(line[i])
		}
	}
	cells = append(cells, cell.String())
	if len(cells) < 2 || strings.TrimSpace(cells[0]) != "" || strings.TrimSpace(cells[len(cells)-1]) != "" {
		return nil
	}
	cells = cells[1 : len(cells)-1]
	for i, c := range cells {
		cells[i] = strings.TrimSpace(c)
	}
	return cells
}

func allSeparators(cells []string) bool {
	for _, c := range cells {
		if !separatorRE.MatchString(c) {
			return false
		}
	}
	return true
}

// column finds a header cell, compared after trimming backticks and spaces;
// with prefix, a cell that starts with label matches too.
func column(header []string, label string, prefix bool) (int, string) {
	for i, c := range header {
		c = strings.Trim(c, "` ")
		if c == label || prefix && strings.HasPrefix(c, label) {
			return i, ""
		}
	}
	return 0, "the table has no " + label + " column"
}
