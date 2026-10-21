package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"text/tabwriter"

	"hop.top/pact-go/core/strictjson"
	"hop.top/pact-go/runner"
	pactmanifest "hop.top/pact-go/runner/manifest"
	"hop.top/pact/internal/pactschema"
)

const vectorsHelp = `Reads the fixture manifest, by default ../spec/v1.0/fixtures/manifest.json as
seen from the cli/ directory, and runs every entry of kind vector of the
binding, digest, jcs, jws and strictjson groups through the matching go/core
package, of the schema group through the JSON Schema library (format
assertion on, uri checked per RFC 3986 by the expression the SDKs share),
every entry of kind schema of scope core through the verdict of
spec/v1.0/fixtures/schema/README.md, with ../schemas/pact.schema.json beside the
fixture directory, and every entry of kind key through the key rule. Prints
one PASS,
FAIL or SKIP row per entry, then a summary line. A SKIP is a known spec
defect, reported with both values, the Ed25519 key (optional, draft section
7.2), an entry whose optional capabilities are not all declared, or a vector
entry of scope runner in a group without a runner here: the Go conformance
runner runs it.

Optional capabilities (spec/v1.0/fixtures/README.md): a manifest entry with
capabilities tests a feature the draft makes optional; jws-ed25519 is
Ed25519 negotiation (draft section 7.2). --capability NAME, repeatable,
declares it. An entry runs only when every capability it lists is declared;
otherwise it is SKIP naming the missing ones, and a skipped entry is never
counted as passed. A JWS entry that lists jws-ed25519 runs with Ed25519
negotiated besides ES256; every other entry runs with ES256 alone. Entries
without capabilities always run. An unknown NAME is a usage error.

The key rule: every P-256 JWK under keys/ parses as a public key, and its
point is the scalar of its record in keys/test-private-scalars.json times the
base point; the record of role holder names the key whose RFC 7638
thumbprint is the holder_jkt of draft Appendix C. The entry of
keys/test-private-scalars.json passes when every P-256 record derives.

With --ndjson, standard output carries only one JSON line per vector, key and
schema entry, {"id","kind","result"}, the result being pass, fail,
skipped:out-of-scope, skipped:spec-defect or skipped:capability; a
spec-defect line also carries spec_defects, each
{"vector","appendix_value","expected_digest"}, and a capability line
missing_capabilities, the capabilities of the entry not declared. An entry of
scope runner is skipped:out-of-scope; one whose group has a runner still
runs, and its failure still fails the run. Every row that is not a PASS,
with its detail, and the summary line go to standard error.

The run also fails when an id repeats, when a path or expected file of any
entry is missing, when a .json file under vectors/ is not registered, when a
vector entry of scope core or adapter belongs to a group without a runner,
and when a .go file sits under the fixture directory or the profiles
directory beside it.

Exit status: 0 no row fails; 1 a row fails; 2 usage error (an unknown
--capability included), or the manifest cannot be read or has an entry of
unknown kind, scope, capability, conformance profile, transport or layer.`

// defaultManifest is the fixture manifest seen from the cli/ directory.
var defaultManifest = filepath.Join("..", "spec", "v1.0", "fixtures", "manifest.json")

// maxFixtureBytes bounds one fixture file. The largest, the RFC 8785 number
// list, is under 1 MiB.
const maxFixtureBytes = 4 << 20

// vectorEntry is one manifest entry, with the members every language reads.
type vectorEntry struct {
	ID           string  `json:"id"`
	Kind         string  `json:"kind"`
	Scope        string  `json:"scope"`
	Path         string  `json:"path"`
	Expected     *string `json:"expected"`
	Outcome      *string `json:"outcome"`
	SpecMapRow   string  `json:"spec_map_row"`
	DraftSection string  `json:"draft_section"`
	// Capabilities are the optional capabilities the entry tests; nil for a
	// mandatory entry.
	Capabilities []string `json:"capabilities"`
	// ConformanceProfile, Transport and Layer say under which conformance
	// profile, over which transport and at which layer the entry runs
	// (spec/v1.0/fixtures/README.md, Manifest entry fields); absent members take
	// their defaults. vectors verify runs every entry whatever they say.
	ConformanceProfile []string `json:"conformance_profile"`
	Transport          []string `json:"transport"`
	Layer              string   `json:"layer"`
}

func (e vectorEntry) outcome() string {
	if e.Outcome == nil {
		return ""
	}
	return *e.Outcome
}

type vectorManifest struct {
	ManifestVersion int           `json:"manifest_version"`
	Entries         []vectorEntry `json:"entries"`
}

// vectorRunner runs one manifest entry of its group. root is the fixture
// directory. A nil error is a PASS; a skipped error is a SKIP.
type vectorRunner func(root string, e vectorEntry) error

// vectorGroups maps the group of a vector id, vectors/<group>/..., to the
// go/core package that runs it.
var vectorGroups = map[string]vectorRunner{
	"binding":    runBindingEntry,
	"digest":     runDigestEntry,
	"jcs":        runJCSEntry,
	"jws":        runJWSEntry,
	"schema":     runSchemaEntry,
	"strictjson": runStrictJSONEntry,
}

// The reasons of a skipped result in the NDJSON result grammar. os-layer,
// a reason of the grammar too, is reserved for a manifest field that does
// not exist yet.
const (
	reasonOutOfScope = "out-of-scope"
	reasonSpecDefect = "spec-defect"
	// reasonCapability: the entry tests an optional capability that was not
	// declared with --capability (spec/v1.0/fixtures/README.md, Optional
	// capabilities), so it is not run.
	reasonCapability = "capability"
)

// skipped is a result that is neither a pass nor a failure: a known spec
// defect, reported with both values, an entry out of scope here, or an
// entry whose capabilities are not all declared, with the missing ones.
type skipped struct {
	reason  string
	msg     string
	defects []specDefect
	missing []string
}

func (s skipped) Error() string { return s.msg }

// specDefect is a vector whose value printed in the draft differs from the
// value its algorithm gives.
type specDefect struct {
	Vector         string `json:"vector"`
	AppendixValue  string `json:"appendix_value"`
	ExpectedDigest string `json:"expected_digest"`
}

type row struct{ result, id, detail string }

// entryResult is the row of a vector or key entry with what an NDJSON line
// needs besides it.
type entryResult struct {
	row
	kind, scope string
	skip        skipped
}

// ndjsonLine is one line of --ndjson.
type ndjsonLine struct {
	ID          string       `json:"id"`
	Kind        string       `json:"kind"`
	Result      string       `json:"result"`
	SpecDefects []specDefect `json:"spec_defects,omitempty"`
	// MissingCapabilities, on a skipped:capability line, are the
	// capabilities of the entry that were not declared.
	MissingCapabilities []string `json:"missing_capabilities,omitempty"`
}

// runVectors runs vectors verify on manifestPath and returns the exit
// status: 0 when every row passes or is skipped, 1 when one fails, 2 when
// a declared capability is unknown, or the manifest cannot be read or has
// an entry of unknown kind, scope, capability, conformance profile,
// transport or layer. ndjson selects the NDJSON
// rendering; caps are the declared optional capabilities.
func runVectors(manifestPath string, ndjson bool, caps []string, stdout, stderr io.Writer) int {
	for _, c := range caps {
		if !slices.Contains(pactmanifest.Capabilities(), c) {
			_, _ = fmt.Fprintf(stderr, "pactconf vectors verify: --capability %q is not an optional capability of the fixtures; want one of %s\n",
				c, strings.Join(pactmanifest.Capabilities(), ", "))
			return 2
		}
	}
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "pactconf vectors verify: %v\n", err)
		return 2
	}
	var m vectorManifest
	if err := strictjson.Unmarshal(data, strictjson.Limits{MaxBytes: maxFixtureBytes}, &m); err != nil {
		_, _ = fmt.Fprintf(stderr, "pactconf vectors verify: %s: %v\n", manifestPath, err)
		return 2
	}
	if err := knownKindsAndScopes(m); err != nil {
		_, _ = fmt.Fprintf(stderr, "pactconf vectors verify: %s: %v\n", manifestPath, err)
		return 2
	}
	root := filepath.Dir(manifestPath)
	tree := treeChecks(root, m)
	results := runVectorEntries(root, m, caps)
	if ndjson {
		return printNDJSON(stdout, stderr, tree, results)
	}
	rows := tree
	for _, r := range results {
		rows = append(rows, r.row)
	}
	return printRows(stdout, rows)
}

// knownKindsAndScopes refuses an entry whose kind, scope, layer or one of
// whose capabilities, conformance profiles or transports is outside the
// closed sets of the manifest format.
func knownKindsAndScopes(m vectorManifest) error {
	for _, e := range m.Entries {
		for _, c := range e.Capabilities {
			if !slices.Contains(pactmanifest.Capabilities(), c) {
				return fmt.Errorf("entry %s: capability %q is not one of %s", e.ID, c, strings.Join(pactmanifest.Capabilities(), ", "))
			}
		}
		for _, f := range []struct {
			member string
			tokens []string
			known  []string
		}{
			{"conformance_profile", e.ConformanceProfile, pactmanifest.ConformanceProfiles()},
			{"transport", e.Transport, pactmanifest.Transports()},
			{"layer", nonEmpty(e.Layer), pactmanifest.Layers()},
		} {
			for _, tok := range f.tokens {
				if !slices.Contains(f.known, tok) {
					return fmt.Errorf("entry %s: %s %q is not one of %s", e.ID, f.member, tok, strings.Join(f.known, ", "))
				}
			}
		}
		if !pactmanifest.Kind(e.Kind).Known() {
			return fmt.Errorf("entry %s: kind %q is not one of %s", e.ID, e.Kind, strings.Join(pactmanifest.Kinds(), ", "))
		}
		if !pactmanifest.Scope(e.Scope).Known() {
			return fmt.Errorf("entry %s: scope %q is not one of %s", e.ID, e.Scope, strings.Join(pactmanifest.Scopes(), ", "))
		}
	}
	return nil
}

// nonEmpty returns s as a one-element list, or nil when s is empty.
func nonEmpty(s string) []string {
	if s == "" {
		return nil
	}
	return []string{s}
}

// runVectorEntries runs every kind vector entry through the runner of its
// group, and every kind key entry through the key rule. An entry with a
// capability that caps does not declare is skipped and not run. An entry
// whose group has no runner is skipped when its scope is runner, since only
// the Go conformance runner must pass it, and fails otherwise.
func runVectorEntries(root string, m vectorManifest, caps []string) []entryResult {
	var out []entryResult
	for _, e := range m.Entries {
		var missing []string
		for _, c := range e.Capabilities {
			if !slices.Contains(caps, c) {
				missing = append(missing, c)
			}
		}
		var run vectorRunner
		switch e.Kind {
		case "vector":
			if parts := strings.Split(e.ID, "/"); len(parts) >= 3 && parts[0] == "vectors" {
				run = vectorGroups[parts[1]]
			}
		case "key":
			run = runKeyEntry
		case "schema":
			// A schema entry of scope runner is the Go conformance
			// runner's alone (pactc run).
			if e.Scope == "runner" {
				continue
			}
			run = runSchemaKindEntry
		default:
			continue
		}
		var err error
		switch {
		case len(missing) > 0:
			err = skipped{reason: reasonCapability, missing: missing, msg: fmt.Sprintf(
				"optional capability %s not declared (--capability): the entry applies only to an implementation that declares it, and a skipped entry is not passed (draft 22.2)",
				strings.Join(missing, ", "))}
		case run != nil:
			err = run(root, e)
		case e.Scope == "runner":
			err = skipped{reason: reasonOutOfScope, msg: "scope runner: run by the Go conformance runner, not by pactconf"}
		default:
			err = fmt.Errorf("no runner for this group; groups: %s", strings.Join(slices.Sorted(maps.Keys(vectorGroups)), ", "))
		}
		r := entryResult{row: row{"PASS", e.ID, ""}, kind: e.Kind, scope: e.Scope}
		switch err := err.(type) {
		case nil:
		case skipped:
			r.result, r.detail, r.skip = "SKIP", err.Error(), err
		default:
			r.result, r.detail = "FAIL", err.Error()
		}
		out = append(out, r)
	}
	return out
}

// printNDJSON writes one line per entry result on stdout, and every row
// that is not a PASS, then the summary, on stderr. It returns the exit code:
// 1 when any row failed, an entry of scope runner included.
func printNDJSON(stdout, stderr io.Writer, tree []row, results []entryResult) int {
	var lines bytes.Buffer
	enc := json.NewEncoder(&lines)
	enc.SetEscapeHTML(false)
	count := map[string]int{}
	note := func(r row) {
		count[r.result]++
		if r.result != "PASS" {
			_, _ = fmt.Fprintf(stderr, "%s %s: %s\n", r.result, r.id, oneLine(r.detail))
		}
	}
	for _, r := range tree {
		note(r)
	}
	for _, r := range results {
		note(r.row)
		l := ndjsonLine{ID: r.id, Kind: r.kind}
		switch {
		case r.scope == "runner":
			l.Result = "skipped:" + reasonOutOfScope
		case r.result == "PASS":
			l.Result = "pass"
		case r.result == "FAIL":
			l.Result = "fail"
		default:
			l.Result = "skipped:" + r.skip.reason
			switch r.skip.reason {
			case reasonSpecDefect:
				l.SpecDefects = r.skip.defects
			case reasonCapability:
				l.MissingCapabilities = r.skip.missing
			}
		}
		_ = enc.Encode(l)
	}
	_, _ = stdout.Write(lines.Bytes())
	_, _ = fmt.Fprintf(stderr, "%d passed, %d failed, %d skipped\n", count["PASS"], count["FAIL"], count["SKIP"])
	if count["FAIL"] > 0 {
		return 1
	}
	return 0
}

// treeChecks checks the manifest against the tree: every id once, every
// path and expected file present, every .json file under vectors/ covered
// by an entry, and no Go source under the fixture or profile directories.
// File rows name the file relative to the spec directory, the parent of
// root.
func treeChecks(root string, m vectorManifest) []row {
	var rows []row
	seen := map[string]bool{}
	var covered []string
	for _, e := range m.Entries {
		if seen[e.ID] {
			rows = append(rows, row{"FAIL", e.ID, "id repeated in the manifest"})
		}
		seen[e.ID] = true
		refs := []string{e.Path}
		if e.Expected != nil {
			refs = append(refs, *e.Expected)
		}
		for _, p := range refs {
			covered = append(covered, p)
			if !localPath(p) {
				rows = append(rows, row{"FAIL", e.ID, fmt.Sprintf("path %q is not a relative path inside the fixture directory", p)})
				continue
			}
			if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(p))); err != nil {
				rows = append(rows, row{"FAIL", e.ID, fmt.Sprintf("%s does not exist", p)})
			}
		}
	}

	spec := filepath.Dir(root)
	walk := func(dir string, visit func(rel string)) {
		_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			if rel, err := filepath.Rel(spec, p); err == nil {
				visit(filepath.ToSlash(rel))
			}
			return nil
		})
	}
	fixturesName := filepath.Base(root)
	walk(filepath.Join(root, "vectors"), func(rel string) {
		inFixtures := strings.TrimPrefix(rel, fixturesName+"/")
		if path.Ext(rel) == ".json" && !slices.ContainsFunc(covered, func(c string) bool { return within(inFixtures, c) }) {
			rows = append(rows, row{"FAIL", rel, "vector file not registered in the manifest"})
		}
	})
	for _, dir := range []string{root, filepath.Join(spec, "profiles")} {
		walk(dir, func(rel string) {
			if path.Ext(rel) == ".go" {
				rows = append(rows, row{"FAIL", rel, "Go source in the language-neutral tree"})
			}
		})
	}
	return rows
}

// within reports whether rel is the entry path p or lies inside it.
func within(rel, p string) bool {
	return rel == p || strings.HasPrefix(rel, strings.TrimSuffix(p, "/")+"/")
}

// localPath reports whether p is a slash-separated relative path with no
// empty, "." or ".." segment.
func localPath(p string) bool {
	if p == "" || strings.HasPrefix(p, "/") || strings.Contains(p, "\\") {
		return false
	}
	for seg := range strings.SplitSeq(p, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
	}
	return true
}

// printRows writes the table and a summary line, and returns the exit code:
// 1 when any row failed.
func printRows(w io.Writer, rows []row) int {
	var table bytes.Buffer
	tw := tabwriter.NewWriter(&table, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "RESULT\tID\tDETAIL")
	count := map[string]int{}
	for _, r := range rows {
		count[r.result]++
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\n", r.result, r.id, oneLine(r.detail))
	}
	_ = tw.Flush()
	for line := range strings.Lines(table.String()) {
		_, _ = io.WriteString(w, strings.TrimRight(line, " \n")+"\n")
	}
	_, _ = fmt.Fprintf(w, "%d passed, %d failed, %d skipped\n", count["PASS"], count["FAIL"], count["SKIP"])
	if count["FAIL"] > 0 {
		return 1
	}
	return 0
}

func oneLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// readFixture reads a fixture file named relative to root.
func readFixture(root, rel string) ([]byte, error) {
	if !localPath(rel) {
		return nil, fmt.Errorf("path %q is not inside the fixture directory", rel)
	}
	return os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
}

// readFixtureJSON strict-parses a fixture file (draft 7.1) into v.
func readFixtureJSON(root, rel string, v any) ([]byte, error) {
	b, err := readFixture(root, rel)
	if err != nil {
		return nil, err
	}
	if err := strictjson.Unmarshal(b, strictjson.Limits{MaxBytes: maxFixtureBytes}, v); err != nil {
		return nil, fmt.Errorf("%s: %w", rel, err)
	}
	return b, nil
}

// singleFile checks that an entry names one JSON file holding its own
// expectations.
func singleFile(e vectorEntry) error {
	if path.Ext(e.Path) != ".json" || e.Expected == nil || *e.Expected != e.Path {
		return fmt.Errorf("path %q and expected %v must name the same JSON file", e.Path, e.Expected)
	}
	return nil
}

// checkMembers reports a member of the JSON object raw that is missing from
// want or not in it. strictjson already refuses unknown members of a struct;
// this also catches a missing one.
func checkMembers(raw []byte, want ...string) error {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return err
	}
	got := make([]string, 0, len(m))
	for k := range m {
		got = append(got, k)
	}
	slices.Sort(got)
	want = slices.Sorted(slices.Values(want))
	if !slices.Equal(got, want) {
		return fmt.Errorf("members %v, want exactly %v", got, want)
	}
	return nil
}

// runSchemaKindEntry applies the verdict of spec/v1.0/fixtures/schema/README.md to
// the schema entry e, with the schema in schemas/pact.schema.json beside the
// fixture directory root: the entry passes when its expected outcome and
// code hold.
func runSchemaKindEntry(root string, e vectorEntry) error {
	v, err := pactschema.Load(filepath.Join(filepath.Dir(root), "schemas", "pact.schema.json"))
	if err != nil {
		return err
	}
	me := pactmanifest.Entry{
		ID: e.ID, Kind: pactmanifest.Kind(e.Kind), Scope: pactmanifest.Scope(e.Scope), Path: e.Path,
		Expected: e.Expected, Outcome: e.Outcome, SpecMapRow: e.SpecMapRow, DraftSection: e.DraftSection,
		Capabilities: e.Capabilities, ConformanceProfile: e.ConformanceProfile, Transport: e.Transport, Layer: e.Layer,
	}
	if problems := runner.CheckSchemaFixture(root, me, v); len(problems) > 0 {
		return errors.New(strings.Join(problems, "; "))
	}
	return nil
}
