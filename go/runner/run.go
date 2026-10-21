package runner

import (
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"hop.top/pact-go/runner/manifest"
)

// Config configures a run. Every command template may be empty: the entries
// of a verb without a command are SKIP.
type Config struct {
	// FixturesRoot is the fixture directory, the one that holds
	// manifest.json.
	FixturesRoot string
	// Fixtures selects entries by manifest id or id prefix. Empty selects
	// every entry of a kind the runner handles.
	Fixtures []string
	// EvaluateCmd is the evaluate template, "tool evaluate {dir} {state}";
	// {state} is optional, needed when ReceiptCmd is set.
	EvaluateCmd string
	// ReceiptCmd is the optional receipt template,
	// "tool receipt {state} {id}": it prints the compact receipt with the jti
	// {id} that the evaluate command of the same case printed, with the same
	// {state}. Without it the receipts of earlier exchanges are not asked for
	// again, and that sub-check is reported as skipped.
	ReceiptCmd string
	// OutcomesCmd is the outcomes template, "tool outcomes {dir} {state}".
	OutcomesCmd string
	// LearningCmd is the learning template, "tool learning {dir} {state}".
	LearningCmd string
	// SchemaCmd is the optional schema template, "tool schema {dir}", where
	// {dir} is the absolute path of the entry's file.
	SchemaCmd string
	// Validator validates documents against the Appendix A.3 schema. With
	// it the schema verb also checks each case's expectation against the
	// schema (spec/v1.0/fixtures/schema/README.md, Verdict); without it that
	// sub-check is reported as skipped.
	Validator SchemaValidator
	// SchemaCheck is the mode of that fixture schema check: [SchemaCheckGate]
	// (also ""), the default, runs it; [SchemaCheckOff] does not run it, so
	// the schema verb judges an entry on the schema command alone and lists
	// the skip, naming --schema-check, in [Result.Skipped]. Any other value
	// is an error of [Run]. Off is a local diagnostic, not a conformance
	// mode.
	SchemaCheck string
	// Capabilities are the optional capabilities the implementation
	// declares, tokens of manifest.Capabilities (spec/v1.0/fixtures/README.md,
	// Optional capabilities). An entry that tests a capability not declared
	// here is SKIP, never judged and never counted as passed.
	Capabilities []string
	// Profile is the conformance profile of the run, an id of
	// manifest.ConformanceProfiles, the entries of kind conformance in
	// spec/v1.0/profiles/registry.json; empty means
	// manifest.DefaultConformanceProfile. Only the entries that list it run
	// (spec/v1.0/fixtures/README.md, Manifest entry fields); the others are not
	// applicable and never PASS.
	Profile string
	// Transport are the transport profiles of the run, ids of
	// manifest.Transports(): https or stdio-ipc; nil means
	// [manifest.DefaultTransport]. Only the
	// entries whose transport shares one with them run.
	Transport []string
}

// Status is the outcome of one check.
type Status string

// Statuses.
const (
	StatusPass Status = "PASS"
	StatusFail Status = "FAIL"
	StatusSkip Status = "SKIP"
)

// Verb is a harness verb. Each runs the manifest entries of the kind of the
// same name.
type Verb string

// Verbs.
const (
	VerbEvaluate Verb = "evaluate"
	VerbOutcomes Verb = "outcomes"
	VerbLearning Verb = "learning"
	VerbSchema   Verb = "schema"
)

var verbs = []Verb{VerbEvaluate, VerbOutcomes, VerbLearning, VerbSchema}

// Verbs returns the verbs in report order.
func Verbs() []Verb { return slices.Clone(verbs) }

// verbOf returns the verb that runs entries of kind k. The other kinds (keys,
// vectors, adapter cases and assets, invalid profiles) belong to other
// harnesses.
func verbOf(k manifest.Kind) (Verb, bool) {
	switch k {
	case manifest.KindEvaluate:
		return VerbEvaluate, true
	case manifest.KindOutcomes:
		return VerbOutcomes, true
	case manifest.KindLearning:
		return VerbLearning, true
	case manifest.KindSchema:
		return VerbSchema, true
	}
	return "", false
}

// command returns the template of v and the flag that sets it.
func (c Config) command(v Verb) (tmpl, flag string) {
	switch v {
	case VerbEvaluate:
		return c.EvaluateCmd, "--evaluate-cmd"
	case VerbOutcomes:
		return c.OutcomesCmd, "--outcomes-cmd"
	case VerbLearning:
		return c.LearningCmd, "--learning-cmd"
	default:
		return c.SchemaCmd, "--schema-cmd"
	}
}

// Modes of the fixture schema check of the schema verb, the values of
// [Config.SchemaCheck].
const (
	// SchemaCheckGate runs the check: a case whose expectation the schema
	// contradicts fails. It is the default.
	SchemaCheckGate = "gate"
	// SchemaCheckOff leaves the check out and lists it in [Result.Skipped].
	SchemaCheckOff = "off"
)

// ParseSchemaCheck returns the mode m of the fixture schema check, or an
// error naming the modes when m is neither [SchemaCheckGate] nor
// [SchemaCheckOff]. m is compared exactly; "" is an error here, the value of
// a flag given empty, while [Config.SchemaCheck] "" means the default.
func ParseSchemaCheck(m string) (string, error) {
	switch m {
	case SchemaCheckGate, SchemaCheckOff:
		return m, nil
	}
	return "", fmt.Errorf("--schema-check %q is not a schema check mode; want %s or %s", m, SchemaCheckGate, SchemaCheckOff)
}

// RuleManifestIncomplete names a fixture file that no manifest entry covers.
const RuleManifestIncomplete = "manifest-incomplete"

// Run loads the manifest of cfg.FixturesRoot, checks it against the fixture
// directory and runs the selected entries. It returns an error, and no
// report, when the manifest cannot be read or is not strict JSON, or when a
// selector selects no entry the runner handles.
func Run(cfg Config) (*Report, error) {
	declared, err := declaredCapabilities(cfg.Capabilities)
	if err != nil {
		return nil, err
	}
	profile, err := runProfile(cfg.Profile)
	if err != nil {
		return nil, err
	}
	if cfg.SchemaCheck == "" {
		cfg.SchemaCheck = SchemaCheckGate
	}
	if cfg.SchemaCheck, err = ParseSchemaCheck(cfg.SchemaCheck); err != nil {
		return nil, err
	}
	transport, err := runTransports(cfg.Transport)
	if err != nil {
		return nil, err
	}
	m, err := manifest.Load(cfg.FixturesRoot)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", filepath.Join(cfg.FixturesRoot, manifest.FileName), err)
	}
	entries, err := selectEntries(m, cfg.Fixtures)
	if err != nil {
		return nil, err
	}
	rep := &Report{
		Manifest: checkManifest(cfg.FixturesRoot, m), Capabilities: declared,
		Profile: profile, Transport: transport, Fixtures: []Result{},
	}
	var sum ProfileSummary
	for _, e := range entries {
		if !applies(e, profile, transport) {
			sum.SkippedNotApplicable++
			continue
		}
		r := runEntry(cfg, e)
		sum.count(r.Status)
		rep.Fixtures = append(rep.Fixtures, r)
	}
	rep.ByProfile = map[string]ProfileSummary{profile: sum}
	return rep, nil
}

// runProfile returns the conformance profile of a run, the default for "",
// or an error naming the conformance profiles of the registry.
func runProfile(p string) (string, error) {
	if p == "" {
		return manifest.DefaultConformanceProfile, nil
	}
	if known := manifest.ConformanceProfiles(); !slices.Contains(known, p) {
		return "", fmt.Errorf("--profile %q is not a conformance profile of spec/v1.0/profiles/registry.json; want one of %s", p, strings.Join(known, ", "))
	}
	return p, nil
}

// runTransports returns the transports of a run, each once in the order of
// manifest.Transports, the default for none, or an error naming one that is
// not a transport.
func runTransports(ts []string) ([]string, error) {
	if len(ts) == 0 {
		return []string{manifest.DefaultTransport}, nil
	}
	known := manifest.Transports()
	for _, t := range ts {
		if !slices.Contains(known, t) {
			return nil, fmt.Errorf("--transport %q is not a transport profile id; want one of %s", t, strings.Join(known, ", "))
		}
	}
	out := []string{}
	for _, t := range known {
		if slices.Contains(ts, t) {
			out = append(out, t)
		}
	}
	return out, nil
}

// applies reports whether the entry e belongs to a run under profile over
// transports: it lists the profile, absent conformance_profile meaning
// ["full"], and shares a transport with the run, absent transport meaning
// ["https"].
func applies(e manifest.Entry, profile string, transports []string) bool {
	return slices.Contains(e.ConformanceProfiles(), profile) &&
		slices.ContainsFunc(e.Transports(), func(t string) bool { return slices.Contains(transports, t) })
}

// declaredCapabilities returns the declared capabilities sorted, each once,
// or an error naming one that is not a capability token.
func declaredCapabilities(caps []string) ([]string, error) {
	known := manifest.Capabilities()
	out := []string{}
	for _, c := range caps {
		if !slices.Contains(known, c) {
			return nil, fmt.Errorf("--capability %q is not an optional capability of the fixtures; want one of %s", c, strings.Join(known, ", "))
		}
		if !slices.Contains(out, c) {
			out = append(out, c)
		}
	}
	slices.Sort(out)
	return out, nil
}

// checkManifest applies the field rules and the completeness check of
// package manifest. A file no entry covers is reported as
// RuleManifestIncomplete; other problems keep their manifest rule.
func checkManifest(root string, m *manifest.Manifest) Check {
	ps := m.Validate()
	ps = append(ps, manifest.Completeness(root, m)...)
	if len(ps) == 0 {
		return Check{Status: StatusPass}
	}
	c := Check{Status: StatusFail}
	for _, p := range ps {
		rule := p.Rule
		if rule == manifest.RuleUncovered {
			rule = RuleManifestIncomplete
		}
		c.Details = append(c.Details, "["+rule+"] "+p.Where+": "+p.Msg)
	}
	return c
}

// selectEntries returns the entries of a kind the runner handles that match
// a selector, in manifest order, each once. Every selector must match one.
func selectEntries(m *manifest.Manifest, selectors []string) ([]manifest.Entry, error) {
	var runnable []manifest.Entry
	for _, e := range m.Entries {
		if _, ok := verbOf(e.Kind); ok {
			runnable = append(runnable, e)
		}
	}
	if len(selectors) == 0 {
		return runnable, nil
	}
	for _, s := range selectors {
		if s == "" {
			return nil, errors.New("--fixture: empty selector")
		}
		if !slices.ContainsFunc(runnable, func(e manifest.Entry) bool { return selects(s, e.ID) }) {
			return nil, fmt.Errorf("--fixture %q selects no manifest entry of kind %s", s, verbList())
		}
	}
	var out []manifest.Entry
	for _, e := range runnable {
		if slices.ContainsFunc(selectors, func(s string) bool { return selects(s, e.ID) }) {
			out = append(out, e)
		}
	}
	return out, nil
}

// selects reports whether the selector s, a manifest id or id prefix,
// selects id.
func selects(s, id string) bool { return strings.HasPrefix(id, s) }

func verbList() string {
	names := make([]string, len(verbs))
	for i, v := range verbs {
		names[i] = string(v)
	}
	return strings.Join(names, ", ")
}

func runEntry(cfg Config, e manifest.Entry) Result {
	v, _ := verbOf(e.Kind)
	r := Result{ID: e.ID, Verb: v, Capabilities: e.Capabilities}
	var missing []string
	for _, c := range e.Capabilities {
		if !slices.Contains(cfg.Capabilities, c) {
			missing = append(missing, c)
		}
	}
	if len(missing) > 0 {
		return r.with(StatusSkip, fmt.Sprintf("optional capability %s not declared (--capability): the entry applies only to an implementation that declares it, and a skipped entry is not passed (draft 22.2)", strings.Join(missing, ", ")))
	}
	tmpl, flag := cfg.command(v)
	if strings.TrimSpace(tmpl) == "" {
		return r.with(StatusSkip, "no "+flag)
	}
	switch v {
	case VerbEvaluate:
		return checkEvaluate(cfg.FixturesRoot, e, tmpl, cfg.ReceiptCmd, r)
	case VerbOutcomes:
		return checkOutcomes(cfg.FixturesRoot, e, tmpl, r)
	case VerbLearning:
		return checkLearning(cfg.FixturesRoot, e, tmpl, r)
	default:
		return checkSchema(cfg, e, tmpl, r)
	}
}

func (r Result) with(s Status, details ...string) Result {
	r.Status = s
	r.Details = details
	return r
}
