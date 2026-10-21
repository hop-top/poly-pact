package runner

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"hop.top/pact-go/runner/manifest"
)

// SchemaID identifies the report format. Its JSON Schema is
// schemas/pactc-report.v1.schema.json, kept in lockstep by schema_test.go.
const SchemaID = "pactc/v1"

// Check is the outcome of the manifest check.
type Check struct {
	Status  Status   `json:"status"`
	Details []string `json:"details,omitempty"`
}

// Result is the outcome of one manifest entry.
type Result struct {
	// ID is the manifest id of the entry.
	ID string `json:"id"`
	// Verb is the verb that ran it, named after the entry's kind.
	Verb   Verb   `json:"verb"`
	Status Status `json:"status"`
	// Details are the differences of a FAIL or the reason of a SKIP.
	Details []string `json:"details,omitempty"`
	// Skipped lists the sub-checks that were not run, each with its reason,
	// when the entry as a whole is PASS or FAIL.
	Skipped []string `json:"skipped,omitempty"`
	// Capabilities are the optional capabilities the entry tests, from its
	// manifest entry; nil for a mandatory entry.
	Capabilities []string `json:"capabilities,omitempty"`
}

// Report is the outcome of a run: the manifest check, then one result per
// selected entry in manifest order.
type Report struct {
	Manifest Check
	// Capabilities are the optional capabilities the implementation
	// declared, sorted, each once.
	Capabilities []string
	// Profile is the conformance profile of the run; "" reads as
	// manifest.DefaultConformanceProfile.
	Profile string
	// Transport are the transports of the run, in the order of
	// manifest.Transports; nil reads as [manifest.DefaultTransport].
	Transport []string
	// ByProfile summarizes the run by conformance profile: one member, the
	// run's profile. The pactc/v1 report adds to each member the roles the
	// profile claims, [RolesClaimed].
	ByProfile map[string]ProfileSummary
	Fixtures  []Result
}

// ProfileSummary counts the entries of a run's kinds that the selectors
// select, for one conformance profile: those that list the profile and share
// a transport with the run are selected and have a result; the others are
// not applicable, never run and never PASS.
type ProfileSummary struct {
	Selected int `json:"selected"`
	// SkippedNotApplicable counts the entries outside the profile or the
	// transports of the run.
	SkippedNotApplicable int `json:"skipped_not_applicable"`
	// SkippedUnsupported counts the selected entries that are SKIP: no
	// command for their verb, no check yet, or an optional capability not
	// declared.
	SkippedUnsupported int `json:"skipped_unsupported"`
	Pass               int `json:"pass"`
	Fail               int `json:"fail"`
}

func (s *ProfileSummary) count(st Status) {
	s.Selected++
	switch st {
	case StatusPass:
		s.Pass++
	case StatusFail:
		s.Fail++
	case StatusSkip:
		s.SkippedUnsupported++
	}
}

// Summary counts the statuses of the manifest check and of every result.
type Summary struct {
	Pass int `json:"pass"`
	Fail int `json:"fail"`
	Skip int `json:"skip"`
}

func (s *Summary) add(st Status) {
	switch st {
	case StatusPass:
		s.Pass++
	case StatusFail:
		s.Fail++
	case StatusSkip:
		s.Skip++
	}
}

// Summary counts the statuses of the manifest check and of every result.
func (r *Report) Summary() Summary {
	var s Summary
	s.add(r.Manifest.Status)
	for _, f := range r.Fixtures {
		s.add(f.Status)
	}
	return s
}

// Failed reports whether the manifest check or any result is FAIL.
func (r *Report) Failed() bool { return r.Summary().Fail > 0 }

// Empty reports whether the run selected no entry. An empty run is never a
// pass: pactc exits 3 for it.
func (r *Report) Empty() bool { return len(r.Fixtures) == 0 }

// profile returns the run's profile, transports and profile summary, with
// the defaults of an unset report.
func (r *Report) profile() (string, []string, map[string]ProfileSummary) {
	p := r.Profile
	if p == "" {
		p = manifest.DefaultConformanceProfile
	}
	t := r.Transport
	if t == nil {
		t = []string{manifest.DefaultTransport}
	}
	by := r.ByProfile
	if by == nil {
		by = map[string]ProfileSummary{p: {}}
	}
	return p, t, by
}

// jsonProfileSummary is the pactc/v1 wire form of a profile summary: the
// counts and the roles the profile claims.
type jsonProfileSummary struct {
	ProfileSummary
	RolesClaimed []string `json:"roles_claimed"`
}

// jsonReport is the pactc/v1 wire form.
type jsonReport struct {
	Schema       string                        `json:"schema"`
	Summary      Summary                       `json:"summary"`
	Manifest     Check                         `json:"manifest"`
	Capabilities []string                      `json:"capabilities"`
	Profile      string                        `json:"profile"`
	Transport    []string                      `json:"transport"`
	ByProfile    map[string]jsonProfileSummary `json:"by_profile"`
	Fixtures     []Result                      `json:"fixtures"`
}

// WriteJSON writes the pactc/v1 report.
func (r *Report) WriteJSON(w io.Writer) error {
	fixtures := r.Fixtures
	if fixtures == nil {
		fixtures = []Result{}
	}
	caps := r.Capabilities
	if caps == nil {
		caps = []string{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	profile, transport, by := r.profile()
	jby := make(map[string]jsonProfileSummary, len(by))
	for p, s := range by {
		roles := RolesClaimed(p)
		if roles == nil {
			roles = []string{}
		}
		jby[p] = jsonProfileSummary{ProfileSummary: s, RolesClaimed: roles}
	}
	return enc.Encode(jsonReport{
		Schema: SchemaID, Summary: r.Summary(), Manifest: r.Manifest, Capabilities: caps,
		Profile: profile, Transport: transport, ByProfile: jby, Fixtures: fixtures,
	})
}

// WriteTable writes the human-readable report: the manifest check, a table
// of results, the details of every FAIL and the summary.
func (r *Report) WriteTable(w io.Writer) {
	idW := len("FIXTURE")
	for _, f := range r.Fixtures {
		idW = max(idW, len(f.ID))
	}
	verbW := len("evaluate")
	caps := "none"
	if len(r.Capabilities) > 0 {
		caps = strings.Join(r.Capabilities, ", ")
	}
	profile, transport, by := r.profile()
	_, _ = fmt.Fprintf(w, "manifest.json  %s\ncapabilities   %s\nprofile        %s\ntransport      %s\n\n",
		r.Manifest.Status, caps, profile, strings.Join(transport, ", "))
	_, _ = fmt.Fprintf(w, "%-*s  %-*s  %s\n", idW, "FIXTURE", verbW, "VERB", "STATUS")
	_, _ = fmt.Fprintln(w, strings.Repeat("-", idW+2+verbW+2+len("STATUS")))
	for _, f := range r.Fixtures {
		_, _ = fmt.Fprintf(w, "%-*s  %-*s  %s\n", idW, f.ID, verbW, f.Verb, f.Status)
	}
	if r.Manifest.Status == StatusFail {
		writeDetails(w, "manifest.json FAIL", r.Manifest.Details)
	}
	for _, f := range r.Fixtures {
		if f.Status == StatusFail {
			writeDetails(w, fmt.Sprintf("%s %s FAIL", f.ID, f.Verb), f.Details)
		}
	}
	for _, f := range r.Fixtures {
		if len(f.Skipped) > 0 {
			writeDetails(w, fmt.Sprintf("%s %s sub-checks skipped", f.ID, f.Verb), f.Skipped)
		}
	}
	s := r.Summary()
	_, _ = fmt.Fprintf(w, "\npass %d, fail %d, skip %d\n", s.Pass, s.Fail, s.Skip)
	for _, p := range manifest.ConformanceProfiles() {
		if ps, ok := by[p]; ok {
			_, _ = fmt.Fprintf(w, "%s: selected %d, not applicable %d, unsupported %d, roles %s\n", p, ps.Selected, ps.SkippedNotApplicable, ps.SkippedUnsupported, strings.Join(RolesClaimed(p), ", "))
		}
	}
}

func writeDetails(w io.Writer, title string, details []string) {
	_, _ = fmt.Fprintf(w, "\n%s:\n", title)
	for _, d := range details {
		_, _ = fmt.Fprintf(w, "  - %s\n", d)
	}
}
