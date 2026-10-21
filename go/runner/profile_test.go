package runner

// Conformance profile and transport selection (spec/v1.0/fixtures/README.md,
// Manifest entry fields): a run under a conformance profile executes only the
// entries that list it, absent conformance_profile meaning ["full"], over the
// transports whose entries share one with the run, absent transport meaning
// ["https"]. An entry outside the run is never reported PASS in it: it is
// counted as not applicable. A run that selects no entry is never green.

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"hop.top/pact-go/runner/manifest"
)

// other is a second committed evaluate case, judged PASS by the good mode.
const other = "admission/old-holder-key"

// withMembers sets members of the manifest entry id in root, as written.
func withMembers(t *testing.T, root, id string, members map[string]any) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		Entries []entry `json:"entries"`
	}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range m.Entries {
		if e["id"] == id {
			for k, v := range members {
				e[k] = v
			}
			found = true
		}
	}
	if !found {
		t.Fatalf("no entry %s", id)
	}
	writeManifest(t, root, m.Entries)
	return root
}

func fixtureIDs(rep *Report) []string {
	var out []string
	for _, f := range rep.Fixtures {
		out = append(out, f.ID)
	}
	return out
}

func runOK(t *testing.T, cfg Config) *Report {
	t.Helper()
	rep, err := Run(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

// TestProfileDefaults: without --profile and --transport a run is a full run
// over http, and an entry without the members belongs to it.
func TestProfileDefaults(t *testing.T) {
	rep := runOK(t, fakeImplCfg(t, "good", subsetRoot(t, validCase, other)))
	if rep.Profile != manifest.ConformanceProfileFull || !slices.Equal(rep.Transport, []string{manifest.TransportHTTPS}) {
		t.Errorf("profile %q transport %v, want full [https]", rep.Profile, rep.Transport)
	}
	if got := fixtureIDs(rep); !slices.Equal(got, []string{other, validCase}) && !slices.Equal(got, []string{validCase, other}) {
		t.Errorf("fixtures %v, want both entries", got)
	}
	want := ProfileSummary{Selected: 2, Pass: 2}
	if got := rep.ByProfile; len(got) != 1 || got[manifest.ConformanceProfileFull] != want {
		t.Errorf("by_profile %+v, want only full %+v", got, want)
	}
	if rep.Empty() || rep.Failed() {
		t.Errorf("empty %v failed %v, want a green run", rep.Empty(), rep.Failed())
	}
}

// TestProfileSelection: each run executes exactly the entries that list its
// profile; the others are counted as not applicable and never PASS.
func TestProfileSelection(t *testing.T) {
	root := subsetRoot(t, validCase, other)
	for _, tt := range []struct {
		name    string
		tag     any // conformance_profile of validCase; nil leaves it out
		profile string
		want    []string
	}{
		// A single-owner run never includes a full-only entry, tagged or not.
		{"single-owner run, untagged entries", nil, "single-owner", nil},
		{"single-owner run, full-only entry", []string{"full"}, "single-owner", nil},
		{"single-owner run, single-owner entry", []string{"single-owner"}, "single-owner", []string{validCase}},
		// A full run never includes a single-owner-only entry.
		{"full run, single-owner-only entry", []string{"single-owner"}, "full", []string{other}},
		{"full run, both profiles", []string{"full", "single-owner"}, "full", []string{other, validCase}},
		{"single-owner run, both profiles", []string{"single-owner", "full"}, "single-owner", []string{validCase}},
		{"empty profile means full", []string{"single-owner"}, "", []string{other}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := root
			if tt.tag != nil {
				r = withMembers(t, subsetRoot(t, validCase, other), validCase, map[string]any{"conformance_profile": tt.tag})
			}
			cfg := fakeImplCfg(t, "good", r)
			cfg.Profile = tt.profile
			rep := runOK(t, cfg)
			got := fixtureIDs(rep)
			slices.Sort(got)
			want := slices.Sorted(slices.Values(tt.want))
			if !slices.Equal(got, want) {
				t.Errorf("fixtures %v, want %v", got, want)
			}
			profile := tt.profile
			if profile == "" {
				profile = manifest.ConformanceProfileFull
			}
			if rep.Profile != profile {
				t.Errorf("report profile %q, want %q", rep.Profile, profile)
			}
			for _, f := range rep.Fixtures {
				e := entryOf(t, r, f.ID)
				if !slices.Contains(e.ConformanceProfiles(), profile) {
					t.Errorf("%s ran (%s) under %s, which it does not list", f.ID, f.Status, profile)
				}
			}
			s := rep.ByProfile[profile]
			if s.Selected != len(want) || s.SkippedNotApplicable != 2-len(want) || s.Pass != len(want) {
				t.Errorf("by_profile[%s] = %+v, want %d selected, %d not applicable, all selected PASS", profile, s, len(want), 2-len(want))
			}
			if rep.Empty() != (len(want) == 0) {
				t.Errorf("Empty() = %v with %d selected", rep.Empty(), len(want))
			}
		})
	}
}

// TestTransportSelection: a run executes the entries whose transport shares
// one with the run's.
func TestTransportSelection(t *testing.T) {
	root := withMembers(t, subsetRoot(t, validCase, other), validCase,
		map[string]any{"transport": []string{"stdio-ipc"}, "layer": "transcript"})
	for _, tt := range []struct {
		transport []string
		want      []string
	}{
		{nil, []string{other}},
		{[]string{"https"}, []string{other}},
		{[]string{"stdio-ipc"}, []string{validCase}},
		{[]string{"https", "stdio-ipc"}, []string{other, validCase}},
		{[]string{"stdio-ipc", "stdio-ipc", "https"}, []string{other, validCase}},
	} {
		t.Run(strings.Join(tt.transport, ","), func(t *testing.T) {
			cfg := fakeImplCfg(t, "good", root)
			cfg.Transport = tt.transport
			rep := runOK(t, cfg)
			got := fixtureIDs(rep)
			slices.Sort(got)
			if !slices.Equal(got, tt.want) {
				t.Errorf("fixtures %v, want %v", got, tt.want)
			}
			wantT := []string{"https"}
			if tt.transport != nil {
				wantT = []string{}
				for _, name := range manifest.Transports() {
					if slices.Contains(tt.transport, name) {
						wantT = append(wantT, name)
					}
				}
			}
			if !slices.Equal(rep.Transport, wantT) {
				t.Errorf("report transport %v, want %v", rep.Transport, wantT)
			}
			if s := rep.ByProfile["full"]; s.Selected != len(tt.want) || s.SkippedNotApplicable != 2-len(tt.want) {
				t.Errorf("by_profile[full] = %+v", s)
			}
		})
	}
}

// TestTransportStdioWithoutEntries: --transport stdio-ipc over fixtures
// without a stdio-ipc entry selects nothing, and the run is empty, never
// green.
func TestTransportStdioWithoutEntries(t *testing.T) {
	cfg := fakeImplCfg(t, "good", subsetRoot(t, validCase, other))
	cfg.Transport = []string{"stdio-ipc"}
	rep := runOK(t, cfg)
	if len(rep.Fixtures) != 0 || !rep.Empty() || rep.Failed() {
		t.Fatalf("fixtures %v, empty %v, failed %v; want an empty run", fixtureIDs(rep), rep.Empty(), rep.Failed())
	}
	if s := rep.ByProfile["full"]; s.Selected != 0 || s.SkippedNotApplicable != 2 || s.Pass != 0 {
		t.Errorf("by_profile[full] = %+v, want 0 selected and 2 not applicable", s)
	}
}

// TestProfileUnknownRequested: a --profile that is not a conformance profile
// of spec/v1.0/profiles/registry.json, or a --transport that is not a transport,
// is a usage error that names the known ones.
func TestProfileUnknownRequested(t *testing.T) {
	root := subsetRoot(t, validCase)
	for _, tt := range []struct {
		name      string
		profile   string
		transport []string
		want      []string
	}{
		{"profile lite", "lite", nil, []string{`"lite"`, "full, single-owner", "registry.json"}},
		{"profile upper case", "FULL", nil, []string{`"FULL"`, "full, single-owner"}},
		{"transport tcp", "", []string{"tcp"}, []string{`"tcp"`, "https, stdio-ipc"}},
		{"transport http", "", []string{"http"}, []string{`"http"`, "https, stdio-ipc"}},
		{"transport stdio", "", []string{"stdio"}, []string{`"stdio"`, "https, stdio-ipc"}},
		{"transport empty", "", []string{""}, []string{`""`}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := fakeImplCfg(t, "good", root)
			cfg.Profile, cfg.Transport = tt.profile, tt.transport
			_, err := Run(cfg)
			if err == nil {
				t.Fatal("Run accepted it")
			}
			for _, w := range tt.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("error %q lacks %q", err, w)
				}
			}
		})
	}
}

// TestProfileUnknownInManifest: an entry that names an unknown profile fails
// the run through the manifest check; it is not skipped into a green run.
func TestProfileUnknownInManifest(t *testing.T) {
	root := withMembers(t, subsetRoot(t, validCase, other), validCase, map[string]any{"conformance_profile": []string{"lite"}})
	for _, profile := range []string{"full", "single-owner"} {
		cfg := fakeImplCfg(t, "good", root)
		cfg.Profile = profile
		rep := runOK(t, cfg)
		if rep.Manifest.Status != StatusFail || !detailsContain(rep.Manifest.Details, "[entry-conformance-profile]", "lite") {
			t.Errorf("%s: manifest %+v, want FAIL naming lite", profile, rep.Manifest)
		}
		if !rep.Failed() {
			t.Errorf("%s: run not failed", profile)
		}
		for _, f := range rep.Fixtures {
			if f.ID == validCase {
				t.Errorf("%s: %s ran (%s) although it lists no known profile", profile, validCase, f.Status)
			}
		}
	}
}

// TestProfileSkippedUnsupported: a selected entry that the run cannot judge
// (no command for its verb, an undeclared capability) is counted as skipped
// unsupported, apart from the not-applicable ones.
func TestProfileSkippedUnsupported(t *testing.T) {
	root := withMembers(t, subsetRoot(t, validCase, other), other, map[string]any{"conformance_profile": []string{"single-owner"}})
	root = withCapabilities(t, root, validCase, manifest.CapabilityJWSEd25519)
	cfg := fakeImplCfg(t, "good", root)
	cfg.Capabilities = nil
	rep := runOK(t, cfg)
	want := ProfileSummary{Selected: 1, SkippedNotApplicable: 1, SkippedUnsupported: 1}
	if got := rep.ByProfile["full"]; got != want {
		t.Errorf("by_profile[full] = %+v, want %+v", got, want)
	}
	cfg = fakeImplCfg(t, "good", root)
	cfg.EvaluateCmd = ""
	cfg.Profile = "single-owner"
	rep = runOK(t, cfg)
	if got := rep.ByProfile["single-owner"]; got != want {
		t.Errorf("by_profile[single-owner] = %+v, want %+v", got, want)
	}
}

// TestProfileByProfileFailures: the profile summary counts the FAIL results
// of the selected entries.
func TestProfileByProfileFailures(t *testing.T) {
	cfg := fakeImplCfg(t, "wrong-decision", subsetRoot(t, validCase))
	rep := runOK(t, cfg)
	if got := rep.ByProfile["full"]; got.Selected != 1 || got.Fail != 1 || got.Pass != 0 {
		t.Errorf("by_profile[full] = %+v, want the one selected entry FAIL", got)
	}
}

// TestProfileIgnoresDisclosureMode: the fake implementation mode
// ignores-profile-disclosure answers every case as the good mode does, but
// does not disclose a conformance profile. No committed entry lists
// single-owner yet, so a single-owner run selects nothing and is never green;
// the single-owner fixtures that check the disclosure turn it red.
func TestProfileIgnoresDisclosureMode(t *testing.T) {
	root := subsetRoot(t, validCase, other)
	rep := runOK(t, fakeImplCfg(t, "ignores-profile-disclosure", root))
	if rep.Failed() || rep.ByProfile["full"].Pass != 2 {
		t.Errorf("full run: %+v, want both entries PASS", rep.ByProfile)
	}
	cfg := fakeImplCfg(t, "ignores-profile-disclosure", root)
	cfg.Profile = "single-owner"
	rep = runOK(t, cfg)
	if !rep.Empty() || rep.ByProfile["single-owner"].Pass != 0 {
		t.Errorf("single-owner run: %+v, want no entry selected and none PASS", rep.ByProfile)
	}
}

// TestProfileRepoFixtures: over the committed fixtures, every entry a run
// selects lists the run's profile and shares a transport with it, and every
// entry the run handles is either selected or not applicable.
func TestProfileRepoFixtures(t *testing.T) {
	m, err := manifest.Load(repoFixtures)
	if err != nil {
		t.Fatal(err)
	}
	runnable := 0
	for _, e := range m.Entries {
		if _, ok := verbOf(e.Kind); ok {
			runnable++
		}
	}
	for _, profile := range manifest.ConformanceProfiles() {
		for _, transport := range [][]string{nil, {"stdio-ipc"}, {"https"}, manifest.Transports()} {
			cfg := Config{FixturesRoot: repoFixtures, Profile: profile, Transport: transport}
			rep := runOK(t, cfg)
			for _, f := range rep.Fixtures {
				e, _ := m.Lookup(f.ID)
				if !slices.Contains(e.ConformanceProfiles(), profile) {
					t.Errorf("%s %v: %s does not list %s", profile, transport, f.ID, profile)
				}
				if !slices.ContainsFunc(e.Transports(), func(x string) bool { return slices.Contains(rep.Transport, x) }) {
					t.Errorf("%s %v: %s has transport %v", profile, transport, f.ID, e.Transports())
				}
				if f.Status == StatusPass {
					t.Errorf("%s: %s PASS without commands", f.ID, profile)
				}
			}
			s := rep.ByProfile[profile]
			if s.Selected+s.SkippedNotApplicable != runnable || s.Selected != len(rep.Fixtures) {
				t.Errorf("%s %v: by_profile %+v, %d runnable entries, %d results", profile, transport, s, runnable, len(rep.Fixtures))
			}
		}
	}
}

// TestProfileReport: the JSON report states the profile, the transports and
// the profile summary, and the table names them.
func TestProfileReport(t *testing.T) {
	cfg := fakeImplCfg(t, "good", subsetRoot(t, validCase, other))
	cfg.Transport = []string{"stdio-ipc", "https"}
	rep := runOK(t, cfg)
	var buf bytes.Buffer
	if err := rep.WriteJSON(&buf); err != nil {
		t.Fatal(err)
	}
	var out struct {
		Profile   *string                    `json:"profile"`
		Transport []string                   `json:"transport"`
		ByProfile map[string]json.RawMessage `json:"by_profile"`
	}
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Profile == nil || *out.Profile != "full" || !slices.Equal(out.Transport, []string{"https", "stdio-ipc"}) {
		t.Errorf("profile %v transport %v", out.Profile, out.Transport)
	}
	var s map[string]any
	if err := json.Unmarshal(out.ByProfile["full"], &s); err != nil {
		t.Fatal(err)
	}
	want := map[string]int{"selected": 2, "skipped_not_applicable": 0, "skipped_unsupported": 0, "pass": 2, "fail": 0}
	if _, ok := s["roles_claimed"]; len(out.ByProfile) != 1 || len(s) != len(want)+1 || !ok {
		t.Errorf("by_profile %s, want the counts and roles_claimed", buf.String())
	}
	for k, v := range want {
		if got, ok := s[k]; !ok || got != float64(v) {
			t.Errorf("by_profile.full.%s = %v (%v), want %d", k, got, ok, v)
		}
	}
	buf.Reset()
	rep.WriteTable(&buf)
	for _, line := range []string{"profile        full", "transport      https, stdio-ipc", "full: selected 2, not applicable 0, unsupported 0, roles Holder, Gateway, Validator, Reputation, Learning"} {
		if !strings.Contains(buf.String(), line) {
			t.Errorf("table lacks %q:\n%s", line, buf.String())
		}
	}
}

// entryOf returns the manifest entry id of the fixture directory root.
func entryOf(t *testing.T, root, id string) manifest.Entry {
	t.Helper()
	m, err := manifest.Load(root)
	if err != nil {
		t.Fatal(err)
	}
	e, ok := m.Lookup(id)
	if !ok {
		t.Fatalf("no entry %s", id)
	}
	return e
}

// draftRoles returns the conformance roles of the table of draft Section 22.1,
// in table order: the rows "| PACT <Role> 0.1 | ... |".
func draftRoles(t *testing.T) []string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "spec", "v1.0", "draft.md"))
	if err != nil {
		t.Fatal(err)
	}
	_, sec, ok := strings.Cut(string(b), "\n### 22.1 Role claims\n")
	if !ok {
		t.Fatal("draft has no Section 22.1 Role claims")
	}
	sec, _, _ = strings.Cut(sec, "\n### ")
	var roles []string
	for _, line := range strings.Split(sec, "\n") {
		if rest, ok := strings.CutPrefix(line, "| PACT "); ok {
			if role, ok := strings.CutSuffix(strings.SplitN(rest, " |", 2)[0], " 0.1"); ok {
				roles = append(roles, role)
			}
		}
	}
	return roles
}

// TestProfileRolesClaimed: a conformance profile claims the roles of draft
// Section 22.1 minus the omitted_roles of its ConformanceDeclaration
// (spec/v1.0/schemas/pact.schema.json): full omits none, single-owner omits
// reputation and learning.
func TestProfileRolesClaimed(t *testing.T) {
	all := []string{"Holder", "Gateway", "Validator", "Reputation", "Learning"}
	if got := draftRoles(t); !slices.Equal(got, all) {
		t.Fatalf("draft Section 22.1 roles %v, want %v", got, all)
	}
	if got := ConformanceRoles(); !slices.Equal(got, all) {
		t.Errorf("ConformanceRoles() = %v, want %v", got, all)
	}
	for profile, want := range map[string][]string{
		"full":         all,
		"single-owner": {"Holder", "Gateway", "Validator"},
		"unknown":      nil,
	} {
		if got := RolesClaimed(profile); !slices.Equal(got, want) {
			t.Errorf("RolesClaimed(%q) = %v, want %v", profile, got, want)
		}
	}
	// A caller's edit of the result does not reach the next call.
	RolesClaimed("full")[0] = "x"
	if got := RolesClaimed("full"); got[0] != "Holder" {
		t.Errorf("RolesClaimed shares its table: %v", got)
	}
}

// TestProfileReportRolesClaimed: every by_profile member of the pactc/v1
// report carries the roles its profile claims, in the JSON report and in the
// table, also for an empty run and for a report without a profile summary.
func TestProfileReportRolesClaimed(t *testing.T) {
	root := withMembers(t, subsetRoot(t, validCase, other), other, map[string]any{"conformance_profile": []string{"single-owner"}})
	for _, tt := range []struct {
		profile string
		want    []string
	}{
		{"full", []string{"Holder", "Gateway", "Validator", "Reputation", "Learning"}},
		{"single-owner", []string{"Holder", "Gateway", "Validator"}},
	} {
		cfg := fakeImplCfg(t, "good", root)
		cfg.Profile = tt.profile
		reps := []*Report{runOK(t, cfg), {Manifest: Check{Status: StatusPass}, Profile: tt.profile}}
		cfg.Transport = []string{"stdio-ipc"}
		reps = append(reps, runOK(t, cfg))
		for i, rep := range reps {
			var buf bytes.Buffer
			if err := rep.WriteJSON(&buf); err != nil {
				t.Fatal(err)
			}
			var out struct {
				ByProfile map[string]struct {
					RolesClaimed []string `json:"roles_claimed"`
				} `json:"by_profile"`
			}
			if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
				t.Fatal(err)
			}
			if got := out.ByProfile[tt.profile].RolesClaimed; len(out.ByProfile) != 1 || !slices.Equal(got, tt.want) {
				t.Errorf("%s report %d: by_profile %s, want roles_claimed %v", tt.profile, i, buf.String(), tt.want)
			}
			buf.Reset()
			rep.WriteTable(&buf)
			if line := ", roles " + strings.Join(tt.want, ", ") + "\n"; !strings.Contains(buf.String(), line) {
				t.Errorf("%s report %d: table lacks %q:\n%s", tt.profile, i, line, buf.String())
			}
		}
	}
}
