package runner

// Optional capabilities (spec/v1.0/fixtures/README.md, Optional capabilities):
// an entry whose manifest capabilities the implementation does not declare
// is SKIP with the missing capabilities, never judged and never counted as
// passed (draft 22.2: a role implementation passes all applicable cases).

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

// withCapabilities sets the capabilities of the manifest entry id in root.
func withCapabilities(t *testing.T, root, id string, caps ...string) string {
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
			e["capabilities"], found = caps, true
		}
	}
	if !found {
		t.Fatalf("no entry %s", id)
	}
	writeManifest(t, root, m.Entries)
	return root
}

func TestCapabilityEntries(t *testing.T) {
	const other = "admission/old-holder-key"
	root := withCapabilities(t, subsetRoot(t, validCase, other), validCase, manifest.CapabilityJWSEd25519)
	for _, tt := range []struct {
		name     string
		mode     string
		declared []string
		want     Status
	}{
		{"not declared", "good", nil, StatusSkip},
		{"not declared, bad implementation", "wrong-decision", nil, StatusSkip},
		{"declared", "good", []string{manifest.CapabilityJWSEd25519}, StatusPass},
		{"declared twice", "good", []string{manifest.CapabilityJWSEd25519, manifest.CapabilityJWSEd25519}, StatusPass},
		{"declared, bad implementation", "wrong-decision", []string{manifest.CapabilityJWSEd25519}, StatusFail},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := fakeImplCfg(t, tt.mode, root)
			cfg.Capabilities = tt.declared
			rep, err := Run(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if rep.Manifest.Status != StatusPass {
				t.Fatalf("manifest = %+v", rep.Manifest)
			}
			r := result(t, rep, validCase)
			if r.Status != tt.want {
				t.Errorf("%s = %+v, want %s", validCase, r, tt.want)
			}
			if !slices.Equal(r.Capabilities, []string{manifest.CapabilityJWSEd25519}) {
				t.Errorf("%s capabilities %q, want the entry's", validCase, r.Capabilities)
			}
			if tt.want == StatusSkip {
				if !detailsContain(r.Details, "jws-ed25519", "--capability", "not declared") {
					t.Errorf("skip reason %q does not name the missing capability", r.Details)
				}
				if s := rep.Summary(); s.Skip != 1 || s.Pass != 2 {
					t.Errorf("summary %+v, want the capability entry counted as skip, not pass", s)
				}
			}
			// An entry without capabilities is mandatory: it runs either way.
			if o := result(t, rep, other); o.Capabilities != nil || (tt.mode == "good" && o.Status != StatusPass) {
				t.Errorf("%s = %+v, want a judged mandatory entry", other, o)
			}
		})
	}
}

// TestCapabilityEntryNeedsEveryCapability: an entry with a capability the
// runner does not know (the manifest check fails it) is never judged.
func TestCapabilityEntryNeedsEveryCapability(t *testing.T) {
	root := withCapabilities(t, subsetRoot(t, validCase), validCase, manifest.CapabilityJWSEd25519, "zz-unknown")
	cfg := fakeImplCfg(t, "good", root)
	cfg.Capabilities = []string{manifest.CapabilityJWSEd25519}
	rep, err := Run(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Manifest.Status != StatusFail || !detailsContain(rep.Manifest.Details, "[entry-capabilities]", "zz-unknown") {
		t.Errorf("manifest = %+v, want FAIL naming the unknown capability", rep.Manifest)
	}
	if r := result(t, rep, validCase); r.Status != StatusSkip || !detailsContain(r.Details, "zz-unknown") || detailsContain(r.Details, "jws-ed25519") {
		t.Errorf("%s = %+v, want SKIP naming only the missing capability", validCase, r)
	}
}

func TestCapabilityUnknownDeclared(t *testing.T) {
	cfg := fakeImplCfg(t, "good", subsetRoot(t, validCase))
	cfg.Capabilities = []string{"ed25519"}
	if _, err := Run(cfg); err == nil || !strings.Contains(err.Error(), `"ed25519"`) || !strings.Contains(err.Error(), "jws-ed25519") {
		t.Errorf("Run = %v, want an error naming the unknown capability and the known ones", err)
	}
}

// TestCapabilityReport: the report states the declared capabilities, and
// each result the capabilities of its entry.
func TestCapabilityReport(t *testing.T) {
	root := withCapabilities(t, subsetRoot(t, validCase), validCase, manifest.CapabilityJWSEd25519)
	for _, declared := range [][]string{nil, {manifest.CapabilityJWSEd25519, manifest.CapabilityJWSEd25519}} {
		cfg := fakeImplCfg(t, "good", root)
		cfg.Capabilities = declared
		rep, err := Run(cfg)
		if err != nil {
			t.Fatal(err)
		}
		var buf bytes.Buffer
		if err := rep.WriteJSON(&buf); err != nil {
			t.Fatal(err)
		}
		var out struct {
			Capabilities *[]string `json:"capabilities"`
			Fixtures     []struct {
				Capabilities []string `json:"capabilities"`
			} `json:"fixtures"`
		}
		if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		want := []string{}
		if declared != nil {
			want = []string{manifest.CapabilityJWSEd25519}
		}
		if out.Capabilities == nil || !slices.Equal(*out.Capabilities, want) {
			t.Errorf("declared %q: report capabilities %v, want %q", declared, out.Capabilities, want)
		}
		if len(out.Fixtures) != 1 || !slices.Equal(out.Fixtures[0].Capabilities, []string{manifest.CapabilityJWSEd25519}) {
			t.Errorf("fixtures %+v, want the entry's capabilities", out.Fixtures)
		}
		buf.Reset()
		rep.WriteTable(&buf)
		line := "capabilities   none"
		if declared != nil {
			line = "capabilities   jws-ed25519"
		}
		if !strings.Contains(buf.String(), line) {
			t.Errorf("table lacks %q:\n%s", line, buf.String())
		}
	}
}

// TestCapabilityReportNoneDeclared: a report built without declared
// capabilities still states them, as an empty array.
func TestCapabilityReportNoneDeclared(t *testing.T) {
	var buf bytes.Buffer
	if err := (&Report{Manifest: Check{Status: StatusPass}}).WriteJSON(&buf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `"capabilities": []`) {
		t.Errorf("report %s, want capabilities []", buf.String())
	}
}
