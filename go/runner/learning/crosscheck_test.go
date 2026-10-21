package learning_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"hop.top/pact-go/runner/evalcase"
	"hop.top/pact-go/runner/learning"
	"hop.top/pact-go/runner/manifest"
)

// repoFixtures is spec/v1.0/fixtures relative to this package directory.
var repoFixtures = filepath.Join("..", "..", "..", "spec", "v1.0", "fixtures")

func learningIDs(t testing.TB) []string {
	t.Helper()
	m, err := manifest.Load(repoFixtures)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, e := range m.Entries {
		if e.Kind == manifest.KindLearning {
			ids = append(ids, e.ID)
		}
	}
	if len(ids) == 0 {
		t.Fatal("no learning entry in the manifest")
	}
	return ids
}

// TestOracleComputesTheCommittedRegistries replays every committed learning
// case through the reference registry state machine and compares the result
// with the case's expected registry.json. The expected files were computed
// from the draft by hand; a difference here is a finding about the fixture
// or about the machine, not a reason to edit either to make them agree.
func TestOracleComputesTheCommittedRegistries(t *testing.T) {
	for _, id := range learningIDs(t) {
		t.Run(id, func(t *testing.T) {
			c, err := evalcase.ReadLearning(repoFixtures, id)
			if err != nil {
				t.Fatal(err)
			}
			got, err := learning.Replay(repoFixtures, c)
			if err != nil {
				t.Fatal(err)
			}
			for _, d := range learning.Diff(c.Expected, got) {
				t.Errorf("oracle disagrees with %s: %s", c.ExpectedPath, d)
			}
		})
	}
}

// TestOracleDisagreementIsReported: the cross-check is not vacuous. An
// expected registry edited to say something the draft does not (a promoted
// artifact still in SHADOW, a rejection with another reason code, a lost
// hold) is reported against the machine.
func TestOracleDisagreementIsReported(t *testing.T) {
	tests := []struct {
		id   string
		edit func(m map[string]any)
		want string
	}{
		{"learning/happy-path", func(m map[string]any) {
			m["artifacts"].(map[string]any)["signed/artifacts/baseline-v1.jws"] = "SHADOW"
		}, "state ACTIVE, want SHADOW"},
		{"learning/gate-not-met", func(m map[string]any) {
			m["rejections"].([]any)[0].(map[string]any)["reason_codes"] = []any{"POLICY_EXPIRED"}
		}, "reason codes [GATE_NOT_MET], want [POLICY_EXPIRED]"},
		{"learning/rollback-preserves-hold", func(m map[string]any) { m["holds"] = []any{} }, "holds: security-event-0001 unexpected"},
	}
	for _, tc := range tests {
		t.Run(tc.id, func(t *testing.T) {
			root := copyCase(t, tc.id)
			p := filepath.Join(root, "expected", filepath.FromSlash(tc.id), "registry.json")
			b, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			var m map[string]any
			if err := json.Unmarshal(b, &m); err != nil {
				t.Fatal(err)
			}
			tc.edit(m)
			if b, err = json.Marshal(m); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, b, 0o644); err != nil {
				t.Fatal(err)
			}
			c, err := evalcase.ReadLearning(root, tc.id)
			if err != nil {
				t.Fatal(err)
			}
			got, err := learning.Replay(root, c)
			if err != nil {
				t.Fatal(err)
			}
			d := learning.Diff(c.Expected, got)
			if len(d) != 1 || !strings.Contains(d[0], tc.want) {
				t.Errorf("details %q, want one with %q", d, tc.want)
			}
		})
	}
}
