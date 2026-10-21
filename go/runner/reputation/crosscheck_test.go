package reputation_test

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"slices"
	"testing"

	"hop.top/pact-go/runner/evalcase"
	"hop.top/pact-go/runner/manifest"
	"hop.top/pact-go/runner/reputation"
)

// repoFixtures is spec/v1.0/fixtures relative to this package directory.
var repoFixtures = filepath.Join("..", "..", "..", "spec", "v1.0", "fixtures")

func outcomesIDs(t testing.TB) []string {
	t.Helper()
	m, err := manifest.Load(repoFixtures)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, e := range m.Entries {
		if e.Kind == manifest.KindOutcomes {
			ids = append(ids, e.ID)
		}
	}
	if len(ids) == 0 {
		t.Fatal("no outcomes entry")
	}
	return ids
}

// Problems returns every difference between the oracle's replay of the case
// and its committed expected files: the acknowledgments of acks.json, the
// qualification and reason of every report of classifications.json, and
// for every query of snapshot.json the value (score and confidence within
// one basis point, every other member exactly), the provenance lists and the
// claims.
func problems(c *evalcase.OutcomesCase, out *reputation.Outcome) []string {
	var ps []string
	for _, a := range c.Acks {
		got := out.Steps[a.Step].Answer
		switch {
		case a.Status != nil && got.Ack != *a.Status:
			ps = append(ps, fmt.Sprintf("step %d: answer %+v, want %s", a.Step, got, *a.Status))
		case a.TransportCode != nil && got.Code != *a.TransportCode:
			ps = append(ps, fmt.Sprintf("step %d: answer %+v, want refusal %s", a.Step, got, *a.TransportCode))
		}
	}
	if c.Classifications != nil {
		for _, e := range c.Classifications.Events {
			v, ok := out.Verdicts[e.EventID]
			want := ""
			if e.Qualification != nil {
				want = *e.Qualification
			}
			if !ok || v.Qualification != want || v.Reason != e.Reason {
				ps = append(ps, fmt.Sprintf("%s: verdict %+v, want %q %s", e.EventID, v, want, e.Reason))
			}
		}
	}
	for _, s := range c.Snapshots {
		got := out.Steps[s.Step]
		if got.Snapshot == nil {
			ps = append(ps, fmt.Sprintf("step %d: no snapshot, refused %s", s.Step, got.QueryCode))
			continue
		}
		b, err := json.Marshal(got.Snapshot.Value)
		if err != nil {
			panic(err)
		}
		for _, p := range reputation.MatchValue(s.Value, b) {
			ps = append(ps, fmt.Sprintf("step %d: %s", s.Step, p))
		}
		m := got.Snapshot.Manifest
		if !slices.Equal(m.QualifiedEventIDs, s.Provenance.QualifiedEventIDs) || !slices.Equal(m.SupersededEventIDs, s.Provenance.SupersededEventIDs) {
			ps = append(ps, fmt.Sprintf("step %d: provenance %v %v, want %v %v", s.Step, m.QualifiedEventIDs, m.SupersededEventIDs,
				s.Provenance.QualifiedEventIDs, s.Provenance.SupersededEventIDs))
		}
		cb, err := json.Marshal(got.Snapshot.Claims)
		if err != nil {
			panic(err)
		}
		var claims map[string]json.RawMessage
		if err := json.Unmarshal(cb, &claims); err != nil {
			panic(err)
		}
		for k, v := range s.Claims {
			if string(claims[k]) != string(v) {
				ps = append(ps, fmt.Sprintf("step %d: claim %s is %s, want %s", s.Step, k, claims[k], v))
			}
		}
	}
	return ps
}

// TestOracleAgreesWithEveryCommittedCase replays every outcomes entry of the
// manifest through the reference oracle: its acknowledgments,
// classifications and snapshots are those the committed expected files
// state, which were computed from the draft, not from an implementation. A
// difference is a finding against the oracle or the fixture, never a reason
// to edit either to fit the other.
func TestOracleAgreesWithEveryCommittedCase(t *testing.T) {
	ids := outcomesIDs(t)
	if len(ids) != 29 {
		t.Errorf("%d outcomes entries, want the 29 of the mapping, qualification, reputation and delegation groups", len(ids))
	}
	for _, id := range ids {
		t.Run(id, func(t *testing.T) {
			c, err := evalcase.ReadOutcomes(repoFixtures, id)
			if err != nil {
				t.Fatal(err)
			}
			out, err := reputation.Replay(repoFixtures, c)
			if err != nil {
				t.Fatal(err)
			}
			if len(out.Steps) != len(c.Steps) {
				t.Fatalf("%d answers for %d steps", len(out.Steps), len(c.Steps))
			}
			for _, p := range problems(c, out) {
				t.Error(p)
			}
			// A refused report is never acknowledged, and every ingest step
			// has one answer.
			for i, s := range c.Steps {
				if s.Ingest == "" {
					continue
				}
				a := out.Steps[i].Answer
				if (a.Ack == "") == (a.Code == "") {
					t.Errorf("step %d: answer %+v, want exactly one of an acknowledgment and a refusal", i, a)
				}
			}
		})
	}
}
