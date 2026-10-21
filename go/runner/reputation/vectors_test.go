package reputation_test

import (
	"os"
	"path/filepath"
	"testing"

	"hop.top/pact-go/core"
	"hop.top/pact-go/core/strictjson"
	"hop.top/pact-go/runner/reputation"
)

// vector is one element of reputation/beta-decay-v1/vectors.json.
type vector struct {
	ID        string         `json:"id"`
	Dimension core.Dimension `json:"dimension"`
	Events    []struct {
		ObservedAt int64              `json:"observed_at"`
		Result     core.OutcomeResult `json:"result"`
		Weight     float64            `json:"weight"`
		Dimension  core.Dimension     `json:"dimension"`
	} `json:"events"`
	T        int64 `json:"t"`
	Expected struct {
		ScoreBPS      int64 `json:"score_bps"`
		ConfidenceBPS int64 `json:"confidence_bps"`
	} `json:"expected"`
	Note string `json:"note"`
}

func readVectors(t *testing.T) []vector {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoFixtures, "reputation", "beta-decay-v1", "vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vs []vector
	if err := strictjson.Unmarshal(b, strictjson.Limits{}, &vs); err != nil {
		t.Fatal(err)
	}
	if len(vs) == 0 {
		t.Fatal("no vector")
	}
	return vs
}

// TestOracleScorerIsTheLibrarys: the names this package forwards score the
// beta-decay-v1 vectors within the one basis point of Section 15.3, as the
// library's tests check exactly.
func TestOracleScorerIsTheLibrarys(t *testing.T) {
	for _, v := range readVectors(t) {
		var events []reputation.Event
		for _, e := range v.Events {
			events = append(events, reputation.Event{ObservedAt: e.ObservedAt, Result: e.Result, Weight: e.Weight, Dimension: e.Dimension})
		}
		got := reputation.Score(v.Dimension, v.T, events)
		s, c := reputation.FromAlphaBeta(got.Alpha, got.Beta)
		if !reputation.WithinTolerance(got.ScoreBPS, v.Expected.ScoreBPS) || !reputation.WithinTolerance(got.ConfidenceBPS, v.Expected.ConfidenceBPS) ||
			s != got.ScoreBPS || c != got.ConfidenceBPS {
			t.Errorf("%s: %+v, want %d and %d", v.ID, got, v.Expected.ScoreBPS, v.Expected.ConfidenceBPS)
		}
	}
	if reputation.Decay(reputation.HalfLifeSeconds, 0) != 0.5 || reputation.ToleranceBPS != 1 {
		t.Error("forwarded constants")
	}
}
