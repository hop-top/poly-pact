package reputation_test

import (
	"math"
	"os"
	"path/filepath"
	"testing"

	"hop.top/pact-go/core"
	"hop.top/pact-go/core/strictjson"
	"hop.top/pact-go/reputation"
)

// repoFixtures is spec/v1.0/fixtures relative to this package directory.
var repoFixtures = filepath.Join("..", "..", "spec", "v1.0", "fixtures")

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

// onBoundary are the vectors whose exact value is an integer, which the
// last bit of the decay factor decides (vectors README, section Expected
// values and tolerance). floor-score-exact-7500-decayed weighs successes by
// 2^(-1/3): a correctly rounded power gives 7500.000000000001, while Go's
// math.Pow is one unit in the last place lower there and gives
// 7499.999999999999, which floors to 7499.
var onBoundary = map[string]bool{"floor-score-exact-7500-decayed": true}

// TestScoreVectors: the scorer gives the expected value of every committed
// beta-decay-v1 vector exactly, and within the one basis point of Section
// 15.3 for a vector whose exact value is an integer. The vectors were
// computed from the draft in binary64 and checked with 60-digit decimals.
// The floor vectors that lie just below an integer, which rounding would get
// wrong, are matched exactly.
func TestScoreVectors(t *testing.T) {
	for _, v := range readVectors(t) {
		t.Run(v.ID, func(t *testing.T) {
			var events []reputation.Event
			for _, e := range v.Events {
				events = append(events, reputation.Event{ObservedAt: e.ObservedAt, Result: e.Result, Weight: e.Weight, Dimension: e.Dimension})
			}
			got := reputation.Score(v.Dimension, v.T, events)
			if onBoundary[v.ID] {
				if !reputation.WithinTolerance(got.ScoreBPS, v.Expected.ScoreBPS) || !reputation.WithinTolerance(got.ConfidenceBPS, v.Expected.ConfidenceBPS) {
					t.Errorf("score %d confidence %d, want %d and %d within 1 bp (%s)", got.ScoreBPS, got.ConfidenceBPS, v.Expected.ScoreBPS, v.Expected.ConfidenceBPS, v.Note)
				}
				return
			}
			if got.ScoreBPS != v.Expected.ScoreBPS || got.ConfidenceBPS != v.Expected.ConfidenceBPS {
				t.Errorf("score %d confidence %d, want %d and %d (%s)", got.ScoreBPS, got.ConfidenceBPS, v.Expected.ScoreBPS, v.Expected.ConfidenceBPS, v.Note)
			}
			if got.Alpha < 1 || got.Beta < 1 {
				t.Errorf("alpha %v beta %v, both start at 1", got.Alpha, got.Beta)
			}
		})
	}
}

// TestScoreFormula pins the parts of Section 15.3 one by one.
func TestScoreFormula(t *testing.T) {
	const t0 int64 = 1792080000
	if d := reputation.Decay(t0, t0); d != 1 {
		t.Errorf("decay at age 0 = %v, want 1", d)
	}
	if d := reputation.Decay(t0, t0-2592000); d != 0.5 {
		t.Errorf("decay at one half-life = %v, want 0.5", d)
	}
	if d := reputation.Decay(t0, t0-2*2592000); d != 0.25 {
		t.Errorf("decay at two half-lives = %v, want 0.25", d)
	}
	// An observation after t has age 0: it weighs its full weight, not more.
	if d := reputation.Decay(t0, t0+5); d != 1 {
		t.Errorf("decay of a future observation = %v, want 1", d)
	}
	// Empty history: 5000 and 0.
	if s, c := reputation.FromAlphaBeta(1, 1); s != 5000 || c != 0 {
		t.Errorf("empty history %d %d, want 5000 0", s, c)
	}
	// floor, not round: 2/3 is 6666.67 and 1/21 is 476.19.
	if s, c := reputation.FromAlphaBeta(2, 1); s != 6666 || c != 476 {
		t.Errorf("one success %d %d, want 6666 476", s, c)
	}
	// alpha 1, beta 2: 3333.33 and 476.19.
	if s, c := reputation.FromAlphaBeta(1, 2); s != 3333 || c != 476 {
		t.Errorf("one failure %d %d, want 3333 476", s, c)
	}
	// Effective weight 20 gives confidence exactly 5000.
	if _, c := reputation.FromAlphaBeta(11, 11); c != 5000 {
		t.Errorf("effective weight 20: confidence %d, want 5000", c)
	}
	// A value just below an integer floors down: alpha a little under 4
	// and beta 1 give 7999.99..., which must not round up to 8000.
	if s, _ := reputation.FromAlphaBeta(4*(1-1e-9), 1); s != 7999 {
		t.Errorf("score just below 8000 = %d, want 7999", s)
	}
	// UNKNOWN and NOT_APPLICABLE weigh nothing, and another dimension is
	// ignored.
	got := reputation.Score(core.DimensionReliability, t0, []reputation.Event{
		{ObservedAt: t0, Result: core.OutcomeUnknown, Weight: 1, Dimension: core.DimensionReliability},
		{ObservedAt: t0, Result: core.OutcomeNotApplicable, Weight: 1, Dimension: core.DimensionReliability},
		{ObservedAt: t0, Result: core.OutcomeSuccess, Weight: 1, Dimension: core.DimensionTaskQuality},
		{ObservedAt: t0, Result: core.OutcomeFailure, Weight: 3, Dimension: core.DimensionReliability},
	})
	if got.Alpha != 1 || got.Beta != 4 || got.ScoreBPS != 2000 || got.ConfidenceBPS != 1304 {
		t.Errorf("filtered score %+v, want alpha 1 beta 4, 2000 and 1304", got)
	}
}

// TestWithinTolerance: one basis point either way, no more (Section 15.3).
func TestWithinTolerance(t *testing.T) {
	for _, tc := range []struct {
		got, want int64
		ok        bool
	}{{6666, 6666, true}, {6667, 6666, true}, {6665, 6666, true}, {6668, 6666, false}, {6664, 6666, false}, {0, 10000, false}} {
		if reputation.WithinTolerance(tc.got, tc.want) != tc.ok {
			t.Errorf("WithinTolerance(%d, %d) = %v, want %v", tc.got, tc.want, !tc.ok, tc.ok)
		}
	}
	if reputation.ToleranceBPS != 1 {
		t.Errorf("tolerance %d bp, want 1", reputation.ToleranceBPS)
	}
	if math.IsNaN(reputation.Decay(0, 0)) {
		t.Error("decay NaN")
	}
}
