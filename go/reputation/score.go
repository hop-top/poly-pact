package reputation

import (
	"math"

	"hop.top/pact-go/core"
)

// The constants of beta-decay-v1 (draft Section 15.3).
const (
	// HalfLifeSeconds is the half-life of an observation's weight: 30 days.
	HalfLifeSeconds int64 = 2592000
	// ToleranceBPS is the numerical tolerance an implementation testing
	// recomputation allows on score_bps and confidence_bps.
	ToleranceBPS int64 = 1
	// confidenceScale is the effective weight at which confidence is 5000.
	confidenceScale = 20
)

// Event is one observation as the scorer sees it, after qualification,
// deduplication and the per-group cap (draft Section 14.3): its time, its
// result and dimension, and its weight in units.
type Event struct {
	ObservedAt int64
	Result     core.OutcomeResult
	Weight     float64
	Dimension  core.Dimension
}

// Stats is the outcome of scoring one dimension: the model's alpha and beta
// and the two values a snapshot carries, in basis points.
type Stats struct {
	Alpha, Beta   float64
	ScoreBPS      int64
	ConfidenceBPS int64
}

// Decay returns the decay factor 2^(-(t - observedAt) / HalfLifeSeconds) of
// an observation at evaluation time t, in IEEE 754 binary64. An observation
// later than t, which the clock skew admits, has age 0: it never weighs more
// than its weight.
func Decay(t, observedAt int64) float64 {
	age := max(t-observedAt, 0)
	return math.Pow(2, -float64(age)/float64(HalfLifeSeconds))
}

// FromAlphaBeta returns score_bps = floor(10000 * alpha / (alpha + beta))
// and confidence_bps = floor(10000 * w / (w + 20)) with the effective weight
// w = alpha + beta - 2, evaluated in binary64 in the order the draft writes
// them.
func FromAlphaBeta(alpha, beta float64) (scoreBPS, confidenceBPS int64) {
	w := alpha + beta - 2
	return int64(math.Floor(10000 * alpha / (alpha + beta))), int64(math.Floor(10000 * w / (w + confidenceScale)))
}

// Score scores dimension dim at time t over events with beta-decay-v1:
// alpha and beta start at 1 and add each qualified success and failure of
// that dimension at its weight times its decay, in the order given. Events
// of another dimension, and UNKNOWN and NOT_APPLICABLE results, contribute
// nothing. The caller applies the cap of one positive unit per independent
// task group and dimension before, so each event here is one group's.
func Score(dim core.Dimension, t int64, events []Event) Stats {
	alpha, beta := 1.0, 1.0
	for _, e := range events {
		if e.Dimension != dim {
			continue
		}
		// The conversion rounds the product before the sum: Go may otherwise
		// fuse the two into one multiply-add, which the draft's binary64
		// steps do not describe.
		w := float64(e.Weight * Decay(t, e.ObservedAt))
		switch e.Result {
		case core.OutcomeSuccess:
			alpha += w
		case core.OutcomeFailure:
			beta += w
		}
	}
	s, c := FromAlphaBeta(alpha, beta)
	return Stats{Alpha: alpha, Beta: beta, ScoreBPS: s, ConfidenceBPS: c}
}

// WithinTolerance reports whether got is within ToleranceBPS of want.
func WithinTolerance(got, want int64) bool {
	return got-want <= ToleranceBPS && want-got <= ToleranceBPS
}
