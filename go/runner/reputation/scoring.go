package reputation

import (
	"hop.top/pact-go/core"
	score "hop.top/pact-go/reputation"
)

// The beta-decay-v1 scorer is package hop.top/pact-go/reputation's (draft
// Section 15.3); these names forward to it, so that the oracle and the
// tests of this package read as before the scorer moved there. Nothing
// here computes a score of its own.

// Event is score.Event.
type Event = score.Event

// Stats is score.Stats.
type Stats = score.Stats

// HalfLifeSeconds and ToleranceBPS are the library's.
const (
	HalfLifeSeconds = score.HalfLifeSeconds
	ToleranceBPS    = score.ToleranceBPS
)

// Decay is score.Decay.
func Decay(t, observedAt int64) float64 { return score.Decay(t, observedAt) }

// FromAlphaBeta is score.FromAlphaBeta.
func FromAlphaBeta(alpha, beta float64) (scoreBPS, confidenceBPS int64) {
	return score.FromAlphaBeta(alpha, beta)
}

// Score is score.Score.
func Score(dim core.Dimension, t int64, events []Event) Stats { return score.Score(dim, t, events) }

// WithinTolerance is score.WithinTolerance.
func WithinTolerance(got, want int64) bool { return score.WithinTolerance(got, want) }
