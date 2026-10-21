package reputation

import (
	"fmt"
	"math"

	"hop.top/pact-go/core"
	score "hop.top/pact-go/reputation"
)

// MaxFailureWeight is the largest weight one failure may carry (draft
// Section 15.3), the bound of package reputation.
const MaxFailureWeight = score.MaxFailureWeight

// CheckWeights checks the events Score is given against the weight bounds
// of draft Section 15.3 under a data policy's maximum_failure_weight:
// maxFailureWeight is 1 to MaxFailureWeight; a success weighs 0 to 1, the
// cap of one positive unit per independent task group and dimension; a
// failure weighs 0 to maxFailureWeight. UNKNOWN and NOT_APPLICABLE events
// weigh nothing whatever their weight. Score does not call it: the caller
// that qualifies and caps the events does.
func CheckWeights(maxFailureWeight int64, events []Event) error {
	if err := score.CheckMaximumFailureWeight(maxFailureWeight); err != nil {
		return err
	}
	for i, e := range events {
		limit := 0.0
		switch e.Result {
		case core.OutcomeSuccess:
			limit = float64(score.PositiveWeightCapPerTask)
		case core.OutcomeFailure:
			limit = float64(maxFailureWeight)
		default:
			continue
		}
		if math.IsNaN(e.Weight) || e.Weight < 0 || e.Weight > limit {
			return fmt.Errorf("event %d: %s weight %v is outside 0..%v (draft Section 15.3)", i, e.Result, e.Weight, limit)
		}
	}
	return nil
}
