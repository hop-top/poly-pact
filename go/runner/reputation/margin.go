package reputation

import "fmt"

// Threshold is a promotion rule on a score_bps or confidence_bps value: the
// value must reach FloorBPS plus an explicit MarginBPS. Draft Section 15.3
// requires promotion policies to use an explicit margin and not to rely on a
// rounding-boundary equality.
type Threshold struct {
	FloorBPS  int64
	MarginBPS int64
}

// Validate rejects a rule that relies on a rounding-boundary equality: a
// margin below ToleranceBPS, so that a value within the recomputation
// tolerance of the floor decides the rule, as "score_bps >= floor" with no
// margin does. It also rejects a floor outside 0..10000 and a rule that no
// value in 0..10000 can meet.
func (th Threshold) Validate() error {
	switch {
	case th.FloorBPS < 0 || th.FloorBPS > 10000:
		return fmt.Errorf("floor %d bp is outside 0..10000", th.FloorBPS)
	case th.MarginBPS < ToleranceBPS:
		return fmt.Errorf("margin %d bp is below the %d bp recomputation tolerance: the rule relies on a rounding-boundary equality (draft Section 15.3)", th.MarginBPS, ToleranceBPS)
	case th.FloorBPS+th.MarginBPS > 10000:
		return fmt.Errorf("floor %d bp plus margin %d bp exceeds 10000", th.FloorBPS, th.MarginBPS)
	}
	return nil
}

// Met reports whether v reaches the floor plus the margin. For a rule that
// passes Validate, a value that meets it stays at or above the floor under
// any recomputation within ToleranceBPS.
func (th Threshold) Met(v int64) bool {
	return v >= th.FloorBPS+th.MarginBPS
}
