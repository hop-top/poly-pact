package installed

import (
	"context"
	"fmt"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/core/clock"
)

// SourceTimes refuses source times that are later than now plus the skew:
// such a time did not happen yet, so the source cannot be relied on at this
// moment, which defers the decision (draft A.2; freshness profile, section
// 3.2). A zero time is a time the source does not give.
func SourceTimes(now time.Time, times ...time.Time) error {
	limit := now.Add(clock.BaselineSkew)
	for _, t := range times {
		if !t.IsZero() && t.After(limit) {
			return fmt.Errorf("the source reports a time later than now plus the skew: %w", adapter.ErrDependencyUnavailable)
		}
	}
	return nil
}

// Dependency returns err wrapped in [adapter.ErrDependencyUnavailable] unless
// it already carries a code.
func Dependency(err error) error {
	if _, ok := adapter.CodeOf(err); ok {
		return err
	}
	return fmt.Errorf("%w: %w", adapter.ErrDependencyUnavailable, err)
}

// Live fails with a dependency error when ctx is already done: a call that
// cannot be completed is not an answer.
func Live(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("%w: %w", adapter.ErrDependencyUnavailable, err)
	}
	return nil
}
