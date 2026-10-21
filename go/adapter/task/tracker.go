package task

import (
	"context"
	"errors"
	"fmt"
	"time"

	"hop.top/pact-go/adapter"
)

// AsyncTracker reads the status of an operation already sent until the
// record is terminal, with bounded attempts (MO-38, MO-41 to MO-48). It
// tracks an accepted operation through its handle and reconciles an
// ambiguous one through the native status source. Status reads are not
// operations and do not count against max_operations (MO-16); they continue
// after the deadline and after the task is no longer Active (MO-23, MO-38,
// MO-50).
type AsyncTracker struct {
	// Ledger records each read.
	Ledger TaskLedger
	// Source is the native status source.
	Source StatusSource
	// MaxReads is max_status_reads per operation. When it is reached the
	// record stays as it is; exhaustion is neither failure nor success
	// (MO-45).
	MaxReads int
	// MinInterval is the wait before a read when the native API gave no
	// Retry-After (MO-45).
	MinInterval time.Duration
	// CheckHandle accepts a handle only when its origin and path prefix are
	// those configured for the native service (MO-43). Without it no handle
	// is followed.
	CheckHandle func(handle string) error
	// Sleep waits d or until ctx ends.
	Sleep func(ctx context.Context, d time.Duration) error
}

// Track reads the status of the operation opID of the task k until its
// record is terminal or MaxReads is reached, and returns the record with the
// report of the last event. Before each read it waits the Retry-After the
// native API gave, or MinInterval when it gave none (MO-45). An accepted
// operation is read only through a handle that CheckHandle accepts (MO-43);
// an ambiguous one is reconciled through the source (MO-38). A read that
// fails ends the tracking with DEPENDENCY_UNAVAILABLE and the record
// unchanged: no success is inferred (MO-46).
func (t *AsyncTracker) Track(ctx context.Context, k Key, opID string) (Settled, error) {
	if t.Ledger == nil || t.Source == nil {
		return Settled{}, fmt.Errorf("task: tracker: no ledger or no status source: %w", adapter.ErrDependencyUnavailable)
	}
	op, err := t.operation(ctx, k, opID)
	if err != nil {
		return Settled{}, err
	}
	last := Settled{Operation: op}
	for range max(t.MaxReads, 0) {
		switch op.State {
		case OpSucceeded, OpFailed, OpReleased:
			return last, nil
		case OpAccepted:
			if op.Handle == "" || t.CheckHandle == nil {
				return last, errors.New("task: tracker: no handle, or no handle check configured (MO-43)")
			}
			if err := t.CheckHandle(op.Handle); err != nil {
				return last, fmt.Errorf("task: tracker: the handle is not followed (MO-43): %w", err)
			}
		case OpUnknown:
		default:
			return last, fmt.Errorf("task: tracker: the operation %s is %s", op.ID, op.State)
		}
		wait := op.RetryAfter
		if wait <= 0 {
			wait = t.MinInterval
		}
		if err := t.sleep(ctx, wait); err != nil {
			return last, fmt.Errorf("task: tracker: %w: %w", adapter.ErrDependencyUnavailable, err)
		}
		s, err := t.Source.ReadStatus(ctx, k, op)
		if err != nil {
			return last, unavailable("tracker: the status source cannot answer", err)
		}
		st, err := t.Ledger.Observe(ctx, k, op.ID, s)
		if err != nil {
			return last, err
		}
		last, op = st, st.Operation
	}
	return last, nil
}

// operation reads the record opID of the task k.
func (t *AsyncTracker) operation(ctx context.Context, k Key, opID string) (Operation, error) {
	e, err := t.Ledger.Entry(ctx, k)
	if err != nil {
		return Operation{}, err
	}
	for _, op := range e.Operations {
		if op.ID == opID {
			return op, nil
		}
	}
	return Operation{}, errNoOperation
}

func (t *AsyncTracker) sleep(ctx context.Context, d time.Duration) error {
	if t.Sleep != nil {
		return t.Sleep(ctx, d)
	}
	if d <= 0 {
		return ctx.Err()
	}
	tm := time.NewTimer(d)
	defer tm.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-tm.C:
		return nil
	}
}
