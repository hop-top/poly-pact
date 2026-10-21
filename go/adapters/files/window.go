package files

import (
	"fmt"
	"runtime"
)

// lockThread and unlockThread pin the window's goroutine to its thread. The
// runtime documents that LockOSThread wires the calling goroutine to its
// thread, that no other goroutine executes in it, that a goroutine should
// call it before calling services that depend on per-thread state, and that
// a goroutine that exits without unlocking terminates the thread.
var (
	lockThread   = runtime.LockOSThread
	unlockThread = runtime.UnlockOSThread
)

// impersonate runs fn in the impersonation window of c (profile 3.5): on a
// goroutine of its own, locked to its thread before the impersonation
// begins, with nothing else run there. It enters the impersonation of c's
// token, compares the thread's effective user with the token's user, runs
// fn, and reverts on every path, an error and a panic of fn included.
//
// A failed entry opens nothing and is not reverted:
// [ErrImpersonationUnavailable] (TA-3). An
// effective user other than the token's opens nothing:
// [ErrExecutorMismatch] (TA-4). A failed revert marks the broker unhealthy
// and returns [ErrUnhealthy]; the thread is not returned to service, because
// its goroutine ends without unlocking it (TA-6). fn starts no goroutine:
// work moved to another thread would run with the broker's identity.
func (b *Broker) impersonate(c Context, fn func() error) error {
	if err := b.Healthy(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() {
		lockThread()
		reverted, err := b.window(c, fn)
		if reverted {
			unlockThread()
		}
		done <- err
	}()
	return <-done
}

// window is the body of the impersonation window. It reports whether the
// thread runs as the broker again.
func (b *Broker) window(c Context, fn func() error) (reverted bool, err error) {
	imp := b.cfg.Impersonator
	if ierr := imp.Impersonate(c.Token); ierr != nil {
		// No revert: the SetThreadToken page asks that the assignment
		// succeed before RevertToSelf is called, and a failed entry leaves
		// the thread in the process's context.
		return true, fmt.Errorf("%w: %v", ErrImpersonationUnavailable, ierr)
	}
	func() {
		defer func() {
			if p := recover(); p != nil {
				err = fmt.Errorf("files: panic in the impersonation window: %v", p)
			}
		}()
		eff, eerr := imp.Effective()
		switch {
		case eerr != nil:
			err = fmt.Errorf("%w: the effective identity cannot be read: %v", ErrImpersonationUnavailable, eerr)
		case eff != c.Token.User():
			err = ErrExecutorMismatch
		default:
			err = fn()
		}
	}()
	if rerr := imp.Revert(); rerr != nil {
		return false, b.revertFailed(rerr)
	}
	return true, err
}

func (b *Broker) revertFailed(err error) error {
	b.MarkUnhealthy(fmt.Errorf("files: the revert failed: %w", err))
	return fmt.Errorf("%w: %v", ErrUnhealthy, err)
}
