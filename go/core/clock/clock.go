// Package clock holds the time rules of Section 7.5 and the baseline lifetimes
// of Section 20.1 of the draft.
//
// Protocol timestamps (iat, nbf, exp, created_at, expires_at) are integer Unix
// seconds in the range 0..2^53-1. A validator reads the current time from a
// [Clock] so that tests control it, then applies:
//
//   - [CheckWindow]: nbf <= now+skew, iat <= now+skew and now < exp, with no
//     grace period after exp;
//   - [CheckLifetime]: the longest span from iat to exp an artifact type may
//     claim;
//   - [CheckPresentation]: the window and lifetime checks plus now-iat <= 60 s
//     for an agent presentation;
//   - [ReplayRetention]: how long a replay record must be kept.
//
// The baseline clock skew is [BaselineSkew]. A deployment may tighten it and
// pass the smaller value; a larger one is an error. The checks compare the
// time.Time they are given exactly, to the nanosecond, so a fractional now is
// not rounded in the artifact's favour.
package clock

import (
	"sync"
	"time"
)

// Clock reports the current time.
type Clock interface {
	Now() time.Time
}

// SystemClock is the Clock of the host: it returns time.Now().
type SystemClock struct{}

// Now returns the current wall-clock time.
func (SystemClock) Now() time.Time { return time.Now() }

// Fake is a Clock that only moves when told to. It is safe for concurrent use.
type Fake struct {
	mu  sync.Mutex
	now time.Time
}

// NewFake returns a Fake that reads start until it is moved.
func NewFake(start time.Time) *Fake { return &Fake{now: start} }

// Now returns the time the Fake was last set to or advanced to.
func (f *Fake) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

// Set moves the Fake to t.
func (f *Fake) Set(t time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = t
}

// Advance moves the Fake by d, which may be negative.
func (f *Fake) Advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = f.now.Add(d)
}
