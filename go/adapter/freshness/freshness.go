package freshness

import (
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/core"
	"hop.top/pact-go/core/clock"
)

// maxLimit is the largest value of an age limit: 2^53-1, the core integer
// range of draft Section 7.1.
const maxLimit = 1<<53 - 1

// Result is the outcome of a freshness check, the type of CheckResult.result.
// Evaluate returns PASS, FAIL or UNKNOWN. [Monotonic.Check] can also return
// NOT_APPLICABLE.
type Result = core.CheckStatus

// ReasonCode is a stable reason code for a freshness result, the value of
// CheckResult.reason_code.
type ReasonCode string

// The reason codes of a freshness check.
const (
	// Satisfied: every age is within its limit (Section 17.3.1).
	Satisfied ReasonCode = "REQUIREMENT_SATISFIED"
	// StaleEvidence: an age is above its limit (Section 13.4).
	StaleEvidence ReasonCode = "STALE_EVIDENCE"
	// ClockAhead: a source time is later than now plus the clock skew, so the
	// source clock runs ahead of the validator's.
	ClockAhead ReasonCode = "CLOCK_AHEAD"
	// Restamped: a source record came back with a later observation time than
	// the first one seen for it. It is treated as [StaleEvidence].
	Restamped ReasonCode = "RESTAMPED"
	// UnsupportedRequirement: the source gives no usable time, or the rule's
	// limit is not a valid one, so the demanded freshness cannot be established
	// (Sections 13.4 and 17.2). The result is UNKNOWN.
	UnsupportedRequirement = ReasonCode(adapter.CodeUnsupportedRequirement)
	// DependencyUnavailable: the guard cannot record the observation, so the
	// check cannot be completed now (Sections 13.4 and 18). The result is
	// UNKNOWN.
	DependencyUnavailable = ReasonCode(adapter.CodeDependencyUnavailable)
)

// TreatedAs returns the code whose handling c shares. [Restamped] is treated
// as [StaleEvidence]: an INADMISSIBLE check with the same transport error. Any
// other code is its own.
func (c ReasonCode) TreatedAs() ReasonCode {
	if c == Restamped {
		return StaleEvidence
	}
	return c
}

// Evaluator holds the parameters of a freshness evaluation. The zero value is
// valid: no skew allowance, an evaluation that began at now, and no guard.
type Evaluator struct {
	// Skew is the clock skew allowance (Section 7.5). A value above
	// [clock.BaselineSkew] counts as the baseline and a negative one as zero, so
	// the evaluator is never more lenient than the baseline. [Evaluate] uses the
	// baseline.
	Skew time.Duration
	// Start is the instant this evaluation began, taken before any source was
	// read for it. A limit of zero seconds requires the time not to precede it.
	// The zero Time means the instant now of the call.
	Start time.Time
	// Guard, when not nil, records the observation time of each source record
	// and reports a later one as [Restamped]. One Guard serves every
	// evaluation that must see the same records.
	Guard *Monotonic
}

// Evaluate checks claim against the age limits of rule at now, with the
// baseline clock skew, no guard, and an evaluation that began at now. It is
// [Evaluator.Evaluate] for the common case.
func Evaluate(rule core.FieldRule, claim adapter.NativeClaim, now time.Time) (Result, ReasonCode) {
	return Evaluator{Skew: clock.BaselineSkew}.Evaluate(rule, claim, now)
}

// Evaluate checks claim against rule.MaxAgeSeconds and
// rule.StatusMaxAgeSeconds at now. See the package documentation for the
// rules and their order.
func (e Evaluator) Evaluate(rule core.FieldRule, claim adapter.NativeClaim, now time.Time) (Result, ReasonCode) {
	if !validLimit(rule.MaxAgeSeconds) || !validLimit(rule.StatusMaxAgeSeconds) {
		return core.CheckUnknown, UnsupportedRequirement
	}
	skew := min(max(e.Skew, 0), clock.BaselineSkew)
	start := e.Start
	if start.IsZero() {
		start = now
	}

	observed, haveObserved := claim.ObservedAt, usable(claim.ObservedAt)
	checked, haveChecked := claim.StatusCheckedAt, usable(claim.StatusCheckedAt)

	// A source clock ahead outranks everything, and an implausible time is
	// never recorded as the baseline of a source record.
	latest := now.Add(skew)
	if haveObserved && observed.After(latest) || haveChecked && checked.After(latest) {
		return core.CheckFail, ClockAhead
	}

	guard := core.CheckNotApplicable
	if e.Guard != nil {
		guard, _ = e.Guard.Check(claim)
	}
	if guard == core.CheckFail {
		return core.CheckFail, Restamped
	}

	if haveObserved && tooOld(observed, now, start, rule.MaxAgeSeconds) ||
		haveChecked && tooOld(checked, now, start, rule.StatusMaxAgeSeconds) {
		return core.CheckFail, StaleEvidence
	}

	if !haveObserved || !haveChecked {
		return core.CheckUnknown, UnsupportedRequirement
	}
	if guard == core.CheckUnknown {
		return core.CheckUnknown, DependencyUnavailable
	}
	return core.CheckPass, Satisfied
}

// validLimit reports whether n is in the range of a core integer.
func validLimit(n int64) bool { return n >= 0 && n <= maxLimit }

// usable reports whether t is a time a source gave and the wire can carry: not
// the zero Time, which means none, and not before the epoch.
func usable(t time.Time) bool { return !t.IsZero() && t.Unix() >= 0 }

// tooOld reports whether t is older than limit seconds at now. A limit of zero
// asks for a time not before start. A positive limit is compared as whole
// seconds plus the nanosecond remainder, so that a limit as large as 2^53-1
// does not overflow a Duration and a fractional now is not rounded.
func tooOld(t, now, start time.Time, limit int64) bool {
	if limit == 0 {
		return t.Before(start)
	}
	whole := now.Unix() - t.Unix()
	if whole != limit {
		return whole > limit
	}
	return now.Nanosecond() > t.Nanosecond()
}
