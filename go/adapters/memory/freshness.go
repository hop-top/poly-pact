package memory

import (
	"errors"
	"fmt"
	"slices"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/freshness"
	"hop.top/pact-go/core"
	"hop.top/pact-go/core/clock"
)

// CodeRequirementsChanged is the reason code of a version-pinned check whose
// source reports another revision than the pinned one: the contract is no
// longer active (draft 13.4).
const CodeRequirementsChanged = "REQUIREMENTS_CHANGED"

// CodeApprovalScopeMismatch is the reason code of an approval-class check
// that is installed but whose native state is for another agent or another
// principal than the call's (draft 17.3.1: scope mismatch).
const CodeApprovalScopeMismatch = "APPROVAL_SCOPE_MISMATCH"

// guardCapacity is the number of source records the guard against
// re-stamping records beyond the sightings of the state. A guard that is full
// defers a record it has not seen; it never evicts.
const guardCapacity = 4096

// CheckFreshness is the pair of age limits of draft 9.2 that an installed
// check applies to the record it consults: max_age_seconds to the record's
// observation time and status_max_age_seconds to its status time. Both are
// required.
type CheckFreshness struct {
	MaxAgeSeconds       *int64 `json:"max_age_seconds"`
	StatusMaxAgeSeconds *int64 `json:"status_max_age_seconds"`
}

// Sighting is an observation time that the guard against re-stamping already
// holds for one source record, named by its source and its reference.
type Sighting struct {
	SourceID   string `json:"source_id"`
	SourceRef  string `json:"source_ref"`
	ObservedAt *int64 `json:"observed_at"`
}

// validateFreshness reports the first problem in the members of the state
// that the freshness rules read.
func (st State) validateFreshness() error {
	for _, c := range st.Checks {
		if f := c.Freshness; f != nil && (f.MaxAgeSeconds == nil || f.StatusMaxAgeSeconds == nil) {
			return fmt.Errorf("check %q: freshness needs max_age_seconds and status_max_age_seconds", c.ID)
		}
	}
	for _, s := range st.Sightings {
		if s.SourceID == "" || s.SourceRef == "" || s.ObservedAt == nil {
			return errors.New("a sighting needs a source_id, a source_ref and an observed_at")
		}
	}
	for _, id := range st.UnavailableSources {
		if id == "" {
			return errors.New("unavailable_sources lists an empty source id")
		}
	}
	return nil
}

// newGuard returns a guard against re-stamping that holds the sightings. Of
// two sightings of one record the earlier is kept, as the guard keeps the
// lowest time it sees.
func newGuard(sightings []Sighting) *freshness.Monotonic {
	g := freshness.NewMonotonic(len(sightings) + guardCapacity)
	for _, s := range sightings {
		g.Check(adapter.NativeClaim{SourceID: s.SourceID, SourceRef: s.SourceRef, ObservedAt: sourceTime(s.ObservedAt)})
	}
	return g
}

// unavailable reports whether the source named id cannot currently answer.
func (a *Adapter) unavailable(id string) bool {
	return slices.Contains(a.st.UnavailableSources, id)
}

// outage is the error of a read from a source that cannot answer. The adapter
// keeps no copy to fall back on, so the answer is a deferral (draft 18).
func outage(fn, source string) error {
	return fmt.Errorf("memory: %s: source %q cannot answer: %w", fn, source, adapter.ErrDependencyUnavailable)
}

// runCheck reports the outcome of the installed check c. The findings are
// taken in order, and the native verdict of c is reported only when there is
// none:
//
//  1. the source of c cannot answer: UNKNOWN with DEPENDENCY_UNAVAILABLE;
//  2. with freshness limits, the record's two times are evaluated against them
//     by the rules of the freshness profile, with the baseline skew and the
//     guard against re-stamping, and a result other than PASS is the outcome.
//     A time ahead of the clock is not passed on. Without limits, a time the
//     adapter cannot pass on defers the check, as it does a claim;
//  3. a check pinned to a revision of its source fails with
//     REQUIREMENTS_CHANGED when the source reports another one, or none.
func (a *Adapter) runCheck(c CheckRecord) adapter.CheckOutcome {
	out := adapter.CheckOutcome{SourceID: c.SourceID, SourceRef: c.SourceRef}
	if a.unavailable(c.SourceID) {
		return adapter.CheckOutcome{Result: adapter.VerdictUnknown, ReasonCode: string(adapter.CodeDependencyUnavailable), SourceID: c.SourceID}
	}
	observed, checked := sourceTime(c.ObservedAt), sourceTime(c.StatusCheckedAt)
	if f := c.Freshness; f != nil {
		rule := core.FieldRule{MaxAgeSeconds: *f.MaxAgeSeconds, StatusMaxAgeSeconds: *f.StatusMaxAgeSeconds}
		claim := adapter.NativeClaim{ObservedAt: observed, StatusCheckedAt: checked, SourceID: c.SourceID, SourceRef: c.SourceRef}
		ev := freshness.Evaluator{Skew: clock.BaselineSkew, Guard: a.guard}
		result, code := ev.Evaluate(rule, claim, a.clk.Now())
		switch {
		case code == freshness.ClockAhead:
			out.Result, out.ReasonCode = adapter.VerdictFail, string(code)
			return out
		case result != core.CheckPass:
			out.Result, out.ReasonCode, out.ObservedAt = verdictOf(result), string(code), observed
			return out
		}
	} else if err := a.checkSourceTimes(observed, checked); err != nil {
		return adapter.CheckOutcome{Result: adapter.VerdictUnknown, ReasonCode: string(adapter.CodeDependencyUnavailable), SourceID: c.SourceID}
	}
	out.ObservedAt = observed
	if c.PinnedRevision != "" && c.Revision != c.PinnedRevision {
		out.Result, out.ReasonCode = adapter.VerdictFail, CodeRequirementsChanged
		return out
	}
	out.Result, out.ReasonCode = adapter.Verdict(c.Result), c.ReasonCode
	return out
}

// verdictOf maps a check status to the verdict of the same name. Anything but
// PASS and FAIL established nothing, so it is UNKNOWN.
func verdictOf(s core.CheckStatus) adapter.Verdict {
	switch s {
	case core.CheckPass:
		return adapter.VerdictPass
	case core.CheckFail:
		return adapter.VerdictFail
	}
	return adapter.VerdictUnknown
}
