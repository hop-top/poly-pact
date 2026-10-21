package broken

import (
	"slices"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/freshness"
	"hop.top/pact-go/adapters/memory"
	"hop.top/pact-go/core/clock"
)

// The freshness defects. Each comment says what the adapter does wrong.
const (
	// CacheBindingForContract keeps the binding status it read when the
	// contract was issued for the contract's lifetime, so a revocation the
	// source confirmed less than a contract lifetime ago is not seen.
	CacheBindingForContract Defect = "cache-binding-for-contract"
	// IgnoreCheckLimits reports the native verdict of a check without
	// applying the check's age limits.
	IgnoreCheckLimits Defect = "ignore-check-limits"
	// StaleAtLimit treats an age equal to its limit as stale.
	StaleAtLimit Defect = "stale-at-limit"
	// DeferClockAhead reports a source clock that runs ahead as a source that
	// cannot answer, which defers instead of refusing.
	DeferClockAhead Defect = "defer-clock-ahead"
	// NoSkewAllowance allows a source clock no skew: a time even a second
	// ahead of now is CLOCK_AHEAD.
	NoSkewAllowance Defect = "no-skew-allowance"
	// IgnorePinnedRevision reports the native verdict of a pinned check
	// whatever revision its source reports.
	IgnorePinnedRevision Defect = "ignore-pinned-revision"
	// ReadThroughOutage reads the records of a source that cannot answer as if
	// it could: the last value it held stands in for an answer.
	ReadThroughOutage Defect = "read-through-outage"
	// ForgetSightings evaluates a check without the observation times its
	// guard already holds, so a re-stamped record reads as fresh.
	ForgetSightings Defect = "forget-sightings"
)

// freshnessState returns st as the adapter sees it with the defects that
// change what it knows: limits, pins, sightings or outages it ignores.
func freshnessState(st memory.State, defects []Defect) memory.State {
	on := func(d Defect) bool { return slices.Contains(defects, d) }
	if on(IgnoreCheckLimits) || on(IgnorePinnedRevision) {
		checks := slices.Clone(st.Checks)
		for i := range checks {
			if on(IgnoreCheckLimits) {
				checks[i].Freshness = nil
			}
			if on(IgnorePinnedRevision) {
				checks[i].PinnedRevision = ""
			}
		}
		st.Checks = checks
	}
	if on(ForgetSightings) {
		st.Sightings = nil
	}
	if on(ReadThroughOutage) {
		st.UnavailableSources = nil
	}
	return st
}

// checkFreshness applies to the outcome of the check checkID the defects that
// misjudge the times of the record it consults.
func (b *Adapter) checkFreshness(checkID string, out adapter.CheckOutcome) adapter.CheckOutcome {
	if b.on[DeferClockAhead] && out.ReasonCode == string(freshness.ClockAhead) {
		return adapter.CheckOutcome{Result: adapter.VerdictUnknown, ReasonCode: string(adapter.CodeDependencyUnavailable), SourceID: out.SourceID}
	}
	i := slices.IndexFunc(b.State().Checks, func(c memory.CheckRecord) bool { return c.ID == checkID })
	if out.Result != adapter.VerdictPass || i < 0 || b.State().Checks[i].Freshness == nil {
		return out
	}
	rec := b.State().Checks[i]
	now := b.now().Unix()
	ahead := func(t *int64) bool { return t != nil && *t > now }
	atLimit := func(t, limit *int64) bool { return t != nil && now-*t == *limit }
	switch {
	case b.on[NoSkewAllowance] && (ahead(rec.ObservedAt) || ahead(rec.StatusCheckedAt)):
		return adapter.CheckOutcome{Result: adapter.VerdictFail, ReasonCode: string(freshness.ClockAhead), SourceID: out.SourceID, SourceRef: out.SourceRef}
	case b.on[StaleAtLimit] && (atLimit(rec.ObservedAt, rec.Freshness.MaxAgeSeconds) || atLimit(rec.StatusCheckedAt, rec.Freshness.StatusMaxAgeSeconds)):
		out.Result, out.ReasonCode = adapter.VerdictFail, string(freshness.StaleEvidence)
	}
	return out
}

// revokedWithinContract reports whether the source holds e as revoked or
// compromised by a status it confirmed less than a contract lifetime ago: the
// change a status cached at the contract's issuance would not show.
func (b *Adapter) revokedWithinContract(e memory.Enrollment) bool {
	switch adapter.BindingStatus(e.Status) {
	case adapter.BindingRevoked, adapter.BindingCompromised:
	default:
		return false
	}
	lifetime, err := clock.MaxLifetime(clock.Contract)
	if err != nil || e.StatusCheckedAt == nil {
		return false
	}
	age := b.now().Sub(time.Unix(*e.StatusCheckedAt, 0))
	return age >= 0 && age < lifetime
}
