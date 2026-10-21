package freshness

import (
	"sync"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/core"
)

// record names one source record: a reference is scoped to its source.
type record struct{ sourceID, sourceRef string }

// Monotonic is the guard against re-stamping. The observation time of a
// source record never changes (draft Section 8.3): an adapter or an issuer
// that refreshes a stale upstream fact must not give it a new time, and a new
// ObservedAt requires a new SourceRef. The guard remembers the first
// observation time it sees for each (SourceID, SourceRef) and reports a later
// one as [Restamped].
//
// The guard compares whole seconds, which is all the wire carries. It keeps
// the lowest time seen for a record, so the baseline never moves up: a
// re-stamped time does not become the new baseline, and an earlier time seen
// later lowers it. A claim seen once, however stale, still sets the baseline,
// which is what stops a refused fact from coming back with a fresh time.
//
// The store is bounded. At the limit it refuses a record it has not seen and
// returns UNKNOWN with [DependencyUnavailable], the deferral Sections 7.5 and
// 18 require of a full state store, and it never evicts. [Monotonic.Forget]
// ends the life of a record the source has retired. The store is in memory
// and local to one process: a deployment with several replicas that must
// catch a re-stamp across replicas shares the store between them, as it
// shares replay state (Section 7.5), or accepts that each replica guards only
// what it has seen itself.
//
// A Monotonic is safe for concurrent use.
type Monotonic struct {
	mu    sync.Mutex
	limit int
	seen  map[record]int64
}

// NewMonotonic returns a guard that records at most limit source records. A
// limit below 1 records none, so every claim with a reference is deferred.
func NewMonotonic(limit int) *Monotonic {
	return &Monotonic{limit: limit, seen: make(map[record]int64)}
}

// Check records the observation time of claim for its source record and
// reports whether it contradicts an earlier one.
//
// It returns FAIL with [Restamped] when the record was seen with an earlier
// time; UNKNOWN with [DependencyUnavailable] when the record is new and the
// store is full; PASS with [Satisfied] otherwise; and NOT_APPLICABLE with the
// empty ReasonCode when the claim has no SourceRef or no usable ObservedAt, so
// that there is nothing to compare and no check took place. A caller does not
// record NOT_APPLICABLE as a pass.
func (m *Monotonic) Check(claim adapter.NativeClaim) (Result, ReasonCode) {
	if claim.SourceRef == "" || !usable(claim.ObservedAt) {
		return core.CheckNotApplicable, ""
	}
	key := record{claim.SourceID, claim.SourceRef}
	at := claim.ObservedAt.Unix()

	m.mu.Lock()
	defer m.mu.Unlock()
	first, ok := m.seen[key]
	switch {
	case !ok && len(m.seen) >= m.limit:
		return core.CheckUnknown, DependencyUnavailable
	case ok && at > first:
		return core.CheckFail, Restamped
	}
	m.seen[key] = at
	return core.CheckPass, Satisfied
}

// Forget drops the record for (sourceID, sourceRef), which ends its guard: a
// later sighting is a first one. Call it when the source retires the record,
// such as a token that has expired. It does nothing for a record never seen.
func (m *Monotonic) Forget(sourceID, sourceRef string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.seen, record{sourceID, sourceRef})
}

// Len returns the number of source records the guard holds.
func (m *Monotonic) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.seen)
}
