package freshness_test

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/freshness"
	"hop.top/pact-go/core"
	"hop.top/pact-go/core/clock"
)

// seen is a claim for (source, ref) observed at the given instant.
func seen(source, ref string, observed time.Time) adapter.NativeClaim {
	return adapter.NativeClaim{
		Value:           "alice",
		ObservedAt:      observed,
		StatusCheckedAt: at(base),
		SourceID:        source,
		SourceRef:       ref,
	}
}

func TestMonotonicCheck(t *testing.T) {
	// Each step runs against one guard, in order. The observation time of a
	// source record never changes (draft 8.3): a later one for the same record
	// is a re-stamp, and a new time needs a new SourceRef.
	type step struct {
		name  string
		claim adapter.NativeClaim
		want  outcome
	}
	notApplicable := outcome{core.CheckNotApplicable, ""}
	restamped := outcome{core.CheckFail, freshness.Restamped}

	tests := []struct {
		name  string
		steps []step
	}{
		{"first sighting passes", []step{
			{"first", seen("dir", "e1", at(100)), pass},
		}},
		{"the same time again passes", []step{
			{"first", seen("dir", "e1", at(100)), pass},
			{"again", seen("dir", "e1", at(100)), pass},
			{"and again", seen("dir", "e1", at(100)), pass},
		}},
		{"a later time for the same record is a re-stamp", []step{
			{"first", seen("dir", "e1", at(100)), pass},
			{"later", seen("dir", "e1", at(101)), restamped},
		}},
		{"a re-stamp does not become the new baseline", []step{
			{"first", seen("dir", "e1", at(100)), pass},
			{"later", seen("dir", "e1", at(500)), restamped},
			{"later again", seen("dir", "e1", at(500)), restamped},
			{"original", seen("dir", "e1", at(100)), pass},
		}},
		{"an earlier time lowers the baseline", []step{
			{"first", seen("dir", "e1", at(100)), pass},
			{"earlier", seen("dir", "e1", at(90)), pass},
			{"the first time is now later than the baseline", seen("dir", "e1", at(100)), restamped},
			{"earlier again", seen("dir", "e1", at(90)), pass},
		}},
		{"a re-stamp is caught however stale the first sighting was", []step{
			{"stale original", seen("dir", "e1", at(base-86400)), pass},
			{"laundered", seen("dir", "e1", at(base)), restamped},
		}},
		{"records are independent", []step{
			{"e1", seen("dir", "e1", at(100)), pass},
			{"e2", seen("dir", "e2", at(200)), pass},
			{"e1 later", seen("dir", "e1", at(101)), restamped},
			{"e2 same", seen("dir", "e2", at(200)), pass},
			{"e2 later", seen("dir", "e2", at(201)), restamped},
		}},
		{"a reference is scoped to its source", []step{
			{"dir", seen("dir", "e1", at(100)), pass},
			{"idp", seen("idp", "e1", at(300)), pass},
			{"dir later", seen("dir", "e1", at(101)), restamped},
			{"idp later", seen("idp", "e1", at(301)), restamped},
			{"idp same", seen("idp", "e1", at(300)), pass},
		}},
		{"the wire carries whole seconds", []step{
			{"first", seen("dir", "e1", time.Unix(100, 100)), pass},
			{"same second, later fraction", seen("dir", "e1", time.Unix(100, 900_000_000)), pass},
			{"next second", seen("dir", "e1", time.Unix(101, 0)), restamped},
			{"same second, earlier fraction", seen("dir", "e1", time.Unix(100, 0)), pass},
		}},
		{"no reference is nothing to compare", []step{
			{"first", seen("dir", "", at(100)), notApplicable},
			{"later", seen("dir", "", at(200)), notApplicable},
		}},
		{"no observation time is nothing to compare", []step{
			{"first", seen("dir", "e1", at(100)), pass},
			{"none", seen("dir", "e1", time.Time{}), notApplicable},
			{"later", seen("dir", "e1", at(101)), restamped},
		}},
		{"a time before the epoch is nothing to compare", []step{
			{"first", seen("dir", "e1", at(100)), pass},
			{"before the epoch", seen("dir", "e1", time.Unix(-5, 0)), notApplicable},
			{"same", seen("dir", "e1", at(100)), pass},
		}},
		{"a claim with no reference leaves the others alone", []step{
			{"first", seen("dir", "e1", at(100)), pass},
			{"no ref", seen("dir", "", at(900)), notApplicable},
			{"e1 same", seen("dir", "e1", at(100)), pass},
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := freshness.NewMonotonic(16)
			for _, s := range tc.steps {
				res, code := m.Check(s.claim)
				if res != s.want.result || code != s.want.code {
					t.Errorf("%s: Check = %s %q, want %s %q", s.name, res, code, s.want.result, s.want.code)
				}
			}
		})
	}
}

func TestMonotonicCapacity(t *testing.T) {
	// A full store defers (draft 7.5 and 18: a full or unavailable state store
	// causes deferral, never a pass), and never evicts to make room.
	deferred := outcome{core.CheckUnknown, freshness.DependencyUnavailable}
	m := freshness.NewMonotonic(2)

	if res, code := m.Check(seen("dir", "e1", at(100))); res != core.CheckPass {
		t.Fatalf("e1: %s %s", res, code)
	}
	if res, code := m.Check(seen("dir", "e2", at(100))); res != core.CheckPass {
		t.Fatalf("e2: %s %s", res, code)
	}
	if got := m.Len(); got != 2 {
		t.Fatalf("Len = %d, want 2", got)
	}

	if res, code := m.Check(seen("dir", "e3", at(100))); res != deferred.result || code != deferred.code {
		t.Errorf("e3 in a full store: %s %s, want UNKNOWN DEPENDENCY_UNAVAILABLE", res, code)
	}
	if got := m.Len(); got != 2 {
		t.Errorf("Len = %d after a refused record, want 2", got)
	}
	// Known records are still guarded, and an old record was not evicted.
	if res, code := m.Check(seen("dir", "e1", at(101))); res != core.CheckFail || code != freshness.Restamped {
		t.Errorf("e1 re-stamp in a full store: %s %s, want FAIL RESTAMPED", res, code)
	}
	if res, code := m.Check(seen("dir", "e2", at(100))); res != core.CheckPass {
		t.Errorf("e2 again in a full store: %s %s, want PASS", res, code)
	}

	// Forget frees one slot, and only that one.
	m.Forget("dir", "e1")
	if got := m.Len(); got != 1 {
		t.Fatalf("Len = %d after Forget, want 1", got)
	}
	if res, code := m.Check(seen("dir", "e3", at(100))); res != core.CheckPass {
		t.Errorf("e3 after Forget: %s %s, want PASS", res, code)
	}
	if res, code := m.Check(seen("dir", "e1", at(100))); res != deferred.result || code != deferred.code {
		t.Errorf("e1 after its slot went: %s %s, want UNKNOWN DEPENDENCY_UNAVAILABLE", res, code)
	}
	m.Forget("dir", "never-seen") // no effect
	m.Forget("other", "e2")       // another source: no effect
	if got := m.Len(); got != 2 {
		t.Errorf("Len = %d after forgetting nothing, want 2", got)
	}
}

func TestMonotonicForgetStartsTheRecordAfresh(t *testing.T) {
	m := freshness.NewMonotonic(4)
	m.Check(seen("dir", "e1", at(100)))
	m.Forget("dir", "e1")
	if res, code := m.Check(seen("dir", "e1", at(500))); res != core.CheckPass {
		t.Errorf("after Forget a new time is a first sighting: %s %s", res, code)
	}
	if res, code := m.Check(seen("dir", "e1", at(501))); res != core.CheckFail || code != freshness.Restamped {
		t.Errorf("and is then guarded: %s %s", res, code)
	}
}

func TestMonotonicWithNoCapacityDefersEveryReference(t *testing.T) {
	for _, limit := range []int{0, -1} {
		m := freshness.NewMonotonic(limit)
		if res, code := m.Check(seen("dir", "e1", at(100))); res != core.CheckUnknown || code != freshness.DependencyUnavailable {
			t.Errorf("limit %d: %s %s, want UNKNOWN DEPENDENCY_UNAVAILABLE", limit, res, code)
		}
		// A claim the guard cannot compare is not refused for want of room.
		if res, _ := m.Check(seen("dir", "", at(100))); res != core.CheckNotApplicable {
			t.Errorf("limit %d, no ref: %s, want NOT_APPLICABLE", limit, res)
		}
	}
}

func TestMonotonicIsSafeForConcurrentUse(t *testing.T) {
	// Every goroutine reports the same record at a different time. Whatever the
	// interleaving, the lowest time recorded is the baseline, and no time above
	// it passes once it is set.
	m := freshness.NewMonotonic(8)
	var wg sync.WaitGroup
	for i := range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 50 {
				m.Check(seen("dir", "e1", at(int64(1000+i))))
			}
		}()
	}
	wg.Wait()
	if res, code := m.Check(seen("dir", "e1", at(1000))); res != core.CheckPass {
		t.Errorf("lowest time: %s %s, want PASS", res, code)
	}
	if res, code := m.Check(seen("dir", "e1", at(1001))); res != core.CheckFail || code != freshness.Restamped {
		t.Errorf("a higher time: %s %s, want FAIL RESTAMPED", res, code)
	}
	if got := m.Len(); got != 1 {
		t.Errorf("Len = %d, want 1", got)
	}
}

func guarded(m *freshness.Monotonic) freshness.Evaluator {
	return freshness.Evaluator{Skew: clock.BaselineSkew, Guard: m}
}

func TestEvaluatorGuard(t *testing.T) {
	now := at(base)
	restamped := outcome{core.CheckFail, freshness.Restamped}
	deferred := outcome{core.CheckUnknown, freshness.DependencyUnavailable}

	t.Run("a refreshed time for a known record is a re-stamp", func(t *testing.T) {
		m := freshness.NewMonotonic(4)
		ev := guarded(m)
		// The source saw the fact 20s ago.
		first := seen("dir", "e1", at(base-20))
		if res, code := ev.Evaluate(rule(30, 0), first, now); res != core.CheckPass {
			t.Fatalf("first: %s %s", res, code)
		}
		// Ten seconds on, the same record comes back stamped "now", fresh
		// enough on its face. Age alone passes it; the guard does not.
		later := at(base + 10)
		relaundered := seen("dir", "e1", later)
		relaundered.StatusCheckedAt = later
		res, code := ev.Evaluate(rule(30, 0), relaundered, later)
		if res != restamped.result || code != restamped.code {
			t.Errorf("guarded: %s %s, want FAIL RESTAMPED", res, code)
		}
		if res, code := freshness.Evaluate(rule(30, 0), relaundered, later); res != core.CheckPass {
			t.Errorf("without a guard the same claim is %s %s, want PASS (the guard is what catches it)", res, code)
		}
	})

	t.Run("a stale first sighting still sets the baseline", func(t *testing.T) {
		// The stale fact is refused, and then the same record re-stamped as
		// fresh must not get through: re-signing never launders an old
		// observation.
		m := freshness.NewMonotonic(4)
		ev := guarded(m)
		old := seen("dir", "e1", at(base-3600))
		if res, code := ev.Evaluate(rule(30, 0), old, now); res != core.CheckFail || code != freshness.StaleEvidence {
			t.Fatalf("stale first: %s %s", res, code)
		}
		fresh := seen("dir", "e1", now)
		fresh.StatusCheckedAt = now
		if res, code := ev.Evaluate(rule(30, 0), fresh, now); res != restamped.result || code != restamped.code {
			t.Errorf("laundered: %s %s, want FAIL RESTAMPED", res, code)
		}
	})

	t.Run("a new record with a new reference is a new observation", func(t *testing.T) {
		m := freshness.NewMonotonic(4)
		ev := guarded(m)
		ev.Evaluate(rule(30, 0), seen("dir", "e1", at(base-3600)), now)
		fresh := seen("dir", "e2", now)
		fresh.StatusCheckedAt = now
		if res, code := ev.Evaluate(rule(30, 0), fresh, now); res != core.CheckPass || code != freshness.Satisfied {
			t.Errorf("new reference: %s %s, want PASS", res, code)
		}
	})

	t.Run("a re-stamp that is also stale reports the re-stamp", func(t *testing.T) {
		m := freshness.NewMonotonic(4)
		ev := guarded(m)
		ev.Evaluate(rule(30, 0), seen("dir", "e1", at(base-7200)), now)
		stillStale := seen("dir", "e1", at(base-3600))
		stillStale.StatusCheckedAt = now
		if res, code := ev.Evaluate(rule(30, 0), stillStale, now); res != restamped.result || code != restamped.code {
			t.Errorf("%s %s, want FAIL RESTAMPED", res, code)
		}
	})

	t.Run("a source clock ahead is reported as that and is not recorded", func(t *testing.T) {
		m := freshness.NewMonotonic(4)
		ev := guarded(m)
		future := seen("dir", "e1", at(base+3600))
		if res, code := ev.Evaluate(rule(30, 0), future, now); res != core.CheckFail || code != freshness.ClockAhead {
			t.Fatalf("future: %s %s, want FAIL CLOCK_AHEAD", res, code)
		}
		if got := m.Len(); got != 0 {
			t.Errorf("Len = %d, an implausible time must not become a baseline", got)
		}
	})

	t.Run("a full store defers a claim that otherwise passes", func(t *testing.T) {
		m := freshness.NewMonotonic(0)
		ev := guarded(m)
		fresh := seen("dir", "e1", now)
		fresh.StatusCheckedAt = now
		if res, code := ev.Evaluate(rule(30, 0), fresh, now); res != deferred.result || code != deferred.code {
			t.Errorf("%s %s, want UNKNOWN DEPENDENCY_UNAVAILABLE", res, code)
		}
	})

	t.Run("a demonstrable failure outranks a full store", func(t *testing.T) {
		m := freshness.NewMonotonic(0)
		ev := guarded(m)
		if res, code := ev.Evaluate(rule(30, 0), seen("dir", "e1", at(base-3600)), now); res != core.CheckFail || code != freshness.StaleEvidence {
			t.Errorf("%s %s, want FAIL STALE_EVIDENCE", res, code)
		}
	})

	t.Run("a claim with no reference passes on age alone", func(t *testing.T) {
		m := freshness.NewMonotonic(0)
		ev := guarded(m)
		fresh := seen("dir", "", now)
		fresh.StatusCheckedAt = now
		if res, code := ev.Evaluate(rule(30, 0), fresh, now); res != core.CheckPass || code != freshness.Satisfied {
			t.Errorf("%s %s, want PASS", res, code)
		}
	})

	t.Run("a rule no source can satisfy is refused before the guard", func(t *testing.T) {
		m := freshness.NewMonotonic(4)
		ev := guarded(m)
		if res, code := ev.Evaluate(rule(-1, 0), seen("dir", "e1", now), now); res != badLimit.result || code != badLimit.code {
			t.Errorf("%s %s, want UNKNOWN UNSUPPORTED_REQUIREMENT", res, code)
		}
		if got := m.Len(); got != 0 {
			t.Errorf("Len = %d, want 0", got)
		}
	})

	t.Run("a missing status time is reported once the guard has passed", func(t *testing.T) {
		m := freshness.NewMonotonic(4)
		ev := guarded(m)
		c := seen("dir", "e1", now)
		c.StatusCheckedAt = time.Time{}
		if res, code := ev.Evaluate(rule(30, 0), c, now); res != noTime.result || code != noTime.code {
			t.Errorf("%s %s, want UNKNOWN UNSUPPORTED_REQUIREMENT", res, code)
		}
		if got := m.Len(); got != 1 {
			t.Errorf("Len = %d, the observation was plausible and is recorded", got)
		}
	})
}

func TestEvaluatorGuardAcrossManyRecords(t *testing.T) {
	m := freshness.NewMonotonic(64)
	ev := guarded(m)
	now := at(base)
	for i := range 64 {
		c := seen("dir", fmt.Sprintf("e%d", i), now)
		c.StatusCheckedAt = now
		if res, code := ev.Evaluate(rule(30, 0), c, now); res != core.CheckPass {
			t.Fatalf("e%d: %s %s", i, res, code)
		}
	}
	later := at(base + 1)
	for i := range 64 {
		c := seen("dir", fmt.Sprintf("e%d", i), later)
		c.StatusCheckedAt = later
		if res, code := ev.Evaluate(rule(30, 0), c, later); res != core.CheckFail || code != freshness.Restamped {
			t.Fatalf("e%d re-stamped: %s %s", i, res, code)
		}
	}
}
