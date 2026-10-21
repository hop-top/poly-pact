package adaptertest

import (
	"encoding/json"
	"slices"
	"testing"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/freshness"
	"hop.top/pact-go/core/clock"
)

// TestFreshnessCasesPinTheProfile: the FRESH cases expect what the freshness
// profile (spec/v1.0/profiles/freshness.md, sections 3.2, 5 and 6) and the draft
// require, so that a case cannot be loosened to an outcome the profile does not
// give. CLOCK_AHEAD and RESTAMPED are check-specific codes with no draft 13.4
// row, so they are pinned as check_context reason codes; the reference
// implementation must spell them the same way.
func TestFreshnessCasesPinTheProfile(t *testing.T) {
	fsys, err := DefaultFixtures()
	if err != nil {
		t.Fatal(err)
	}
	cases, err := Load(fsys, "")
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]Case{}
	for _, c := range cases {
		byID[c.ID] = c
	}
	want := []struct{ id, function, outcome, code string }{
		{"FRESH-01.revoked-after-issuance", fnBinding, outUnusable, ""},
		{"FRESH-02.stale-snapshot", fnCheck, outFail, "STALE_EVIDENCE"},
		{"FRESH-02.at-limit", fnCheck, outPass, "REQUIREMENT_SATISFIED"},
		{"FRESH-03.observed-ahead", fnCheck, outFail, "CLOCK_AHEAD"},
		{"FRESH-03.at-skew", fnCheck, outPass, "REQUIREMENT_SATISFIED"},
		{"FRESH-04.pinned-revision-changed", fnCheck, outFail, "REQUIREMENTS_CHANGED"},
		{"FRESH-05.binding-source-down", fnBinding, outError, "DEPENDENCY_UNAVAILABLE"},
		{"FRESH-05.claim-source-down", fnClaim, outError, "DEPENDENCY_UNAVAILABLE"},
		{"FRESH-05.check-source-down", fnCheck, outUnknown, "DEPENDENCY_UNAVAILABLE"},
		{"FRESH-06.restamped", fnCheck, outFail, "RESTAMPED"},
	}
	for _, w := range want {
		t.Run(w.id, func(t *testing.T) {
			c, ok := byID[w.id]
			if !ok {
				t.Fatalf("no case %s", w.id)
			}
			e := c.Expect
			if e.Function != w.function || e.Outcome != w.outcome || e.ReasonCode != w.code {
				t.Errorf("expects %s %s %q, want %s %s %q", e.Function, e.Outcome, e.ReasonCode, w.function, w.outcome, w.code)
			}
			if c.Now == nil {
				t.Error("states no now: a freshness case fixes the clock")
			}
		})
	}

	for code, impl := range map[string]freshness.ReasonCode{
		"STALE_EVIDENCE": freshness.StaleEvidence, "CLOCK_AHEAD": freshness.ClockAhead,
		"RESTAMPED": freshness.Restamped, "REQUIREMENT_SATISFIED": freshness.Satisfied,
		"DEPENDENCY_UNAVAILABLE": freshness.DependencyUnavailable,
	} {
		if string(impl) != code {
			t.Errorf("package freshness spells %s as %q", code, impl)
		}
	}
}

// TestFreshnessCaseTimes: the times of the FRESH cases sit where the draft's
// bounds put them, as go/core/clock states the bounds: one second past the
// 5-second skew and exactly at it (draft 7.5), and a revocation inside the
// 60-second lifetime of a contract issued before it (draft 9.1, 20.1).
func TestFreshnessCaseTimes(t *testing.T) {
	fsys, err := DefaultFixtures()
	if err != nil {
		t.Fatal(err)
	}
	cases, err := Load(fsys, "")
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]Case{}
	for _, c := range cases {
		byID[c.ID] = c
	}
	var state struct {
		Checks []struct {
			ObservedAt int64 `json:"observed_at"`
		} `json:"checks"`
		Enrollments []struct {
			StatusCheckedAt int64 `json:"status_checked_at"`
		} `json:"enrollments"`
	}
	read := func(id string) int64 {
		t.Helper()
		c, ok := byID[id]
		if !ok || c.Now == nil {
			t.Fatalf("no case %s with a now", id)
		}
		state.Checks, state.Enrollments = nil, nil
		if err := json.Unmarshal(c.NativeState, &state); err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		return *c.Now
	}
	skew := int64(clock.BaselineSkew / time.Second)

	now := read("FRESH-03.observed-ahead")
	if len(state.Checks) != 1 || state.Checks[0].ObservedAt != now+skew+1 {
		t.Errorf("FRESH-03.observed-ahead: observed_at is not now plus the skew plus one second")
	}
	now = read("FRESH-03.at-skew")
	if len(state.Checks) != 1 || state.Checks[0].ObservedAt != now+skew {
		t.Errorf("FRESH-03.at-skew: observed_at is not now plus the skew")
	}

	lifetime, err := clock.MaxLifetime(clock.Contract)
	if err != nil {
		t.Fatal(err)
	}
	now = read("FRESH-01.revoked-after-issuance")
	if len(state.Enrollments) != 1 {
		t.Fatal("FRESH-01.revoked-after-issuance: want one enrollment")
	}
	if age := now - state.Enrollments[0].StatusCheckedAt; age <= 0 || age >= int64(lifetime/time.Second) {
		t.Errorf("FRESH-01.revoked-after-issuance: the revocation is %d s old, want inside a contract lifetime of %s", age, lifetime)
	}
}

// TestStatusCheckCaseTimes: the COMMON-04 status-check cases sit at the bound
// of draft A.2, "No source observation or status-check time may be later than
// now + clock_skew": exactly at now plus the 5-second skew for the control,
// and one second past it for the case that must not be passed on, which the
// freshness profile has refused with DEPENDENCY_UNAVAILABLE.
func TestStatusCheckCaseTimes(t *testing.T) {
	fsys, err := DefaultFixtures()
	if err != nil {
		t.Fatal(err)
	}
	cases, err := Load(fsys, "")
	if err != nil {
		t.Fatal(err)
	}
	skew := int64(clock.BaselineSkew / time.Second)
	for id, want := range map[string]struct {
		ahead   int64
		outcome string
	}{
		"COMMON-04.status-checked-at-skew": {skew, outClaim},
		"COMMON-04.future-status-checked":  {skew + 1, outError},
	} {
		i := slices.IndexFunc(cases, func(c Case) bool { return c.ID == id })
		if i < 0 {
			t.Errorf("no case %s", id)
			continue
		}
		c := cases[i]
		var state struct {
			Claims []struct {
				StatusCheckedAt int64 `json:"status_checked_at"`
			} `json:"claims"`
		}
		if err := json.Unmarshal(c.NativeState, &state); err != nil || len(state.Claims) != 1 {
			t.Errorf("%s: want one claim record: %v", id, err)
			continue
		}
		now := defaultNow
		if c.Now != nil {
			now = *c.Now
		}
		if got := state.Claims[0].StatusCheckedAt - now; got != want.ahead {
			t.Errorf("%s: status_checked_at is now plus %d s, want now plus %d s", id, got, want.ahead)
		}
		if c.Expect.Outcome != want.outcome {
			t.Errorf("%s: outcome %s, want %s", id, c.Expect.Outcome, want.outcome)
		}
	}
}

// TestClaimClockAheadCasesRequireRefusal: a read_native_claim whose source
// observation or status time is later than now plus the skew is refused with
// DEPENDENCY_UNAVAILABLE (freshness profile, section 3; draft A.2, 13.4). The
// cases require that error: a claim that holds the bounds, with the time
// clamped or replaced, is not accepted.
func TestClaimClockAheadCasesRequireRefusal(t *testing.T) {
	fsys, err := DefaultFixtures()
	if err != nil {
		t.Fatal(err)
	}
	cases, err := Load(fsys, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"COMMON-04.future-observed-at", "COMMON-04.future-status-checked"} {
		i := slices.IndexFunc(cases, func(c Case) bool { return c.ID == id })
		if i < 0 {
			t.Errorf("no case %s", id)
			continue
		}
		e := cases[i].Expect
		if e.Function != fnClaim || e.Outcome != outError || e.ReasonCode != string(adapter.CodeDependencyUnavailable) {
			t.Errorf("%s: expects %s %s %q, want %s error DEPENDENCY_UNAVAILABLE", id, e.Function, e.Outcome, e.ReasonCode, fnClaim)
		}
	}
}
