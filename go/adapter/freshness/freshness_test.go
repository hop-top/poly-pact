package freshness_test

import (
	"math"
	"testing"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/freshness"
	"hop.top/pact-go/core"
	"hop.top/pact-go/core/clock"
)

// base is the instant every table below measures against: the iat of the
// worked example in Appendix B of the draft.
const base = 1_792_080_000

func at(sec int64) time.Time { return time.Unix(sec, 0) }

// rule returns an evidence or native field rule with the given age limits. The
// worked contract of Appendix B.4 uses max_age_seconds 30 and
// status_max_age_seconds 0.
func rule(maxAge, statusMaxAge int64) core.FieldRule {
	return core.FieldRule{
		RuleID:              "r",
		Path:                "/attributes/environment/principal_id",
		Source:              core.RuleSourceNative,
		Comparison:          core.ComparisonEqual,
		MaxAgeSeconds:       maxAge,
		StatusMaxAgeSeconds: statusMaxAge,
	}
}

func claim(observed, status time.Time) adapter.NativeClaim {
	return adapter.NativeClaim{
		Value:           "alice",
		ObservedAt:      observed,
		StatusCheckedAt: status,
		SourceID:        "directory",
		SourceRef:       "entry-1",
	}
}

func TestBaselineSkewIsTheClockPackageBaseline(t *testing.T) {
	// Section 7.5 gives 5 seconds; the clock package owns the constant and the
	// evaluator must take it from there, so a change reaches both.
	if clock.BaselineSkew != 5*time.Second {
		t.Fatalf("clock.BaselineSkew = %v, the tables below assume 5s", clock.BaselineSkew)
	}
}

func TestReasonCodes(t *testing.T) {
	// The spelling of every code is part of the wire contract: it lands in
	// CheckResult.reason_code. STALE_EVIDENCE is the Section 13.4 code,
	// DEPENDENCY_UNAVAILABLE and UNSUPPORTED_REQUIREMENT are the Section 13.4
	// and 17.1 codes, REQUIREMENT_SATISFIED is the Section 17.3.1 code, and
	// CLOCK_AHEAD and RESTAMPED are the freshness profile's own.
	tests := []struct {
		got  freshness.ReasonCode
		want string
	}{
		{freshness.Satisfied, "REQUIREMENT_SATISFIED"},
		{freshness.StaleEvidence, "STALE_EVIDENCE"},
		{freshness.ClockAhead, "CLOCK_AHEAD"},
		{freshness.Restamped, "RESTAMPED"},
		{freshness.UnsupportedRequirement, "UNSUPPORTED_REQUIREMENT"},
		{freshness.DependencyUnavailable, "DEPENDENCY_UNAVAILABLE"},
	}
	for _, tc := range tests {
		if string(tc.got) != tc.want {
			t.Errorf("code = %q, want %q", tc.got, tc.want)
		}
	}
	if got := freshness.Restamped.TreatedAs(); got != freshness.StaleEvidence {
		t.Errorf("RESTAMPED.TreatedAs() = %q, want STALE_EVIDENCE", got)
	}
	for _, c := range []freshness.ReasonCode{
		freshness.Satisfied, freshness.StaleEvidence, freshness.ClockAhead,
		freshness.UnsupportedRequirement, freshness.DependencyUnavailable,
	} {
		if got := c.TreatedAs(); got != c {
			t.Errorf("%s.TreatedAs() = %q, want itself", c, got)
		}
	}
}

// outcome is the expected return of Evaluate.
type outcome struct {
	result core.CheckStatus
	code   freshness.ReasonCode
}

var (
	pass     = outcome{core.CheckPass, freshness.Satisfied}
	stale    = outcome{core.CheckFail, freshness.StaleEvidence}
	ahead    = outcome{core.CheckFail, freshness.ClockAhead}
	noTime   = outcome{core.CheckUnknown, freshness.UnsupportedRequirement}
	badLimit = outcome{core.CheckUnknown, freshness.UnsupportedRequirement}
)

func TestEvaluate(t *testing.T) {
	now := at(base)
	nano := func(sec int64, ns int) time.Time { return time.Unix(sec, int64(ns)) }

	tests := []struct {
		name string
		rule core.FieldRule
		got  adapter.NativeClaim
		now  time.Time
		want outcome
	}{
		// max_age_seconds against ObservedAt: the age may equal the limit and
		// not exceed it (Section 7.5 phrases its own bounds as "at most").
		{"observed 10s ago, status now", rule(30, 0), claim(at(base-10), now), now, pass},
		{"observed exactly at the limit", rule(30, 0), claim(at(base-30), now), now, pass},
		{"observed one nanosecond past the limit", rule(30, 0), claim(nano(base-31, 999_999_999), now), now, stale},
		{"observed one second past the limit", rule(30, 0), claim(at(base-31), now), now, stale},
		{"observed long ago", rule(30, 0), claim(at(base-86400), now), now, stale},
		{"observed now", rule(30, 0), claim(now, now), now, pass},

		// status_max_age_seconds against StatusCheckedAt.
		{"status exactly at a 30s limit", rule(30, 30), claim(at(base-5), at(base-30)), now, pass},
		{"status one second past a 30s limit", rule(30, 30), claim(at(base-5), at(base-31)), now, stale},
		{"status fresh but observation stale", rule(30, 30), claim(at(base-31), now), now, stale},
		{"observation fresh but status stale", rule(30, 30), claim(now, at(base-31)), now, stale},

		// A zero status limit means a check in this evaluation: Start is now, so
		// the status time must not precede now.
		{"zero status limit, checked at now", rule(30, 0), claim(at(base-5), now), now, pass},
		{"zero status limit, checked one nanosecond ago", rule(30, 0), claim(at(base-5), nano(base-1, 999_999_999)), now, stale},
		{"zero status limit, checked one second ago", rule(30, 0), claim(at(base-5), at(base-1)), now, stale},
		{"zero status limit, cached status", rule(30, 0), claim(at(base-5), at(base-25)), now, stale},
		{"zero status limit, checked within skew ahead", rule(30, 0), claim(at(base-5), at(base+2)), now, pass},
		{"zero observation limit, observed at now", rule(0, 0), claim(now, now), now, pass},
		{"zero observation limit, observed one second ago", rule(0, 0), claim(at(base-1), now), now, stale},

		// Fractional now: the comparison is exact, never rounded in the claim's
		// favour (core/clock does the same for window checks).
		{"fractional now, age equals limit", rule(30, 30), claim(nano(base-30, 500), nano(base, 0)), nano(base, 500), pass},
		{"fractional now, age one nanosecond over", rule(30, 30), claim(nano(base-30, 499), nano(base, 0)), nano(base, 500), stale},
		{"fractional now, status one nanosecond over", rule(30, 30), claim(nano(base, 0), nano(base-30, 499)), nano(base, 500), stale},

		// Source clock ahead: a time later than now+skew is rejected, however
		// fresh it looks (Appendix A.2).
		{"observed at now+skew", rule(30, 0), claim(at(base+5), now), now, pass},
		{"observed one nanosecond past now+skew", rule(30, 0), claim(nano(base+5, 1), now), now, ahead},
		{"observed one second past now+skew", rule(30, 0), claim(at(base+6), now), now, ahead},
		{"observed far in the future", rule(30, 0), claim(at(base+3600), now), now, ahead},
		{"status at now+skew", rule(30, 0), claim(now, at(base+5)), now, pass},
		{"status one second past now+skew", rule(30, 0), claim(now, at(base+6)), now, ahead},
		{"status far in the future", rule(30, 0), claim(now, at(base+3600)), now, ahead},
		{"observed beyond 2^53-1 seconds", rule(30, 0), claim(time.Unix(1<<53, 0), now), now, ahead},

		// Missing times: a source that gives none cannot establish freshness,
		// and unknown status is not evidence of validity (Sections 8.3, 17.2).
		{"no observation time", rule(30, 0), claim(time.Time{}, now), now, noTime},
		{"no status time", rule(30, 0), claim(now, time.Time{}), now, noTime},
		{"no status time, positive status limit", rule(30, 30), claim(now, time.Time{}), now, noTime},
		{"neither time", rule(30, 30), claim(time.Time{}, time.Time{}), now, noTime},
		{"observation before the epoch is no usable time", rule(30, 30), claim(time.Unix(-1, 0), now), now, noTime},
		{"status before the epoch is no usable time", rule(30, 30), claim(now, time.Unix(-1, 0)), now, noTime},
		{"observation at the epoch is a time", rule(math.MaxInt32*2, 30), claim(time.Unix(0, 0), now), now, pass},

		// A demonstrable failure outranks a missing time, and a source clock
		// ahead outranks staleness.
		{"stale observation, no status time", rule(30, 30), claim(at(base-31), time.Time{}), now, stale},
		{"observation ahead, no status time", rule(30, 30), claim(at(base+6), time.Time{}), now, ahead},
		{"no observation time, stale status", rule(30, 30), claim(time.Time{}, at(base-31)), now, stale},
		{"observation ahead, status stale", rule(30, 30), claim(at(base+6), at(base-31)), now, ahead},
		{"observation stale, status ahead", rule(30, 30), claim(at(base-31), at(base+6)), now, ahead},

		// The limits are 0..2^53-1 (Appendix A schema); anything else is a rule
		// no source can satisfy.
		{"negative observation limit", rule(-1, 0), claim(now, now), now, badLimit},
		{"negative status limit", rule(30, -1), claim(now, now), now, badLimit},
		{"observation limit above 2^53-1", rule(1<<53, 0), claim(now, now), now, badLimit},
		{"status limit above 2^53-1", rule(30, 1<<53), claim(now, now), now, badLimit},
		{"observation limit int64 max", rule(math.MaxInt64, 0), claim(now, now), now, badLimit},

		// A limit as large as the schema allows must not overflow a duration.
		{"largest observation limit", rule(1<<53-1, 0), claim(at(base-86400*365), now), now, pass},
		{"largest status limit", rule(30, 1<<53-1), claim(now, at(base-86400*365)), now, pass},
		{"largest limit, claim at the epoch", rule(1<<53-1, 1<<53-1), claim(at(0), at(0)), now, pass},
		{"limit of 292 years in seconds, one year old", rule(9_223_372_037, 0), claim(at(base-86400*365), now), now, pass},
		{"limit past 292 years, claim at the epoch", rule(9_223_372_037, 9_223_372_037), claim(at(0), at(0)), now, pass},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res, code := freshness.Evaluate(tc.rule, tc.got, tc.now)
			if res != tc.want.result || code != tc.want.code {
				t.Errorf("Evaluate = %s %s, want %s %s", res, code, tc.want.result, tc.want.code)
			}
		})
	}
}

func TestEvaluateIgnoresTheClaimValue(t *testing.T) {
	// Freshness says nothing about the value; a nil value is JSON null and
	// evaluates like any other.
	c := claim(at(base-1), at(base))
	c.Value = nil
	if res, code := freshness.Evaluate(rule(30, 0), c, at(base)); res != core.CheckPass || code != freshness.Satisfied {
		t.Errorf("Evaluate = %s %s, want PASS REQUIREMENT_SATISFIED", res, code)
	}
}

func TestEvaluator(t *testing.T) {
	now := at(base)
	nano := func(sec int64, ns int) time.Time { return time.Unix(sec, int64(ns)) }

	tests := []struct {
		name string
		ev   freshness.Evaluator
		rule core.FieldRule
		got  adapter.NativeClaim
		want outcome
	}{
		// Skew may be tightened (Section 7.5: deployments MAY tighten).
		{"zero skew, observed at now", freshness.Evaluator{}, rule(30, 0), claim(now, now), pass},
		{"zero skew, observed one nanosecond ahead", freshness.Evaluator{}, rule(30, 0), claim(nano(base, 1), now), ahead},
		{"zero skew, status one nanosecond ahead", freshness.Evaluator{}, rule(30, 0), claim(now, nano(base, 1)), ahead},
		{"2s skew, observed at now+2s", freshness.Evaluator{Skew: 2 * time.Second}, rule(30, 0), claim(at(base+2), now), pass},
		{"2s skew, observed at now+3s", freshness.Evaluator{Skew: 2 * time.Second}, rule(30, 0), claim(at(base+3), now), ahead},
		{"5s skew is the baseline", freshness.Evaluator{Skew: clock.BaselineSkew}, rule(30, 0), claim(at(base+5), now), pass},

		// Skew above the baseline is not honoured, and a negative skew counts as
		// zero, the way core/clock treats it in ReplayRetention.
		{"6s skew is held to the baseline, at now+5s", freshness.Evaluator{Skew: 6 * time.Second}, rule(30, 0), claim(at(base+5), now), pass},
		{"6s skew is held to the baseline, at now+6s", freshness.Evaluator{Skew: 6 * time.Second}, rule(30, 0), claim(at(base+6), now), ahead},
		{"hour skew is held to the baseline", freshness.Evaluator{Skew: time.Hour}, rule(30, 0), claim(at(base+3600), now), ahead},
		{"negative skew counts as zero, at now", freshness.Evaluator{Skew: -time.Second}, rule(30, 0), claim(now, now), pass},
		{"negative skew counts as zero, one nanosecond ahead", freshness.Evaluator{Skew: -time.Second}, rule(30, 0), claim(nano(base, 1), now), ahead},

		// Start is when this evaluation began. A zero limit asks for a time not
		// before it, and a positive limit is measured from now regardless.
		{"start 10s ago, status 5s ago", freshness.Evaluator{Skew: clock.BaselineSkew, Start: at(base - 10)}, rule(30, 0), claim(at(base-5), at(base-5)), pass},
		{"start 10s ago, status at start", freshness.Evaluator{Skew: clock.BaselineSkew, Start: at(base - 10)}, rule(30, 0), claim(at(base-5), at(base-10)), pass},
		{"start 10s ago, status before start", freshness.Evaluator{Skew: clock.BaselineSkew, Start: at(base - 10)}, rule(30, 0), claim(at(base-5), nano(base-11, 999_999_999)), stale},
		{"start 10s ago, observed before start, zero observation limit", freshness.Evaluator{Skew: clock.BaselineSkew, Start: at(base - 10)}, rule(0, 0), claim(at(base-11), now), stale},
		{"start 100s ago does not loosen a positive status limit", freshness.Evaluator{Skew: clock.BaselineSkew, Start: at(base - 100)}, rule(30, 30), claim(at(base-5), at(base-31)), stale},
		{"start 100s ago does not loosen a positive observation limit", freshness.Evaluator{Skew: clock.BaselineSkew, Start: at(base - 100)}, rule(30, 30), claim(at(base-31), now), stale},
		{"zero Start means now", freshness.Evaluator{Skew: clock.BaselineSkew}, rule(30, 0), claim(at(base-5), at(base-1)), stale},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res, code := tc.ev.Evaluate(tc.rule, tc.got, now)
			if res != tc.want.result || code != tc.want.code {
				t.Errorf("Evaluate = %s %s, want %s %s", res, code, tc.want.result, tc.want.code)
			}
		})
	}
}

func TestEvaluateIsTheBaselineEvaluator(t *testing.T) {
	now := at(base)
	cases := []adapter.NativeClaim{
		claim(now, now), claim(at(base-31), now), claim(at(base+5), now),
		claim(at(base+6), now), claim(time.Time{}, now), claim(now, at(base-1)),
	}
	for i, c := range cases {
		r1, c1 := freshness.Evaluate(rule(30, 0), c, now)
		r2, c2 := freshness.Evaluator{Skew: clock.BaselineSkew}.Evaluate(rule(30, 0), c, now)
		if r1 != r2 || c1 != c2 {
			t.Errorf("case %d: Evaluate = %s %s, baseline Evaluator = %s %s", i, r1, c1, r2, c2)
		}
	}
}

func TestEvaluateWithAFakeClock(t *testing.T) {
	// The evaluator takes the instant as an argument, so a test moves it with
	// the fake clock of core/clock and never reads the wall clock.
	clk := clock.NewFake(at(base))
	c := claim(clk.Now(), clk.Now())
	if res, code := freshness.Evaluate(rule(30, 30), c, clk.Now()); res != core.CheckPass || code != freshness.Satisfied {
		t.Fatalf("at issue: %s %s, want PASS", res, code)
	}
	clk.Advance(30 * time.Second)
	if res, code := freshness.Evaluate(rule(30, 30), c, clk.Now()); res != core.CheckPass || code != freshness.Satisfied {
		t.Fatalf("30s later: %s %s, want PASS", res, code)
	}
	clk.Advance(time.Second)
	if res, code := freshness.Evaluate(rule(30, 30), c, clk.Now()); res != core.CheckFail || code != freshness.StaleEvidence {
		t.Fatalf("31s later: %s %s, want FAIL STALE_EVIDENCE", res, code)
	}
	// A validator clock 30s behind the source puts the claim in the future.
	clk.Advance(-61 * time.Second)
	if res, code := freshness.Evaluate(rule(30, 30), c, clk.Now()); res != core.CheckFail || code != freshness.ClockAhead {
		t.Fatalf("validator clock 30s behind the source: %s %s, want FAIL CLOCK_AHEAD", res, code)
	}
}
