package clock_test

import (
	"errors"
	"math"
	"testing"
	"time"

	"hop.top/pact-go/core/clock"
)

// base is the instant every table below measures against.
const base = 1_000_000

func at(sec int64) time.Time { return time.Unix(sec, 0) }

func TestBaselineSkew(t *testing.T) {
	if clock.BaselineSkew != 5*time.Second {
		t.Fatalf("BaselineSkew = %v, want 5s", clock.BaselineSkew)
	}
}

func TestCheckWindow(t *testing.T) {
	const skew = clock.BaselineSkew
	subsecond := time.Unix(base, 999_999_999)

	tests := []struct {
		name          string
		iat, nbf, exp int64
		now           time.Time
		skew          time.Duration
		want          error
	}{
		{"inside the window", base - 10, base - 10, base + 50, at(base), skew, nil},
		{"all claims at now", base, base, base + 1, at(base), skew, nil},

		// nbf <= now + skew
		{"nbf equals now+skew", base, base + 5, base + 60, at(base), skew, nil},
		{"nbf one second past now+skew", base, base + 6, base + 60, at(base), skew, clock.ErrNotYetValid},
		{"nbf far in the future", base, base + 3600, base + 7200, at(base), skew, clock.ErrNotYetValid},
		{"nbf in the past", base, base - 3600, base + 60, at(base), skew, nil},
		{"nbf vs fractional now, equal bound", base, base + 5, base + 60, subsecond, skew, nil},
		{"nbf vs fractional now, past bound", base, base + 6, base + 60, subsecond, skew, clock.ErrNotYetValid},

		// iat <= now + skew
		{"iat equals now+skew", base + 5, base, base + 60, at(base), skew, nil},
		{"iat one second past now+skew", base + 6, base, base + 60, at(base), skew, clock.ErrIssuedInFuture},
		{"iat far in the future", base + 3600, base, base + 7200, at(base), skew, clock.ErrIssuedInFuture},
		{"iat vs fractional now, equal bound", base + 5, base, base + 60, subsecond, skew, nil},
		{"iat vs fractional now, past bound", base + 6, base, base + 60, subsecond, skew, clock.ErrIssuedInFuture},

		// now < exp, with no grace period
		{"exp one second after now", base - 10, base - 10, base + 1, at(base), skew, nil},
		{"exp equals now", base - 10, base - 10, base, at(base), skew, clock.ErrExpired},
		{"exp one second before now", base - 10, base - 10, base - 1, at(base), skew, clock.ErrExpired},
		{"exp within skew of now gets no grace", base - 10, base - 10, base - 5, at(base), skew, clock.ErrExpired},
		{"exp long past", base - 7200, base - 7200, base - 3600, at(base), skew, clock.ErrExpired},
		{"fractional now before exp", base - 10, base - 10, base + 1, subsecond, skew, nil},
		{"fractional now past exp", base - 10, base - 10, base, subsecond, skew, clock.ErrExpired},

		// tighter skew is allowed
		{"zero skew, nbf equals now", base, base, base + 60, at(base), 0, nil},
		{"zero skew, nbf one second ahead", base, base + 1, base + 60, at(base), 0, clock.ErrNotYetValid},
		{"zero skew, iat one second ahead", base + 1, base, base + 60, at(base), 0, clock.ErrIssuedInFuture},
		{"2s skew, nbf equals now+2", base, base + 2, base + 60, at(base), 2 * time.Second, nil},
		{"2s skew, nbf at now+3", base, base + 3, base + 60, at(base), 2 * time.Second, clock.ErrNotYetValid},

		// claims outside the core integer range 0..2^53-1 are rejected
		{"iat negative", -1, base, base + 60, at(base), skew, clock.ErrTimestamp},
		{"nbf negative", base, -1, base + 60, at(base), skew, clock.ErrTimestamp},
		{"exp negative", base, base, -1, at(base), skew, clock.ErrTimestamp},
		{"iat above 2^53-1", 1 << 53, base, base + 60, at(base), skew, clock.ErrTimestamp},
		{"nbf above 2^53-1", base, 1 << 53, base + 60, at(base), skew, clock.ErrTimestamp},
		{"exp above 2^53-1", base, base, 1 << 53, at(base), skew, clock.ErrTimestamp},
		{"nbf int64 max must not wrap into the past", base, math.MaxInt64, base + 60, at(base), skew, clock.ErrTimestamp},
		{"exp int64 max", base, base, math.MaxInt64, at(base), skew, clock.ErrTimestamp},
		{"claims at the epoch are in range", 0, 0, 1, at(0), skew, nil},
		{"all claims at 2^53-1", 1<<53 - 1, 1<<53 - 1, 1<<53 - 1, at(1<<53 - 1), skew, clock.ErrExpired},
		{"exp at 2^53-1 is still ahead", 1<<53 - 3, 1<<53 - 3, 1<<53 - 1, at(1<<53 - 2), skew, nil},

		// skew above the baseline or negative is rejected
		{"skew one nanosecond over baseline", base, base, base + 60, at(base), skew + 1, clock.ErrSkew},
		{"skew 6s", base, base, base + 60, at(base), 6 * time.Second, clock.ErrSkew},
		{"negative skew", base, base, base + 60, at(base), -time.Second, clock.ErrSkew},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := clock.CheckWindow(tc.iat, tc.nbf, tc.exp, tc.now, tc.skew)
			assertIs(t, err, tc.want)
		})
	}
}

func TestCheckWindowErrorsAreDistinct(t *testing.T) {
	all := []error{clock.ErrNotYetValid, clock.ErrIssuedInFuture, clock.ErrExpired, clock.ErrSkew, clock.ErrTimestamp}
	cases := []struct {
		name          string
		iat, nbf, exp int64
		want          error
	}{
		{"nbf", base, base + 100, base + 200, clock.ErrNotYetValid},
		{"iat", base + 100, base, base + 200, clock.ErrIssuedInFuture},
		{"exp", base - 10, base - 10, base - 1, clock.ErrExpired},
	}
	for _, tc := range cases {
		err := clock.CheckWindow(tc.iat, tc.nbf, tc.exp, at(base), clock.BaselineSkew)
		for _, e := range all {
			if got, want := errors.Is(err, e), e == tc.want; got != want {
				t.Errorf("%s: errors.Is(%v, %v) = %v, want %v", tc.name, err, e, got, want)
			}
		}
	}
}

func TestMaxLifetime(t *testing.T) {
	tests := []struct {
		a    clock.Artifact
		want time.Duration
	}{
		{clock.Presentation, 60 * time.Second},
		{clock.Contract, 60 * time.Second},
		{clock.Evidence, time.Hour},
		{clock.Snapshot, 300 * time.Second},
		{clock.Outcome, 300 * time.Second},
		{clock.Profile, 24 * time.Hour},
	}
	for _, tc := range tests {
		got, err := clock.MaxLifetime(tc.a)
		if err != nil || got != tc.want {
			t.Errorf("MaxLifetime(%v) = %v, %v; want %v", tc.a, got, err, tc.want)
		}
	}
	if _, err := clock.MaxLifetime(clock.Artifact(0)); !errors.Is(err, clock.ErrUnknownArtifact) {
		t.Errorf("MaxLifetime(zero) error = %v, want ErrUnknownArtifact", err)
	}
	if _, err := clock.MaxLifetime(clock.Artifact(99)); !errors.Is(err, clock.ErrUnknownArtifact) {
		t.Errorf("MaxLifetime(99) error = %v, want ErrUnknownArtifact", err)
	}
}

func TestCheckLifetime(t *testing.T) {
	limits := []struct {
		a   clock.Artifact
		max int64
	}{
		{clock.Presentation, 60},
		{clock.Contract, 60},
		{clock.Evidence, 3600},
		{clock.Snapshot, 300},
		{clock.Outcome, 300},
		{clock.Profile, 86400},
	}
	const iat = 1_700_000_000
	for _, l := range limits {
		t.Run(l.a.String(), func(t *testing.T) {
			assertIs(t, clock.CheckLifetime(l.a, iat, iat+l.max), nil)
			assertIs(t, clock.CheckLifetime(l.a, iat, iat+l.max+1), clock.ErrLifetime)
			assertIs(t, clock.CheckLifetime(l.a, iat, iat+l.max-1), nil)
			assertIs(t, clock.CheckLifetime(l.a, iat, iat+1), nil)
			// A.2: iat < exp, so an empty or negative lifetime is malformed.
			assertIs(t, clock.CheckLifetime(l.a, iat, iat), clock.ErrLifetime)
			assertIs(t, clock.CheckLifetime(l.a, iat, iat-1), clock.ErrLifetime)
		})
	}

	t.Run("unknown artifact", func(t *testing.T) {
		assertIs(t, clock.CheckLifetime(clock.Artifact(0), iat, iat+1), clock.ErrUnknownArtifact)
	})
	t.Run("range extremes do not wrap", func(t *testing.T) {
		assertIs(t, clock.CheckLifetime(clock.Profile, math.MinInt64, math.MaxInt64), clock.ErrLifetime)
		assertIs(t, clock.CheckLifetime(clock.Profile, -1, math.MaxInt64), clock.ErrLifetime)
		assertIs(t, clock.CheckLifetime(clock.Presentation, 0, math.MaxInt64), clock.ErrLifetime)
	})
	t.Run("largest core integers", func(t *testing.T) {
		const top = 1<<53 - 1
		assertIs(t, clock.CheckLifetime(clock.Presentation, top-60, top), nil)
		assertIs(t, clock.CheckLifetime(clock.Presentation, top-61, top), clock.ErrLifetime)
	})
}

func TestCheckPresentationAge(t *testing.T) {
	tests := []struct {
		name string
		iat  int64
		now  time.Time
		want error
	}{
		{"age 0", base, at(base), nil},
		{"age 60 equals the bound", base - 60, at(base), nil},
		{"age 61", base - 61, at(base), clock.ErrTooOld},
		{"age 60s + 1ns", base - 60, time.Unix(base, 1), clock.ErrTooOld},
		{"age 60s - 1ns", base - 60, time.Unix(base-1, 999_999_999), nil},
		{"issued in the future is not too old", base + 5, at(base), nil},
		{"long ago", base - 86400, at(base), clock.ErrTooOld},
		{"iat at the epoch", 0, at(0), nil},
		{"negative iat", -1, at(base), clock.ErrTimestamp},
		{"iat above 2^53-1", 1 << 53, at(base), clock.ErrTimestamp},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assertIs(t, clock.CheckPresentationAge(tc.iat, tc.now), tc.want)
		})
	}
}

func TestCheckPresentation(t *testing.T) {
	const skew = clock.BaselineSkew
	tests := []struct {
		name          string
		iat, nbf, exp int64
		now           time.Time
		want          error
	}{
		{"fresh presentation", base - 10, base - 10, base + 50, at(base), nil},
		{"issued now, full lifetime", base, base, base + 60, at(base), nil},
		{"issued within skew of the future", base + 5, base + 5, base + 65, at(base), nil},
		{"exp - iat is 61", base - 10, base - 10, base + 51, at(base), clock.ErrLifetime},
		{"exp - iat is 60", base - 10, base - 10, base + 50, at(base), nil},
		{"last second of validity", base - 59, base - 59, base + 1, at(base), nil},
		{"expired", base - 60, base - 60, base, at(base), clock.ErrExpired},
		{"iat too far ahead", base + 6, base, base + 66, at(base), clock.ErrIssuedInFuture},
		{"nbf too far ahead", base, base + 6, base + 60, at(base), clock.ErrNotYetValid},
		{"expiry before issue", base + 4, base, base + 2, at(base), clock.ErrLifetime},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assertIs(t, clock.CheckPresentation(tc.iat, tc.nbf, tc.exp, tc.now, skew), tc.want)
		})
	}

	t.Run("skew is validated", func(t *testing.T) {
		err := clock.CheckPresentation(base, base, base+60, at(base), 6*time.Second)
		assertIs(t, err, clock.ErrSkew)
	})
	t.Run("tighter skew applies", func(t *testing.T) {
		err := clock.CheckPresentation(base+3, base, base+63, at(base), 2*time.Second)
		assertIs(t, err, clock.ErrIssuedInFuture)
	})
}

func TestReplayRetention(t *testing.T) {
	const iat = 1_700_000_000
	tests := []struct {
		name string
		exp  int64
		skew time.Duration
		want time.Time
	}{
		{"60s presentation, baseline skew", iat + 60, clock.BaselineSkew, at(iat + 65)},
		{"short presentation is held for iat+60+skew", iat + 10, clock.BaselineSkew, at(iat + 65)},
		{"exp equals iat+60+skew", iat + 65, clock.BaselineSkew, at(iat + 65)},
		{"exp one second past iat+60+skew", iat + 66, clock.BaselineSkew, at(iat + 66)},
		{"expiry later than the window", iat + 600, clock.BaselineSkew, at(iat + 600)},
		{"zero skew", iat + 60, 0, at(iat + 60)},
		{"2s skew", iat + 30, 2 * time.Second, at(iat + 62)},
		{"fractional skew", iat + 30, 1500 * time.Millisecond, time.Unix(iat+61, 500_000_000)},
		{"negative skew counts as zero", iat + 30, -time.Second, at(iat + 60)},
		{"exp before iat", iat - 5, clock.BaselineSkew, at(iat + 65)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := clock.ReplayRetention(tc.exp, iat, tc.skew); !got.Equal(tc.want) {
				t.Fatalf("ReplayRetention(%d, %d, %v) = %v, want %v", tc.exp, int64(iat), tc.skew, got, tc.want)
			}
		})
	}

	t.Run("out-of-range claims never shorten retention", func(t *testing.T) {
		const top = 1<<53 - 1
		got := clock.ReplayRetention(math.MaxInt64, math.MaxInt64, clock.BaselineSkew)
		if want := at(top + 65); !got.Equal(want) {
			t.Fatalf("int64 max: got %v, want %v", got, want)
		}
	})
	t.Run("an out-of-range expiry is clamped, not wrapped", func(t *testing.T) {
		const top = 1<<53 - 1
		got := clock.ReplayRetention(math.MaxInt64, base, clock.BaselineSkew)
		if want := at(top); !got.Equal(want) {
			t.Fatalf("exp int64 max: got %v, want %v", got, want)
		}
		got = clock.ReplayRetention(math.MinInt64, base, clock.BaselineSkew)
		if want := at(base + 65); !got.Equal(want) {
			t.Fatalf("exp int64 min: got %v, want %v", got, want)
		}
	})
	t.Run("largest core integers do not wrap", func(t *testing.T) {
		const top = 1<<53 - 1
		got := clock.ReplayRetention(top, top-30, clock.BaselineSkew)
		if want := at(top - 30 + 65); !got.Equal(want) {
			t.Fatalf("got %v, want %v", got, want)
		}
		if got := clock.ReplayRetention(top-100, top, clock.BaselineSkew); !got.Equal(at(top + 65)) {
			t.Fatalf("iat near the top: got %v, want %v", got, at(top+65))
		}
	})
}

func assertIs(t *testing.T, got, want error) {
	t.Helper()
	switch {
	case want == nil && got != nil:
		t.Fatalf("unexpected error: %v", got)
	case want != nil && !errors.Is(got, want):
		t.Fatalf("got %v, want %v", got, want)
	}
}
