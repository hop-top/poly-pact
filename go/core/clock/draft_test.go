package clock_test

import (
	"os"
	"regexp"
	"strconv"
	"testing"
	"time"

	"hop.top/pact-go/core/clock"
)

// draftPath is the specification relative to this package directory. A missing
// file fails the tests: a skipped drift check would let drift through.
const draftPath = "../../../spec/v1.0/draft.md"

func readDraft(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(draftPath)
	if err != nil {
		t.Fatalf("read draft: %v", err)
	}
	return string(b)
}

// draftDuration returns the "At most N seconds|hour|hours" value of the Section
// 20.1 baseline-limit row labelled item.
func draftDuration(t *testing.T, draft, item string) time.Duration {
	t.Helper()
	re := regexp.MustCompile(`(?m)^\| ` + regexp.QuoteMeta(item) + ` \| At most (\d+) (second|hour)s?\b`)
	m := re.FindStringSubmatch(draft)
	if m == nil {
		t.Fatalf("draft has no 20.1 row %q of the form \"At most N seconds|hours\"", item)
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		t.Fatalf("row %q: %v", item, err)
	}
	if m[2] == "hour" {
		return time.Duration(n) * time.Hour
	}
	return time.Duration(n) * time.Second
}

// draftKey returns the value cell of the Section 20.1 metadata row for key.
func draftKey(t *testing.T, draft, key string) string {
	t.Helper()
	re := regexp.MustCompile("(?m)^\\| `" + regexp.QuoteMeta(key) + "` \\| ([^|]+?) \\|")
	m := re.FindStringSubmatch(draft)
	if m == nil {
		t.Fatalf("draft has no 20.1 metadata row for %q", key)
	}
	return m[1]
}

func draftSeconds(t *testing.T, draft, key string) time.Duration {
	t.Helper()
	n, err := strconv.Atoi(draftKey(t, draft, key))
	if err != nil {
		t.Fatalf("metadata row %q: %v", key, err)
	}
	return time.Duration(n) * time.Second
}

func TestLifetimesMatchTheDraft(t *testing.T) {
	draft := readDraft(t)
	rows := []struct {
		item string
		a    clock.Artifact
	}{
		{"Contract validity", clock.Contract},
		{"Presentation validity", clock.Presentation},
		{"Profile lifetime", clock.Profile},
		{"Evidence artifact lifetime", clock.Evidence},
		{"Reputation snapshot lifetime", clock.Snapshot},
		{"Outcome report validity", clock.Outcome},
	}
	for _, r := range rows {
		want := draftDuration(t, draft, r.item)
		got, err := clock.MaxLifetime(r.a)
		if err != nil || got != want {
			t.Errorf("%s: MaxLifetime(%v) = %v, %v; draft says %v", r.item, r.a, got, err, want)
		}
	}
}

func TestSkewAndRetentionMatchTheDraft(t *testing.T) {
	draft := readDraft(t)

	if got, want := clock.BaselineSkew, draftDuration(t, draft, "Clock skew"); got != want {
		t.Errorf("BaselineSkew = %v, 20.1 table says %v", got, want)
	}
	if got, want := clock.BaselineSkew, draftSeconds(t, draft, "clock_skew_seconds"); got != want {
		t.Errorf("BaselineSkew = %v, clock_skew_seconds says %v", got, want)
	}
	for key, a := range map[string]clock.Artifact{
		"contract_validity_seconds":     clock.Contract,
		"presentation_validity_seconds": clock.Presentation,
	} {
		want := draftSeconds(t, draft, key)
		if got, _ := clock.MaxLifetime(a); got != want {
			t.Errorf("MaxLifetime(%v) = %v, %s says %v", a, got, key, want)
		}
	}

	// replay_retention_seconds is "At least 65": iat+60+skew with the baseline
	// skew, for a presentation that lives its full 60 seconds.
	cell := draftKey(t, draft, "replay_retention_seconds")
	m := regexp.MustCompile(`^At least (\d+)$`).FindStringSubmatch(cell)
	if m == nil {
		t.Fatalf("replay_retention_seconds cell %q is not \"At least N\"", cell)
	}
	min, _ := strconv.Atoi(m[1])
	const iat = 1_700_000_000
	got := clock.ReplayRetention(iat+60, iat, clock.BaselineSkew).Sub(time.Unix(iat, 0))
	if want := time.Duration(min) * time.Second; got != want {
		t.Errorf("baseline replay retention = %v, 20.1 says at least %v", got, want)
	}

	// 7.5 states the same formula in prose.
	if !regexp.MustCompile("later of the artifact expiry and `iat \\+ 60 \\+ clock_skew`").MatchString(draft) {
		t.Error("draft 7.5 no longer states the replay retention formula; revisit ReplayRetention")
	}
}
