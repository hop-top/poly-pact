package freshness_test

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/freshness"
	"hop.top/pact-go/core"
	"hop.top/pact-go/core/clock"
)

// profilePath is the freshness profile relative to this package directory. A
// missing file fails the tests: a skipped drift check would let drift through.
const profilePath = "../../../spec/v1.0/profiles/freshness.md"

func readProfile(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(profilePath)
	if err != nil {
		t.Fatalf("read profile: %v", err)
	}
	return string(b)
}

// section returns the text under the heading line head, up to the next
// heading of the same or a higher level.
func section(t *testing.T, doc, head string) string {
	t.Helper()
	level := strings.IndexByte(head, ' ')
	start := strings.Index(doc, "\n"+head+"\n")
	if start < 0 {
		t.Fatalf("profile has no heading %q", head)
	}
	body := doc[start+len(head)+2:]
	pos := 0
	for _, line := range strings.SplitAfter(body, "\n") {
		if n := len(line) - len(strings.TrimLeft(line, "#")); n >= 1 && n <= level && strings.HasPrefix(line[n:], " ") {
			return body[:pos]
		}
		pos += len(line)
	}
	return body
}

// offset reads a worked-evaluation time: seconds relative to now, or "none".
func offset(t *testing.T, cell string, now time.Time) time.Time {
	t.Helper()
	cell = strings.Trim(cell, "` ")
	if cell == "none" {
		return time.Time{}
	}
	n, err := strconv.Atoi(strings.TrimPrefix(cell, "+"))
	if err != nil {
		t.Fatalf("time cell %q is neither an offset nor none", cell)
	}
	return now.Add(time.Duration(n) * time.Second)
}

func cells(line string) []string {
	parts := strings.Split(strings.Trim(strings.TrimSpace(line), "|"), "|")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

// TestProfileWorkedEvaluations runs every row of the profile's table of
// worked evaluations through Evaluate: the document and the code say the same.
func TestProfileWorkedEvaluations(t *testing.T) {
	table := section(t, readProfile(t), "### 3.3 Worked evaluations")
	now := at(base)
	rows := 0
	row := regexp.MustCompile("^\\| `([-+]?\\d+|none)` \\|")
	for _, line := range strings.Split(table, "\n") {
		if !row.MatchString(line) {
			continue
		}
		c := cells(line)
		if len(c) != 7 {
			t.Fatalf("row %q has %d cells, want 7", line, len(c))
		}
		maxAge, err1 := strconv.ParseInt(c[2], 10, 64)
		statusAge, err2 := strconv.ParseInt(c[3], 10, 64)
		if err1 != nil || err2 != nil {
			t.Fatalf("row %q: limits are not integers", line)
		}
		got := adapter.NativeClaim{
			ObservedAt:      offset(t, c[0], now),
			StatusCheckedAt: offset(t, c[1], now),
		}
		res, code := freshness.Evaluate(rule(maxAge, statusAge), got, now)
		wantRes, wantCode := core.CheckStatus(c[4]), freshness.ReasonCode(strings.Trim(c[5], "`"))
		if res != wantRes || code != wantCode {
			t.Errorf("row %q: Evaluate = %s %s, profile says %s %s", line, res, code, wantRes, wantCode)
		}
		rows++
	}
	if rows < 10 {
		t.Errorf("found %d worked evaluations, want at least 10 (did the table format change?)", rows)
	}
}

// TestProfileReasonCodes pins the results and decisions the profile gives each
// reason code.
func TestProfileReasonCodes(t *testing.T) {
	table := section(t, readProfile(t), "### 3.2 Results and reason codes")
	want := map[freshness.ReasonCode][2]string{
		freshness.Satisfied:              {"PASS", "Contributes to `ADMISSIBLE`"},
		freshness.StaleEvidence:          {"FAIL", "`INADMISSIBLE`"},
		freshness.ClockAhead:             {"FAIL", "`INADMISSIBLE`"},
		freshness.Restamped:              {"FAIL", "`INADMISSIBLE`"},
		freshness.UnsupportedRequirement: {"UNKNOWN", "`DEFERRED`"},
		freshness.DependencyUnavailable:  {"UNKNOWN", "`DEFERRED`"},
	}
	got := map[freshness.ReasonCode][2]string{}
	for _, line := range strings.Split(table, "\n") {
		if !strings.HasPrefix(line, "| `") {
			continue
		}
		c := cells(line)
		if len(c) != 5 {
			t.Fatalf("row %q has %d cells, want 5", line, len(c))
		}
		got[freshness.ReasonCode(strings.Trim(c[0], "`"))] = [2]string{strings.Trim(c[1], "`"), c[2]}
	}
	for code, w := range want {
		if g, ok := got[code]; !ok || g != w {
			t.Errorf("%s: profile has %v (present %v), want %v", code, g, ok, w)
		}
	}
	if len(got) != len(want) {
		t.Errorf("profile lists %d reason codes, the package has %d", len(got), len(want))
	}
}

// TestProfileClockCrossReferences checks that the clock constants the profile
// names carry the values it quotes.
func TestProfileClockCrossReferences(t *testing.T) {
	table := section(t, readProfile(t), "## 8. Reference implementation (informative)")
	re := regexp.MustCompile("^\\| `clock\\.(BaselineSkew|MaxLifetime\\(clock\\.(\\w+)\\))` \\| (\\d+) seconds? \\|")

	want := map[string]time.Duration{"BaselineSkew": clock.BaselineSkew}
	for name, a := range map[string]clock.Artifact{
		"Contract": clock.Contract, "Presentation": clock.Presentation, "Evidence": clock.Evidence,
		"Snapshot": clock.Snapshot, "Outcome": clock.Outcome, "Profile": clock.Profile,
	} {
		d, err := clock.MaxLifetime(a)
		if err != nil {
			t.Fatalf("MaxLifetime(%s): %v", name, err)
		}
		want[name] = d
	}

	seen := map[string]bool{}
	for _, line := range strings.Split(table, "\n") {
		m := re.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		key := m[2]
		if m[1] == "BaselineSkew" {
			key = "BaselineSkew"
		}
		secs, _ := strconv.Atoi(m[3])
		w, ok := want[key]
		if !ok {
			t.Errorf("profile names clock constant %q, which the test does not know", key)
			continue
		}
		if got := time.Duration(secs) * time.Second; got != w {
			t.Errorf("%s: profile says %v, package clock says %v", key, got, w)
		}
		seen[key] = true
	}
	for key := range want {
		if !seen[key] {
			t.Errorf("profile does not cross-reference %s", key)
		}
	}
}
