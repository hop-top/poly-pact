package oauth

import (
	"net/http"
	"testing"
	"time"
)

// TestFreshFor: the freshness lifetime of a key-set response, from RFC 9111
// section 4.2.1 (max-age, then Expires minus Date), 4.2.3 and 5.1 (Age),
// 5.2.2.4 and 5.2.2.5 (no-cache, no-store) and 5.3 (Expires). The expected
// values are the RFC's, not the function's.
func TestFreshFor(t *testing.T) {
	recv := time.Date(2026, 10, 19, 13, 0, 0, 0, time.UTC)
	const def, max = 3600 * time.Second, 86400 * time.Second
	hdr := func(kv ...string) http.Header {
		h := http.Header{}
		for i := 0; i < len(kv); i += 2 {
			h.Add(kv[i], kv[i+1])
		}
		return h
	}
	for _, tc := range []struct {
		name string
		h    http.Header
		want time.Duration
	}{
		{"google's own response", hdr("Cache-Control", "public, max-age=20123, must-revalidate, no-transform", "Age", "3"), 20120 * time.Second},
		{"no information is the default", hdr(), def},
		{"max-age", hdr("Cache-Control", "max-age=600"), 600 * time.Second},
		{"directive names are case-insensitive", hdr("Cache-Control", "MAX-AGE=600"), 600 * time.Second},
		{"max-age above the bound", hdr("Cache-Control", "max-age=999999"), max},
		{"max-age overflow", hdr("Cache-Control", "max-age=99999999999999999999"), max},
		{"max-age zero", hdr("Cache-Control", "max-age=0"), 0},
		{"max-age not a number", hdr("Cache-Control", "max-age=soon"), 0},
		{"max-age negative", hdr("Cache-Control", "max-age=-5"), 0},
		{"max-age empty", hdr("Cache-Control", "max-age="), 0},
		{"max-age quoted", hdr("Cache-Control", `max-age="600"`), 0},
		{"max-age twice", hdr("Cache-Control", "max-age=5, max-age=600"), 0},
		{"max-age on two lines", hdr("Cache-Control", "max-age=600", "Cache-Control", "public"), 600 * time.Second},
		{"no-store", hdr("Cache-Control", "no-store, max-age=600"), 0},
		{"no-cache", hdr("Cache-Control", "max-age=600, no-cache"), 0},
		{"no-cache with fields", hdr("Cache-Control", `no-cache="set-cookie", max-age=600`), 0},
		{"s-maxage is for shared caches", hdr("Cache-Control", "s-maxage=10, max-age=600"), 600 * time.Second},
		{"s-maxage alone says nothing here", hdr("Cache-Control", "s-maxage=10"), def},
		{"age is subtracted", hdr("Cache-Control", "max-age=600", "Age", "100"), 500 * time.Second},
		{"age equal to max-age is stale", hdr("Cache-Control", "max-age=600", "Age", "600"), 0},
		{"age above max-age is stale", hdr("Cache-Control", "max-age=600", "Age", "9000"), 0},
		{"invalid age is ignored", hdr("Cache-Control", "max-age=600", "Age", "x"), 600 * time.Second},
		{"negative age is ignored", hdr("Cache-Control", "max-age=600", "Age", "-1"), 600 * time.Second},
		{"age without max-age counts against the default", hdr("Age", "600"), 3000 * time.Second},
		{"expires minus date",
			hdr("Date", "Mon, 19 Oct 2026 13:00:00 GMT", "Expires", "Mon, 19 Oct 2026 13:01:40 GMT"), 100 * time.Second},
		{"expires without date uses the receipt time", hdr("Expires", "Mon, 19 Oct 2026 13:02:00 GMT"), 120 * time.Second},
		{"expires before date", hdr("Date", "Mon, 19 Oct 2026 13:00:00 GMT", "Expires", "Mon, 19 Oct 2026 12:00:00 GMT"), 0},
		{"expires zero is in the past", hdr("Expires", "0"), 0},
		{"expires invalid", hdr("Expires", "tomorrow"), 0},
		{"max-age wins over expires",
			hdr("Cache-Control", "max-age=600", "Date", "Mon, 19 Oct 2026 13:00:00 GMT", "Expires", "Mon, 19 Oct 2026 13:00:10 GMT"), 600 * time.Second},
		{"expires beyond the bound", hdr("Expires", "Wed, 28 Oct 2026 13:00:00 GMT", "Date", "Sun, 18 Oct 2026 13:00:00 GMT"), max},
		{"quoted commas do not split a directive", hdr("Cache-Control", `private="x,max-age=5", max-age=600`), 600 * time.Second},
		{"two expires lines are stale",
			hdr("Expires", "Mon, 19 Oct 2026 13:02:00 GMT", "Expires", "Mon, 19 Oct 2026 14:02:00 GMT"), 0},
	} {
		if got := freshFor(tc.h, recv, def, max); got != tc.want {
			t.Errorf("%s: freshFor = %v, want %v", tc.name, got, tc.want)
		}
	}
}
