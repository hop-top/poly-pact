package azurerm

import (
	"testing"
	"time"
)

// TestRetryAfter: delay-seconds and HTTP-date (RFC 9110 Section 10.2.3);
// anything else is no wait.
func TestRetryAfter(t *testing.T) {
	now := time.Date(1999, 12, 31, 23, 57, 59, 0, time.UTC)
	for v, want := range map[string]time.Duration{
		"":                              0,
		"120":                           120 * time.Second,
		"0":                             0,
		"Fri, 31 Dec 1999 23:59:59 GMT": 2 * time.Minute,
		"Fri, 31 Dec 1999 23:00:00 GMT": 0,
		"-5":                            0,
		"+5":                            0,
		"1.5":                           0,
		"soon":                          0,
	} {
		if got := retryAfter(v, now); got != want {
			t.Errorf("Retry-After %q: %v, want %v", v, got, want)
		}
	}
}
