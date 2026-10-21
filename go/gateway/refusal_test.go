package gateway

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/core"
	"hop.top/pact-go/validator"
)

// TestRefusalCodes: the code and HTTP status with which an enforcing route
// refuses a request after an authenticated evaluation follow from the
// sealed receipt (draft 13.4): a FAIL reason of the table for INADMISSIBLE,
// otherwise INVALID_CLAIM; for DEFERRED, REQUIREMENTS_CHANGED for a stale
// contract, an UNKNOWN reason of the table, otherwise DEPENDENCY_UNAVAILABLE;
// EXPIRED for an evaluation past its deadline (draft 11.4, 12.2, 17.3.1).
func TestRefusalCodes(t *testing.T) {
	check := func(result core.CheckStatus, reason string) core.CheckResult {
		return core.CheckResult{CheckID: "check-" + strings.ToLower(reason), Result: result, ReasonCode: reason}
	}
	fail := func(reason string) core.CheckResult { return check(core.CheckFail, reason) }
	unknown := func(reason string) core.CheckResult { return check(core.CheckUnknown, reason) }
	pass := check(core.CheckPass, "REQUIREMENT_SATISFIED")
	cases := []struct {
		name     string
		decision core.Decision
		terminal core.TerminalReason
		checks   []core.CheckResult
		code     adapter.Code
		status   int
	}{
		{"inadmissible, reason outside the table", core.DecisionInadmissible, core.TerminalCompleted,
			[]core.CheckResult{pass, fail("APPROVAL_REJECTED")}, "INVALID_CLAIM", http.StatusForbidden},
		{"inadmissible, every approval reason outside the table", core.DecisionInadmissible, core.TerminalCompleted,
			[]core.CheckResult{fail("APPROVAL_EXPIRED"), fail("APPROVAL_REVOKED"), fail("APPROVAL_AUTHORITY_MISMATCH"), fail("APPROVAL_SCOPE_MISMATCH")}, "INVALID_CLAIM", http.StatusForbidden},
		{"inadmissible, first reason of the table", core.DecisionInadmissible, core.TerminalCompleted,
			[]core.CheckResult{pass, fail("APPROVAL_EXPIRED"), fail("STALE_EVIDENCE"), fail("CONTEXT_MISMATCH")}, "STALE_EVIDENCE", http.StatusForbidden},
		{"inadmissible, a stale contract is not the reason", core.DecisionInadmissible, core.TerminalCompleted,
			[]core.CheckResult{fail("REQUIREMENTS_CHANGED"), fail("APPROVAL_REVOKED")}, "INVALID_CLAIM", http.StatusForbidden},
		{"inadmissible, an unknown result is not the reason", core.DecisionInadmissible, core.TerminalCompleted,
			[]core.CheckResult{unknown("UNSUPPORTED_PURPOSE"), fail("APPROVAL_SCOPE_MISMATCH")}, "INVALID_CLAIM", http.StatusForbidden},
		{"deferred, reason outside the table", core.DecisionDeferred, core.TerminalCompleted,
			[]core.CheckResult{pass, unknown("APPROVAL_PENDING")}, "DEPENDENCY_UNAVAILABLE", http.StatusServiceUnavailable},
		{"deferred, not evaluated", core.DecisionDeferred, core.TerminalCancelled,
			[]core.CheckResult{unknown("NOT_EVALUATED")}, "DEPENDENCY_UNAVAILABLE", http.StatusServiceUnavailable},
		{"deferred, first unknown reason of the table", core.DecisionDeferred, core.TerminalCompleted,
			[]core.CheckResult{unknown("APPROVAL_PENDING"), unknown("UNSUPPORTED_PURPOSE"), unknown("DEPENDENCY_UNAVAILABLE")}, "UNSUPPORTED_PURPOSE", http.StatusUnprocessableEntity},
		{"deferred, selection input changed", core.DecisionDeferred, core.TerminalCompleted,
			[]core.CheckResult{unknown("DEPENDENCY_UNAVAILABLE"), fail("SELECTION_INPUT_CHANGED")}, "REQUIREMENTS_CHANGED", http.StatusConflict},
		{"deferred, inactive contract", core.DecisionDeferred, core.TerminalCompleted,
			[]core.CheckResult{fail("REQUIREMENTS_CHANGED")}, "REQUIREMENTS_CHANGED", http.StatusConflict},
		{"deferred, evaluation deadline", core.DecisionDeferred, core.TerminalExpired,
			[]core.CheckResult{unknown("NOT_EVALUATED")}, "EXPIRED", http.StatusGone},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := core.AdmissionAttestation{Decision: c.decision, TerminalReason: c.terminal, Checks: c.checks}
			code := refusal(a)
			if code != c.code {
				t.Fatalf("code %s, want %s", code, c.code)
			}
			rec := httptest.NewRecorder()
			refuse(rec, code, nil)
			if rec.Code != c.status {
				t.Fatalf("status %d, want %d", rec.Code, c.status)
			}
		})
	}
}

// TestAdmissionHeaderSize: PACT-Admission carries the compact receipt only up
// to the deployment limit, 8192 bytes by default; a longer receipt is
// omitted, never truncated, and a negative limit sends none (draft 13.2).
func TestAdmissionHeaderSize(t *testing.T) {
	if DefaultAdmissionHeaderBytes != 8192 {
		t.Fatalf("default limit %d, want 8192 (8 KiB)", DefaultAdmissionHeaderBytes)
	}
	for _, c := range []struct {
		limit, size int
		sent        bool
	}{
		{0, 8192, true},
		{0, 8193, false},
		{100, 100, true},
		{100, 101, false},
		{16384, 16384, true},
		{-1, 10, false},
	} {
		g := &gateway{cfg: Config{AdmissionHeaderBytes: c.limit}}
		rec := httptest.NewRecorder()
		receipt := strings.Repeat("a", c.size)
		g.attach(rec, validator.Result{Receipt: receipt})
		got, present := rec.Header()[http.CanonicalHeaderKey(HeaderAdmission)]
		switch {
		case c.sent && (len(got) != 1 || got[0] != receipt):
			t.Errorf("limit %d, receipt of %d bytes: PACT-Admission not sent whole", c.limit, c.size)
		case !c.sent && present:
			t.Errorf("limit %d, receipt of %d bytes: PACT-Admission sent (%d bytes)", c.limit, c.size, len(got[0]))
		}
	}
}
