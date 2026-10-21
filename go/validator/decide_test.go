package validator

import (
	"errors"
	"testing"

	"hop.top/pact-go/core"
)

func results(rs ...string) []core.CheckResult {
	out := make([]core.CheckResult, 0, len(rs)/2)
	for i := 0; i+1 < len(rs); i += 2 {
		out = append(out, core.CheckResult{CheckID: "c", Result: core.CheckStatus(rs[i]), ReasonCode: rs[i+1]})
	}
	return out
}

// TestDecide pins the decision table of draft 11.4 and 12.2.
func TestDecide(t *testing.T) {
	const ok, sat = "PASS", "REQUIREMENT_SATISFIED"
	cases := []struct {
		name     string
		checks   []core.CheckResult
		terminal core.TerminalReason
		want     core.Decision
	}{
		{"all pass", results(ok, sat, ok, sat), core.TerminalCompleted, core.DecisionAdmissible},
		{"not applicable counts toward admissible (A.2)", results(ok, sat, "NOT_APPLICABLE", "POLICY"), core.TerminalCompleted, core.DecisionAdmissible},
		{"unknown defers, never admits", results(ok, sat, "UNKNOWN", "DEPENDENCY_UNAVAILABLE"), core.TerminalCompleted, core.DecisionDeferred},
		{"not evaluated defers", results(ok, sat, "UNKNOWN", "NOT_EVALUATED"), core.TerminalCompleted, core.DecisionDeferred},
		{"fail is inadmissible", results(ok, sat, "FAIL", "INVALID_CLAIM"), core.TerminalCompleted, core.DecisionInadmissible},
		{"fail and unknown is inadmissible (11.4)", results("UNKNOWN", "DEPENDENCY_UNAVAILABLE", "FAIL", "MISSING_FIELD"), core.TerminalCompleted, core.DecisionInadmissible},
		{"selection input changed defers", results(ok, sat, "FAIL", "SELECTION_INPUT_CHANGED"), core.TerminalCompleted, core.DecisionDeferred},
		{"requirements changed defers", results(ok, sat, "FAIL", "REQUIREMENTS_CHANGED"), core.TerminalCompleted, core.DecisionDeferred},
		{"stale contract beside a demonstrated fail is inadmissible", results("FAIL", "SELECTION_INPUT_CHANGED", "FAIL", "SECURITY_HOLD"), core.TerminalCompleted, core.DecisionInadmissible},
		{"undefined result defers", results(ok, sat, "MAYBE", sat), core.TerminalCompleted, core.DecisionDeferred},
		{"no results never admits", nil, core.TerminalCompleted, core.DecisionDeferred},
		{"cancelled is deferred (12.2)", results(ok, sat), core.TerminalCancelled, core.DecisionDeferred},
		{"expired is deferred even with a fail (12.2)", results("FAIL", "INVALID_CLAIM"), core.TerminalExpired, core.DecisionDeferred},
	}
	for _, c := range cases {
		if got := Decide(c.checks, c.terminal); got != c.want {
			t.Errorf("%s: Decide = %s, want %s", c.name, got, c.want)
		}
	}
}

// TestNext pins the transition table of draft 12.2: every row, and no
// transition out of a terminal state.
func TestNext(t *testing.T) {
	rows := []struct {
		from State
		on   Event
		to   State
	}{
		{StateContractIssued, EventPresented, StateEvaluating},
		{StateContractIssued, EventContractExp, StateExpired},
		{StateEvaluating, EventPassed, StateSealedAdmissible},
		{StateEvaluating, EventFailed, StateSealedInadmissible},
		{StateEvaluating, EventUnavailable, StateSealedDeferred},
		{StateEvaluating, EventCancelled, StateCancelled},
		{StateEvaluating, EventDeadline, StateExpired},
	}
	for _, r := range rows {
		got, err := Next(r.from, r.on)
		if err != nil || got != r.to {
			t.Errorf("Next(%s, %s) = %s, %v; want %s", r.from, r.on, got, err, r.to)
		}
	}
	terminal := []State{StateSealedAdmissible, StateSealedInadmissible, StateSealedDeferred, StateCancelled, StateExpired}
	events := []Event{EventPresented, EventContractExp, EventPassed, EventFailed, EventUnavailable, EventCancelled, EventDeadline}
	for _, s := range terminal {
		if !s.Terminal() {
			t.Errorf("%s is not terminal", s)
		}
		for _, e := range events {
			if got, err := Next(s, e); !errors.Is(err, ErrTransition) || got != s {
				t.Errorf("Next(%s, %s) = %s, %v; a terminal state never changes", s, e, got, err)
			}
		}
	}
	if _, err := Next(StateContractIssued, EventPassed); !errors.Is(err, ErrTransition) {
		t.Errorf("a contract cannot seal before its evaluation: %v", err)
	}
	if StateEvaluating.Terminal() || StateContractIssued.Terminal() {
		t.Error("CONTRACT_ISSUED and EVALUATING are not terminal")
	}
}

// TestMachineSealsOnce: the first terminal transition wins and is immutable.
func TestMachineSealsOnce(t *testing.T) {
	m := newMachine()
	if _, err := m.fire(EventPresented); err != nil {
		t.Fatal(err)
	}
	if s, err := m.fire(EventCancelled); err != nil || s != StateCancelled {
		t.Fatalf("cancel = %s, %v", s, err)
	}
	if s, err := m.fire(EventPassed); err == nil || s != StateCancelled {
		t.Fatalf("a cancelled evaluation was resealed: %s, %v", s, err)
	}
}

func TestSealEvent(t *testing.T) {
	cases := []struct {
		d    core.Decision
		t    core.TerminalReason
		want Event
	}{
		{core.DecisionAdmissible, core.TerminalCompleted, EventPassed},
		{core.DecisionInadmissible, core.TerminalCompleted, EventFailed},
		{core.DecisionDeferred, core.TerminalCompleted, EventUnavailable},
		{core.DecisionDeferred, core.TerminalCancelled, EventCancelled},
		{core.DecisionDeferred, core.TerminalExpired, EventDeadline},
	}
	for _, c := range cases {
		if got := sealEvent(c.d, c.t); got != c.want {
			t.Errorf("sealEvent(%s, %s) = %s, want %s", c.d, c.t, got, c.want)
		}
	}
}
