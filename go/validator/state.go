package validator

import (
	"errors"
	"fmt"
	"sync"

	"hop.top/pact-go/core"
)

// State is a state of the admission state machine of draft 12.2.
type State string

// The states of draft 12.2. The sealed, cancelled and expired states are
// terminal.
const (
	StateContractIssued     State = "CONTRACT_ISSUED"
	StateEvaluating         State = "EVALUATING"
	StateSealedAdmissible   State = "SEALED_ADMISSIBLE"
	StateSealedInadmissible State = "SEALED_INADMISSIBLE"
	StateSealedDeferred     State = "SEALED_DEFERRED"
	StateCancelled          State = "CANCELLED"
	StateExpired            State = "EXPIRED"
)

// Terminal reports whether s is a terminal state.
func (s State) Terminal() bool {
	switch s {
	case StateSealedAdmissible, StateSealedInadmissible, StateSealedDeferred, StateCancelled, StateExpired:
		return true
	}
	return false
}

// Event is an event of the draft 12.2 table.
type Event string

// The events of draft 12.2, one per row of its table.
const (
	EventPresented   Event = "PRESENTED" // authenticated, valid holder presentation arrives
	EventContractExp Event = "CONTRACT_EXPIRED"
	EventPassed      Event = "PASSED"      // all required checks pass
	EventFailed      Event = "FAILED"      // a required condition demonstrably fails
	EventUnavailable Event = "UNAVAILABLE" // a required dependency or approval is unavailable
	EventCancelled   Event = "CANCELLED"   // requestor cancels through native session control
	EventDeadline    Event = "DEADLINE"    // evaluation deadline or input validity expires
)

// ErrTransition is the error of an event the current state has no row for;
// a terminal state has none, so a sealed result is never changed.
var ErrTransition = errors.New("validator: no transition")

var transitions = map[State]map[Event]State{
	StateContractIssued: {EventPresented: StateEvaluating, EventContractExp: StateExpired},
	StateEvaluating: {
		EventPassed:      StateSealedAdmissible,
		EventFailed:      StateSealedInadmissible,
		EventUnavailable: StateSealedDeferred,
		EventCancelled:   StateCancelled,
		EventDeadline:    StateExpired,
	},
}

// Next returns the state the draft 12.2 table moves s to on e, or an error
// that wraps ErrTransition. Terminal states have no transitions.
func Next(s State, e Event) (State, error) {
	if n, ok := transitions[s][e]; ok {
		return n, nil
	}
	return s, fmt.Errorf("%w from %s on %s", ErrTransition, s, e)
}

// machine is the state of one exchange. Every transition is atomic, and the
// first terminal transition wins: a later one fails.
type machine struct {
	mu    sync.Mutex
	state State
}

func newMachine() *machine { return &machine{state: StateContractIssued} }

func (m *machine) fire(e Event) (State, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n, err := Next(m.state, e)
	if err != nil {
		return m.state, err
	}
	m.state = n
	return n, nil
}

// sealEvent is the event that seals an evaluation with the decision d after
// the terminal reason t.
func sealEvent(d core.Decision, t core.TerminalReason) Event {
	switch {
	case t == core.TerminalCancelled:
		return EventCancelled
	case t == core.TerminalExpired:
		return EventDeadline
	case d == core.DecisionAdmissible:
		return EventPassed
	case d == core.DecisionInadmissible:
		return EventFailed
	}
	return EventUnavailable
}
