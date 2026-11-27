"""The admission state machine of draft 12.2."""

from __future__ import annotations

import threading
from enum import StrEnum
from typing import Final

from hop_top_pact.core.enums import Decision, TerminalReason
from hop_top_pact.validator._errors import ValidatorError, ValidatorErrorKind

__all__ = ["Event", "State", "next"]


class State(StrEnum):
    """A state of the admission state machine of draft 12.2. The sealed, cancelled and
    expired states are terminal."""

    CONTRACT_ISSUED = "CONTRACT_ISSUED"
    EVALUATING = "EVALUATING"
    SEALED_ADMISSIBLE = "SEALED_ADMISSIBLE"
    SEALED_INADMISSIBLE = "SEALED_INADMISSIBLE"
    SEALED_DEFERRED = "SEALED_DEFERRED"
    CANCELLED = "CANCELLED"
    EXPIRED = "EXPIRED"

    def terminal(self) -> bool:
        """Report whether the state is a terminal state."""
        return self in _TERMINAL


_TERMINAL: Final = frozenset(
    {
        State.SEALED_ADMISSIBLE,
        State.SEALED_INADMISSIBLE,
        State.SEALED_DEFERRED,
        State.CANCELLED,
        State.EXPIRED,
    }
)


class Event(StrEnum):
    """An event of the draft 12.2 table, one per row."""

    PRESENTED = "PRESENTED"
    """An authenticated, valid holder presentation arrives."""
    CONTRACT_EXP = "CONTRACT_EXPIRED"
    PASSED = "PASSED"
    """All required checks pass."""
    FAILED = "FAILED"
    """A required condition demonstrably fails."""
    UNAVAILABLE = "UNAVAILABLE"
    """A required dependency or approval is unavailable."""
    CANCELLED = "CANCELLED"
    """The requestor cancels through native session control."""
    DEADLINE = "DEADLINE"
    """The evaluation deadline or an input validity expires."""


_TRANSITIONS: Final = {
    State.CONTRACT_ISSUED: {
        Event.PRESENTED: State.EVALUATING,
        Event.CONTRACT_EXP: State.EXPIRED,
    },
    State.EVALUATING: {
        Event.PASSED: State.SEALED_ADMISSIBLE,
        Event.FAILED: State.SEALED_INADMISSIBLE,
        Event.UNAVAILABLE: State.SEALED_DEFERRED,
        Event.CANCELLED: State.CANCELLED,
        Event.DEADLINE: State.EXPIRED,
    },
}


def next(s: State, e: Event) -> State:
    """Return the state the draft 12.2 table moves s to on e, or raise ValidatorError
    (TRANSITION). Terminal states have no transitions."""
    n = _TRANSITIONS.get(s, {}).get(e)
    if n is None:
        raise ValidatorError(ValidatorErrorKind.TRANSITION, f"from {s} on {e}")
    return n


class Machine:
    """The state of one exchange. Every transition is atomic, and the first terminal
    transition wins: a later one fails."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.state = State.CONTRACT_ISSUED

    def fire(self, e: Event) -> State:
        """Move the machine on e and return the new state; raise ValidatorError (TRANSITION)
        and keep the state when the table has no row."""
        with self._lock:
            self.state = next(self.state, e)
            return self.state


def seal_event(d: Decision, t: TerminalReason) -> Event:
    """The event that seals an evaluation with the decision d after the terminal reason t."""
    if t == TerminalReason.CANCELLED:
        return Event.CANCELLED
    if t == TerminalReason.EXPIRED:
        return Event.DEADLINE
    if d == Decision.ADMISSIBLE:
        return Event.PASSED
    if d == Decision.INADMISSIBLE:
        return Event.FAILED
    return Event.UNAVAILABLE
