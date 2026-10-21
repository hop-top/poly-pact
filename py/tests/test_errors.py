"""The exception hierarchy: one PactError subclass per Go error family."""

from __future__ import annotations

import hop_top_pact
from hop_top_pact import core
from hop_top_pact.core import clock, limits
from hop_top_pact.errors import PactError


def test_pact_error_is_the_root() -> None:
    assert issubclass(PactError, Exception)
    assert hop_top_pact.PactError is PactError
    for cls in (limits.LimitError, clock.ClockError):
        assert issubclass(cls, PactError), cls.__name__
    assert isinstance(limits.LimitError(limits.LimitErrorKind.LIMIT_EXCEEDED), PactError)
    assert isinstance(clock.ClockError(clock.ClockErrorKind.EXPIRED), PactError)


def test_limits_are_reexported_from_core() -> None:
    for name in limits.__all__:
        assert getattr(core, name) is getattr(limits, name), name
        assert name in core.__all__, name
