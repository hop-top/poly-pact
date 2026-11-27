"""One check result before it is stamped with its check id and evaluation time."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import Final

from hop_top_pact.core.enums import CheckStatus
from hop_top_pact.validator._decide import REASON_NOT_EVALUATED, REASON_SATISFIED

__all__ = ["Outcome"]

_EPOCH: Final = datetime(1970, 1, 1, tzinfo=UTC)


def unix_of(t: datetime | None) -> int | None:
    """The wire form of a source time: None for no time, which the source does not give."""
    if t is None:
        return None
    return unix(t)


def unix(t: datetime) -> int:
    """Whole Unix seconds of t, rounded down."""
    d = t - _EPOCH
    return d.days * 86400 + d.seconds


@dataclass(slots=True, kw_only=True)
class Outcome:
    result: CheckStatus
    reason: str
    observed: int | None = None
    status: int | None = None
    evidence: list[str] | None = None
    source_id: str = ""
    source_ref: str | None = None

    def at(self, t: datetime | None) -> Outcome:
        """A copy observed and status-checked at t."""
        return replace(self, observed=unix_of(t), status=unix_of(t))


def ok() -> Outcome:
    return Outcome(result=CheckStatus.PASS, reason=REASON_SATISFIED)


def fail(reason: str) -> Outcome:
    return Outcome(result=CheckStatus.FAIL, reason=reason)


def unknown(reason: str) -> Outcome:
    return Outcome(result=CheckStatus.UNKNOWN, reason=reason)


def not_evaluated() -> Outcome:
    return unknown(REASON_NOT_EVALUATED)
