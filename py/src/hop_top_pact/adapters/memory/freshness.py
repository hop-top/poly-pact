"""Freshness, revision pins and source outages of the memory adapter's checks
(Go adapters/memory, freshness.go)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Final

from hop_top_pact.adapter import (
    CheckOutcome,
    DependencyUnavailable,
    NativeClaim,
    Verdict,
)
from hop_top_pact.adapter import freshness as fr
from hop_top_pact.adapters.memory.state import CheckRecord, Sighting
from hop_top_pact.core.clock import BASELINE_SKEW
from hop_top_pact.core.enums import CheckStatus, Comparison, RuleSource
from hop_top_pact.core.types import FieldRule

if TYPE_CHECKING:
    from hop_top_pact.adapters.memory.memory import MemoryAdapter

CODE_REQUIREMENTS_CHANGED: Final = "REQUIREMENTS_CHANGED"
"""The reason code of a version-pinned check whose source reports another
revision than the pinned one: the contract is no longer active (draft 13.4)."""

CODE_APPROVAL_SCOPE_MISMATCH: Final = "APPROVAL_SCOPE_MISMATCH"
"""The reason code of an approval-class check that is installed but whose native
state is for another agent or another principal than the call's (draft
17.3.1: scope mismatch)."""

GUARD_CAPACITY: Final = 4096
"""The number of source records the guard against re-stamping records beyond the
sightings of the state. A guard that is full defers a record it has not seen; it
never evicts."""

EPOCH: Final = datetime(1970, 1, 1, tzinfo=UTC)


def source_time(sec: int | None) -> datetime | None:
    """The instant of a Unix-seconds member of a source record. An absent member is
    None: the source gives none, and the adapter does not make one up."""
    return None if sec is None else EPOCH + timedelta(seconds=sec)


def new_guard(sightings: tuple[Sighting, ...]) -> fr.Monotonic:
    """A guard against re-stamping that holds the sightings. Of two sightings of one
    record the earlier is kept, as the guard keeps the lowest time it sees."""
    g = fr.Monotonic(len(sightings) + GUARD_CAPACITY)
    for s in sightings:
        g.check(
            NativeClaim(
                source_id=s.source_id,
                source_ref=s.source_ref,
                observed_at=source_time(s.observed_at),
            )
        )
    return g


def outage(fn: str, source: str) -> DependencyUnavailable:
    """The error of a read from a source that cannot answer. The adapter keeps no
    copy to fall back on, so the answer is a deferral (draft 18)."""
    return DependencyUnavailable(f"memory: {fn}: source {source!r} cannot answer")


def verdict_of(s: CheckStatus) -> Verdict:
    """The verdict of the same name as s. Anything but PASS and FAIL established
    nothing, so it is UNKNOWN."""
    if s == CheckStatus.PASS:
        return Verdict.PASS
    if s == CheckStatus.FAIL:
        return Verdict.FAIL
    return Verdict.UNKNOWN


def run_check(a: MemoryAdapter, c: CheckRecord) -> CheckOutcome:
    """The outcome of the installed check c. The findings are taken in order, and
    the native verdict of c is reported only when there is none:

    1. the source of c cannot answer: UNKNOWN with DEPENDENCY_UNAVAILABLE;
    2. with freshness limits, the record's two times are evaluated against them
       by the rules of the freshness profile, with the baseline skew and the
       guard against re-stamping, and a result other than PASS is the outcome.
       A time ahead of the clock is not passed on. Without limits, a time the
       adapter cannot pass on defers the check, as it does a claim;
    3. a check pinned to a revision of its source fails with
       REQUIREMENTS_CHANGED when the source reports another one, or none.
    """
    deferred = CheckOutcome(
        result=Verdict.UNKNOWN, reason_code="DEPENDENCY_UNAVAILABLE", source_id=c.source_id
    )
    if a.unavailable(c.source_id):
        return deferred
    observed, checked = source_time(c.observed_at), source_time(c.status_checked_at)
    f = c.freshness
    if f is not None and f.max_age_seconds is not None and f.status_max_age_seconds is not None:
        rule = FieldRule(
            rule_id="",
            path="",
            schema=True,
            source=RuleSource.NATIVE,
            comparison=Comparison.EQUAL,
            allowed_issuers=(),
            native_path=None,
            max_age_seconds=f.max_age_seconds,
            status_max_age_seconds=f.status_max_age_seconds,
        )
        claim = NativeClaim(
            observed_at=observed,
            status_checked_at=checked,
            source_id=c.source_id,
            source_ref=c.source_ref,
        )
        ev = fr.Evaluator(skew=BASELINE_SKEW, guard=a.guard)
        result, code = ev.evaluate(rule, claim, a.clock.now())
        if code == fr.ReasonCode.CLOCK_AHEAD:
            return CheckOutcome(
                result=Verdict.FAIL,
                reason_code=str(code),
                source_id=c.source_id,
                source_ref=c.source_ref,
            )
        if result != CheckStatus.PASS:
            return CheckOutcome(
                result=verdict_of(result),
                reason_code=str(code),
                source_id=c.source_id,
                source_ref=c.source_ref,
                observed_at=observed,
            )
    else:
        try:
            a.check_source_times(observed, checked)
        except DependencyUnavailable:
            return deferred
    if c.pinned_revision and c.revision != c.pinned_revision:
        return CheckOutcome(
            result=Verdict.FAIL,
            reason_code=CODE_REQUIREMENTS_CHANGED,
            source_id=c.source_id,
            source_ref=c.source_ref,
            observed_at=observed,
        )
    return CheckOutcome(
        result=Verdict(c.result),
        reason_code=c.reason_code,
        source_id=c.source_id,
        source_ref=c.source_ref,
        observed_at=observed,
    )


__all__ = [
    "CODE_APPROVAL_SCOPE_MISMATCH",
    "CODE_REQUIREMENTS_CHANGED",
    "new_guard",
    "outage",
    "run_check",
    "source_time",
]
