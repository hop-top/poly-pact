"""The two age limits of a field rule against a NativeClaim.

Mirrors hop.top/pact-go/adapter/freshness. PACT draft sections 8.3, 9.2,
17.2 and 18. A field rule bounds two different ages (section 9.2):

- max_age_seconds bounds the original source observation,
  NativeClaim.observed_at. It is the time the source gave, never an
  intermediary's receipt time;
- status_max_age_seconds bounds the last confirmation that the value is still
  in force, NativeClaim.status_checked_at. Zero requires a check made in this
  evaluation.

The module is one function, evaluate; one type that carries its parameters,
Evaluator; and the guard against re-stamping, Monotonic. evaluate uses the
baseline clock skew. An Evaluator tightens it, says when the evaluation
began, and attaches a Monotonic guard. The freshness profile
(spec/v1.0/profiles/freshness.md) defines the vocabulary, the source classes, and
the check points these rules serve.

Rules
-----

With now the instant of the evaluation, skew the clock skew allowance (at
most core.clock.BASELINE_SKEW, section 7.5), and each limit read as whole
seconds:

- A time later than now+skew is a source clock that runs ahead. The claim
  fails with CLOCK_AHEAD (Appendix A.2: no observation or status-check time
  may be later than now+skew). This outranks every finding but an invalid
  limit, because a time that cannot be true says nothing about age.
- A source that gives no time cannot establish freshness (section 17.2), and
  unknown status is not evidence of validity (section 8.3). The result is
  UNKNOWN with UNSUPPORTED_REQUIREMENT: the requirement is changed by an
  authorized publisher or the exchange is deferred. A time before the epoch
  counts as no time, because it has no wire form.
- An age above its limit fails with STALE_EVIDENCE. The age may equal the
  limit: now-observed_at <= max_age_seconds, the way section 7.5 phrases its
  own bounds. The comparison is exact, to the microsecond, and is not
  rounded in the claim's favour.
- A limit of zero means the time must not precede the start of this
  evaluation (Evaluator.start). The draft defines zero only for
  status_max_age_seconds (section 9.2); this module reads max_age_seconds = 0
  the same way, which fails closed.
- A limit outside 0..2^53-1 cannot come from a valid contract and no source
  can satisfy it. The result is UNKNOWN with UNSUPPORTED_REQUIREMENT.
- With a Monotonic guard, a later observed_at for a source record already
  seen is a re-stamp and fails with RESTAMPED, which is treated as
  STALE_EVIDENCE.

A demonstrable failure outranks a missing time: a claim already known to be
stale is FAIL, not UNKNOWN. After an invalid limit, the order of the
findings is CLOCK_AHEAD, RESTAMPED, STALE_EVIDENCE, then the UNKNOWN
findings: no usable time (UNSUPPORTED_REQUIREMENT) and a guard that cannot
record (DEPENDENCY_UNAVAILABLE).

Calling it
----------

The evaluator does not read a clock. The caller passes now, normally from a
core.clock.Clock, so a test drives it with FakeClock. To honour a zero limit
the caller also gives the instant the evaluation began, taken before any
source was read for it. Without start, the instant now stands in for it,
which suits a caller that reads now immediately before it reads the source.

evaluate reads only the two age limits. A self rule has none (Appendix A.2)
and is not evaluated here. Instants are aware datetimes; they are compared
as integer microseconds since the epoch, so no limit overflows and no
fraction is rounded.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Final, TypeAlias

from hop_top_pact.adapter._errors import Code
from hop_top_pact.adapter._types import NativeClaim
from hop_top_pact.core.clock import BASELINE_SKEW
from hop_top_pact.core.enums import CheckStatus
from hop_top_pact.core.types import FieldRule

__all__ = ["Evaluator", "Monotonic", "ReasonCode", "Result", "evaluate"]

# The largest value of an age limit: 2^53-1, the core integer range of draft
# section 7.1.
_MAX_LIMIT: Final = (1 << 53) - 1
_EPOCH: Final = datetime(1970, 1, 1, tzinfo=UTC)
_US: Final = 1_000_000
_ONE_US: Final = timedelta(microseconds=1)

Result: TypeAlias = CheckStatus
"""The outcome of a freshness check, the type of CheckResult.result. evaluate
returns PASS, FAIL or UNKNOWN; Monotonic.check can also return NOT_APPLICABLE."""


class ReasonCode(StrEnum):
    """A stable reason code for a freshness result, the value of
    CheckResult.reason_code."""

    SATISFIED = "REQUIREMENT_SATISFIED"
    """Every age is within its limit (section 17.3.1)."""
    STALE_EVIDENCE = "STALE_EVIDENCE"
    """An age is above its limit (section 13.4)."""
    CLOCK_AHEAD = "CLOCK_AHEAD"
    """A source time is later than now plus the clock skew, so the source clock runs
    ahead of the validator's."""
    RESTAMPED = "RESTAMPED"
    """A source record came back with a later observation time than the first one
    seen for it. It is treated as STALE_EVIDENCE."""
    UNSUPPORTED_REQUIREMENT = Code.UNSUPPORTED_REQUIREMENT.value
    """The source gives no usable time, or the rule's limit is not a valid one, so
    the demanded freshness cannot be established (sections 13.4 and 17.2). The
    result is UNKNOWN."""
    DEPENDENCY_UNAVAILABLE = Code.DEPENDENCY_UNAVAILABLE.value
    """The guard cannot record the observation, so the check cannot be completed now
    (sections 13.4 and 18). The result is UNKNOWN."""

    def treated_as(self) -> ReasonCode:
        """The code whose handling this one shares: RESTAMPED is treated as
        STALE_EVIDENCE, an INADMISSIBLE check with the same transport error. Any
        other code is its own."""
        if self is ReasonCode.RESTAMPED:
            return ReasonCode.STALE_EVIDENCE
        return self


def _micros(t: datetime) -> int:
    """t as integer microseconds since the epoch."""
    return (t - _EPOCH) // _ONE_US


def _usable(t: datetime | None) -> int | None:
    """t in microseconds when it is a time a source gave and the wire can carry,
    else None: None means none, and a time before the epoch has no wire form."""
    if t is None or t < _EPOCH:
        return None
    return _micros(t)


def _valid_limit(n: int) -> bool:
    return 0 <= n <= _MAX_LIMIT


def _too_old(t: int, now: int, start: int, limit: int) -> bool:
    """Whether t is older than limit seconds at now, all in microseconds. A limit
    of zero asks for a time not before start. A positive limit is compared as
    whole seconds plus the microsecond remainder, so a fractional now is not
    rounded."""
    if limit == 0:
        return t < start
    now_s, now_us = divmod(now, _US)
    t_s, t_us = divmod(t, _US)
    whole = now_s - t_s
    if whole != limit:
        return whole > limit
    return now_us > t_us


@dataclass(frozen=True, slots=True, kw_only=True)
class Evaluator:
    """The parameters of a freshness evaluation. The default is valid: no skew
    allowance, an evaluation that began at now, and no guard.

    skew is the clock skew allowance (section 7.5); a value above BASELINE_SKEW
    counts as the baseline and a negative one as zero, so the evaluator is never
    more lenient than the baseline (evaluate uses the baseline). start is the
    instant this evaluation began, taken before any source was read for it; a
    limit of zero seconds requires the time not to precede it, and None means
    the instant now of the call. guard, when set, records the observation time
    of each source record and reports a later one as RESTAMPED; one guard serves
    every evaluation that must see the same records.
    """

    skew: timedelta = timedelta(0)
    start: datetime | None = None
    guard: Monotonic | None = None

    def evaluate(
        self, rule: FieldRule, claim: NativeClaim, now: datetime
    ) -> tuple[Result, ReasonCode]:
        """Check claim against rule.max_age_seconds and rule.status_max_age_seconds at
        now. See the module documentation for the rules and their order."""
        if not _valid_limit(rule.max_age_seconds) or not _valid_limit(rule.status_max_age_seconds):
            return CheckStatus.UNKNOWN, ReasonCode.UNSUPPORTED_REQUIREMENT
        skew = min(max(self.skew, timedelta(0)), BASELINE_SKEW)
        now_us = _micros(now)
        start_us = now_us if self.start is None else _micros(self.start)

        observed = _usable(claim.observed_at)
        checked = _usable(claim.status_checked_at)

        # A source clock ahead outranks everything, and an implausible time is
        # never recorded as the baseline of a source record.
        latest = now_us + skew // _ONE_US
        if (observed is not None and observed > latest) or (
            checked is not None and checked > latest
        ):
            return CheckStatus.FAIL, ReasonCode.CLOCK_AHEAD

        guard = CheckStatus.NOT_APPLICABLE
        if self.guard is not None:
            guard, _ = self.guard.check(claim)
        if guard == CheckStatus.FAIL:
            return CheckStatus.FAIL, ReasonCode.RESTAMPED

        if (
            observed is not None and _too_old(observed, now_us, start_us, rule.max_age_seconds)
        ) or (
            checked is not None and _too_old(checked, now_us, start_us, rule.status_max_age_seconds)
        ):
            return CheckStatus.FAIL, ReasonCode.STALE_EVIDENCE

        if observed is None or checked is None:
            return CheckStatus.UNKNOWN, ReasonCode.UNSUPPORTED_REQUIREMENT
        if guard == CheckStatus.UNKNOWN:
            return CheckStatus.UNKNOWN, ReasonCode.DEPENDENCY_UNAVAILABLE
        return CheckStatus.PASS, ReasonCode.SATISFIED


def evaluate(rule: FieldRule, claim: NativeClaim, now: datetime) -> tuple[Result, ReasonCode]:
    """Check claim against the age limits of rule at now, with the baseline clock
    skew, no guard, and an evaluation that began at now: Evaluator.evaluate for
    the common case."""
    return Evaluator(skew=BASELINE_SKEW).evaluate(rule, claim, now)


class Monotonic:
    """The guard against re-stamping.

    The observation time of a source record never changes (draft section 8.3):
    an adapter or an issuer that refreshes a stale upstream fact must not give
    it a new time, and a new observed_at requires a new source_ref. The guard
    remembers the first observation time it sees for each (source_id,
    source_ref) and reports a later one as RESTAMPED.

    The guard compares whole seconds, which is all the wire carries. It keeps
    the lowest time seen for a record, so the baseline never moves up: a
    re-stamped time does not become the new baseline, and an earlier time seen
    later lowers it. A claim seen once, however stale, still sets the baseline,
    which is what stops a refused fact from coming back with a fresh time.

    The store is bounded. At the limit it refuses a record it has not seen and
    returns UNKNOWN with DEPENDENCY_UNAVAILABLE, the deferral sections 7.5 and
    18 require of a full state store, and it never evicts. forget ends the life
    of a record the source has retired. The store is in memory and local to one
    process: a deployment with several replicas that must catch a re-stamp
    across replicas shares the store between them, as it shares replay state
    (section 7.5), or accepts that each replica guards only what it has seen
    itself.

    A Monotonic is safe for concurrent use. Monotonic(limit) records at most
    limit source records; a limit below 1 records none, so every claim with a
    reference is deferred.
    """

    def __init__(self, limit: int) -> None:
        self._lock = threading.Lock()
        self._limit = limit
        self._seen: dict[tuple[str, str], int] = {}

    def check(self, claim: NativeClaim) -> tuple[Result, ReasonCode | None]:
        """Record the observation time of claim for its source record and report
        whether it contradicts an earlier one.

        FAIL with RESTAMPED when the record was seen with an earlier time;
        UNKNOWN with DEPENDENCY_UNAVAILABLE when the record is new and the store
        is full; PASS with SATISFIED otherwise; and NOT_APPLICABLE with no code
        (None) when the claim has no source_ref or no usable observed_at, so
        that there is nothing to compare and no check took place. A caller does
        not record NOT_APPLICABLE as a pass.
        """
        observed = _usable(claim.observed_at)
        if claim.source_ref == "" or observed is None:
            return CheckStatus.NOT_APPLICABLE, None
        key = (claim.source_id, claim.source_ref)
        at = observed // _US
        with self._lock:
            first = self._seen.get(key)
            if first is None and len(self._seen) >= self._limit:
                return CheckStatus.UNKNOWN, ReasonCode.DEPENDENCY_UNAVAILABLE
            if first is not None and at > first:
                return CheckStatus.FAIL, ReasonCode.RESTAMPED
            self._seen[key] = at
            return CheckStatus.PASS, ReasonCode.SATISFIED

    def forget(self, source_id: str, source_ref: str) -> None:
        """Drop the record for (source_id, source_ref), which ends its guard: a later
        sighting is a first one. Call it when the source retires the record, such
        as a token that has expired. It does nothing for a record never seen."""
        with self._lock:
            self._seen.pop((source_id, source_ref), None)

    def len(self) -> int:
        """The number of source records the guard holds."""
        with self._lock:
            return len(self._seen)
