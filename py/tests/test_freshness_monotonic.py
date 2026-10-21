"""Monotonic, the guard against re-stamping, alone and in the Evaluator.

Port of go/adapter/freshness/monotonic_test.go. The observation time of a
source record never changes (draft 8.3): a later one for the same record is
a re-stamp, and a new time needs a new source_ref.
"""

from __future__ import annotations

import threading
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from hop_top_pact.adapter import NativeClaim
from hop_top_pact.adapter.freshness import Evaluator, Monotonic, ReasonCode, evaluate
from hop_top_pact.core.clock import BASELINE_SKEW
from hop_top_pact.core.enums import CheckStatus, Comparison, RuleSource
from hop_top_pact.core.types import FieldRule

BASE = 1_792_080_000
EPOCH = datetime(1970, 1, 1, tzinfo=UTC)

PASS = (CheckStatus.PASS, ReasonCode.SATISFIED)
STALE = (CheckStatus.FAIL, ReasonCode.STALE_EVIDENCE)
AHEAD = (CheckStatus.FAIL, ReasonCode.CLOCK_AHEAD)
RESTAMPED = (CheckStatus.FAIL, ReasonCode.RESTAMPED)
DEFERRED = (CheckStatus.UNKNOWN, ReasonCode.DEPENDENCY_UNAVAILABLE)
NO_TIME = (CheckStatus.UNKNOWN, ReasonCode.UNSUPPORTED_REQUIREMENT)
BAD_LIMIT = (CheckStatus.UNKNOWN, ReasonCode.UNSUPPORTED_REQUIREMENT)
NOT_APPLICABLE = (CheckStatus.NOT_APPLICABLE, None)


def at(sec: int) -> datetime:
    return EPOCH + timedelta(seconds=sec)


def us(sec: int, micro: int) -> datetime:
    return EPOCH + timedelta(seconds=sec, microseconds=micro)


def rule(max_age: int, status_max_age: int) -> FieldRule:
    return FieldRule(
        rule_id="r",
        path="/attributes/environment/principal_id",
        schema=True,
        source=RuleSource.NATIVE,
        comparison=Comparison.EQUAL,
        allowed_issuers=(),
        native_path=None,
        max_age_seconds=max_age,
        status_max_age_seconds=status_max_age,
    )


def seen(source: str, ref: str, observed: datetime | None) -> NativeClaim:
    """A claim for (source, ref) observed at the given instant."""
    return NativeClaim(
        value="alice",
        observed_at=observed,
        status_checked_at=at(BASE),
        source_id=source,
        source_ref=ref,
    )


Step = tuple[str, NativeClaim, tuple[CheckStatus, ReasonCode | None]]

MONOTONIC: list[tuple[str, list[Step]]] = [
    ("first sighting passes", [("first", seen("dir", "e1", at(100)), PASS)]),
    (
        "the same time again passes",
        [
            ("first", seen("dir", "e1", at(100)), PASS),
            ("again", seen("dir", "e1", at(100)), PASS),
            ("and again", seen("dir", "e1", at(100)), PASS),
        ],
    ),
    (
        "a later time for the same record is a re-stamp",
        [
            ("first", seen("dir", "e1", at(100)), PASS),
            ("later", seen("dir", "e1", at(101)), RESTAMPED),
        ],
    ),
    (
        "a re-stamp does not become the new baseline",
        [
            ("first", seen("dir", "e1", at(100)), PASS),
            ("later", seen("dir", "e1", at(500)), RESTAMPED),
            ("later again", seen("dir", "e1", at(500)), RESTAMPED),
            ("original", seen("dir", "e1", at(100)), PASS),
        ],
    ),
    (
        "an earlier time lowers the baseline",
        [
            ("first", seen("dir", "e1", at(100)), PASS),
            ("earlier", seen("dir", "e1", at(90)), PASS),
            (
                "the first time is now later than the baseline",
                seen("dir", "e1", at(100)),
                RESTAMPED,
            ),
            ("earlier again", seen("dir", "e1", at(90)), PASS),
        ],
    ),
    (
        "a re-stamp is caught however stale the first sighting was",
        [
            ("stale original", seen("dir", "e1", at(BASE - 86400)), PASS),
            ("laundered", seen("dir", "e1", at(BASE)), RESTAMPED),
        ],
    ),
    (
        "records are independent",
        [
            ("e1", seen("dir", "e1", at(100)), PASS),
            ("e2", seen("dir", "e2", at(200)), PASS),
            ("e1 later", seen("dir", "e1", at(101)), RESTAMPED),
            ("e2 same", seen("dir", "e2", at(200)), PASS),
            ("e2 later", seen("dir", "e2", at(201)), RESTAMPED),
        ],
    ),
    (
        "a reference is scoped to its source",
        [
            ("dir", seen("dir", "e1", at(100)), PASS),
            ("idp", seen("idp", "e1", at(300)), PASS),
            ("dir later", seen("dir", "e1", at(101)), RESTAMPED),
            ("idp later", seen("idp", "e1", at(301)), RESTAMPED),
            ("idp same", seen("idp", "e1", at(300)), PASS),
        ],
    ),
    (
        "the wire carries whole seconds",
        [
            ("first", seen("dir", "e1", us(100, 100)), PASS),
            ("same second, later fraction", seen("dir", "e1", us(100, 900_000)), PASS),
            ("next second", seen("dir", "e1", us(101, 0)), RESTAMPED),
            ("same second, earlier fraction", seen("dir", "e1", us(100, 0)), PASS),
        ],
    ),
    (
        "no reference is nothing to compare",
        [
            ("first", seen("dir", "", at(100)), NOT_APPLICABLE),
            ("later", seen("dir", "", at(200)), NOT_APPLICABLE),
        ],
    ),
    (
        "no observation time is nothing to compare",
        [
            ("first", seen("dir", "e1", at(100)), PASS),
            ("none", seen("dir", "e1", None), NOT_APPLICABLE),
            ("later", seen("dir", "e1", at(101)), RESTAMPED),
        ],
    ),
    (
        "a time before the epoch is nothing to compare",
        [
            ("first", seen("dir", "e1", at(100)), PASS),
            ("before the epoch", seen("dir", "e1", at(-5)), NOT_APPLICABLE),
            ("same", seen("dir", "e1", at(100)), PASS),
        ],
    ),
    (
        "a claim with no reference leaves the others alone",
        [
            ("first", seen("dir", "e1", at(100)), PASS),
            ("no ref", seen("dir", "", at(900)), NOT_APPLICABLE),
            ("e1 same", seen("dir", "e1", at(100)), PASS),
        ],
    ),
]


@pytest.mark.parametrize("steps", [m[1] for m in MONOTONIC], ids=[m[0] for m in MONOTONIC])
def test_monotonic_check(steps: list[Step]) -> None:
    m = Monotonic(16)
    for name, c, want in steps:
        assert m.check(c) == want, name


def test_monotonic_capacity() -> None:
    """A full store defers (draft 7.5 and 18: a full or unavailable state store
    causes deferral, never a pass), and never evicts to make room."""
    m = Monotonic(2)
    assert m.check(seen("dir", "e1", at(100))) == PASS
    assert m.check(seen("dir", "e2", at(100))) == PASS
    assert m.len() == 2

    assert m.check(seen("dir", "e3", at(100))) == DEFERRED, "e3 in a full store"
    assert m.len() == 2, "after a refused record"
    # Known records are still guarded, and an old record was not evicted.
    assert m.check(seen("dir", "e1", at(101))) == RESTAMPED
    assert m.check(seen("dir", "e2", at(100))) == PASS

    # forget frees one slot, and only that one.
    m.forget("dir", "e1")
    assert m.len() == 1
    assert m.check(seen("dir", "e3", at(100))) == PASS
    assert m.check(seen("dir", "e1", at(100))) == DEFERRED, "e1 after its slot went"
    m.forget("dir", "never-seen")  # no effect
    m.forget("other", "e2")  # another source: no effect
    assert m.len() == 2


def test_monotonic_forget_starts_the_record_afresh() -> None:
    m = Monotonic(4)
    m.check(seen("dir", "e1", at(100)))
    m.forget("dir", "e1")
    assert m.check(seen("dir", "e1", at(500))) == PASS, "a first sighting after forget"
    assert m.check(seen("dir", "e1", at(501))) == RESTAMPED, "and is then guarded"


@pytest.mark.parametrize("limit", [0, -1])
def test_monotonic_with_no_capacity_defers_every_reference(limit: int) -> None:
    m = Monotonic(limit)
    assert m.check(seen("dir", "e1", at(100))) == DEFERRED
    # A claim the guard cannot compare is not refused for want of room.
    assert m.check(seen("dir", "", at(100)))[0] == CheckStatus.NOT_APPLICABLE


def test_monotonic_is_safe_for_concurrent_use() -> None:
    """Every thread reports the same record at a different time. Whatever the
    interleaving, the lowest time recorded is the baseline, and no time above it
    passes once it is set."""
    m = Monotonic(8)
    barrier = threading.Barrier(16)

    def run(i: int) -> None:
        barrier.wait()
        for _ in range(50):
            m.check(seen("dir", "e1", at(1000 + i)))

    threads = [threading.Thread(target=run, args=(i,)) for i in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert m.check(seen("dir", "e1", at(1000))) == PASS, "lowest time"
    assert m.check(seen("dir", "e1", at(1001))) == RESTAMPED, "a higher time"
    assert m.len() == 1


def guarded(m: Monotonic) -> Evaluator:
    return Evaluator(skew=BASELINE_SKEW, guard=m)


NOW = at(BASE)


def test_evaluator_guard_refreshed_time_is_a_restamp() -> None:
    m = Monotonic(4)
    ev = guarded(m)
    # The source saw the fact 20 s ago.
    assert ev.evaluate(rule(30, 0), seen("dir", "e1", at(BASE - 20)), NOW)[0] == CheckStatus.PASS
    # Ten seconds on, the same record comes back stamped "now", fresh enough on
    # its face. Age alone passes it; the guard does not.
    later = at(BASE + 10)
    relaundered = replace(seen("dir", "e1", later), status_checked_at=later)
    assert ev.evaluate(rule(30, 0), relaundered, later) == RESTAMPED
    assert evaluate(rule(30, 0), relaundered, later) == PASS, "the guard is what catches it"


def test_evaluator_guard_stale_first_sighting_sets_the_baseline() -> None:
    """The stale fact is refused, and then the same record re-stamped as fresh
    must not get through: re-signing never launders an old observation."""
    m = Monotonic(4)
    ev = guarded(m)
    assert ev.evaluate(rule(30, 0), seen("dir", "e1", at(BASE - 3600)), NOW) == STALE
    fresh = replace(seen("dir", "e1", NOW), status_checked_at=NOW)
    assert ev.evaluate(rule(30, 0), fresh, NOW) == RESTAMPED


def test_evaluator_guard_new_reference_is_a_new_observation() -> None:
    m = Monotonic(4)
    ev = guarded(m)
    ev.evaluate(rule(30, 0), seen("dir", "e1", at(BASE - 3600)), NOW)
    fresh = replace(seen("dir", "e2", NOW), status_checked_at=NOW)
    assert ev.evaluate(rule(30, 0), fresh, NOW) == PASS


def test_evaluator_guard_restamp_that_is_also_stale_reports_the_restamp() -> None:
    m = Monotonic(4)
    ev = guarded(m)
    ev.evaluate(rule(30, 0), seen("dir", "e1", at(BASE - 7200)), NOW)
    still_stale = replace(seen("dir", "e1", at(BASE - 3600)), status_checked_at=NOW)
    assert ev.evaluate(rule(30, 0), still_stale, NOW) == RESTAMPED


def test_evaluator_guard_clock_ahead_is_reported_and_not_recorded() -> None:
    """CLOCK_AHEAD outranks RESTAMPED, and an implausible time never becomes a
    baseline."""
    m = Monotonic(4)
    ev = guarded(m)
    assert ev.evaluate(rule(30, 0), seen("dir", "e1", at(BASE + 3600)), NOW) == AHEAD
    assert m.len() == 0
    # A record already seen, then reported ahead of the clock: still CLOCK_AHEAD.
    assert ev.evaluate(rule(30, 0), seen("dir", "e2", at(BASE - 5)), NOW) == PASS
    assert ev.evaluate(rule(30, 0), seen("dir", "e2", at(BASE + 3600)), NOW) == AHEAD
    assert m.check(seen("dir", "e2", at(BASE - 5))) == PASS, "the baseline did not move"


def test_evaluator_guard_full_store_defers_a_passing_claim() -> None:
    ev = guarded(Monotonic(0))
    fresh = replace(seen("dir", "e1", NOW), status_checked_at=NOW)
    assert ev.evaluate(rule(30, 0), fresh, NOW) == DEFERRED


def test_evaluator_guard_demonstrable_failure_outranks_full_store() -> None:
    ev = guarded(Monotonic(0))
    assert ev.evaluate(rule(30, 0), seen("dir", "e1", at(BASE - 3600)), NOW) == STALE


def test_evaluator_guard_no_reference_passes_on_age_alone() -> None:
    ev = guarded(Monotonic(0))
    fresh = replace(seen("dir", "", NOW), status_checked_at=NOW)
    assert ev.evaluate(rule(30, 0), fresh, NOW) == PASS


def test_evaluator_guard_invalid_rule_is_refused_before_the_guard() -> None:
    m = Monotonic(4)
    assert guarded(m).evaluate(rule(-1, 0), seen("dir", "e1", NOW), NOW) == BAD_LIMIT
    assert m.len() == 0


def test_evaluator_guard_missing_status_time_after_the_guard() -> None:
    m = Monotonic(4)
    c = replace(seen("dir", "e1", NOW), status_checked_at=None)
    assert guarded(m).evaluate(rule(30, 0), c, NOW) == NO_TIME
    assert m.len() == 1, "the observation was plausible and is recorded"


def test_evaluator_guard_across_many_records() -> None:
    m = Monotonic(64)
    ev = guarded(m)
    for i in range(64):
        c = replace(seen("dir", f"e{i}", NOW), status_checked_at=NOW)
        assert ev.evaluate(rule(30, 0), c, NOW) == PASS, i
    later = at(BASE + 1)
    for i in range(64):
        c = replace(seen("dir", f"e{i}", later), status_checked_at=later)
        assert ev.evaluate(rule(30, 0), c, later) == RESTAMPED, i
