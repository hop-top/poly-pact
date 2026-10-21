"""The freshness evaluator: the two age limits of a field rule (draft 8.3, 9.2,
17.2, 18).

Port of go/adapter/freshness/freshness_test.go, with the finding order of
the package documentation: an invalid limit, then CLOCK_AHEAD, RESTAMPED,
STALE_EVIDENCE, then the UNKNOWN findings. Instants have microsecond
precision where Go has nanoseconds, so the one-nanosecond rows are
one-microsecond rows; Go's row for an observation beyond 2^53-1 seconds uses
the last instant a datetime holds.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from hop_top_pact.adapter import NativeClaim
from hop_top_pact.adapter import freshness as fr
from hop_top_pact.adapter.freshness import Evaluator, ReasonCode, evaluate
from hop_top_pact.core.clock import BASELINE_SKEW, FakeClock
from hop_top_pact.core.enums import CheckStatus, Comparison, RuleSource
from hop_top_pact.core.types import FieldRule

# The instant every table below measures against: the iat of the worked
# example in Appendix B of the draft.
BASE = 1_792_080_000
EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


def at(sec: int) -> datetime:
    return EPOCH + timedelta(seconds=sec)


def us(sec: int, micro: int) -> datetime:
    return EPOCH + timedelta(seconds=sec, microseconds=micro)


def rule(max_age: int, status_max_age: int) -> FieldRule:
    """An evidence or native field rule with the given age limits. The worked
    contract of Appendix B.4 uses max_age_seconds 30 and status_max_age_seconds 0."""
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


def claim(observed: datetime | None, status: datetime | None) -> NativeClaim:
    return NativeClaim(
        value="alice",
        observed_at=observed,
        status_checked_at=status,
        source_id="directory",
        source_ref="entry-1",
    )


PASS = (CheckStatus.PASS, ReasonCode.SATISFIED)
STALE = (CheckStatus.FAIL, ReasonCode.STALE_EVIDENCE)
AHEAD = (CheckStatus.FAIL, ReasonCode.CLOCK_AHEAD)
NO_TIME = (CheckStatus.UNKNOWN, ReasonCode.UNSUPPORTED_REQUIREMENT)
BAD_LIMIT = (CheckStatus.UNKNOWN, ReasonCode.UNSUPPORTED_REQUIREMENT)

NOW = at(BASE)
LAST = datetime.max.replace(tzinfo=UTC)


def test_baseline_skew_is_the_clock_package_baseline() -> None:
    """Section 7.5 gives 5 seconds; the clock module owns the constant and the
    evaluator takes it from there, so a change reaches both."""
    assert timedelta(seconds=5) == BASELINE_SKEW, "the tables below assume 5 s"


def test_reason_codes() -> None:
    """The spelling of every code is part of the wire contract: it lands in
    CheckResult.reason_code. STALE_EVIDENCE is the section 13.4 code,
    DEPENDENCY_UNAVAILABLE and UNSUPPORTED_REQUIREMENT the 13.4 and 17.1 codes,
    REQUIREMENT_SATISFIED the 17.3.1 code, and CLOCK_AHEAD and RESTAMPED the
    freshness profile's own."""
    want = [
        (ReasonCode.SATISFIED, "REQUIREMENT_SATISFIED"),
        (ReasonCode.STALE_EVIDENCE, "STALE_EVIDENCE"),
        (ReasonCode.CLOCK_AHEAD, "CLOCK_AHEAD"),
        (ReasonCode.RESTAMPED, "RESTAMPED"),
        (ReasonCode.UNSUPPORTED_REQUIREMENT, "UNSUPPORTED_REQUIREMENT"),
        (ReasonCode.DEPENDENCY_UNAVAILABLE, "DEPENDENCY_UNAVAILABLE"),
    ]
    assert [(c, c.value) for c in ReasonCode] == want
    assert ReasonCode.RESTAMPED.treated_as() == ReasonCode.STALE_EVIDENCE
    for c in ReasonCode:
        if c is not ReasonCode.RESTAMPED:
            assert c.treated_as() == c
    assert fr.Result is CheckStatus


EVALUATE: list[tuple[str, FieldRule, NativeClaim, datetime, tuple[CheckStatus, ReasonCode]]] = [
    # max_age_seconds against observed_at: the age may equal the limit and not
    # exceed it (section 7.5 phrases its own bounds as "at most").
    ("observed 10s ago, status now", rule(30, 0), claim(at(BASE - 10), NOW), NOW, PASS),
    ("observed exactly at the limit", rule(30, 0), claim(at(BASE - 30), NOW), NOW, PASS),
    (
        "observed one microsecond past the limit",
        rule(30, 0),
        claim(us(BASE - 31, 999_999), NOW),
        NOW,
        STALE,
    ),
    ("observed one second past the limit", rule(30, 0), claim(at(BASE - 31), NOW), NOW, STALE),
    ("observed long ago", rule(30, 0), claim(at(BASE - 86400), NOW), NOW, STALE),
    ("observed now", rule(30, 0), claim(NOW, NOW), NOW, PASS),
    # status_max_age_seconds against status_checked_at.
    ("status exactly at a 30s limit", rule(30, 30), claim(at(BASE - 5), at(BASE - 30)), NOW, PASS),
    (
        "status one second past a 30s limit",
        rule(30, 30),
        claim(at(BASE - 5), at(BASE - 31)),
        NOW,
        STALE,
    ),
    ("status fresh but observation stale", rule(30, 30), claim(at(BASE - 31), NOW), NOW, STALE),
    ("observation fresh but status stale", rule(30, 30), claim(NOW, at(BASE - 31)), NOW, STALE),
    # A zero status limit means a check in this evaluation: start is now, so
    # the status time must not precede now.
    ("zero status limit, checked at now", rule(30, 0), claim(at(BASE - 5), NOW), NOW, PASS),
    (
        "zero status limit, checked one microsecond ago",
        rule(30, 0),
        claim(at(BASE - 5), us(BASE - 1, 999_999)),
        NOW,
        STALE,
    ),
    (
        "zero status limit, checked one second ago",
        rule(30, 0),
        claim(at(BASE - 5), at(BASE - 1)),
        NOW,
        STALE,
    ),
    (
        "zero status limit, cached status",
        rule(30, 0),
        claim(at(BASE - 5), at(BASE - 25)),
        NOW,
        STALE,
    ),
    (
        "zero status limit, checked within skew ahead",
        rule(30, 0),
        claim(at(BASE - 5), at(BASE + 2)),
        NOW,
        PASS,
    ),
    ("zero observation limit, observed at now", rule(0, 0), claim(NOW, NOW), NOW, PASS),
    (
        "zero observation limit, observed one second ago",
        rule(0, 0),
        claim(at(BASE - 1), NOW),
        NOW,
        STALE,
    ),
    # Fractional now: the comparison is exact, never rounded in the claim's
    # favour (core.clock does the same for window checks).
    (
        "fractional now, age equals limit",
        rule(30, 30),
        claim(us(BASE - 30, 500), us(BASE, 0)),
        us(BASE, 500),
        PASS,
    ),
    (
        "fractional now, age one microsecond over",
        rule(30, 30),
        claim(us(BASE - 30, 499), us(BASE, 0)),
        us(BASE, 500),
        STALE,
    ),
    (
        "fractional now, status one microsecond over",
        rule(30, 30),
        claim(us(BASE, 0), us(BASE - 30, 499)),
        us(BASE, 500),
        STALE,
    ),
    # Source clock ahead: a time later than now+skew is rejected, however fresh
    # it looks (Appendix A.2).
    ("observed at now+skew", rule(30, 0), claim(at(BASE + 5), NOW), NOW, PASS),
    (
        "observed one microsecond past now+skew",
        rule(30, 0),
        claim(us(BASE + 5, 1), NOW),
        NOW,
        AHEAD,
    ),
    ("observed one second past now+skew", rule(30, 0), claim(at(BASE + 6), NOW), NOW, AHEAD),
    ("observed far in the future", rule(30, 0), claim(at(BASE + 3600), NOW), NOW, AHEAD),
    ("status at now+skew", rule(30, 0), claim(NOW, at(BASE + 5)), NOW, PASS),
    ("status one second past now+skew", rule(30, 0), claim(NOW, at(BASE + 6)), NOW, AHEAD),
    ("status far in the future", rule(30, 0), claim(NOW, at(BASE + 3600)), NOW, AHEAD),
    ("observed at the last instant a datetime holds", rule(30, 0), claim(LAST, NOW), NOW, AHEAD),
    # Missing times: a source that gives none cannot establish freshness, and
    # unknown status is not evidence of validity (sections 8.3, 17.2).
    ("no observation time", rule(30, 0), claim(None, NOW), NOW, NO_TIME),
    ("no status time", rule(30, 0), claim(NOW, None), NOW, NO_TIME),
    ("no status time, positive status limit", rule(30, 30), claim(NOW, None), NOW, NO_TIME),
    ("neither time", rule(30, 30), claim(None, None), NOW, NO_TIME),
    (
        "observation before the epoch is no usable time",
        rule(30, 30),
        claim(at(-1), NOW),
        NOW,
        NO_TIME,
    ),
    ("status before the epoch is no usable time", rule(30, 30), claim(NOW, at(-1)), NOW, NO_TIME),
    (
        "observation at the epoch is a time",
        rule((2**31 - 1) * 2, 30),
        claim(at(0), NOW),
        NOW,
        PASS,
    ),
    # A demonstrable failure outranks a missing time, and a source clock ahead
    # outranks staleness.
    ("stale observation, no status time", rule(30, 30), claim(at(BASE - 31), None), NOW, STALE),
    ("observation ahead, no status time", rule(30, 30), claim(at(BASE + 6), None), NOW, AHEAD),
    ("no observation time, stale status", rule(30, 30), claim(None, at(BASE - 31)), NOW, STALE),
    (
        "observation ahead, status stale",
        rule(30, 30),
        claim(at(BASE + 6), at(BASE - 31)),
        NOW,
        AHEAD,
    ),
    (
        "observation stale, status ahead",
        rule(30, 30),
        claim(at(BASE - 31), at(BASE + 6)),
        NOW,
        AHEAD,
    ),
    # The limits are 0..2^53-1 (Appendix A schema); anything else is a rule no
    # source can satisfy.
    ("negative observation limit", rule(-1, 0), claim(NOW, NOW), NOW, BAD_LIMIT),
    ("negative status limit", rule(30, -1), claim(NOW, NOW), NOW, BAD_LIMIT),
    ("observation limit above 2^53-1", rule(1 << 53, 0), claim(NOW, NOW), NOW, BAD_LIMIT),
    ("status limit above 2^53-1", rule(30, 1 << 53), claim(NOW, NOW), NOW, BAD_LIMIT),
    ("observation limit int64 max", rule(2**63 - 1, 0), claim(NOW, NOW), NOW, BAD_LIMIT),
    # A limit as large as the schema allows must not overflow.
    (
        "largest observation limit",
        rule((1 << 53) - 1, 0),
        claim(at(BASE - 86400 * 365), NOW),
        NOW,
        PASS,
    ),
    (
        "largest status limit",
        rule(30, (1 << 53) - 1),
        claim(NOW, at(BASE - 86400 * 365)),
        NOW,
        PASS,
    ),
    (
        "largest limit, claim at the epoch",
        rule((1 << 53) - 1, (1 << 53) - 1),
        claim(at(0), at(0)),
        NOW,
        PASS,
    ),
    (
        "limit of 292 years in seconds, one year old",
        rule(9_223_372_037, 0),
        claim(at(BASE - 86400 * 365), NOW),
        NOW,
        PASS,
    ),
    (
        "limit past 292 years, claim at the epoch",
        rule(9_223_372_037, 9_223_372_037),
        claim(at(0), at(0)),
        NOW,
        PASS,
    ),
]


@pytest.mark.parametrize(
    ("rule_", "got", "now", "want"),
    [row[1:] for row in EVALUATE],
    ids=[row[0] for row in EVALUATE],
)
def test_evaluate(
    rule_: FieldRule, got: NativeClaim, now: datetime, want: tuple[CheckStatus, ReasonCode]
) -> None:
    assert evaluate(rule_, got, now) == want


def test_evaluate_ignores_the_claim_value() -> None:
    """Freshness says nothing about the value; None is JSON null and evaluates
    like any other."""
    c = replace(claim(at(BASE - 1), at(BASE)), value=None)
    assert evaluate(rule(30, 0), c, at(BASE)) == PASS


SKEW = BASELINE_SKEW
EVALUATOR: list[tuple[str, Evaluator, FieldRule, NativeClaim, tuple[CheckStatus, ReasonCode]]] = [
    # Skew may be tightened (section 7.5: deployments MAY tighten).
    ("zero skew, observed at now", Evaluator(), rule(30, 0), claim(NOW, NOW), PASS),
    (
        "zero skew, observed one microsecond ahead",
        Evaluator(),
        rule(30, 0),
        claim(us(BASE, 1), NOW),
        AHEAD,
    ),
    (
        "zero skew, status one microsecond ahead",
        Evaluator(),
        rule(30, 0),
        claim(NOW, us(BASE, 1)),
        AHEAD,
    ),
    (
        "2s skew, observed at now+2s",
        Evaluator(skew=timedelta(seconds=2)),
        rule(30, 0),
        claim(at(BASE + 2), NOW),
        PASS,
    ),
    (
        "2s skew, observed at now+3s",
        Evaluator(skew=timedelta(seconds=2)),
        rule(30, 0),
        claim(at(BASE + 3), NOW),
        AHEAD,
    ),
    ("5s skew is the baseline", Evaluator(skew=SKEW), rule(30, 0), claim(at(BASE + 5), NOW), PASS),
    # Skew above the baseline is not honoured, and a negative skew counts as
    # zero, the way core.clock treats it in replay_retention.
    (
        "6s skew is held to the baseline, at now+5s",
        Evaluator(skew=timedelta(seconds=6)),
        rule(30, 0),
        claim(at(BASE + 5), NOW),
        PASS,
    ),
    (
        "6s skew is held to the baseline, at now+6s",
        Evaluator(skew=timedelta(seconds=6)),
        rule(30, 0),
        claim(at(BASE + 6), NOW),
        AHEAD,
    ),
    (
        "hour skew is held to the baseline",
        Evaluator(skew=timedelta(hours=1)),
        rule(30, 0),
        claim(at(BASE + 3600), NOW),
        AHEAD,
    ),
    (
        "negative skew counts as zero, at now",
        Evaluator(skew=timedelta(seconds=-1)),
        rule(30, 0),
        claim(NOW, NOW),
        PASS,
    ),
    (
        "negative skew counts as zero, one microsecond ahead",
        Evaluator(skew=timedelta(seconds=-1)),
        rule(30, 0),
        claim(us(BASE, 1), NOW),
        AHEAD,
    ),
    # start is when this evaluation began. A zero limit asks for a time not
    # before it, and a positive limit is measured from now regardless.
    (
        "start 10s ago, status 5s ago",
        Evaluator(skew=SKEW, start=at(BASE - 10)),
        rule(30, 0),
        claim(at(BASE - 5), at(BASE - 5)),
        PASS,
    ),
    (
        "start 10s ago, status at start",
        Evaluator(skew=SKEW, start=at(BASE - 10)),
        rule(30, 0),
        claim(at(BASE - 5), at(BASE - 10)),
        PASS,
    ),
    (
        "start 10s ago, status before start",
        Evaluator(skew=SKEW, start=at(BASE - 10)),
        rule(30, 0),
        claim(at(BASE - 5), us(BASE - 11, 999_999)),
        STALE,
    ),
    (
        "start 10s ago, observed before start, zero observation limit",
        Evaluator(skew=SKEW, start=at(BASE - 10)),
        rule(0, 0),
        claim(at(BASE - 11), NOW),
        STALE,
    ),
    (
        "start 100s ago does not loosen a positive status limit",
        Evaluator(skew=SKEW, start=at(BASE - 100)),
        rule(30, 30),
        claim(at(BASE - 5), at(BASE - 31)),
        STALE,
    ),
    (
        "start 100s ago does not loosen a positive observation limit",
        Evaluator(skew=SKEW, start=at(BASE - 100)),
        rule(30, 30),
        claim(at(BASE - 31), NOW),
        STALE,
    ),
    (
        "no start means now",
        Evaluator(skew=SKEW),
        rule(30, 0),
        claim(at(BASE - 5), at(BASE - 1)),
        STALE,
    ),
]


@pytest.mark.parametrize(
    ("ev", "rule_", "got", "want"),
    [row[1:] for row in EVALUATOR],
    ids=[row[0] for row in EVALUATOR],
)
def test_evaluator(
    ev: Evaluator, rule_: FieldRule, got: NativeClaim, want: tuple[CheckStatus, ReasonCode]
) -> None:
    assert ev.evaluate(rule_, got, NOW) == want


def test_evaluator_defaults() -> None:
    """The default Evaluator has no skew allowance, an evaluation that began at
    now, and no guard."""
    ev = Evaluator()
    assert (ev.skew, ev.start, ev.guard) == (timedelta(0), None, None)


def test_evaluate_is_the_baseline_evaluator() -> None:
    cases = [
        claim(NOW, NOW),
        claim(at(BASE - 31), NOW),
        claim(at(BASE + 5), NOW),
        claim(at(BASE + 6), NOW),
        claim(None, NOW),
        claim(NOW, at(BASE - 1)),
    ]
    for i, c in enumerate(cases):
        assert evaluate(rule(30, 0), c, NOW) == Evaluator(skew=SKEW).evaluate(
            rule(30, 0), c, NOW
        ), i


def test_evaluate_with_a_fake_clock() -> None:
    """The evaluator takes the instant as an argument, so a test moves it with the
    fake clock of core.clock and never reads the wall clock."""
    clk = FakeClock(at(BASE))
    c = claim(clk.now(), clk.now())
    assert evaluate(rule(30, 30), c, clk.now()) == PASS, "at issue"
    clk.advance(timedelta(seconds=30))
    assert evaluate(rule(30, 30), c, clk.now()) == PASS, "30 s later"
    clk.advance(timedelta(seconds=1))
    assert evaluate(rule(30, 30), c, clk.now()) == STALE, "31 s later"
    # A validator clock 30 s behind the source puts the claim in the future.
    clk.advance(timedelta(seconds=-61))
    assert evaluate(rule(30, 30), c, clk.now()) == AHEAD, "validator clock 30 s behind"
