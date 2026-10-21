"""Time windows, lifetimes and replay retention (draft sections 7.5 and 20.1).

Port of go/core/clock/window_test.go. Python instants are aware datetimes
with microsecond precision, so Go's nanosecond cases use one microsecond.
A datetime ends in year 9999, far below 2^53-1 seconds: the cases that put
now at 2^53-1 are replaced by claims at 2^53-1 against now at the base
instant and at the latest datetime, which also proves that a wire value is
never turned into a datetime. A replay retention beyond the latest datetime
is that latest datetime, meaning no expiry, never a shorter instant.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import cast

import pytest

from hop_top_pact.core import clock
from hop_top_pact.core.clock import Artifact, ClockError, ClockErrorKind

EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
BASE = 1_000_000
TOP = 2**53 - 1
INT64_MAX = 2**63 - 1
INT64_MIN = -(2**63)
SKEW = clock.BASELINE_SKEW
S = timedelta(seconds=1)
US = timedelta(microseconds=1)
MS = timedelta(milliseconds=1)

# datetime.max as Unix time: 9999-12-31T23:59:59.999999Z is 253402300799 whole
# seconds and 999999 microseconds after the epoch.
LAST = datetime.max.replace(tzinfo=UTC)
LAST_SEC = 253_402_300_799


def at(sec: int, usec: int = 0) -> datetime:
    return EPOCH + timedelta(seconds=sec, microseconds=usec)


def assert_is(call: Callable[[], object], want: ClockErrorKind | None) -> None:
    if want is None:
        call()
        return
    with pytest.raises(ClockError) as ei:
        call()
    assert ei.value.kind is want, f"got {ei.value.kind}, want {want}"


def test_baseline_skew() -> None:
    assert timedelta(seconds=5) == clock.BASELINE_SKEW


def test_last_datetime_is_last_sec() -> None:
    assert at(LAST_SEC, 999_999) == LAST


SUBSECOND = at(BASE, 999_999)
K = ClockErrorKind

WINDOW: list[tuple[str, int, int, int, datetime, timedelta, ClockErrorKind | None]] = [
    ("inside the window", BASE - 10, BASE - 10, BASE + 50, at(BASE), SKEW, None),
    ("all claims at now", BASE, BASE, BASE + 1, at(BASE), SKEW, None),
    # nbf <= now + skew
    ("nbf equals now+skew", BASE, BASE + 5, BASE + 60, at(BASE), SKEW, None),
    ("nbf one second past now+skew", BASE, BASE + 6, BASE + 60, at(BASE), SKEW, K.NOT_YET_VALID),
    ("nbf far in the future", BASE, BASE + 3600, BASE + 7200, at(BASE), SKEW, K.NOT_YET_VALID),
    ("nbf in the past", BASE, BASE - 3600, BASE + 60, at(BASE), SKEW, None),
    ("nbf vs fractional now, equal bound", BASE, BASE + 5, BASE + 60, SUBSECOND, SKEW, None),
    (
        "nbf vs fractional now, past bound",
        BASE,
        BASE + 6,
        BASE + 60,
        SUBSECOND,
        SKEW,
        K.NOT_YET_VALID,
    ),
    # iat <= now + skew
    ("iat equals now+skew", BASE + 5, BASE, BASE + 60, at(BASE), SKEW, None),
    ("iat one second past now+skew", BASE + 6, BASE, BASE + 60, at(BASE), SKEW, K.ISSUED_IN_FUTURE),
    ("iat far in the future", BASE + 3600, BASE, BASE + 7200, at(BASE), SKEW, K.ISSUED_IN_FUTURE),
    ("iat vs fractional now, equal bound", BASE + 5, BASE, BASE + 60, SUBSECOND, SKEW, None),
    (
        "iat vs fractional now, past bound",
        BASE + 6,
        BASE,
        BASE + 60,
        SUBSECOND,
        SKEW,
        K.ISSUED_IN_FUTURE,
    ),
    # now < exp, with no grace period
    ("exp one second after now", BASE - 10, BASE - 10, BASE + 1, at(BASE), SKEW, None),
    ("exp equals now", BASE - 10, BASE - 10, BASE, at(BASE), SKEW, K.EXPIRED),
    ("exp one second before now", BASE - 10, BASE - 10, BASE - 1, at(BASE), SKEW, K.EXPIRED),
    (
        "exp within skew of now gets no grace",
        BASE - 10,
        BASE - 10,
        BASE - 5,
        at(BASE),
        SKEW,
        K.EXPIRED,
    ),
    ("exp long past", BASE - 7200, BASE - 7200, BASE - 3600, at(BASE), SKEW, K.EXPIRED),
    ("fractional now before exp", BASE - 10, BASE - 10, BASE + 1, SUBSECOND, SKEW, None),
    ("fractional now past exp", BASE - 10, BASE - 10, BASE, SUBSECOND, SKEW, K.EXPIRED),
    (
        "now one microsecond before exp",
        BASE - 10,
        BASE - 10,
        BASE,
        at(BASE - 1, 999_999),
        SKEW,
        None,
    ),
    # tighter skew is allowed
    ("zero skew, nbf equals now", BASE, BASE, BASE + 60, at(BASE), 0 * S, None),
    (
        "zero skew, nbf one second ahead",
        BASE,
        BASE + 1,
        BASE + 60,
        at(BASE),
        0 * S,
        K.NOT_YET_VALID,
    ),
    (
        "zero skew, iat one second ahead",
        BASE + 1,
        BASE,
        BASE + 60,
        at(BASE),
        0 * S,
        K.ISSUED_IN_FUTURE,
    ),
    ("2s skew, nbf equals now+2", BASE, BASE + 2, BASE + 60, at(BASE), 2 * S, None),
    ("2s skew, nbf at now+3", BASE, BASE + 3, BASE + 60, at(BASE), 2 * S, K.NOT_YET_VALID),
    # a fractional now plus a fractional skew carries into the next second
    (
        "now+0.6s, skew 1.5s, nbf at now+2",
        BASE,
        BASE + 2,
        BASE + 60,
        at(BASE, 600_000),
        1500 * MS,
        None,
    ),
    (
        "now+0.4s, skew 1.5s, nbf at now+2",
        BASE,
        BASE + 2,
        BASE + 60,
        at(BASE, 400_000),
        1500 * MS,
        K.NOT_YET_VALID,
    ),
    # claims outside the core integer range 0..2^53-1 are rejected
    ("iat negative", -1, BASE, BASE + 60, at(BASE), SKEW, K.TIMESTAMP),
    ("nbf negative", BASE, -1, BASE + 60, at(BASE), SKEW, K.TIMESTAMP),
    ("exp negative", BASE, BASE, -1, at(BASE), SKEW, K.TIMESTAMP),
    ("iat above 2^53-1", 2**53, BASE, BASE + 60, at(BASE), SKEW, K.TIMESTAMP),
    ("nbf above 2^53-1", BASE, 2**53, BASE + 60, at(BASE), SKEW, K.TIMESTAMP),
    ("exp above 2^53-1", BASE, BASE, 2**53, at(BASE), SKEW, K.TIMESTAMP),
    (
        "nbf int64 max must not wrap into the past",
        BASE,
        INT64_MAX,
        BASE + 60,
        at(BASE),
        SKEW,
        K.TIMESTAMP,
    ),
    ("exp int64 max", BASE, BASE, INT64_MAX, at(BASE), SKEW, K.TIMESTAMP),
    ("claims at the epoch are in range", 0, 0, 1, at(0), SKEW, None),
    # exp = 2^53-1 is in range and ahead of every datetime
    ("exp at 2^53-1 is still ahead", BASE, BASE, TOP, at(BASE), SKEW, None),
    ("exp at 2^53-1, now at the last datetime", LAST_SEC, LAST_SEC, TOP, LAST, SKEW, None),
    ("nbf at 2^53-1 is in the future", BASE, TOP, TOP, at(BASE), SKEW, K.NOT_YET_VALID),
    ("all claims at 2^53-1, now at the last datetime", TOP, TOP, TOP, LAST, SKEW, K.NOT_YET_VALID),
    # now + skew beyond the last datetime is still compared exactly
    ("nbf at the last datetime plus skew", BASE, LAST_SEC + 5, TOP, LAST, SKEW, None),
    (
        "nbf one second past the last datetime plus skew",
        BASE,
        LAST_SEC + 6,
        TOP,
        LAST,
        SKEW,
        K.NOT_YET_VALID,
    ),
    (
        "exp at the last second, now at the last datetime",
        BASE,
        BASE,
        LAST_SEC,
        LAST,
        SKEW,
        K.EXPIRED,
    ),
    ("exp one second after the last datetime", BASE, BASE, LAST_SEC + 1, LAST, SKEW, None),
    # skew above the baseline or negative is rejected
    ("skew one microsecond over baseline", BASE, BASE, BASE + 60, at(BASE), SKEW + US, K.SKEW),
    ("skew 6s", BASE, BASE, BASE + 60, at(BASE), 6 * S, K.SKEW),
    ("negative skew", BASE, BASE, BASE + 60, at(BASE), -S, K.SKEW),
    ("negative skew of one microsecond", BASE, BASE, BASE + 60, at(BASE), -US, K.SKEW),
]


@pytest.mark.parametrize(
    ("name", "iat", "nbf", "exp", "now", "skew", "want"), WINDOW, ids=[c[0] for c in WINDOW]
)
def test_check_window(
    name: str,
    iat: int,
    nbf: int,
    exp: int,
    now: datetime,
    skew: timedelta,
    want: ClockErrorKind | None,
) -> None:
    assert_is(lambda: clock.check_window(iat, nbf, exp, now, skew), want)


def test_check_window_refuses_a_naive_now() -> None:
    with pytest.raises(TypeError):
        clock.check_window(BASE, BASE, BASE + 60, datetime(2026, 1, 1), SKEW)


def test_check_window_errors_are_distinct() -> None:
    every = [K.NOT_YET_VALID, K.ISSUED_IN_FUTURE, K.EXPIRED, K.SKEW, K.TIMESTAMP]
    cases = [
        ("nbf", BASE, BASE + 100, BASE + 200, K.NOT_YET_VALID),
        ("iat", BASE + 100, BASE, BASE + 200, K.ISSUED_IN_FUTURE),
        ("exp", BASE - 10, BASE - 10, BASE - 1, K.EXPIRED),
    ]
    for name, iat, nbf, exp, want in cases:
        with pytest.raises(ClockError) as ei:
            clock.check_window(iat, nbf, exp, at(BASE), SKEW)
        for e in every:
            assert (ei.value.kind is e) == (e is want), (
                f"{name}: kind {ei.value.kind}, checking {e}"
            )


def test_max_lifetime() -> None:
    cases = [
        (Artifact.PRESENTATION, timedelta(seconds=60)),
        (Artifact.CONTRACT, timedelta(seconds=60)),
        (Artifact.EVIDENCE, timedelta(hours=1)),
        (Artifact.SNAPSHOT, timedelta(seconds=300)),
        (Artifact.OUTCOME, timedelta(seconds=300)),
        (Artifact.PROFILE, timedelta(hours=24)),
    ]
    for a, want in cases:
        assert clock.max_lifetime(a) == want, str(a)
    for bad in (0, 99):
        with pytest.raises(ClockError) as ei:
            clock.max_lifetime(cast(Artifact, bad))
        assert ei.value.kind is K.UNKNOWN_ARTIFACT, bad


def test_artifact_names() -> None:
    assert [str(a) for a in Artifact] == [
        "presentation",
        "requirement contract",
        "evidence",
        "reputation snapshot",
        "outcome report",
        "profile",
    ]
    assert [int(a) for a in Artifact] == [1, 2, 3, 4, 5, 6]


LIFETIMES = [
    (Artifact.PRESENTATION, 60),
    (Artifact.CONTRACT, 60),
    (Artifact.EVIDENCE, 3600),
    (Artifact.SNAPSHOT, 300),
    (Artifact.OUTCOME, 300),
    (Artifact.PROFILE, 86400),
]


@pytest.mark.parametrize(("a", "most"), LIFETIMES, ids=[str(a) for a, _ in LIFETIMES])
def test_check_lifetime(a: Artifact, most: int) -> None:
    iat = 1_700_000_000
    assert_is(lambda: clock.check_lifetime(a, iat, iat + most), None)
    assert_is(lambda: clock.check_lifetime(a, iat, iat + most + 1), K.LIFETIME)
    assert_is(lambda: clock.check_lifetime(a, iat, iat + most - 1), None)
    assert_is(lambda: clock.check_lifetime(a, iat, iat + 1), None)
    # A.2: iat < exp, so an empty or negative lifetime is malformed.
    assert_is(lambda: clock.check_lifetime(a, iat, iat), K.LIFETIME)
    assert_is(lambda: clock.check_lifetime(a, iat, iat - 1), K.LIFETIME)


def test_check_lifetime_edges() -> None:
    iat = 1_700_000_000
    # unknown artifact
    assert_is(lambda: clock.check_lifetime(cast(Artifact, 0), iat, iat + 1), K.UNKNOWN_ARTIFACT)
    # range extremes do not wrap
    assert_is(lambda: clock.check_lifetime(Artifact.PROFILE, INT64_MIN, INT64_MAX), K.LIFETIME)
    assert_is(lambda: clock.check_lifetime(Artifact.PROFILE, -1, INT64_MAX), K.LIFETIME)
    assert_is(lambda: clock.check_lifetime(Artifact.PRESENTATION, 0, INT64_MAX), K.LIFETIME)
    # largest core integers
    assert_is(lambda: clock.check_lifetime(Artifact.PRESENTATION, TOP - 60, TOP), None)
    assert_is(lambda: clock.check_lifetime(Artifact.PRESENTATION, TOP - 61, TOP), K.LIFETIME)


AGE: list[tuple[str, int, datetime, ClockErrorKind | None]] = [
    ("age 0", BASE, at(BASE), None),
    ("age 60 equals the bound", BASE - 60, at(BASE), None),
    ("age 61", BASE - 61, at(BASE), K.TOO_OLD),
    ("age 60s + 1us", BASE - 60, at(BASE, 1), K.TOO_OLD),
    ("age 60s - 1us", BASE - 60, at(BASE - 1, 999_999), None),
    ("age 60.5s: a 0.5 s remainder is not rounded away", BASE - 60, at(BASE, 500_000), K.TOO_OLD),
    ("age 59.5s", BASE - 59, at(BASE, 500_000), None),
    ("issued in the future is not too old", BASE + 5, at(BASE), None),
    ("long ago", BASE - 86400, at(BASE), K.TOO_OLD),
    ("iat at the epoch", 0, at(0), None),
    ("iat at 2^53-1 is not too old", TOP, at(BASE), None),
    ("iat at the last second, now at the last datetime", LAST_SEC, LAST, None),
    ("iat 60 s before the last datetime", LAST_SEC - 60, LAST, K.TOO_OLD),
    ("negative iat", -1, at(BASE), K.TIMESTAMP),
    ("iat above 2^53-1", 2**53, at(BASE), K.TIMESTAMP),
]


@pytest.mark.parametrize(("name", "iat", "now", "want"), AGE, ids=[c[0] for c in AGE])
def test_check_presentation_age(
    name: str, iat: int, now: datetime, want: ClockErrorKind | None
) -> None:
    assert_is(lambda: clock.check_presentation_age(iat, now), want)


PRESENTATION: list[tuple[str, int, int, int, datetime, ClockErrorKind | None]] = [
    ("fresh presentation", BASE - 10, BASE - 10, BASE + 50, at(BASE), None),
    ("issued now, full lifetime", BASE, BASE, BASE + 60, at(BASE), None),
    ("issued within skew of the future", BASE + 5, BASE + 5, BASE + 65, at(BASE), None),
    ("exp - iat is 61", BASE - 10, BASE - 10, BASE + 51, at(BASE), K.LIFETIME),
    ("exp - iat is 60", BASE - 10, BASE - 10, BASE + 50, at(BASE), None),
    ("last second of validity", BASE - 59, BASE - 59, BASE + 1, at(BASE), None),
    ("expired", BASE - 60, BASE - 60, BASE, at(BASE), K.EXPIRED),
    ("iat too far ahead", BASE + 6, BASE, BASE + 66, at(BASE), K.ISSUED_IN_FUTURE),
    ("nbf too far ahead", BASE, BASE + 6, BASE + 60, at(BASE), K.NOT_YET_VALID),
    ("expiry before issue", BASE + 4, BASE, BASE + 2, at(BASE), K.LIFETIME),
]


@pytest.mark.parametrize(
    ("name", "iat", "nbf", "exp", "now", "want"), PRESENTATION, ids=[c[0] for c in PRESENTATION]
)
def test_check_presentation(
    name: str, iat: int, nbf: int, exp: int, now: datetime, want: ClockErrorKind | None
) -> None:
    assert_is(lambda: clock.check_presentation(iat, nbf, exp, now, SKEW), want)


def test_check_presentation_skew() -> None:
    # skew is validated
    assert_is(lambda: clock.check_presentation(BASE, BASE, BASE + 60, at(BASE), 6 * S), K.SKEW)
    # tighter skew applies
    assert_is(
        lambda: clock.check_presentation(BASE + 3, BASE, BASE + 63, at(BASE), 2 * S),
        K.ISSUED_IN_FUTURE,
    )


IAT = 1_700_000_000
RETENTION: list[tuple[str, int, timedelta, datetime]] = [
    ("60s presentation, baseline skew", IAT + 60, SKEW, at(IAT + 65)),
    ("short presentation is held for iat+60+skew", IAT + 10, SKEW, at(IAT + 65)),
    ("exp equals iat+60+skew", IAT + 65, SKEW, at(IAT + 65)),
    ("exp one second past iat+60+skew", IAT + 66, SKEW, at(IAT + 66)),
    ("expiry later than the window", IAT + 600, SKEW, at(IAT + 600)),
    ("zero skew", IAT + 60, 0 * S, at(IAT + 60)),
    ("2s skew", IAT + 30, 2 * S, at(IAT + 62)),
    ("fractional skew", IAT + 30, timedelta(milliseconds=1500), at(IAT + 61, 500_000)),
    ("fractional skew past exp", IAT + 61, timedelta(milliseconds=1500), at(IAT + 61, 500_000)),
    ("negative skew counts as zero", IAT + 30, -S, at(IAT + 60)),
    ("exp before iat", IAT - 5, SKEW, at(IAT + 65)),
]


@pytest.mark.parametrize(("name", "exp", "skew", "want"), RETENTION, ids=[c[0] for c in RETENTION])
def test_replay_retention(name: str, exp: int, skew: timedelta, want: datetime) -> None:
    got = clock.replay_retention(exp, IAT, skew)
    assert got == want
    assert got.tzinfo is not None


def test_replay_retention_edges() -> None:
    # Out-of-range claims never shorten retention: past the last datetime the
    # record is kept with no expiry, the last datetime.
    assert clock.replay_retention(INT64_MAX, INT64_MAX, SKEW) == LAST
    # An out-of-range expiry is clamped to 2^53-1, not wrapped.
    assert clock.replay_retention(INT64_MAX, BASE, SKEW) == LAST
    assert clock.replay_retention(INT64_MIN, BASE, SKEW) == at(BASE + 65)
    # The largest core integers do not wrap.
    assert clock.replay_retention(TOP, TOP - 30, SKEW) == LAST
    assert clock.replay_retention(TOP - 100, TOP, SKEW) == LAST
    # The last datetime is still returned exactly.
    assert clock.replay_retention(LAST_SEC, LAST_SEC - 65, SKEW) == at(LAST_SEC)
    assert clock.replay_retention(LAST_SEC, LAST_SEC - 64, SKEW) == LAST


NO_EXPIRY: list[tuple[str, int, int, timedelta]] = [
    ("exp 2^53-1", TOP, BASE, SKEW),
    ("exp 2^53-1, zero skew", TOP, BASE, 0 * S),
    ("iat 2^53-1", BASE, TOP, SKEW),
    ("iat one second past the last datetime", LAST_SEC + 61, LAST_SEC + 1, SKEW),
    ("iat past the last datetime, exp before it", BASE, LAST_SEC + 1, SKEW),
    ("exp one second past the last datetime", LAST_SEC + 1, BASE, SKEW),
    ("horizon one microsecond past the last datetime", BASE, LAST_SEC - 65, SKEW + S),
]


@pytest.mark.parametrize(("name", "exp", "iat", "skew"), NO_EXPIRY, ids=[c[0] for c in NO_EXPIRY])
def test_replay_retention_no_expiry(name: str, exp: int, iat: int, skew: timedelta) -> None:
    # Section 7.5 retention past year 9999 cannot be represented: the record
    # is kept with no expiry, the latest aware instant, and nothing is raised.
    got = clock.replay_retention(exp, iat, skew)
    assert got == datetime.max.replace(tzinfo=UTC)
    assert got.tzinfo is UTC


def true_retention_us(exp: int, iat: int, skew: timedelta) -> int:
    """Section 7.5 in integer microseconds: max(exp, iat + 60 + skew), skew >= 0."""
    skew_us = max(skew // US, 0)
    expiry = min(max(exp, 0), TOP) * 1_000_000
    horizon = (min(max(iat, 0), TOP) + 60) * 1_000_000 + skew_us
    return max(expiry, horizon)


def test_replay_retention_never_earlier() -> None:
    last_us = LAST_SEC * 1_000_000 + 999_999
    claims = [BASE, IAT, LAST_SEC - 600, LAST_SEC - 66, LAST_SEC - 65, LAST_SEC - 64]
    claims += [LAST_SEC - 1, LAST_SEC, LAST_SEC + 1, TOP - 60, TOP]
    skews = [-S, 0 * S, US, 999_999 * US, SKEW, SKEW + 999_999 * US, SKEW + S]
    for exp in claims:
        for iat in claims:
            for skew in skews:
                want = true_retention_us(exp, iat, skew)
                got = clock.replay_retention(exp, iat, skew)
                assert got.tzinfo is not None
                if want <= last_us:
                    assert (got - EPOCH) // US == want, (exp, iat, skew)
                else:
                    assert got == LAST, (exp, iat, skew)
