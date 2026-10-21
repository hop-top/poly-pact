"""Time rules of draft section 7.5 and baseline lifetimes of section 20.1.

Mirrors hop.top/pact-go/core/clock. Protocol timestamps (iat, nbf, exp,
created_at, expires_at) are integer Unix seconds in the range 0..2^53-1. A
validator reads the current time from a Clock, so that tests control it, then
applies:

- check_window: nbf <= now+skew, iat <= now+skew and now < exp, with no grace
  period after exp;
- check_lifetime: the longest span from iat to exp an artifact type may claim;
- check_presentation: the window and lifetime checks plus now-iat <= 60 s for
  an agent presentation;
- replay_retention: how long a replay record must be kept.

The baseline clock skew is BASELINE_SKEW. A deployment may tighten it and
pass the smaller value; a larger one is an error.

Instants are aware datetimes, with microsecond precision where Go has
nanoseconds. The checks compare exactly: now is split once into whole Unix
seconds (floor) and microseconds, and a wire integer is compared against that
pair, so a fractional now is never rounded in the artifact's favour. A wire
value is never turned into a datetime (2^53-1 seconds is far beyond year
9999), so every claim in range is checked against every representable now.
"""

from __future__ import annotations

import threading
from datetime import UTC, datetime, timedelta
from enum import IntEnum, StrEnum
from typing import Final, Protocol

from hop_top_pact.errors import PactError

__all__ = [
    "BASELINE_SKEW",
    "Artifact",
    "Clock",
    "ClockError",
    "ClockErrorKind",
    "FakeClock",
    "SystemClock",
    "check_lifetime",
    "check_presentation",
    "check_presentation_age",
    "check_window",
    "max_lifetime",
    "replay_retention",
]

BASELINE_SKEW: Final = timedelta(seconds=5)
"""The largest clock skew a validator may allow (sections 7.5, 20.1); no expiry grace."""

# The largest value of a core integer field: 2^53-1 (section 7.1).
_MAX_TIMESTAMP: Final = (1 << 53) - 1

# The longest presentation lifetime, and the 60 of the replay retention
# formula of section 7.5.
_PRESENTATION_VALIDITY: Final = 60

_EPOCH: Final = datetime(1970, 1, 1, tzinfo=UTC)
_US: Final = 1_000_000

# The latest aware instant, 9999-12-31T23:59:59.999999Z, and its Unix time in
# microseconds. As a replay retention it means "no expiry".
_LAST: Final = datetime.max.replace(tzinfo=UTC)
_LAST_US: Final = (_LAST - _EPOCH) // timedelta(microseconds=1)


class Clock(Protocol):
    """A source of the current time."""

    def now(self) -> datetime:
        """Return the current time as an aware datetime."""
        ...


class SystemClock:
    """The Clock of the host."""

    def now(self) -> datetime:
        """Return the current wall-clock time in UTC."""
        return datetime.now(UTC)


def _aware(t: datetime) -> datetime:
    if t.tzinfo is None or t.utcoffset() is None:
        raise TypeError(f"clock: naive datetime {t.isoformat()}; want an aware instant")
    return t


class FakeClock:
    """A Clock that only moves when told to. It is safe for concurrent use."""

    def __init__(self, start: datetime) -> None:
        self._lock = threading.Lock()
        self._now = _aware(start)

    def now(self) -> datetime:
        """Return the time the clock was last set to or advanced to."""
        with self._lock:
            return self._now

    def set(self, t: datetime) -> None:
        """Move the clock to t."""
        t = _aware(t)
        with self._lock:
            self._now = t

    def advance(self, d: timedelta) -> None:
        """Move the clock by d, which may be negative."""
        with self._lock:
            self._now = self._now + d


class ClockErrorKind(StrEnum):
    """Why a time check failed: the Go sentinels Err* of the clock package."""

    SKEW = "SKEW"
    """The skew passed to a check is negative or above BASELINE_SKEW."""
    TIMESTAMP = "TIMESTAMP"
    """A timestamp is outside 0..2^53-1."""
    NOT_YET_VALID = "NOT_YET_VALID"
    """nbf is later than now+skew."""
    ISSUED_IN_FUTURE = "ISSUED_IN_FUTURE"
    """iat is later than now+skew."""
    EXPIRED = "EXPIRED"
    """now is at or after exp."""
    LIFETIME = "LIFETIME"
    """exp is not after iat, or exp-iat is longer than the artifact type allows."""
    TOO_OLD = "TOO_OLD"
    """A presentation was issued more than 60 seconds before now."""
    UNKNOWN_ARTIFACT = "UNKNOWN_ARTIFACT"
    """The Artifact value names no artifact type."""


_MESSAGES: Final = {
    ClockErrorKind.SKEW: "clock: skew must be between 0 and 5s",
    ClockErrorKind.TIMESTAMP: "clock: timestamp outside 0..9007199254740991",
    ClockErrorKind.NOT_YET_VALID: "clock: not yet valid (nbf is in the future)",
    ClockErrorKind.ISSUED_IN_FUTURE: (
        "clock: issued in the future (iat is later than now plus skew)"
    ),
    ClockErrorKind.EXPIRED: "clock: expired",
    ClockErrorKind.LIFETIME: "clock: invalid lifetime",
    ClockErrorKind.TOO_OLD: "clock: presentation issued more than 60s ago",
    ClockErrorKind.UNKNOWN_ARTIFACT: "clock: unknown artifact type",
}


class ClockError(PactError):
    """A time check failed for kind; detail names the values compared."""

    def __init__(self, kind: ClockErrorKind, detail: str = "") -> None:
        self.kind = kind
        self.detail = detail
        super().__init__(_MESSAGES[kind] + (f": {detail}" if detail else ""))


class Artifact(IntEnum):
    """An artifact type that section 20.1 gives a lifetime."""

    PRESENTATION = 1
    CONTRACT = 2
    EVIDENCE = 3
    SNAPSHOT = 4
    OUTCOME = 5
    PROFILE = 6

    def __str__(self) -> str:
        return _ARTIFACT_NAMES[self]


_ARTIFACT_NAMES: Final = {
    Artifact.PRESENTATION: "presentation",
    Artifact.CONTRACT: "requirement contract",
    Artifact.EVIDENCE: "evidence",
    Artifact.SNAPSHOT: "reputation snapshot",
    Artifact.OUTCOME: "outcome report",
    Artifact.PROFILE: "profile",
}

# Section 20.1, in whole seconds.
_LIFETIMES: Final = {
    Artifact.PRESENTATION: _PRESENTATION_VALIDITY,
    Artifact.CONTRACT: 60,
    Artifact.EVIDENCE: 3600,
    Artifact.SNAPSHOT: 300,
    Artifact.OUTCOME: 300,
    Artifact.PROFILE: 86400,
}


def _lifetime_seconds(a: Artifact) -> int:
    most = _LIFETIMES.get(a)
    if most is None:
        raise ClockError(ClockErrorKind.UNKNOWN_ARTIFACT, f"Artifact({int(a)})")
    return most


def max_lifetime(a: Artifact) -> timedelta:
    """Return the longest lifetime of an artifact of type a, from iat to exp.

    From created_at to expires_at for a profile. Section 20.1: presentation
    60 s, contract 60 s, evidence 1 h, reputation snapshot 300 s, outcome
    report 300 s, profile 24 h.
    """
    return timedelta(seconds=_lifetime_seconds(a))


def _split(now: datetime) -> tuple[int, int]:
    """Return now as whole Unix seconds (floor) and microseconds, without float arithmetic."""
    d = _aware(now) - _EPOCH
    return d.days * 86400 + d.seconds, d.microseconds


def _skew_us(skew: timedelta) -> int:
    us = skew // timedelta(microseconds=1)
    if us < 0 or us > BASELINE_SKEW // timedelta(microseconds=1):
        raise ClockError(ClockErrorKind.SKEW, f"got {skew}")
    return us


def _check_range(name: str, sec: int) -> None:
    if sec < 0 or sec > _MAX_TIMESTAMP:
        raise ClockError(ClockErrorKind.TIMESTAMP, f"{name} is {sec}")


def check_window(iat: int, nbf: int, exp: int, now: datetime, skew: timedelta) -> None:
    """Apply section 7.5 to an artifact's claims at time now; raise ClockError on failure.

    nbf <= now + skew, iat <= now + skew and now < exp. There is no grace
    period: an artifact whose exp is at or before now is expired, however
    small the skew. skew must lie in 0..BASELINE_SKEW; a deployment that
    tightens the baseline passes its own smaller value. The checks run in the
    order skew, range, nbf, iat, exp, and the first failure is raised.

    For an agent profile call check_window(created_at, created_at, expires_at, ...).
    """
    skew_us = _skew_us(skew)
    for name, sec in (("iat", iat), ("nbf", nbf), ("exp", exp)):
        _check_range(name, sec)
    now_sec, now_us = _split(now)
    # now + skew as whole seconds; a claim is a whole second, so claim <=
    # now + skew exactly when claim <= latest.
    latest = now_sec + (now_us + skew_us) // _US
    if nbf > latest:
        raise ClockError(ClockErrorKind.NOT_YET_VALID, f"nbf {nbf}, now {now_sec}, skew {skew}")
    if iat > latest:
        raise ClockError(ClockErrorKind.ISSUED_IN_FUTURE, f"iat {iat}, now {now_sec}, skew {skew}")
    # now < exp exactly when its whole seconds are below exp.
    if now_sec >= exp:
        raise ClockError(ClockErrorKind.EXPIRED, f"exp {exp}, now {now_sec}")


def check_lifetime(a: Artifact, iat: int, exp: int) -> None:
    """Raise ClockError unless iat < exp (appendix A.2) and exp-iat <= max_lifetime(a).

    It compares the claims alone and does not need the current time.
    """
    most = _lifetime_seconds(a)
    if exp <= iat:
        raise ClockError(ClockErrorKind.LIFETIME, f"{a} exp {exp} is not after iat {iat}")
    if exp - iat > most:
        raise ClockError(ClockErrorKind.LIFETIME, f"{a} lives {exp - iat} s, at most {most} s")


def check_presentation_age(iat: int, now: datetime) -> None:
    """Raise ClockError (TOO_OLD) unless a presentation issued at iat is at most 60 s old at now.

    now - iat <= 60 s (section 7.5). A presentation issued ahead of now is not
    too old; check_window bounds that case.
    """
    _check_range("iat", iat)
    now_sec, now_us = _split(now)
    bound = iat + _PRESENTATION_VALIDITY
    if now_sec > bound or (now_sec == bound and now_us > 0):
        raise ClockError(ClockErrorKind.TOO_OLD, f"iat {iat}, now {now_sec}")


def check_presentation(iat: int, nbf: int, exp: int, now: datetime, skew: timedelta) -> None:
    """Apply every time rule of section 7.5 to an agent presentation.

    check_window, then exp-iat <= 60 s, then now-iat <= 60 s; the first
    failure is raised. Claims that pass the first two checks always pass the
    third (now < exp <= iat+60); it stays so that each rule is enforced by
    name and survives a change to either bound.
    """
    check_window(iat, nbf, exp, now, skew)
    check_lifetime(Artifact.PRESENTATION, iat, exp)
    check_presentation_age(iat, now)


def replay_retention(exp: int, iat: int, skew: timedelta) -> datetime:
    """Return the instant before which a replay record must not be evicted.

    The later of the artifact expiry and iat + 60 s + skew (section 7.5).
    Evicting earlier, even under load, lets a presentation be replayed. A
    negative skew counts as zero. Claims outside 0..2^53-1 are clamped into
    that range, which can only lengthen the retention of a valid claim; such
    claims fail check_window before a record is written.

    A retention past the latest datetime (year 9999), which an aware datetime
    cannot represent, returns datetime.max with tzinfo=UTC: the record is kept
    with no expiry. The result is never earlier than the retention section 7.5
    requires, and no claim raises.
    """
    skew_us = max(skew // timedelta(microseconds=1), 0)
    expiry = min(max(exp, 0), _MAX_TIMESTAMP)
    horizon_sec = min(max(iat, 0), _MAX_TIMESTAMP) + _PRESENTATION_VALIDITY + skew_us // _US
    horizon_us = skew_us % _US
    sec, us = (expiry, 0) if expiry > horizon_sec else (horizon_sec, horizon_us)
    total_us = sec * _US + us
    if total_us > _LAST_US:
        return _LAST
    return _EPOCH + timedelta(microseconds=total_us)
