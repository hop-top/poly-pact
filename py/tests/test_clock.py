"""The clocks. Port of go/core/clock/clock_test.go."""

from __future__ import annotations

import threading
from datetime import UTC, datetime, timedelta

import pytest

from hop_top_pact.core import clock

EPOCH = datetime(1970, 1, 1, tzinfo=UTC)

# Both satisfy the Clock protocol (checked by mypy).
_SYSTEM: clock.Clock = clock.SystemClock()
_FAKE: clock.Clock = clock.FakeClock(EPOCH)


def at(sec: int, usec: int = 0) -> datetime:
    return EPOCH + timedelta(seconds=sec, microseconds=usec)


def test_system_clock_tracks_wall_time() -> None:
    before = datetime.now(UTC)
    got = clock.SystemClock().now()
    after = datetime.now(UTC)
    assert got.tzinfo is not None, "SystemClock().now() is naive"
    assert before <= got <= after


def test_fake() -> None:
    start = at(1_000_000)
    f = clock.FakeClock(start)
    assert f.now() == start
    assert f.now() == start, "a fake clock moved on its own"

    f.advance(timedelta(seconds=90))
    assert f.now() == start + timedelta(seconds=90)
    f.advance(timedelta(seconds=-30))
    assert f.now() == start + timedelta(seconds=60)

    reset = at(5, 500)
    f.set(reset)
    assert f.now() == reset


def test_fake_is_safe_for_concurrent_use() -> None:
    f = clock.FakeClock(at(0))

    def work() -> None:
        for _ in range(100):
            f.advance(timedelta(seconds=1))
            f.now()

    threads = [threading.Thread(target=work) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert f.now() == at(800), "an advance was lost"


def test_fake_refuses_a_naive_instant() -> None:
    with pytest.raises(TypeError):
        clock.FakeClock(datetime(2026, 1, 1))
    f = clock.FakeClock(at(0))
    with pytest.raises(TypeError):
        f.set(datetime(2026, 1, 1))
