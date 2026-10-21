<?php

declare(strict_types=1);

namespace HopTop\Pact\Tests\Core\Clock;

use HopTop\Pact\Core\Clock\Clock;
use HopTop\Pact\Core\Clock\Clocks;
use HopTop\Pact\Core\Clock\FakeClock;
use HopTop\Pact\Core\Clock\SystemClock;
use PHPUnit\Framework\TestCase;

/**
 * The clocks. Port of go/core/clock/clock_test.go and the Python port's
 * test_clock.py. PHP has no threads, so Go's concurrency test has no
 * counterpart; durations are integer microseconds.
 */
final class ClockTest extends TestCase
{
    public function testSystemClockTracksWallTime(): void
    {
        $c = new SystemClock();
        self::assertInstanceOf(Clock::class, $c);
        $before = new \DateTimeImmutable('now');
        $got = $c->now();
        $after = new \DateTimeImmutable('now');
        self::assertSame('UTC', $got->getTimezone()->getName());
        self::assertGreaterThanOrEqual($before, $got);
        self::assertLessThanOrEqual($after, $got);
    }

    public function testFake(): void
    {
        $start = At::at(1_000_000);
        $f = new FakeClock($start);
        self::assertInstanceOf(Clock::class, $f);
        self::assertSame(At::split($start), At::split($f->now()));
        self::assertSame(At::split($start), At::split($f->now()), 'a fake clock moved on its own');

        $f->advance(90 * Clocks::SECOND);
        self::assertSame(At::split(At::at(1_000_090)), At::split($f->now()));
        $f->advance(-30 * Clocks::SECOND);
        self::assertSame(At::split(At::at(1_000_060)), At::split($f->now()));
        $f->advance(-1);
        self::assertSame('1000059.999999', At::split($f->now()));
        $f->advance(1_500_001);
        self::assertSame('1000061.500000', At::split($f->now()));

        $reset = At::at(5, 500);
        $f->set($reset);
        self::assertSame('5.000500', At::split($f->now()));
    }

    public function testFakeKeepsTheInstantInUtc(): void
    {
        $paris = new \DateTime('2026-01-01 01:00:00.25', new \DateTimeZone('Europe/Paris'));
        $f = new FakeClock($paris);
        self::assertSame('UTC', $f->now()->getTimezone()->getName());
        self::assertSame('2026-01-01T00:00:00.250000', $f->now()->format('Y-m-d\TH:i:s.u'));
        // The clock holds its own copy: changing the argument does not move it.
        $paris->modify('+1 day');
        self::assertSame(1767225600, $f->now()->getTimestamp());
        $f->set(new \DateTimeImmutable('@-1.5'));
        self::assertSame('-2.500000', At::split($f->now()));
        self::assertSame('UTC', $f->now()->getTimezone()->getName());
    }

    public function testFakeAdvanceRefusesToWrap(): void
    {
        $f = new FakeClock(At::at(\PHP_INT_MAX, 999_998));
        $f->advance(1);
        self::assertSame(\PHP_INT_MAX . '.999999', At::split($f->now()));
        try {
            $f->advance(1);
            self::fail('wrapped');
        } catch (\OverflowException) {
            self::assertSame(\PHP_INT_MAX, $f->now()->getTimestamp());
        }
        $g = new FakeClock(At::at(\PHP_INT_MIN));
        $this->expectException(\OverflowException::class);
        $g->advance(-1);
    }
}
