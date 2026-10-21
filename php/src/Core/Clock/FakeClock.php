<?php

declare(strict_types=1);

namespace HopTop\Pact\Core\Clock;

/**
 * A Clock that only moves when told to (Go clock.Fake). It keeps its
 * instant in UTC. PHP shares no object between threads, so it needs no lock.
 */
final class FakeClock implements Clock
{
    private \DateTimeImmutable $now;

    /** A clock that reads $start until it is moved. */
    public function __construct(\DateTimeInterface $start)
    {
        $this->now = Instant::utc($start);
    }

    /** The time the clock was last set to or advanced to. */
    public function now(): \DateTimeImmutable
    {
        return $this->now;
    }

    /** Move the clock to $t. */
    public function set(\DateTimeInterface $t): void
    {
        $this->now = Instant::utc($t);
    }

    /**
     * Move the clock by $microseconds, which may be negative.
     *
     * @throws \OverflowException when the instant would leave the PHP range
     *                            (PHP_INT_MIN to PHP_INT_MAX seconds), where
     *                            DateTime arithmetic wraps
     */
    public function advance(int $microseconds): void
    {
        [$sec, $us] = Instant::split($this->now);
        $carry = intdiv($us + $microseconds % Clocks::SECOND, Clocks::SECOND);
        $us = ($us + $microseconds % Clocks::SECOND) % Clocks::SECOND;
        if ($us < 0) {
            $us += Clocks::SECOND;
            --$carry;
        }
        $d = intdiv($microseconds, Clocks::SECOND) + $carry;
        if (($d > 0 && $sec > \PHP_INT_MAX - $d) || ($d < 0 && $sec < \PHP_INT_MIN - $d)) {
            throw new \OverflowException('clock: advance leaves the range of DateTimeImmutable');
        }
        $this->now = Instant::of($sec + $d, $us);
    }
}
