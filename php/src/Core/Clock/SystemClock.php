<?php

declare(strict_types=1);

namespace HopTop\Pact\Core\Clock;

/** The Clock of the host. */
final class SystemClock implements Clock
{
    /** The current wall-clock time in UTC. */
    public function now(): \DateTimeImmutable
    {
        return new \DateTimeImmutable('now', new \DateTimeZone('UTC'));
    }
}
