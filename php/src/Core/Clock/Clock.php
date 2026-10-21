<?php

declare(strict_types=1);

namespace HopTop\Pact\Core\Clock;

/** A source of the current time (Go clock.Clock). */
interface Clock
{
    /** The current time, with microsecond precision. */
    public function now(): \DateTimeImmutable;
}
