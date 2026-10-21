<?php

declare(strict_types=1);

namespace HopTop\Pact\Tests\Core\Clock;

/** Test instants from Unix seconds and microseconds. */
final class At
{
    public static function at(int $sec, int $usec = 0): \DateTimeImmutable
    {
        $t = \DateTimeImmutable::createFromFormat('U.u', \sprintf('%d.%06d', $sec, $usec), new \DateTimeZone('UTC'));
        if ($t === false) {
            throw new \LogicException('bad instant');
        }

        return $t->setTimezone(new \DateTimeZone('UTC'));
    }

    /** The microsecond pair of $t, for exact comparison. */
    public static function split(\DateTimeInterface $t): string
    {
        return $t->getTimestamp() . '.' . $t->format('u');
    }
}
