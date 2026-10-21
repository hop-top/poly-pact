<?php

declare(strict_types=1);

namespace HopTop\Pact\Core\Clock;

/**
 * Instants as exact (whole Unix seconds, microseconds) pairs, without float
 * arithmetic.
 *
 * @internal
 */
final class Instant
{
    /**
     * $t as whole Unix seconds (floor) and microseconds 0..999999.
     *
     * @return array{int, int}
     */
    public static function split(\DateTimeInterface $t): array
    {
        return [$t->getTimestamp(), (int) $t->format('u')];
    }

    /** The UTC instant $sec seconds and $us microseconds (0..999999) after the epoch. */
    public static function of(int $sec, int $us): \DateTimeImmutable
    {
        $t = \DateTimeImmutable::createFromFormat('U.u', \sprintf('%d.%06d', $sec, $us));
        if ($t === false) {
            throw new \LogicException(\sprintf('clock: no instant %d.%06d', $sec, $us));
        }

        return $t->setTimezone(new \DateTimeZone('UTC'));
    }

    /** $t as an immutable UTC instant. */
    public static function utc(\DateTimeInterface $t): \DateTimeImmutable
    {
        return \DateTimeImmutable::createFromInterface($t)->setTimezone(new \DateTimeZone('UTC'));
    }
}
