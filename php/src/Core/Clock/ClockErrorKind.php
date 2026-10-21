<?php

declare(strict_types=1);

namespace HopTop\Pact\Core\Clock;

/** Why a time check failed: the Go sentinels Err* of package clock. */
enum ClockErrorKind: string
{
    /** The skew passed to a check is negative or above Clocks::BASELINE_SKEW. */
    case SKEW = 'SKEW';
    /** A timestamp is outside 0..2^53-1. */
    case TIMESTAMP = 'TIMESTAMP';
    /** nbf is later than now+skew. */
    case NOT_YET_VALID = 'NOT_YET_VALID';
    /** iat is later than now+skew. */
    case ISSUED_IN_FUTURE = 'ISSUED_IN_FUTURE';
    /** now is at or after exp. */
    case EXPIRED = 'EXPIRED';
    /** exp is not after iat, or exp-iat is longer than the artifact type allows. */
    case LIFETIME = 'LIFETIME';
    /** A presentation was issued more than 60 seconds before now. */
    case TOO_OLD = 'TOO_OLD';
    /**
     * The Artifact value names no artifact type. Kept for parity with Go:
     * the Artifact enum admits no such value, so no check throws it.
     */
    case UNKNOWN_ARTIFACT = 'UNKNOWN_ARTIFACT';

    /** The text of the Go sentinel error. */
    public function message(): string
    {
        return match ($this) {
            self::SKEW => 'clock: skew must be between 0 and 5s',
            self::TIMESTAMP => 'clock: timestamp outside 0..9007199254740991',
            self::NOT_YET_VALID => 'clock: not yet valid (nbf is in the future)',
            self::ISSUED_IN_FUTURE => 'clock: issued in the future (iat is later than now plus skew)',
            self::EXPIRED => 'clock: expired',
            self::LIFETIME => 'clock: invalid lifetime',
            self::TOO_OLD => 'clock: presentation issued more than 60s ago',
            self::UNKNOWN_ARTIFACT => 'clock: unknown artifact type',
        };
    }
}
