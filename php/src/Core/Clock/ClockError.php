<?php

declare(strict_types=1);

namespace HopTop\Pact\Core\Clock;

use HopTop\Pact\PactError;

/** A time check failed for $kind; $detail names the values compared. */
final class ClockError extends PactError
{
    public function __construct(
        public readonly ClockErrorKind $kind,
        public readonly string $detail = '',
    ) {
        parent::__construct($kind->message() . ($detail !== '' ? ': ' . $detail : ''));
    }
}
