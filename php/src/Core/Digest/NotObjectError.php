<?php

declare(strict_types=1);

namespace HopTop\Pact\Core\Digest;

use HopTop\Pact\PactError;

/** objectDigest() was given a value that is not a JSON object (Go: ErrNotObject). */
final class NotObjectError extends PactError
{
    public function __construct()
    {
        parent::__construct('digest: value is not a JSON object');
    }
}
