<?php

declare(strict_types=1);

namespace HopTop\Pact\Core\StrictJson;

/**
 * A token could not be read.
 *
 * @internal
 */
final class Stop extends \Exception
{
    /**
     * @param bool $eof   the input ended inside or before the token
     * @param bool $clean the input ended where a token would begin
     */
    public function __construct(string $detail, public readonly bool $eof = false, public readonly bool $clean = false)
    {
        parent::__construct($detail);
    }
}
