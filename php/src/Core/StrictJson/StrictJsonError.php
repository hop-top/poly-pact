<?php

declare(strict_types=1);

namespace HopTop\Pact\Core\StrictJson;

use HopTop\Pact\PactError;

/**
 * A strict decode refused its input (Go strictjson.Error).
 *
 * The message is Go's Error() text: the kind's message, then ": detail",
 * " at path" and " (offset n)".
 */
final class StrictJsonError extends PactError
{
    /**
     * @param StrictJsonErrorKind $kind   the reason
     * @param string              $path   the RFC 6901 pointer of the offending member, empty for the document root
     * @param int                 $offset the byte offset in the input at which the problem was found;
     *                                    approximate for a TYPE or LONE_SURROGATE finding, which is
     *                                    reported after the whole input was read
     * @param string              $detail specifics, such as the member name
     */
    public function __construct(
        public readonly StrictJsonErrorKind $kind,
        public readonly string $path = '',
        public readonly int $offset = 0,
        public readonly string $detail = '',
        ?\Throwable $previous = null,
    ) {
        $s = $kind->message();
        if ($detail !== '') {
            $s .= ': ' . $detail;
        }
        if ($path !== '') {
            $s .= ' at ' . $path;
        }
        parent::__construct(\sprintf('%s (offset %d)', $s, $offset), 0, $previous);
    }
}
