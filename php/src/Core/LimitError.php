<?php

declare(strict_types=1);

namespace HopTop\Pact\Core;

use HopTop\Pact\PactError;

/**
 * A limit check failed, naming the limit (Go core.LimitError).
 *
 * The message is Go's Error() text, for example "core: limit exceeded:
 * max_json_depth is 17, at most 16".
 */
final class LimitError extends PactError
{
    /**
     * @param string $key    the section 20.1 metadata key of the limit, such as "max_json_depth"
     * @param int    $max    what the limit allows: the configured value for LIMIT_EXCEEDED, the
     *                       baseline for LIMITS_INVALID
     * @param int    $got    the offending value: the measured quantity, or the configured limit
     *                       that is out of range
     * @param string $detail for NIL_OBJECT, the missing object
     */
    public function __construct(
        public readonly LimitErrorKind $kind,
        public readonly string $key = '',
        public readonly int $max = 0,
        public readonly int $got = 0,
        public readonly string $detail = '',
    ) {
        parent::__construct(match ($kind) {
            LimitErrorKind::NIL_OBJECT => \sprintf('%s: %s', $kind->message(), $detail),
            LimitErrorKind::LIMITS_INVALID => \sprintf('%s: %s is %d, must be 1..%d', $kind->message(), $key, $got, $max),
            LimitErrorKind::LIMIT_EXCEEDED => \sprintf('%s: %s is %d, at most %d', $kind->message(), $key, $got, $max),
        });
    }
}
