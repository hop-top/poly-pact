<?php

declare(strict_types=1);

namespace HopTop\Pact\Core;

/** Why a limit check failed (Go: ErrLimitExceeded, ErrLimitsInvalid, ErrNilObject). */
enum LimitErrorKind: string
{
    /** An object is larger or has more members than a limit allows. */
    case LIMIT_EXCEEDED = 'LIMIT_EXCEEDED';
    /** A Limits value is not positive or is looser than the baseline. */
    case LIMITS_INVALID = 'LIMITS_INVALID';
    /** A validate method was given null. */
    case NIL_OBJECT = 'NIL_OBJECT';

    /** The text of the Go sentinel error. */
    public function message(): string
    {
        return match ($this) {
            self::LIMIT_EXCEEDED => 'core: limit exceeded',
            self::LIMITS_INVALID => 'core: invalid limits',
            self::NIL_OBJECT => 'core: nil object',
        };
    }
}
