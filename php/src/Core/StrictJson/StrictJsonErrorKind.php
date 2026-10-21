<?php

declare(strict_types=1);

namespace HopTop\Pact\Core\StrictJson;

/** Why a strict decode failed: the Go sentinels Err* of package strictjson. */
enum StrictJsonErrorKind: string
{
    /** decode was given a target the decoder cannot fill. */
    case TARGET = 'TARGET';
    /** The input is larger than Limits::$maxBytes. */
    case SIZE = 'SIZE';
    /** The input is not JSON. */
    case SYNTAX = 'SYNTAX';
    /** The input is not UTF-8. */
    case INVALID_UTF8 = 'INVALID_UTF8';
    /** A \u escape is a surrogate that is not half of a pair. */
    case LONE_SURROGATE = 'LONE_SURROGATE';
    /** Objects and arrays nest deeper than Limits::$maxDepth. */
    case DEPTH = 'DEPTH';
    /** An object has two members of the same name. */
    case DUPLICATE_KEY = 'DUPLICATE_KEY';
    /** A member name is not a member of the target. */
    case UNKNOWN_FIELD = 'UNKNOWN_FIELD';
    /** A number is NaN or Infinity, or overflows binary64. */
    case NON_FINITE = 'NON_FINITE';
    /** An integer is outside ±(2^53-1), or not a non-negative integer for an integer member. */
    case INTEGER = 'INTEGER';
    /** null where the target cannot hold it. */
    case NULL = 'NULL';
    /** Text follows the JSON value. */
    case TRAILING_DATA = 'TRAILING_DATA';
    /** A value does not fit the target type. */
    case TYPE = 'TYPE';

    /** The text of the Go sentinel error. */
    public function message(): string
    {
        return match ($this) {
            self::TARGET => 'strictjson: target is not a type the decoder can fill',
            self::SIZE => 'strictjson: input too large',
            self::SYNTAX => 'strictjson: invalid JSON',
            self::INVALID_UTF8 => 'strictjson: invalid UTF-8',
            self::LONE_SURROGATE => 'strictjson: unpaired surrogate escape',
            self::DEPTH => 'strictjson: nesting too deep',
            self::DUPLICATE_KEY => 'strictjson: duplicate member name',
            self::UNKNOWN_FIELD => 'strictjson: unknown field',
            self::NON_FINITE => 'strictjson: non-finite number',
            self::INTEGER => 'strictjson: integer out of range or not an integer',
            self::NULL => 'strictjson: null not allowed',
            self::TRAILING_DATA => 'strictjson: data after the JSON value',
            self::TYPE => 'strictjson: value does not fit the target type',
        };
    }
}
