<?php

declare(strict_types=1);

namespace HopTop\Pact\Core\StrictJson;

/**
 * The bounds of one decode: input size in bytes and nesting depth (Go
 * strictjson.Limits). A field that is zero or negative selects its default,
 * StrictJson::DEFAULT_MAX_BYTES or StrictJson::DEFAULT_MAX_DEPTH.
 */
final readonly class Limits
{
    /**
     * @param int $maxBytes the largest input in bytes
     * @param int $maxDepth the deepest nesting of objects and arrays; the
     *                      outermost object or array has depth 1
     */
    public function __construct(
        public int $maxBytes = 0,
        public int $maxDepth = 0,
    ) {}

    /** The byte limit in force: maxBytes, or the default when it is not positive. */
    public function bytes(): int
    {
        return $this->maxBytes > 0 ? $this->maxBytes : StrictJson::DEFAULT_MAX_BYTES;
    }

    /** The depth limit in force: maxDepth, or the default when it is not positive. */
    public function depth(): int
    {
        return $this->maxDepth > 0 ? $this->maxDepth : StrictJson::DEFAULT_MAX_DEPTH;
    }
}
