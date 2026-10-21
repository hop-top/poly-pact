<?php

declare(strict_types=1);

namespace HopTop\Pact\Tests\Core\StrictJson;

/** The inner struct of the Go test: {"n": int64}. */
final readonly class Inner
{
    public const array MEMBERS = [
        'n' => ['kind' => 'integer', 'items' => null, 'required' => true, 'nullable' => false, 'ref' => null, 'enum' => null],
    ];

    public function __construct(public int $n = 0) {}
}
