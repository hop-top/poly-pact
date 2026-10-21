<?php

declare(strict_types=1);

namespace HopTop\Pact\Tests\Core\StrictJson;

/** A target whose constructor takes a parameter MEMBERS does not list. */
final readonly class BadConstructor
{
    public const array MEMBERS = [
        'a' => ['kind' => 'string', 'items' => null, 'required' => true, 'nullable' => false, 'ref' => null, 'enum' => null],
    ];

    public function __construct(public string $a, public string $b) {}
}
