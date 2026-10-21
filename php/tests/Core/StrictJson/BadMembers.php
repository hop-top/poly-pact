<?php

declare(strict_types=1);

namespace HopTop\Pact\Tests\Core\StrictJson;

/** A target whose MEMBERS row names an unknown kind. */
final readonly class BadMembers
{
    public const array MEMBERS = [
        'a' => ['kind' => 'date', 'items' => null, 'required' => true, 'nullable' => false, 'ref' => null, 'enum' => null],
    ];

    public function __construct(public mixed $a = null) {}
}
