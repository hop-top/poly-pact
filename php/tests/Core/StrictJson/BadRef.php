<?php

declare(strict_types=1);

namespace HopTop\Pact\Tests\Core\StrictJson;

/** A target whose member refers to a class without a MEMBERS table. */
final readonly class BadRef
{
    public const array MEMBERS = [
        'a' => ['kind' => 'object', 'items' => null, 'required' => true, 'nullable' => true, 'ref' => \ArrayObject::class, 'enum' => null],
    ];

    public function __construct(public ?object $a) {}
}
