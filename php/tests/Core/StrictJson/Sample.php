<?php

declare(strict_types=1);

namespace HopTop\Pact\Tests\Core\StrictJson;

use HopTop\Pact\Core\JsonObject;

/**
 * The sample struct of go/core/strictjson/strictjson_test.go: a pointer field
 * is a nullable member, json.RawMessage an any member, map[string]string a
 * map of strings, map[string]json.RawMessage an open object. Every member is
 * required, so an absent one holds its Go zero value.
 */
final readonly class Sample
{
    public const array MEMBERS = [
        'name' => ['kind' => 'string', 'items' => null, 'required' => true, 'nullable' => false, 'ref' => null, 'enum' => null],
        'count' => ['kind' => 'integer', 'items' => null, 'required' => true, 'nullable' => false, 'ref' => null, 'enum' => null],
        'ratio' => ['kind' => 'number', 'items' => null, 'required' => true, 'nullable' => false, 'ref' => null, 'enum' => null],
        'opt' => ['kind' => 'string', 'items' => null, 'required' => true, 'nullable' => true, 'ref' => null, 'enum' => null],
        'opt_count' => ['kind' => 'integer', 'items' => null, 'required' => true, 'nullable' => true, 'ref' => null, 'enum' => null],
        'inner' => ['kind' => 'object', 'items' => null, 'required' => true, 'nullable' => true, 'ref' => Inner::class, 'enum' => null],
        'items' => ['kind' => 'array', 'items' => 'object', 'required' => true, 'nullable' => false, 'ref' => Inner::class, 'enum' => null],
        'raw' => ['kind' => 'any', 'items' => null, 'required' => true, 'nullable' => false, 'ref' => null, 'enum' => null],
        'headers' => ['kind' => 'object', 'items' => 'string', 'required' => true, 'nullable' => false, 'ref' => null, 'enum' => null],
        'extensions' => ['kind' => 'object', 'items' => null, 'required' => true, 'nullable' => false, 'ref' => null, 'enum' => null],
    ];

    /** @param list<Inner> $items */
    public function __construct(
        public string $name,
        public int $count,
        public float $ratio,
        public ?string $opt,
        public ?int $opt_count,
        public ?Inner $inner,
        public array $items,
        public mixed $raw,
        public JsonObject $headers,
        public JsonObject $extensions,
    ) {}
}
