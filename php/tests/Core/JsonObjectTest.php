<?php

declare(strict_types=1);

namespace HopTop\Pact\Tests\Core;

use HopTop\Pact\Core\JsonObject;
use PHPUnit\Framework\TestCase;

final class JsonObjectTest extends TestCase
{
    public function testKeepsDocumentOrder(): void
    {
        $o = JsonObject::fromPairs([['b', 1], ['a', 2], ['c', 3]]);
        self::assertSame(['b', 'a', 'c'], $o->names());
        self::assertSame([['b', 1], ['a', 2], ['c', 3]], $o->pairs());
    }

    public function testIntegerLikeNamesStayStrings(): void
    {
        $o = JsonObject::fromPairs([['1', 'x'], ['0', 'y']]);
        $seen = [];
        foreach ($o as $name => $value) {
            $seen[] = [$name, $value];
        }
        self::assertSame([['1', 'x'], ['0', 'y']], $seen);
        self::assertSame(['1', '0'], $o->names());
        self::assertTrue($o->has('1'));
    }

    public function testNulLeadingNameIsHeld(): void
    {
        $o = JsonObject::fromPairs([["\0a", true]]);
        self::assertTrue($o->get("\0a"));
    }

    public function testDuplicateNameRefused(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        JsonObject::fromPairs([['a', 1], ['a', 2]]);
    }

    public function testGetDistinguishesNullFromAbsent(): void
    {
        $o = new JsonObject(['a' => null]);
        self::assertTrue($o->has('a'));
        self::assertNull($o->get('a', 'absent'));
        self::assertSame('absent', $o->get('b', 'absent'));
    }

    public function testWithAndWithoutCopy(): void
    {
        $o = new JsonObject(['a' => 1, 'b' => 2]);
        $p = $o->with('a', 9)->with('c', 3)->without('b');
        self::assertSame([['a', 1], ['b', 2]], $o->pairs());
        self::assertSame([['a', 9], ['c', 3]], $p->pairs());
        self::assertCount(2, $p);
    }

    public function testEmptyObjectIsNotEmptyList(): void
    {
        $o = new JsonObject();
        self::assertCount(0, $o);
        self::assertNotSame([], $o);
    }
}
