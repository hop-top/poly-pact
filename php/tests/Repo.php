<?php

declare(strict_types=1);

namespace HopTop\Pact\Tests;

use PHPUnit\Framework\Assert;

/**
 * Files of the source repository around php/: the spec tree and the Go
 * sources. A mirror checkout of the package has neither, so a test that reads
 * one skips, unless PACT_REQUIRE_VECTORS=1 (make php-test) makes the absence
 * a failure.
 */
final class Repo
{
    /** The repository root: the parent of php/. */
    public static function root(): string
    {
        return \dirname(__DIR__, 2);
    }

    /** The package root, php/. */
    public static function package(): string
    {
        return \dirname(__DIR__);
    }

    /** The text of the repository file $rel, or a skip (a failure under PACT_REQUIRE_VECTORS=1). */
    public static function read(string $rel): string
    {
        $path = self::root() . '/' . $rel;
        $text = is_file($path) ? file_get_contents($path) : false;
        if ($text === false) {
            if (getenv('PACT_REQUIRE_VECTORS') === '1') {
                Assert::fail($rel . ' absent under PACT_REQUIRE_VECTORS=1');
            }
            Assert::markTestSkipped($rel . ' is not part of this checkout');
        }

        return $text;
    }
}
