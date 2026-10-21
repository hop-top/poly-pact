<?php

declare(strict_types=1);

namespace HopTop\Pact\Tests\Core;

use HopTop\Pact\Core\Core;
use HopTop\Pact\Core\Wire;
use HopTop\Pact\Tests\Repo;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The generated string enums. Port of go/core/enums_test.go, plus the
 * source-level check against go/core/enums.go (skipped where go/ is absent).
 */
final class EnumsTest extends TestCase
{
    /** @return iterable<string, array{class-string<\BackedEnum>}> */
    public static function enums(): iterable
    {
        foreach (Wire::ENUMS as $name => $class) {
            yield $name => [$class];
        }
    }

    /** @param class-string<\BackedEnum> $class */
    #[DataProvider('enums')]
    public function testEnumValid(string $class): void
    {
        $values = array_map(static fn(\BackedEnum $c): string => (string) $c->value, $class::cases());
        self::assertNotSame([], $values);
        $isValid = [$class, 'isValid'];
        self::assertIsCallable($isValid);
        foreach ($values as $v) {
            self::assertTrue($isValid((string) $v), \sprintf('%s::isValid(%s)', $class, $v));
        }
        foreach (['', 'bogus', ' ', 'Enforced', 'enforced '] as $bad) {
            if (\in_array($bad, $values, true)) {
                continue;
            }
            self::assertFalse($isValid($bad), \sprintf('%s::isValid(%s)', $class, json_encode($bad)));
        }
    }

    public function testCaseNamesFollowTheValues(): void
    {
        foreach (Wire::ENUMS as $class) {
            foreach ($class::cases() as $c) {
                self::assertSame(strtoupper((string) preg_replace('/[^0-9A-Za-z]/', '_', (string) $c->value)), $c->name);
            }
        }
    }

    public function testEnumsFollowTheGoSource(): void
    {
        $src = Repo::read('go/core/enums.go');
        preg_match_all('/^type (\w+) string$/m', $src, $m);
        self::assertSame($m[1], array_keys(Wire::ENUMS), 'Go enum types, in declaration order');
        foreach (Wire::ENUMS as $name => $class) {
            preg_match_all('/^\s+\w+\s+' . $name . '\s+=\s+"([^"]*)"$/m', $src, $mm);
            $values = array_map(static fn(\BackedEnum $c): string => (string) $c->value, $class::cases());
            self::assertSame($mm[1], $values, $name . ', in Go order');
        }
        self::assertSame(1, preg_match('/^const Version = "([^"]+)"$/m', $src, $v));
        self::assertSame($v[1] ?? null, Core::VERSION);
    }
}
