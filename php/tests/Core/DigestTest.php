<?php

declare(strict_types=1);

namespace HopTop\Pact\Tests\Core;

use HopTop\Pact\Core\Core;
use HopTop\Pact\Core\Digest;
use HopTop\Pact\PactError;
use PHPUnit\Framework\TestCase;

/** Port of go/core/digest_test.go. */
final class DigestTest extends TestCase
{
    public function testDigestValidate(): void
    {
        $valid = [
            '47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU',
            str_repeat('A', 43),
            str_repeat('-', 43),
            str_repeat('_', 43),
            str_repeat('0', 43),
        ];
        foreach ($valid as $d) {
            (new Digest($d))->validate();
            self::assertSame($d, (string) new Digest($d));
        }

        $invalid = [
            'empty' => '',
            '42 chars' => str_repeat('A', 42),
            '44 chars' => str_repeat('A', 44),
            'padded' => str_repeat('A', 42) . '=',
            'standard plus' => str_repeat('A', 42) . '+',
            'standard slash' => str_repeat('A', 42) . '/',
            'space' => str_repeat('A', 42) . ' ',
            'newline suffix' => str_repeat('A', 43) . "\n",
            'newline in place' => str_repeat('A', 42) . "\n",
            'non-ascii' => str_repeat('A', 42) . 'é',
            '43 bytes unicode' => str_repeat('A', 41) . 'é',
            'nul' => str_repeat('A', 42) . "\x00",
        ];
        foreach ($invalid as $name => $d) {
            try {
                (new Digest($d))->validate();
                self::fail($name . ': validate() accepted ' . json_encode($d));
            } catch (PactError $e) {
                self::assertStringStartsWith('core: digest has ', $e->getMessage(), $name);
            }
        }
        self::assertSame(43, Core::DIGEST_LEN);
    }
}
