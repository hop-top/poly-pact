<?php

declare(strict_types=1);

namespace HopTop\Pact\Tests\Examples;

use PHPUnit\Framework\TestCase;

/** The usage example of README.md, run as a program; its output is the README's. */
final class SignVerifyExampleTest extends TestCase
{
    public function testOutputMatchesReadme(): void
    {
        $dir = \dirname(__DIR__, 2);
        $out = [];
        $code = 0;
        exec(escapeshellarg(\PHP_BINARY) . ' ' . escapeshellarg($dir . '/examples/sign_verify.php'), $out, $code);
        self::assertSame(0, $code);
        $want = "requirement-publisher publisher-1 {\"pact_version\":\"0.1\",\"jti\":\"contract-1\"}\nJ0GfvClw7hrBhHyvkkriLn5ZbdWqmdwQtBHF_DZCYo4";
        self::assertSame($want, implode("\n", $out));
        $readme = (string) file_get_contents($dir . '/README.md');
        self::assertStringContainsString("```text\n" . $want . "\n```", $readme);
        self::assertStringContainsString("```php\n" . file_get_contents($dir . '/examples/sign_verify.php') . '```', $readme);
    }
}
