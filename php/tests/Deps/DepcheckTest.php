<?php

declare(strict_types=1);

namespace HopTop\Pact\Tests\Deps;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Dependency guard: composer.json, composer.lock and the PHP sources hold
 * only the vetted sets of tests/testdata/deps-vetted.json, and
 * docs/sdk/deps-php.md records the same sets.
 */
final class DepcheckTest extends TestCase
{
    public function testPackageDependenciesAreVetted(): void
    {
        self::assertSame([], Inputs::load()->problems());
    }

    public function testTheVettedSetsAreComplete(): void
    {
        $v = Vetted::from(Inputs::load()->vetted);
        self::assertNotSame('', $v->php);
        self::assertNotSame([], $v->packages);
        self::assertNotSame([], $v->packagesDev);
        $trees = array_keys($v->namespaces);
        sort($trees);
        self::assertSame(['examples', 'scripts', 'src', 'tests'], $trees);
    }

    /** @return iterable<string, array{\Closure(Inputs): Inputs, string}> */
    public static function badInputs(): iterable
    {
        yield 'unvetted runtime package' => [static fn(Inputs $in): Inputs => $in->composer('require.guzzlehttp/guzzle', '7.9.2'), 'composer.json require: guzzlehttp/guzzle 7.9.2 is not vetted'];
        yield 'runtime version changed' => [static fn(Inputs $in): Inputs => $in->composer('require.opis/json-schema', '2.5.0'), 'composer.json require: opis/json-schema 2.5.0, vetted 2.6.0'];
        yield 'unvetted development package' => [static fn(Inputs $in): Inputs => $in->composer('require-dev.mockery/mockery', '1.6.12'), 'composer.json require-dev: mockery/mockery 1.6.12 is not vetted'];
        yield 'range constraint' => [static fn(Inputs $in): Inputs => $in->composer('require-dev.phpstan/phpstan', '^2.3'), 'composer.json: phpstan/phpstan ^2.3 is not an exact version'];
        yield 'php constraint' => [static fn(Inputs $in): Inputs => $in->composer('require.php', '>=8.3'), 'composer.json: php constraint'];
        yield 'extension beyond the documented set' => [static fn(Inputs $in): Inputs => $in->composer('require.ext-curl', '*'), 'composer.json: extensions [ext-curl, '];
        yield 'vcs repository' => [static fn(Inputs $in): Inputs => $in->composer('repositories', [['type' => 'vcs', 'url' => 'https://example.org/fork.git']]), 'composer.json: repositories is set'];
        yield 'path repository' => [static fn(Inputs $in): Inputs => $in->composer('repositories', [['type' => 'path', 'url' => '../fork']]), 'composer.json: repositories is set'];
        yield 'plugins allowed' => [static fn(Inputs $in): Inputs => $in->composer('config.allow-plugins', true), 'composer.json: config.allow-plugins is not false'];
        yield 'platform override' => [static fn(Inputs $in): Inputs => $in->composer('config.platform.php', '8.3.0'), 'composer.json config.platform: php 8.3.0, vetted'];
        yield 'vetted pin not the locked version' => [static fn(Inputs $in): Inputs => $in->vetted('require-dev.phpstan/phpstan', '2.3.0')->composer('require-dev.phpstan/phpstan', '2.3.0'), 'composer.lock: phpstan/phpstan is pinned 2.3.0, locked 2.3.1'];
        yield 'unvetted locked package' => [static fn(Inputs $in): Inputs => $in->lockAppend('packages-dev', ['name' => 'psr/clock', 'version' => '1.0.0', 'dist' => ['type' => 'zip', 'url' => 'https://api.github.com/repos/php-fig/clock/zipball/x']]), 'composer.lock packages-dev: psr/clock 1.0.0 is not vetted'];
        yield 'locked transitive version changed' => [static fn(Inputs $in): Inputs => $in->lockEdit('packages', 'opis/uri', ['version' => '1.0.0']), 'composer.lock packages: opis/uri 1.0.0, vetted'];
        yield 'locked package moved to runtime' => [static fn(Inputs $in): Inputs => $in->lockMove('symfony/console'), 'composer.lock packages: symfony/console '];
        yield 'locked path dist' => [static fn(Inputs $in): Inputs => $in->lockEdit('packages', 'opis/string', ['dist' => ['type' => 'path', 'url' => '../string']]), 'composer.lock packages: opis/string dist is not a GitHub zip'];
        yield 'locked non-GitHub source' => [static fn(Inputs $in): Inputs => $in->lockEdit('packages-dev', 'sebastian/diff', ['source' => ['type' => 'git', 'url' => 'https://example.org/diff.git']]), 'composer.lock packages-dev: sebastian/diff source is not a GitHub git repository'];
        yield 'locked plugin' => [static fn(Inputs $in): Inputs => $in->lockEdit('packages-dev', 'sebastian/diff', ['type' => 'composer-plugin']), 'composer.lock packages-dev: sebastian/diff is a plugin'];
        yield 'lock and vetted set changed, record not' => [static fn(Inputs $in): Inputs => $in->lockEdit('packages-dev', 'symfony/console', ['version' => 'v8.1.9'])->vetted('packages-dev.symfony/console', 'v8.1.9'), 'deps-php.md development: symfony/console 8.1.8, vetted 8.1.9'];
        yield 'record row dropped' => [static fn(Inputs $in): Inputs => $in->docDrop('| `theseer/tokenizer`'), 'deps-php.md development: theseer/tokenizer '];
        yield 'record floor stale' => [static fn(Inputs $in): Inputs => $in->docReplace('the floor is 8.4:', 'the floor is 8.3:'), 'deps-php.md: the floor line'];
        yield 'record extension added' => [static fn(Inputs $in): Inputs => $in->docReplace('- Runtime set: `ext-hash`,', '- Runtime set: `ext-curl`, `ext-hash`,'), 'deps-php.md: runtime extensions'];
        yield 'src imports an unvetted namespace' => [static fn(Inputs $in): Inputs => $in->source('src', 'Bad.php', "<?php\nnamespace HopTop\\Pact;\n\nuse GuzzleHttp\\Client;\n"), 'src/Bad.php:4: GuzzleHttp\Client outside the vetted namespaces of src'];
        yield 'src imports a transitive package' => [static fn(Inputs $in): Inputs => $in->source('src', 'Bad.php', "<?php\nnamespace HopTop\\Pact;\n\nuse Opis\\Uri\\Uri;\n"), 'src/Bad.php:4: Opis\Uri\Uri outside'];
        yield 'src names a development package' => [static fn(Inputs $in): Inputs => $in->source('src', 'Bad.php', "<?php\nnamespace HopTop\\Pact;\n\n\\PHPUnit\\Framework\\Assert::fail('x');\n"), 'src/Bad.php:4: PHPUnit\Framework\Assert outside'];
        yield 'tests import a tool package' => [static fn(Inputs $in): Inputs => $in->source('tests', 'Bad.php', "<?php\nnamespace HopTop\\Pact\\Tests;\n\nuse function Symfony\\Component\\String\\u;\n"), 'tests/Bad.php:4: Symfony\Component\String\u outside'];
        yield 'example uses the schema library' => [static fn(Inputs $in): Inputs => $in->source('examples', 'bad.php', "<?php\n\nuse HopTop\\Pact\\Core\\Jcs\\Jcs, Opis\\JsonSchema\\Validator;\n"), 'examples/bad.php:3: Opis\JsonSchema\Validator outside'];
    }

    /**
     * Negative control: on a copy of the inputs the guard passes untouched
     * and reports each injected violation.
     *
     * @param \Closure(Inputs): Inputs $edit
     */
    #[DataProvider('badInputs')]
    public function testGuardNegativeControl(\Closure $edit, string $want): void
    {
        $in = Inputs::load();
        self::assertSame([], $in->problems(), 'the unmodified copy passes');
        $problems = $edit($in)->problems();
        $hit = array_filter($problems, static fn(string $p): bool => str_contains($p, $want));
        self::assertNotSame([], $hit, sprintf("guard missed: %s\n%s", $want, implode("\n", $problems)));
    }

    public function testNamesReadsImportsAndFullyQualifiedNames(): void
    {
        $code = <<<'PHP'
            <?php
            namespace HopTop\Pact;

            use A\B, C\D as E;
            use function F\g;
            use const H\I;
            use J\{K, L};
            use \N\O\{P};
            use Plain;

            final class X
            {
                use Trait1\T;

                public function f(): void
                {
                    $g = function () use ($x) {};
                    \M\N::o();
                    \strlen('');
                    Rel\Name::p();
                }
            }
            PHP;
        self::assertSame(
            [['A\B', 4], ['C\D', 4], ['F\g', 5], ['H\I', 6], ['J\K', 7], ['J\L', 7], ['N\O\P', 8], ['M\N', 18]],
            Depcheck::names($code),
        );
    }
}
