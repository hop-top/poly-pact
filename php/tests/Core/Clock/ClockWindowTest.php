<?php

declare(strict_types=1);

namespace HopTop\Pact\Tests\Core\Clock;

use HopTop\Pact\Core\Clock\Artifact;
use HopTop\Pact\Core\Clock\ClockError;
use HopTop\Pact\Core\Clock\ClockErrorKind as K;
use HopTop\Pact\Core\Clock\Clocks;
use HopTop\Pact\PactError;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Time windows, lifetimes and replay retention (draft sections 7.5 and
 * 20.1). Port of go/core/clock/window_test.go and the Python port's
 * test_clock_window.py.
 *
 * Instants have microsecond precision, so Go's nanosecond cases use one
 * microsecond. A DateTimeImmutable reaches PHP_INT_MAX seconds, so Go's
 * cases with now at 2^53-1 stand as they are, and further cases put now at
 * the extremes of the PHP range, where now plus skew would overflow an int.
 */
final class ClockWindowTest extends TestCase
{
    private const BASE = 1_000_000;
    private const TOP = 9007199254740991;
    private const SKEW = Clocks::BASELINE_SKEW;
    private const S = Clocks::SECOND;
    private const MS = Clocks::MILLISECOND;
    private const US = Clocks::MICROSECOND;
    private const IAT = 1_700_000_000;

    private function assertIs(\Closure $call, ?K $want): void
    {
        if ($want === null) {
            $call();
            $this->addToAssertionCount(1);

            return;
        }
        try {
            $call();
        } catch (ClockError $e) {
            self::assertSame($want, $e->kind, $e->getMessage());
            self::assertTrue(str_starts_with($e->getMessage(), $want->message()), $e->getMessage());

            return;
        }
        self::fail('no ClockError, want ' . $want->value);
    }

    public function testBaselineSkew(): void
    {
        self::assertSame(5 * self::S, Clocks::BASELINE_SKEW);
        self::assertSame([1_000_000, 1000, 1], [self::S, self::MS, self::US]);
    }

    /** @return iterable<string, array{int, int, int, \DateTimeImmutable, int, ?K}> */
    public static function window(): iterable
    {
        $b = self::BASE;
        $at = At::at(...);
        $sub = At::at($b, 999_999);
        $top = self::TOP;
        $last = At::at(\PHP_INT_MAX, 999_999);
        $first = At::at(\PHP_INT_MIN);
        $cases = [
            ['inside the window', $b - 10, $b - 10, $b + 50, $at($b), self::SKEW, null],
            ['all claims at now', $b, $b, $b + 1, $at($b), self::SKEW, null],
            // nbf <= now + skew
            ['nbf equals now+skew', $b, $b + 5, $b + 60, $at($b), self::SKEW, null],
            ['nbf one second past now+skew', $b, $b + 6, $b + 60, $at($b), self::SKEW, K::NOT_YET_VALID],
            ['nbf far in the future', $b, $b + 3600, $b + 7200, $at($b), self::SKEW, K::NOT_YET_VALID],
            ['nbf in the past', $b, $b - 3600, $b + 60, $at($b), self::SKEW, null],
            ['nbf vs fractional now, equal bound', $b, $b + 5, $b + 60, $sub, self::SKEW, null],
            ['nbf vs fractional now, past bound', $b, $b + 6, $b + 60, $sub, self::SKEW, K::NOT_YET_VALID],
            // iat <= now + skew
            ['iat equals now+skew', $b + 5, $b, $b + 60, $at($b), self::SKEW, null],
            ['iat one second past now+skew', $b + 6, $b, $b + 60, $at($b), self::SKEW, K::ISSUED_IN_FUTURE],
            ['iat far in the future', $b + 3600, $b, $b + 7200, $at($b), self::SKEW, K::ISSUED_IN_FUTURE],
            ['iat vs fractional now, equal bound', $b + 5, $b, $b + 60, $sub, self::SKEW, null],
            ['iat vs fractional now, past bound', $b + 6, $b, $b + 60, $sub, self::SKEW, K::ISSUED_IN_FUTURE],
            // now < exp, with no grace period
            ['exp one second after now', $b - 10, $b - 10, $b + 1, $at($b), self::SKEW, null],
            ['exp equals now', $b - 10, $b - 10, $b, $at($b), self::SKEW, K::EXPIRED],
            ['exp one second before now', $b - 10, $b - 10, $b - 1, $at($b), self::SKEW, K::EXPIRED],
            ['exp within skew of now gets no grace', $b - 10, $b - 10, $b - 5, $at($b), self::SKEW, K::EXPIRED],
            ['exp long past', $b - 7200, $b - 7200, $b - 3600, $at($b), self::SKEW, K::EXPIRED],
            ['fractional now before exp', $b - 10, $b - 10, $b + 1, $sub, self::SKEW, null],
            ['fractional now past exp', $b - 10, $b - 10, $b, $sub, self::SKEW, K::EXPIRED],
            ['now one microsecond before exp', $b - 10, $b - 10, $b, $at($b - 1, 999_999), self::SKEW, null],
            // tighter skew is allowed
            ['zero skew, nbf equals now', $b, $b, $b + 60, $at($b), 0, null],
            ['zero skew, nbf one second ahead', $b, $b + 1, $b + 60, $at($b), 0, K::NOT_YET_VALID],
            ['zero skew, iat one second ahead', $b + 1, $b, $b + 60, $at($b), 0, K::ISSUED_IN_FUTURE],
            ['2s skew, nbf equals now+2', $b, $b + 2, $b + 60, $at($b), 2 * self::S, null],
            ['2s skew, nbf at now+3', $b, $b + 3, $b + 60, $at($b), 2 * self::S, K::NOT_YET_VALID],
            // a fractional now plus a fractional skew carries into the next second
            ['now+0.6s, skew 1.5s, nbf at now+2', $b, $b + 2, $b + 60, $at($b, 600_000), 1500 * self::MS, null],
            ['now+0.4s, skew 1.5s, nbf at now+2', $b, $b + 2, $b + 60, $at($b, 400_000), 1500 * self::MS, K::NOT_YET_VALID],
            // claims outside the core integer range 0..2^53-1 are rejected
            ['iat negative', -1, $b, $b + 60, $at($b), self::SKEW, K::TIMESTAMP],
            ['nbf negative', $b, -1, $b + 60, $at($b), self::SKEW, K::TIMESTAMP],
            ['exp negative', $b, $b, -1, $at($b), self::SKEW, K::TIMESTAMP],
            ['iat above 2^53-1', $top + 1, $b, $b + 60, $at($b), self::SKEW, K::TIMESTAMP],
            ['nbf above 2^53-1', $b, $top + 1, $b + 60, $at($b), self::SKEW, K::TIMESTAMP],
            ['exp above 2^53-1', $b, $b, $top + 1, $at($b), self::SKEW, K::TIMESTAMP],
            ['nbf int max must not wrap into the past', $b, \PHP_INT_MAX, $b + 60, $at($b), self::SKEW, K::TIMESTAMP],
            ['exp int max', $b, $b, \PHP_INT_MAX, $at($b), self::SKEW, K::TIMESTAMP],
            ['iat int min', \PHP_INT_MIN, $b, $b + 60, $at($b), self::SKEW, K::TIMESTAMP],
            ['claims at the epoch are in range', 0, 0, 1, $at(0), self::SKEW, null],
            // Go's cases at 2^53-1
            ['all claims at 2^53-1', $top, $top, $top, $at($top), self::SKEW, K::EXPIRED],
            ['exp at 2^53-1 is still ahead', $top - 2, $top - 2, $top, $at($top - 1), self::SKEW, null],
            ['exp at 2^53-1, now a microsecond before', $top - 2, $top - 2, $top, $at($top - 1, 999_999), self::SKEW, null],
            ['nbf at 2^53-1 is in the future', $b, $top, $top, $at($b), self::SKEW, K::NOT_YET_VALID],
            ['nbf at 2^53-1, now within skew', $top - 10, $top, $top, $at($top - 5), self::SKEW, null],
            ['nbf at 2^53-1, now just past skew', $top - 10, $top, $top, $at($top - 6, 999_999), self::SKEW, K::NOT_YET_VALID],
            // now at the extremes of the PHP range: now + skew does not overflow
            ['nbf at 2^53-1, now at the last instant', $top, $top, $top, $last, self::SKEW, K::EXPIRED],
            ['claims ahead of the first instant', 0, 0, 1, $first, self::SKEW, K::NOT_YET_VALID],
            ['claims ahead of the first instant, zero skew', 0, 0, 1, $first, 0, K::NOT_YET_VALID],
            ['now before the epoch, nbf within skew', 0, 0, 1, $at(-5), self::SKEW, null],
            ['now before the epoch, nbf past skew', 0, 0, 1, $at(-6), self::SKEW, K::NOT_YET_VALID],
            ['now before the epoch, fractional, past skew', 0, 0, 1, $at(-6, 1), self::SKEW, K::NOT_YET_VALID],
            ['now before the epoch, fractional, within skew', 0, 0, 1, $at(-5, 1), self::SKEW, null],
            // skew above the baseline or negative is rejected
            ['skew one microsecond over baseline', $b, $b, $b + 60, $at($b), self::SKEW + self::US, K::SKEW],
            ['skew 6s', $b, $b, $b + 60, $at($b), 6 * self::S, K::SKEW],
            ['negative skew', $b, $b, $b + 60, $at($b), -self::S, K::SKEW],
            ['negative skew of one microsecond', $b, $b, $b + 60, $at($b), -self::US, K::SKEW],
            ['skew int max', $b, $b, $b + 60, $at($b), \PHP_INT_MAX, K::SKEW],
            ['skew before range', -1, $b, $b + 60, $at($b), -1, K::SKEW],
        ];
        foreach ($cases as [$name, $iat, $nbf, $exp, $now, $skew, $want]) {
            yield $name => [$iat, $nbf, $exp, $now, $skew, $want];
        }
    }

    #[DataProvider('window')]
    public function testCheckWindow(int $iat, int $nbf, int $exp, \DateTimeImmutable $now, int $skew, ?K $want): void
    {
        $this->assertIs(static fn() => Clocks::checkWindow($iat, $nbf, $exp, $now, $skew), $want);
    }

    public function testCheckWindowTakesAnyTimeZone(): void
    {
        $now = At::at(self::BASE, 500_000)->setTimezone(new \DateTimeZone('Asia/Kolkata'));
        $this->assertIs(static fn() => Clocks::checkWindow(self::BASE, self::BASE, self::BASE + 1, $now, 0), null);
        $this->assertIs(static fn() => Clocks::checkWindow(self::BASE, self::BASE, self::BASE, $now, 0), K::EXPIRED);
        $this->assertIs(static fn() => Clocks::checkWindow(self::BASE, self::BASE, self::BASE + 1, \DateTime::createFromImmutable($now), 0), null);
    }

    public function testCheckWindowErrorsAreDistinct(): void
    {
        $every = [K::NOT_YET_VALID, K::ISSUED_IN_FUTURE, K::EXPIRED, K::SKEW, K::TIMESTAMP];
        $b = self::BASE;
        foreach ([['nbf', $b, $b + 100, $b + 200, K::NOT_YET_VALID], ['iat', $b + 100, $b, $b + 200, K::ISSUED_IN_FUTURE], ['exp', $b - 10, $b - 10, $b - 1, K::EXPIRED]] as [$name, $iat, $nbf, $exp, $want]) {
            try {
                Clocks::checkWindow($iat, $nbf, $exp, At::at($b), self::SKEW);
                self::fail($name . ': no error');
            } catch (ClockError $e) {
                foreach ($every as $k) {
                    self::assertSame($k === $want, $e->kind === $k, $name . ': ' . $k->value);
                }
                self::assertInstanceOf(PactError::class, $e);
            }
        }
    }

    public function testMaxLifetime(): void
    {
        foreach ([
            [Artifact::PRESENTATION, 60 * self::S], [Artifact::CONTRACT, 60 * self::S], [Artifact::EVIDENCE, 3600 * self::S],
            [Artifact::SNAPSHOT, 300 * self::S], [Artifact::OUTCOME, 300 * self::S], [Artifact::PROFILE, 86400 * self::S],
        ] as [$a, $want]) {
            self::assertSame($want, Clocks::maxLifetime($a), $a->toString());
            $this->assertIs(static fn() => Clocks::checkLifetime($a, \PHP_INT_MAX - intdiv($want, self::S) + 1, \PHP_INT_MAX), null);
        }
    }

    public function testArtifactNames(): void
    {
        self::assertSame(['presentation', 'requirement contract', 'evidence', 'reputation snapshot', 'outcome report', 'profile'], array_map(static fn(Artifact $a): string => $a->toString(), Artifact::cases()));
        self::assertSame([1, 2, 3, 4, 5, 6], array_map(static fn(Artifact $a): int => $a->value, Artifact::cases()));
        self::assertNull(Artifact::tryFrom(0));
    }

    public function testErrorKinds(): void
    {
        self::assertSame(['SKEW', 'TIMESTAMP', 'NOT_YET_VALID', 'ISSUED_IN_FUTURE', 'EXPIRED', 'LIFETIME', 'TOO_OLD', 'UNKNOWN_ARTIFACT'], array_map(static fn(K $k): string => $k->value, K::cases()));
        self::assertSame('clock: skew must be between 0 and 5s', K::SKEW->message());
        self::assertSame('clock: timestamp outside 0..9007199254740991', K::TIMESTAMP->message());
        $e = new ClockError(K::EXPIRED, 'exp 1, now 2');
        self::assertSame('clock: expired: exp 1, now 2', $e->getMessage());
        self::assertSame('exp 1, now 2', $e->detail);
        self::assertSame('clock: unknown artifact type', (new ClockError(K::UNKNOWN_ARTIFACT))->getMessage());
        // The skew is written as Go writes a time.Duration.
        foreach ([6 * self::S => '6s', self::SKEW + 1 => '5.000001s', -self::US => '-1µs', -self::S => '-1s', -1500 * self::MS => '-1.5s', -2 * self::MS => '-2ms'] as $skew => $want) {
            try {
                Clocks::checkWindow(self::BASE, self::BASE, self::BASE + 1, At::at(self::BASE), $skew);
                self::fail('accepted skew ' . $skew);
            } catch (ClockError $e) {
                self::assertSame('got ' . $want, $e->detail);
            }
        }
        foreach ([1500 * self::MS => '1.5s', 7 * self::MS => '7ms', 3 => '3µs', 0 => '0s'] as $skew => $want) {
            try {
                Clocks::checkWindow(self::BASE, self::BASE + 9, self::BASE + 60, At::at(self::BASE), $skew);
                self::fail('accepted');
            } catch (ClockError $e) {
                self::assertSame('nbf 1000009, now 1000000, skew ' . $want, $e->detail);
            }
        }
    }

    /** @return iterable<string, array{Artifact, int}> */
    public static function lifetimes(): iterable
    {
        foreach ([[Artifact::PRESENTATION, 60], [Artifact::CONTRACT, 60], [Artifact::EVIDENCE, 3600], [Artifact::SNAPSHOT, 300], [Artifact::OUTCOME, 300], [Artifact::PROFILE, 86400]] as [$a, $most]) {
            yield $a->toString() => [$a, $most];
        }
    }

    #[DataProvider('lifetimes')]
    public function testCheckLifetime(Artifact $a, int $most): void
    {
        $iat = self::IAT;
        $this->assertIs(static fn() => Clocks::checkLifetime($a, $iat, $iat + $most), null);
        $this->assertIs(static fn() => Clocks::checkLifetime($a, $iat, $iat + $most + 1), K::LIFETIME);
        $this->assertIs(static fn() => Clocks::checkLifetime($a, $iat, $iat + $most - 1), null);
        $this->assertIs(static fn() => Clocks::checkLifetime($a, $iat, $iat + 1), null);
        // A.2: iat < exp, so an empty or negative lifetime is malformed.
        $this->assertIs(static fn() => Clocks::checkLifetime($a, $iat, $iat), K::LIFETIME);
        $this->assertIs(static fn() => Clocks::checkLifetime($a, $iat, $iat - 1), K::LIFETIME);
    }

    public function testCheckLifetimeEdges(): void
    {
        // range extremes do not wrap
        $this->assertIs(static fn() => Clocks::checkLifetime(Artifact::PROFILE, \PHP_INT_MIN, \PHP_INT_MAX), K::LIFETIME);
        $this->assertIs(static fn() => Clocks::checkLifetime(Artifact::PROFILE, -1, \PHP_INT_MAX), K::LIFETIME);
        $this->assertIs(static fn() => Clocks::checkLifetime(Artifact::PRESENTATION, 0, \PHP_INT_MAX), K::LIFETIME);
        $this->assertIs(static fn() => Clocks::checkLifetime(Artifact::PRESENTATION, \PHP_INT_MIN, \PHP_INT_MIN + 61), K::LIFETIME);
        $this->assertIs(static fn() => Clocks::checkLifetime(Artifact::PRESENTATION, \PHP_INT_MIN, \PHP_INT_MIN + 60), null);
        // largest core integers
        $this->assertIs(static fn() => Clocks::checkLifetime(Artifact::PRESENTATION, self::TOP - 60, self::TOP), null);
        $this->assertIs(static fn() => Clocks::checkLifetime(Artifact::PRESENTATION, self::TOP - 61, self::TOP), K::LIFETIME);
    }

    /** @return iterable<string, array{int, \DateTimeImmutable, ?K}> */
    public static function age(): iterable
    {
        $b = self::BASE;
        $at = At::at(...);
        $cases = [
            ['age 0', $b, $at($b), null],
            ['age 60 equals the bound', $b - 60, $at($b), null],
            ['age 61', $b - 61, $at($b), K::TOO_OLD],
            ['age 60s + 1us', $b - 60, $at($b, 1), K::TOO_OLD],
            ['age 60s - 1us', $b - 60, $at($b - 1, 999_999), null],
            ['age 60.5s: a 0.5 s remainder is not rounded away', $b - 60, $at($b, 500_000), K::TOO_OLD],
            ['age 59.5s', $b - 59, $at($b, 500_000), null],
            ['issued in the future is not too old', $b + 5, $at($b), null],
            ['long ago', $b - 86400, $at($b), K::TOO_OLD],
            ['iat at the epoch', 0, $at(0), null],
            ['iat at 2^53-1 is not too old', self::TOP, $at($b), null],
            ['iat at 2^53-1, now 60 s later', self::TOP, $at(self::TOP + 60), null],
            ['iat at 2^53-1, now 60 s and 1 us later', self::TOP, $at(self::TOP + 60, 1), K::TOO_OLD],
            ['iat at 2^53-1, now at the last instant', self::TOP, $at(\PHP_INT_MAX, 999_999), K::TOO_OLD],
            ['now at the first instant', 0, $at(\PHP_INT_MIN), null],
            ['negative iat', -1, $at($b), K::TIMESTAMP],
            ['iat above 2^53-1', self::TOP + 1, $at($b), K::TIMESTAMP],
        ];
        foreach ($cases as [$name, $iat, $now, $want]) {
            yield $name => [$iat, $now, $want];
        }
    }

    #[DataProvider('age')]
    public function testCheckPresentationAge(int $iat, \DateTimeImmutable $now, ?K $want): void
    {
        $this->assertIs(static fn() => Clocks::checkPresentationAge($iat, $now), $want);
    }

    /** @return iterable<string, array{int, int, int, ?K}> */
    public static function presentation(): iterable
    {
        $b = self::BASE;
        yield 'fresh presentation' => [$b - 10, $b - 10, $b + 50, null];
        yield 'issued now, full lifetime' => [$b, $b, $b + 60, null];
        yield 'issued within skew of the future' => [$b + 5, $b + 5, $b + 65, null];
        yield 'exp - iat is 61' => [$b - 10, $b - 10, $b + 51, K::LIFETIME];
        yield 'exp - iat is 60' => [$b - 10, $b - 10, $b + 50, null];
        yield 'last second of validity' => [$b - 59, $b - 59, $b + 1, null];
        yield 'expired' => [$b - 60, $b - 60, $b, K::EXPIRED];
        yield 'iat too far ahead' => [$b + 6, $b, $b + 66, K::ISSUED_IN_FUTURE];
        yield 'nbf too far ahead' => [$b, $b + 6, $b + 60, K::NOT_YET_VALID];
        yield 'expiry before issue' => [$b + 4, $b, $b + 2, K::LIFETIME];
    }

    #[DataProvider('presentation')]
    public function testCheckPresentation(int $iat, int $nbf, int $exp, ?K $want): void
    {
        $this->assertIs(static fn() => Clocks::checkPresentation($iat, $nbf, $exp, At::at(self::BASE), self::SKEW), $want);
    }

    public function testCheckPresentationSkew(): void
    {
        $b = self::BASE;
        $this->assertIs(static fn() => Clocks::checkPresentation($b, $b, $b + 60, At::at($b), 6 * self::S), K::SKEW);
        $this->assertIs(static fn() => Clocks::checkPresentation($b + 3, $b, $b + 63, At::at($b), 2 * self::S), K::ISSUED_IN_FUTURE);
    }

    /** @return iterable<string, array{int, int, string}> */
    public static function retention(): iterable
    {
        $i = self::IAT;
        yield '60s presentation, baseline skew' => [$i + 60, self::SKEW, ($i + 65) . '.000000'];
        yield 'short presentation is held for iat+60+skew' => [$i + 10, self::SKEW, ($i + 65) . '.000000'];
        yield 'exp equals iat+60+skew' => [$i + 65, self::SKEW, ($i + 65) . '.000000'];
        yield 'exp one second past iat+60+skew' => [$i + 66, self::SKEW, ($i + 66) . '.000000'];
        yield 'expiry later than the window' => [$i + 600, self::SKEW, ($i + 600) . '.000000'];
        yield 'zero skew' => [$i + 60, 0, ($i + 60) . '.000000'];
        yield '2s skew' => [$i + 30, 2 * self::S, ($i + 62) . '.000000'];
        yield 'fractional skew' => [$i + 30, 1500 * self::MS, ($i + 61) . '.500000'];
        yield 'fractional skew past exp' => [$i + 61, 1500 * self::MS, ($i + 61) . '.500000'];
        yield 'negative skew counts as zero' => [$i + 30, -self::S, ($i + 60) . '.000000'];
        yield 'exp before iat' => [$i - 5, self::SKEW, ($i + 65) . '.000000'];
    }

    #[DataProvider('retention')]
    public function testReplayRetention(int $exp, int $skew, string $want): void
    {
        $got = Clocks::replayRetention($exp, self::IAT, $skew);
        self::assertSame($want, At::split($got));
        self::assertSame('UTC', $got->getTimezone()->getName());
    }

    /**
     * Out-of-range claims never shorten retention, and the largest claims
     * and skews are kept exactly: a DateTimeImmutable reaches PHP_INT_MAX
     * seconds, beyond 2^53-1 + 60 + PHP_INT_MAX microseconds, so no
     * retention saturates.
     */
    public function testReplayRetentionEdges(): void
    {
        $top = self::TOP;
        self::assertSame(($top + 65) . '.000000', At::split(Clocks::replayRetention(\PHP_INT_MAX, \PHP_INT_MAX, self::SKEW)));
        // An out-of-range expiry is clamped, not wrapped.
        self::assertSame($top . '.000000', At::split(Clocks::replayRetention(\PHP_INT_MAX, self::BASE, self::SKEW)));
        self::assertSame((self::BASE + 65) . '.000000', At::split(Clocks::replayRetention(\PHP_INT_MIN, self::BASE, self::SKEW)));
        self::assertSame('60.000000', At::split(Clocks::replayRetention(\PHP_INT_MIN, \PHP_INT_MIN, \PHP_INT_MIN)));
        // The largest core integers do not wrap.
        self::assertSame(($top - 30 + 65) . '.000000', At::split(Clocks::replayRetention($top, $top - 30, self::SKEW)));
        self::assertSame(($top + 65) . '.000000', At::split(Clocks::replayRetention($top - 100, $top, self::SKEW)));
        self::assertSame(($top + 65) . '.999999', At::split(Clocks::replayRetention($top - 100, $top, self::SKEW + 999_999)));
        // The largest skew is kept exactly.
        $sec = intdiv(\PHP_INT_MAX, self::S);
        self::assertSame(($top + 60 + $sec) . '.' . \sprintf('%06d', \PHP_INT_MAX % self::S), At::split(Clocks::replayRetention($top, $top, \PHP_INT_MAX)));
    }

    /** max(exp, iat + 60 + skew) in exact integer arithmetic, as (seconds, microseconds). */
    private static function trueRetention(int $exp, int $iat, int $skew): string
    {
        $skew = max($skew, 0);
        $expiry = min(max($exp, 0), self::TOP);
        $hs = min(max($iat, 0), self::TOP) + 60 + intdiv($skew, self::S);
        $hu = $skew % self::S;

        return $expiry > $hs || ($expiry === $hs && $hu === 0) ? $expiry . '.000000' : $hs . '.' . \sprintf('%06d', $hu);
    }

    public function testReplayRetentionNeverEarlier(): void
    {
        $claims = [\PHP_INT_MIN, -1, 0, self::BASE, self::IAT, self::TOP - 66, self::TOP - 65, self::TOP - 64, self::TOP - 1, self::TOP, self::TOP + 1, \PHP_INT_MAX];
        $skews = [\PHP_INT_MIN, -self::S, 0, self::US, 999_999, self::SKEW, self::SKEW + 999_999, self::SKEW + self::S, \PHP_INT_MAX];
        foreach ($claims as $exp) {
            foreach ($claims as $iat) {
                foreach ($skews as $skew) {
                    self::assertSame(self::trueRetention($exp, $iat, $skew), At::split(Clocks::replayRetention($exp, $iat, $skew)), \sprintf('%d %d %d', $exp, $iat, $skew));
                }
            }
        }
    }
}
