<?php

declare(strict_types=1);

namespace HopTop\Pact\Core\Clock;

/**
 * Time rules of draft section 7.5 and baseline lifetimes of section 20.1.
 * Mirrors Go package hop.top/pact-go/core/clock.
 *
 * Protocol timestamps (iat, nbf, exp, created_at, expires_at) are integer
 * Unix seconds in the range 0..2^53-1. A validator reads the current time
 * from a Clock, so that tests control it, then applies:
 *
 * - checkWindow(): nbf <= now+skew, iat <= now+skew and now < exp, with no
 *   grace period after exp;
 * - checkLifetime(): the longest span from iat to exp an artifact type may
 *   claim;
 * - checkPresentation(): the window and lifetime checks plus now-iat <= 60 s
 *   for an agent presentation;
 * - replayRetention(): how long a replay record must be kept.
 *
 * Durations are integer microseconds (SECOND, MILLISECOND, MICROSECOND), the
 * precision of a DateTimeImmutable, where Go has nanoseconds. The checks
 * compare exactly: now is split once into whole Unix seconds (floor) and
 * microseconds, and a wire integer is compared against that pair, so a
 * fractional now is never rounded in the artifact's favour. A wire value is
 * never turned into a DateTime, and no sum leaves the int range, so every
 * claim is checked against every representable now.
 */
final class Clocks
{
    public const int MICROSECOND = 1;
    public const int MILLISECOND = 1000;
    public const int SECOND = 1_000_000;

    /**
     * The largest clock skew a validator may allow, in microseconds (sections
     * 7.5, 20.1); there is no expiry grace period in addition to it.
     */
    public const int BASELINE_SKEW = 5 * self::SECOND;

    /** The largest value of a core integer field: 2^53-1 (section 7.1). */
    private const int MAX_TIMESTAMP = 9007199254740991;

    /** The longest presentation lifetime, and the 60 of the replay retention formula of section 7.5, in seconds. */
    private const int PRESENTATION_VALIDITY = 60;

    private function __construct() {}

    /**
     * The longest lifetime of an artifact of type $a, from iat to exp (from
     * created_at to expires_at for a profile), in microseconds.
     *
     * Section 20.1: presentation 60 s, contract 60 s, evidence 1 h,
     * reputation snapshot 300 s, outcome report 300 s, profile 24 h.
     */
    public static function maxLifetime(Artifact $a): int
    {
        return self::lifetimeSeconds($a) * self::SECOND;
    }

    /**
     * Apply section 7.5 to an artifact's claims at time $now.
     *
     * nbf <= now + skew, iat <= now + skew and now < exp. There is no grace
     * period: an artifact whose exp is at or before now is expired, however
     * small the skew. $skew, in microseconds, must lie in 0..BASELINE_SKEW;
     * a deployment that tightens the baseline passes its own smaller value.
     * The checks run in the order skew, range, nbf, iat, exp, and the first
     * failure is thrown.
     *
     * For an agent profile call checkWindow(created_at, created_at,
     * expires_at, ...).
     *
     * @throws ClockError
     */
    public static function checkWindow(int $iat, int $nbf, int $exp, \DateTimeInterface $now, int $skew): void
    {
        self::checkSkew($skew);
        self::checkRange('iat', $iat);
        self::checkRange('nbf', $nbf);
        self::checkRange('exp', $exp);
        [$sec, $us] = Instant::split($now);
        // now + skew as whole seconds; a claim is a whole second, so claim <=
        // now + skew exactly when claim <= latest. A now past 2^53-1 is past
        // every claim, so it is capped before the sum, which cannot overflow.
        $latest = min($sec, self::MAX_TIMESTAMP + 1) + intdiv($us + $skew, self::SECOND);
        if ($nbf > $latest) {
            throw new ClockError(ClockErrorKind::NOT_YET_VALID, \sprintf('nbf %d, now %d, skew %s', $nbf, $sec, self::duration($skew)));
        }
        if ($iat > $latest) {
            throw new ClockError(ClockErrorKind::ISSUED_IN_FUTURE, \sprintf('iat %d, now %d, skew %s', $iat, $sec, self::duration($skew)));
        }
        // now < exp exactly when its whole seconds are below exp.
        if ($sec >= $exp) {
            throw new ClockError(ClockErrorKind::EXPIRED, \sprintf('exp %d, now %d', $exp, $sec));
        }
    }

    /**
     * Throw ClockError unless iat < exp (appendix A.2) and exp-iat <=
     * maxLifetime($a). It compares the claims alone and does not need the
     * current time.
     *
     * @throws ClockError
     */
    public static function checkLifetime(Artifact $a, int $iat, int $exp): void
    {
        $most = self::lifetimeSeconds($a);
        if ($exp <= $iat) {
            throw new ClockError(ClockErrorKind::LIFETIME, \sprintf('%s exp %d is not after iat %d', $a->toString(), $exp, $iat));
        }
        // exp - iat may overflow; iat + most only when every exp is within it.
        if ($iat <= \PHP_INT_MAX - $most && $exp > $iat + $most) {
            throw new ClockError(ClockErrorKind::LIFETIME, \sprintf('%s exp %d is more than %d s after iat %d', $a->toString(), $exp, $most, $iat));
        }
    }

    /**
     * Throw ClockError (TOO_OLD) unless a presentation issued at $iat is at
     * most 60 s old at $now: now - iat <= 60 s (section 7.5). A presentation
     * issued ahead of now is not too old; checkWindow() bounds that case.
     *
     * @throws ClockError
     */
    public static function checkPresentationAge(int $iat, \DateTimeInterface $now): void
    {
        self::checkRange('iat', $iat);
        [$sec, $us] = Instant::split($now);
        $bound = $iat + self::PRESENTATION_VALIDITY;
        if ($sec > $bound || ($sec === $bound && $us > 0)) {
            throw new ClockError(ClockErrorKind::TOO_OLD, \sprintf('iat %d, now %d', $iat, $sec));
        }
    }

    /**
     * Apply every time rule of section 7.5 to an agent presentation:
     * checkWindow(), then exp-iat <= 60 s, then now-iat <= 60 s; the first
     * failure is thrown. Claims that pass the first two checks always pass
     * the third (now < exp <= iat+60); it stays so that each rule is enforced
     * by name and survives a change to either bound.
     *
     * @throws ClockError
     */
    public static function checkPresentation(int $iat, int $nbf, int $exp, \DateTimeInterface $now, int $skew): void
    {
        self::checkWindow($iat, $nbf, $exp, $now, $skew);
        self::checkLifetime(Artifact::PRESENTATION, $iat, $exp);
        self::checkPresentationAge($iat, $now);
    }

    /**
     * The instant before which a replay record must not be evicted: the
     * later of the artifact expiry and iat + 60 s + skew (section 7.5).
     * Evicting earlier, even under load, lets a presentation be replayed.
     *
     * A negative skew counts as zero. Claims outside 0..2^53-1 are clamped
     * into that range, which can only lengthen the retention of a valid
     * claim; such claims fail checkWindow() before a record is written. The
     * result is exact for every argument: the latest retention, 2^53-1 + 60
     * seconds plus PHP_INT_MAX microseconds, is far inside the range of a
     * DateTimeImmutable (PHP_INT_MAX seconds), so none saturates and none
     * throws.
     */
    public static function replayRetention(int $exp, int $iat, int $skew): \DateTimeImmutable
    {
        $skew = max($skew, 0);
        $expiry = min(max($exp, 0), self::MAX_TIMESTAMP);
        $horizon = min(max($iat, 0), self::MAX_TIMESTAMP) + self::PRESENTATION_VALIDITY + intdiv($skew, self::SECOND);
        $us = $skew % self::SECOND;
        if ($expiry > $horizon || ($expiry === $horizon && $us === 0)) {
            return Instant::of($expiry, 0);
        }

        return Instant::of($horizon, $us);
    }

    private static function lifetimeSeconds(Artifact $a): int
    {
        return match ($a) {
            Artifact::PRESENTATION => self::PRESENTATION_VALIDITY,
            Artifact::CONTRACT => 60,
            Artifact::EVIDENCE => 3600,
            Artifact::SNAPSHOT, Artifact::OUTCOME => 300,
            Artifact::PROFILE => 86400,
        };
    }

    private static function checkSkew(int $skew): void
    {
        if ($skew < 0 || $skew > self::BASELINE_SKEW) {
            throw new ClockError(ClockErrorKind::SKEW, 'got ' . self::duration($skew));
        }
    }

    private static function checkRange(string $name, int $sec): void
    {
        if ($sec < 0 || $sec > self::MAX_TIMESTAMP) {
            throw new ClockError(ClockErrorKind::TIMESTAMP, \sprintf('%s is %d', $name, $sec));
        }
    }

    /** $us microseconds as Go prints a duration of whole microseconds: 5s, 1.5s, 0s, -1µs. */
    private static function duration(int $us): string
    {
        if ($us === 0) {
            return '0s';
        }
        $sign = $us < 0 ? '-' : '';
        $whole = intdiv($us, self::SECOND);
        $frac = $us % self::SECOND;
        if ($whole === 0) {
            $ms = intdiv($frac, self::MILLISECOND);

            return $frac % self::MILLISECOND === 0 ? $ms . 'ms' : $frac . 'µs';
        }
        $text = $sign . abs($whole);

        return $frac === 0 ? $text . 's' : $text . '.' . rtrim(\sprintf('%06d', abs($frac)), '0') . 's';
    }
}
