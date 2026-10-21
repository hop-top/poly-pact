<?php

declare(strict_types=1);

namespace HopTop\Pact\Tests\Core\Clock;

use HopTop\Pact\Core\Clock\Artifact;
use HopTop\Pact\Core\Clock\Clocks;
use HopTop\Pact\Tests\Repo;
use PHPUnit\Framework\TestCase;

/**
 * Lifetimes, skew and replay retention against draft section 20.1. Port of
 * go/core/clock/draft_test.go and the Python port's test_clock_draft.py.
 */
final class ClockDraftTest extends TestCase
{
    /** The "At most N seconds|hours" value of the 20.1 baseline-limit row $item, in microseconds. */
    private static function duration(string $draft, string $item): int
    {
        if (preg_match('/^\| ' . preg_quote($item, '/') . ' \| At most (\d+) (second|hour)s?\b/m', $draft, $m) !== 1) {
            self::fail(\sprintf('draft has no 20.1 row %s of the form "At most N seconds|hours"', $item));
        }
        $n = (int) $m[1];

        return ($m[2] === 'hour' ? 3600 * $n : $n) * Clocks::SECOND;
    }

    /** The value cell of the 20.1 metadata row for $key. */
    private static function key(string $draft, string $key): string
    {
        if (preg_match('/^\| `' . preg_quote($key, '/') . '` \| ([^|]+?) \|/m', $draft, $m) !== 1) {
            self::fail('draft has no 20.1 metadata row for ' . $key);
        }

        return $m[1];
    }

    public function testLifetimesMatchTheDraft(): void
    {
        $draft = Repo::read('spec/v1.0/draft.md');
        foreach ([
            ['Contract validity', Artifact::CONTRACT],
            ['Presentation validity', Artifact::PRESENTATION],
            ['Profile lifetime', Artifact::PROFILE],
            ['Evidence artifact lifetime', Artifact::EVIDENCE],
            ['Reputation snapshot lifetime', Artifact::SNAPSHOT],
            ['Outcome report validity', Artifact::OUTCOME],
        ] as [$item, $a]) {
            self::assertSame(self::duration($draft, $item), Clocks::maxLifetime($a), $item);
        }
    }

    public function testSkewAndRetentionMatchTheDraft(): void
    {
        $draft = Repo::read('spec/v1.0/draft.md');
        self::assertSame(self::duration($draft, 'Clock skew'), Clocks::BASELINE_SKEW);
        self::assertSame((int) self::key($draft, 'clock_skew_seconds') * Clocks::SECOND, Clocks::BASELINE_SKEW);
        foreach (['contract_validity_seconds' => Artifact::CONTRACT, 'presentation_validity_seconds' => Artifact::PRESENTATION] as $key => $a) {
            self::assertSame((int) self::key($draft, $key) * Clocks::SECOND, Clocks::maxLifetime($a), $key);
        }
        // replay_retention_seconds is "At least 65": iat+60+skew with the
        // baseline skew, for a presentation that lives its full 60 seconds.
        $cell = self::key($draft, 'replay_retention_seconds');
        if (preg_match('/\AAt least (\d+)\z/', $cell, $m) !== 1) {
            self::fail(\sprintf('replay_retention_seconds cell %s is not "At least N"', $cell));
        }
        $iat = 1_700_000_000;
        $got = Clocks::replayRetention($iat + 60, $iat, Clocks::BASELINE_SKEW);
        self::assertSame(($iat + (int) $m[1]) . '.000000', At::split($got));
        // 7.5 states the same formula in prose.
        self::assertSame(1, preg_match('/later of the artifact expiry and `iat \+ 60 \+ clock_skew`/', $draft), 'draft 7.5 no longer states the replay retention formula; revisit replayRetention');
    }
}
