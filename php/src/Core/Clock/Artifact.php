<?php

declare(strict_types=1);

namespace HopTop\Pact\Core\Clock;

/** An artifact type that section 20.1 gives a lifetime (Go clock.Artifact). */
enum Artifact: int
{
    case PRESENTATION = 1;
    case CONTRACT = 2;
    case EVIDENCE = 3;
    case SNAPSHOT = 4;
    case OUTCOME = 5;
    case PROFILE = 6;

    /** The name of the artifact type (Go Artifact.String). */
    public function toString(): string
    {
        return match ($this) {
            self::PRESENTATION => 'presentation',
            self::CONTRACT => 'requirement contract',
            self::EVIDENCE => 'evidence',
            self::SNAPSHOT => 'reputation snapshot',
            self::OUTCOME => 'outcome report',
            self::PROFILE => 'profile',
        };
    }
}
