<?php

declare(strict_types=1);

namespace HopTop\Pact\Vectors\Group;

use HopTop\Pact\Vectors\Entry;
use HopTop\Pact\Vectors\Fail;
use HopTop\Pact\Vectors\SchemaCase\SchemaFixture;

/**
 * The entries of kind schema, groups parse and schema: the verdict of
 * spec/v1.0/fixtures/schema/README.md on each document of the input, with
 * the package's validator, against the entry's outcome and decision.json
 * (SchemaFixture::check()).
 */
final class SchemaCaseGroup implements Group
{
    public function run(string $root, Entry $e): void
    {
        $problems = SchemaFixture::check($root, $e);
        if ($problems !== []) {
            throw new Fail(implode('; ', $problems));
        }
    }
}
