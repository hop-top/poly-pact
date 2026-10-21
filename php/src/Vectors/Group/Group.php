<?php

declare(strict_types=1);

namespace HopTop\Pact\Vectors\Group;

use HopTop\Pact\Vectors\Entry;

/** The runner of one (kind, prefix) group of the shared fixtures. */
interface Group
{
    /**
     * Run $e against the package: return on a pass, throw Fail or Skipped
     * otherwise.
     *
     * @param string $root the fixture directory that holds manifest.json
     */
    public function run(string $root, Entry $e): void;
}
