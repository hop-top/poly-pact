<?php

declare(strict_types=1);

// Shared-vector harness entry point; see HopTop\Pact\Vectors\Harness.

require \dirname(__DIR__) . '/vendor/autoload.php';

$argv = $_SERVER['argv'] ?? [];
$args = \is_array($argv) ? array_values(array_filter(\array_slice($argv, 1), 'is_string')) : [];

exit(HopTop\Pact\Vectors\Harness::main($args));
