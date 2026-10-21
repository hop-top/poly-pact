<?php

declare(strict_types=1);

namespace HopTop\Pact\Vectors;

/** The run cannot start or cannot be trusted: exit status 2, nothing on standard output. */
final class HarnessError extends \RuntimeException {}
