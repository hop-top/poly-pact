<?php

declare(strict_types=1);

namespace HopTop\Pact;

/**
 * Root of every exception the package throws on purpose.
 *
 * Each module has its own subclass carrying the Go strings of its family
 * (a kind, a reason or a code), so a caller can catch one module's failures
 * or every failure of the package.
 */
class PactError extends \RuntimeException {}
