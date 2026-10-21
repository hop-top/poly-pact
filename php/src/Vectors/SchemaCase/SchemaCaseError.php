<?php

declare(strict_types=1);

namespace HopTop\Pact\Vectors\SchemaCase;

use HopTop\Pact\PactError;

/**
 * A schema case that breaks the format of spec/v1.0/fixtures/schema/README.md
 * (Inputs, Outcomes), or a file of it that cannot be read: a problem of the
 * case, not a verdict.
 */
final class SchemaCaseError extends PactError {}
