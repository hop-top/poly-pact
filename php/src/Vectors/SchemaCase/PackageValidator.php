<?php

declare(strict_types=1);

namespace HopTop\Pact\Vectors\SchemaCase;

use HopTop\Pact\Core\Schema\Schema;
use HopTop\Pact\Core\Schema\SchemaError;
use HopTop\Pact\Core\StrictJson\StrictJsonError;

/** SchemaValidator over the package's vendored schema (Core\Schema\Schema). */
final class PackageValidator implements SchemaValidator
{
    public function validateDef(string $def, string $doc): array
    {
        try {
            Schema::validate($def, $doc);
        } catch (SchemaError $e) {
            return $e->issues;
        } catch (StrictJsonError $e) {
            throw new \RuntimeException('not strict JSON: ' . $e->getMessage(), 0, $e);
        }

        return [];
    }
}
