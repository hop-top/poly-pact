<?php

declare(strict_types=1);

namespace HopTop\Pact\Core\Schema;

use HopTop\Pact\Core\JsonObject;
use HopTop\Pact\Core\StrictJson\Limits;
use HopTop\Pact\Core\StrictJson\StrictJson;
use HopTop\Pact\Core\StrictJson\StrictJsonError;
use Opis\JsonSchema\Errors\ErrorFormatter;
use Opis\JsonSchema\Errors\ValidationError;
use Opis\JsonSchema\Validator;

/**
 * JSON Schema validation of PACT objects, an SDK extra with no Go library
 * counterpart: the definitions of the vendored Appendix A.3 schema
 * (schema/pact.schema.json), JSON Schema Draft 2020-12, validated by
 * opis/json-schema with format uri asserted by the RFC 3986 matcher every
 * PACT SDK shares (UriFormat).
 *
 * The schema is read from the package file by the strict parser and
 * registered under its $id, so no reference leaves the process. opis
 * compiles pattern with the PCRE D modifier, so an anchored pattern does not
 * accept a trailing line feed, as in ECMA-262.
 *
 * validate() only ever validates what the strict parser returns. opis takes
 * objects as stdClass, so the value model is converted first; a member name
 * a PHP object cannot hold (one that starts with NUL) fails validation.
 */
final class Schema
{
    /** The vendored schema, relative to this file. */
    private const FILE = __DIR__ . '/../../../schema/pact.schema.json';

    private static ?Validator $validator = null;

    private static string $id = '';

    /** @var list<string> */
    private static array $defs = [];

    private function __construct() {}

    /**
     * Strictly parse $json (StrictJson::parse() under $limits) and validate
     * the value against the $defs entry $def; return the parsed value.
     *
     * @throws StrictJsonError          for a document that is not strict JSON
     * @throws SchemaError              for one that fails the definition
     * @throws \InvalidArgumentException for a $def the schema does not define
     */
    public static function validate(string $def, string $json, ?Limits $limits = null): mixed
    {
        self::check($def);
        $value = StrictJson::parse($json, $limits);
        self::validateValue($def, $value);

        return $value;
    }

    /**
     * Validate a value of the package's value model (JsonObject, list,
     * string, int, float, bool, null) against the $defs entry $def.
     *
     * @throws SchemaError
     * @throws \InvalidArgumentException for a $def the schema does not define, or a value outside the model
     */
    public static function validateValue(string $def, mixed $value): void
    {
        self::check($def);
        $issues = [];
        $data = self::plain($value, '', $issues);
        if ($issues !== []) {
            throw new SchemaError($def, $issues);
        }
        $result = self::validator()->validate($data, self::$id . '#/$defs/' . $def);
        $error = $result->error();
        if ($error !== null) {
            $leaves = [];
            self::leaves($error, new ErrorFormatter(), $leaves);
            throw new SchemaError($def, $leaves !== [] ? $leaves : [self::issue($error, new ErrorFormatter())]);
        }
    }

    /**
     * The names of the $defs entries of the schema, in schema order.
     *
     * @return list<string>
     */
    public static function definitions(): array
    {
        self::validator();

        return self::$defs;
    }

    /**
     * The $id of the vendored schema, under which validator() registers it.
     */
    public static function id(): string
    {
        self::validator();

        return self::$id;
    }

    /**
     * The opis validator the module uses: the vendored schema registered
     * under its $id, UriFormat registered as format uri, every error
     * collected. Pass it stdClass objects, not JsonObject.
     */
    public static function validator(): Validator
    {
        if (self::$validator !== null) {
            return self::$validator;
        }
        $text = @file_get_contents(self::FILE);
        if ($text === false) {
            throw new \RuntimeException('schema: cannot read the vendored schema');
        }
        $doc = StrictJson::parse($text, new Limits(4 << 20, 64));
        $id = $doc instanceof JsonObject ? $doc->get('$id') : null;
        $defs = $doc instanceof JsonObject ? $doc->get('$defs') : null;
        if (!\is_string($id) || !$defs instanceof JsonObject) {
            throw new \RuntimeException('schema: the vendored schema has no $id or $defs');
        }
        $issues = [];
        $schema = self::plain($doc, '', $issues);
        if (!$schema instanceof \stdClass || $issues !== []) {
            throw new \RuntimeException('schema: the vendored schema is not an object opis can hold');
        }
        $v = new Validator(null, 1 << 16, false);
        $v->parser()->getFormatResolver()?->register('string', 'uri', new UriFormat());
        $v->resolver()?->registerRaw($schema, $id);
        self::$id = $id;
        self::$defs = $defs->names();

        return self::$validator = $v;
    }

    private static function check(string $def): void
    {
        if (!\in_array($def, self::definitions(), true)) {
            throw new \InvalidArgumentException(\sprintf('schema: %s is not a $defs entry of the schema', json_encode($def, \JSON_UNESCAPED_SLASHES | \JSON_INVALID_UTF8_SUBSTITUTE)));
        }
    }

    /**
     * $v with each JsonObject as a stdClass, for opis. A name a PHP object
     * cannot hold is added to $issues.
     *
     * @param list<SchemaIssue> $issues
     */
    private static function plain(mixed $v, string $path, array &$issues): mixed
    {
        if ($v instanceof JsonObject) {
            $o = new \stdClass();
            foreach ($v->pairs() as [$name, $x]) {
                $p = $path . '/' . strtr($name, ['~' => '~0', '/' => '~1']);
                if (str_starts_with($name, "\0")) {
                    $issues[] = new SchemaIssue($path, 'propertyNames', \sprintf('member name %s starts with NUL, which the validator cannot represent', json_encode($name, \JSON_UNESCAPED_SLASHES | \JSON_UNESCAPED_UNICODE | \JSON_INVALID_UTF8_SUBSTITUTE)));
                    continue;
                }
                $o->{$name} = self::plain($x, $p, $issues);
            }

            return $o;
        }
        if (\is_array($v)) {
            if (!array_is_list($v)) {
                throw new \InvalidArgumentException('schema: an array that is not a list is not a JSON value of the package model');
            }
            $out = [];
            foreach ($v as $i => $x) {
                $out[] = self::plain($x, $path . '/' . $i, $issues);
            }

            return $out;
        }
        if ($v === null || \is_scalar($v)) {
            return $v;
        }

        throw new \InvalidArgumentException(\sprintf('schema: %s is not a JSON value of the package model', get_debug_type($v)));
    }

    /** @param list<SchemaIssue> $out */
    private static function leaves(ValidationError $e, ErrorFormatter $f, array &$out): void
    {
        $sub = $e->subErrors();
        if ($sub === []) {
            $out[] = self::issue($e, $f);

            return;
        }
        foreach ($sub as $s) {
            if ($s instanceof ValidationError) {
                self::leaves($s, $f, $out);
            }
        }
    }

    private static function issue(ValidationError $e, ErrorFormatter $f): SchemaIssue
    {
        $path = '';
        foreach ($e->data()->fullPath() as $p) {
            $path .= '/' . strtr((string) $p, ['~' => '~0', '/' => '~1']);
        }

        return new SchemaIssue($path, $e->keyword(), $f->formatErrorMessage($e));
    }
}
