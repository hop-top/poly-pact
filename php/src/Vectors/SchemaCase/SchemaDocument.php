<?php

declare(strict_types=1);

namespace HopTop\Pact\Vectors\SchemaCase;

use HopTop\Pact\Core\Jcs\Jcs;
use HopTop\Pact\Core\JsonObject;
use HopTop\Pact\Core\Jws\Base64Url;
use HopTop\Pact\Core\Schema\SchemaIssue;
use HopTop\Pact\Core\StrictJson\StrictJson;
use HopTop\Pact\Core\StrictJson\StrictJsonError;

/**
 * One document of a schema case's input: a compact JWS, or an object of an
 * object list with the definition its typ or def selects.
 */
final readonly class SchemaDocument
{
    /**
     * @param string      $compact the compact JWS, '' for an object of an object list
     * @param string      $def     the definition of an object of an object list, '' for a JWS
     * @param string|null $object  the object of an object list as JSON text, null for a JWS
     */
    public function __construct(
        public string $compact = '',
        public string $def = '',
        public ?string $object = null,
    ) {}

    /**
     * Apply the steps of spec/v1.0/fixtures/schema/README.md, Verdict: the
     * form of a compact JWS, its typ, strict JSON, then the schema. The
     * signature is not verified.
     *
     * @throws \InvalidArgumentException|\RuntimeException when $v cannot validate: no verdict
     */
    public function verdict(SchemaValidator $v): Verdict
    {
        $def = $this->def;
        $object = $this->object;
        if ($object === null) {
            $seg = explode('.', $this->compact);
            if (\count($seg) !== 3) {
                return Verdict::rejected(\sprintf('a compact JWS has three segments separated by two periods, not %d', \count($seg)));
            }
            try {
                $raw = Base64Url::decode($seg[0]);
            } catch (\UnexpectedValueException $e) {
                return Verdict::rejected('protected header: not canonical base64url: ' . $e->getMessage());
            }
            try {
                $header = StrictJson::parse($raw);
            } catch (StrictJsonError $e) {
                return Verdict::rejected('protected header: ' . $e->getMessage());
            }
            if (!$header instanceof JsonObject) {
                return Verdict::rejected('protected header: not a JSON object');
            }
            $typ = $header->get('typ');
            if (!\is_string($typ)) {
                return Verdict::rejected('protected header: no typ string');
            }
            $def = SchemaFixture::typDef($typ);
            if ($def === null) {
                return Verdict::rejected(\sprintf('typ %s is not a typ of the draft 7.3 table', json_encode($typ, \JSON_UNESCAPED_SLASHES | \JSON_UNESCAPED_UNICODE | \JSON_INVALID_UTF8_SUBSTITUTE)));
            }
            try {
                $object = Base64Url::decode($seg[1]);
            } catch (\UnexpectedValueException $e) {
                return Verdict::rejected('payload: not canonical base64url: ' . $e->getMessage());
            }
        }
        try {
            StrictJson::parse($object);
        } catch (StrictJsonError $e) {
            return Verdict::rejected($def . ': ' . $e->getMessage());
        }
        $issues = $v->validateDef($def, $object);
        if ($issues !== []) {
            return Verdict::rejected($def . ': ' . implode('; ', array_map(self::issue(...), $issues)));
        }

        return Verdict::accepted();
    }

    /**
     * The decoded object as far as it decodes, as RFC 8785 canonical JSON:
     * the payload of a compact JWS, or the object of an object list; null
     * for a payload that does not decode or is not strict JSON.
     */
    public function decoded(): ?string
    {
        $text = $this->object;
        if ($text === null) {
            $seg = explode('.', $this->compact);
            if (\count($seg) !== 3) {
                return null;
            }
            try {
                $text = Base64Url::decode($seg[1]);
            } catch (\UnexpectedValueException) {
                return null;
            }
        }
        try {
            return Jcs::canonicalize($text);
        } catch (StrictJsonError) {
            return null;
        }
    }

    /** An issue as Go's SchemaViolation.String() writes it: "POINTER: KEYWORD: MESSAGE", the pointer '' written "(document)". */
    public static function issue(SchemaIssue $i): string
    {
        return ($i->instancePath !== '' ? $i->instancePath : '(document)') . ': ' . $i->keyword . ': ' . $i->message;
    }
}
