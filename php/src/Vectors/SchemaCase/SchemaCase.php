<?php

declare(strict_types=1);

namespace HopTop\Pact\Vectors\SchemaCase;

use HopTop\Pact\Core\JsonObject;
use HopTop\Pact\Core\StrictJson\Limits;
use HopTop\Pact\Core\StrictJson\StrictJson;
use HopTop\Pact\Core\StrictJson\StrictJsonError;
use HopTop\Pact\Vectors\Entry;

/**
 * A schema entry's input and expectation (spec/v1.0/fixtures/schema/README.md,
 * Inputs and Outcomes).
 */
final readonly class SchemaCase
{
    public const string ACCEPTED = 'ACCEPTED';

    public const string REJECTED = 'REJECTED';

    /**
     * Bounds the nesting of an object list file. The depth limit of draft
     * 20.1 applies to each object, counted from the object, so the file
     * itself may nest deeper: the file's object, the objects array and the
     * element add three levels above an object that may be over the limit.
     */
    public const int OBJECT_LIST_MAX_DEPTH = 4 * StrictJson::DEFAULT_MAX_DEPTH;

    /**
     * @param string               $file    the input file
     * @param list<SchemaDocument> $docs    its documents, in order
     * @param string               $outcome ACCEPTED or REJECTED
     * @param string               $code    the expected transport_code of a REJECTED entry
     */
    public function __construct(
        public string $file,
        public array $docs,
        public string $outcome,
        public string $code = '',
    ) {}

    /**
     * Read the input and the expectation of the schema entry $e of the
     * fixture directory $root.
     *
     * @throws SchemaCaseError
     */
    public static function read(string $root, Entry $e): self
    {
        $outcome = $e->outcome ?? '';
        $code = '';
        if ($outcome === self::ACCEPTED) {
            if ($e->expected !== $e->path) {
                throw new SchemaCaseError('an ACCEPTED schema case carries its expectation inline: expected must be its path');
            }
        } elseif ($outcome === self::REJECTED) {
            if ($e->expected === null) {
                throw new SchemaCaseError('a REJECTED schema case names its decision.json as expected');
            }
            $code = self::decisionCode($root, $e->expected);
        } else {
            throw new SchemaCaseError(\sprintf('outcome %s, want ACCEPTED or REJECTED', json_encode($outcome, \JSON_UNESCAPED_SLASHES | \JSON_UNESCAPED_UNICODE)));
        }
        $file = rtrim($root, '/') . '/' . $e->path;

        return new self($file, self::documents($file, $e->path), $outcome, $code);
    }

    /**
     * The documents of the input file $file: one compact JWS for a .jws
     * file, the objects of an object list for a .json file. $name names the
     * file in errors.
     *
     * @return list<SchemaDocument>
     *
     * @throws SchemaCaseError
     */
    public static function documents(string $file, string $name = ''): array
    {
        $name = $name !== '' ? $name : $file;
        $b = self::readFile($file, $name);
        if (str_ends_with($name, '.jws')) {
            return [new SchemaDocument(trim($b, " \t\n\v\f\r"))];
        }
        if (!str_ends_with($name, '.json')) {
            throw new SchemaCaseError(\sprintf('%s: a schema case is a .jws or a .json file', $name));
        }
        try {
            return self::objectList($b);
        } catch (SchemaCaseError|StrictJsonError $err) {
            throw new SchemaCaseError(\sprintf('%s: %s', $name, $err->getMessage()), 0, $err);
        }
    }

    /**
     * Apply the verdict to each document and return how the verdicts
     * contradict the expectation: a document of an ACCEPTED case that is
     * rejected, or one of a REJECTED case that is accepted or rejected with
     * another code. None means the expectation holds.
     *
     * @return list<string>
     */
    public function verdicts(SchemaValidator $v): array
    {
        $problems = [];
        foreach ($this->docs as $i => $d) {
            $where = \sprintf('document %d', $i + 1);
            try {
                $r = $d->verdict($v);
            } catch (\InvalidArgumentException|\RuntimeException $err) {
                $problems[] = \sprintf('%s: validate against %s: %s', $where, $d->def !== '' ? $d->def : 'its definition', $err->getMessage());
                continue;
            }
            if ($this->outcome === self::ACCEPTED && !$r->accepted) {
                $problems[] = \sprintf('%s: rejected with %s (%s), want accepted', $where, $r->code, $r->why);
            } elseif ($this->outcome === self::REJECTED && $r->accepted) {
                $problems[] = \sprintf('%s: accepted, want rejected with %s', $where, $this->code);
            } elseif ($this->outcome === self::REJECTED && $r->code !== $this->code) {
                $problems[] = \sprintf('%s: rejected with %s (%s), want %s', $where, $r->code, $r->why, $this->code);
            }
        }

        return $problems;
    }

    /** The transport_code of the decision.json $rel. */
    private static function decisionCode(string $root, string $rel): string
    {
        $b = self::readFile(rtrim($root, '/') . '/' . $rel, $rel);
        try {
            $d = StrictJson::parse($b);
        } catch (StrictJsonError $err) {
            throw new SchemaCaseError(\sprintf('%s: %s', $rel, $err->getMessage()), 0, $err);
        }
        if (!$d instanceof JsonObject) {
            throw new SchemaCaseError(\sprintf('%s: not a JSON object', $rel));
        }
        foreach ($d->names() as $n) {
            if (!\in_array($n, ['transport_code', 'rejected_before_crypto', 'reason'], true)) {
                throw new SchemaCaseError(\sprintf('%s: unknown member %s', $rel, json_encode($n, \JSON_UNESCAPED_UNICODE)));
            }
        }
        $rbc = $d->get('rejected_before_crypto');
        $reason = $d->get('reason');
        if (($rbc !== null && !\is_bool($rbc)) || ($reason !== null && !\is_string($reason))) {
            throw new SchemaCaseError(\sprintf('%s: rejected_before_crypto is not a boolean or reason not a string', $rel));
        }
        $code = $d->get('transport_code');
        if ($code !== null && !\is_string($code)) {
            throw new SchemaCaseError(\sprintf('%s: transport_code is not a string', $rel));
        }
        if ($code === null || $code === '') {
            throw new SchemaCaseError(\sprintf('%s: no transport_code', $rel));
        }

        return $code;
    }

    private static function readFile(string $path, string $name): string
    {
        $b = is_file($path) ? @file_get_contents($path) : false;
        if ($b === false) {
            throw new SchemaCaseError(\sprintf('open %s: %s', $name, file_exists($path) ? 'cannot be read' : 'no such file or directory'));
        }

        return $b;
    }

    /**
     * The documents of an object list. The file is strict JSON as a whole;
     * each object is checked as a document of its own by the verdict.
     *
     * @return list<SchemaDocument>
     */
    private static function objectList(string $b): array
    {
        $l = StrictJson::parse($b, new Limits(0, self::OBJECT_LIST_MAX_DEPTH));
        if (!$l instanceof JsonObject) {
            throw new SchemaCaseError('not a JSON object');
        }
        self::members($l, ['description', 'objects'], '');
        $desc = $l->get('description');
        if (!\is_string($desc) && $desc !== null) {
            throw new SchemaCaseError('description is not a string');
        }
        if ($desc === null || $desc === '') {
            throw new SchemaCaseError('no description');
        }
        $objects = $l->get('objects');
        if (!\is_array($objects) && $objects !== null) {
            throw new SchemaCaseError('objects is not an array');
        }
        if ($objects === null || $objects === []) {
            throw new SchemaCaseError('no objects');
        }
        $docs = [];
        foreach ($objects as $i => $o) {
            $where = \sprintf('objects[%d]', $i);
            if (!$o instanceof JsonObject) {
                throw new SchemaCaseError($where . ': not a JSON object');
            }
            self::members($o, ['section', 'typ', 'def', 'object'], $where . ': ');
            foreach (['section', 'typ', 'def'] as $m) {
                if ($o->get($m) !== null && !\is_string($o->get($m))) {
                    throw new SchemaCaseError(\sprintf('%s: %s is not a string', $where, $m));
                }
            }
            $typ = $o->get('typ');
            $def = $o->get('def');
            $object = $o->get('object');
            if ($o->get('section') === null || $o->get('section') === '') {
                throw new SchemaCaseError($where . ': no section');
            }
            if (!$object instanceof JsonObject) {
                throw new SchemaCaseError($where . ': object is not a JSON object');
            }
            if (($typ === null) === ($def === null)) {
                throw new SchemaCaseError($where . ': exactly one of typ and def');
            }
            if (\is_string($def)) {
                $docs[] = new SchemaDocument('', $def, self::encode($object));
                continue;
            }
            \assert(\is_string($typ));
            $d = SchemaFixture::typDef($typ);
            if ($d === null) {
                throw new SchemaCaseError(\sprintf('%s: typ %s is not a typ of the draft 7.3 table', $where, json_encode($typ, \JSON_UNESCAPED_SLASHES | \JSON_UNESCAPED_UNICODE)));
            }
            $docs[] = new SchemaDocument('', $d, self::encode($object));
        }

        return $docs;
    }

    /** @param list<string> $known */
    private static function members(JsonObject $o, array $known, string $where): void
    {
        foreach ($o->names() as $n) {
            if (!\in_array($n, $known, true)) {
                throw new SchemaCaseError(\sprintf('%sunknown member %s', $where, json_encode($n, \JSON_UNESCAPED_SLASHES | \JSON_UNESCAPED_UNICODE)));
            }
        }
    }

    /** A value of the package's model as compact JSON text, members in order, at any depth. */
    private static function encode(mixed $v): string
    {
        if ($v instanceof JsonObject) {
            $parts = [];
            foreach ($v->pairs() as [$k, $x]) {
                $parts[] = self::encode($k) . ':' . self::encode($x);
            }

            return '{' . implode(',', $parts) . '}';
        }
        if (\is_array($v)) {
            return '[' . implode(',', array_map(self::encode(...), $v)) . ']';
        }

        return json_encode($v, \JSON_UNESCAPED_SLASHES | \JSON_UNESCAPED_UNICODE | \JSON_PRESERVE_ZERO_FRACTION | \JSON_THROW_ON_ERROR);
    }
}
