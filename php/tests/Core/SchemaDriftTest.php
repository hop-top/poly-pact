<?php

declare(strict_types=1);

namespace HopTop\Pact\Tests\Core;

use HopTop\Pact\Core\Core;
use HopTop\Pact\Core\JsonObject;
use HopTop\Pact\Core\Wire;
use HopTop\Pact\Tests\Repo;
use HopTop\Pact\Vectors\Fixtures;
use PHPUnit\Framework\TestCase;

/**
 * The generated wire classes against the vendored schema. Port of
 * go/core/schema_drift_test.go.
 *
 * The expected MEMBERS row and constructor parameter of every member are
 * derived here from schema/pact.schema.json, independently of
 * scripts/gen-types.php. A schema change the committed classes do not follow
 * fails here; so does a stale generated file (testGeneratorCheckPasses).
 */
final class SchemaDriftTest extends TestCase
{
    private const NS = 'HopTop\Pact\Core\\';

    private const DIGEST_PATTERN = '^[A-Za-z0-9_-]{43}$';

    /** Inline object members with classes of their own, named as the Go structs. */
    private const INLINE = [
        'GatewayMetadata.endpoints' => 'GatewayEndpoints',
        'ReputationValue.dimensions' => 'ReputationDimensions',
    ];

    /** Payload schemas of extension values: no class (go/core payloadOnly). */
    private const PAYLOAD_ONLY = ['ConformanceDeclaration', 'TransportDeclaration'];

    /** @var list<string> */
    private array $problems = [];

    /** @var array<string, true> */
    private array $reached = [];

    /** @var array<string, list<string>> enum class => the schema values it stands for */
    private array $enumUses = [];

    private static function schema(): JsonObject
    {
        $s = Fixtures::parseJson((string) file_get_contents(Repo::package() . '/schema/pact.schema.json'));
        self::assertInstanceOf(JsonObject::class, $s);

        return $s;
    }

    private static function defs(): JsonObject
    {
        $d = self::schema()->get('$defs');
        self::assertInstanceOf(JsonObject::class, $d);

        return $d;
    }

    public function testSchemaDrift(): void
    {
        $schema = self::schema();
        $defs = self::defs();
        self::assertCount(33, $defs, 'schema $defs entries');
        self::assertCount(33, Wire::TYPES, 'Wire::TYPES: 31 definitions plus 2 inline objects');

        $wire = self::reachable($schema);
        foreach ($defs as $name => $def) {
            if (\in_array($name, self::PAYLOAD_ONLY, true)) {
                if (isset($wire[$name])) {
                    $this->problems[] = \sprintf('$defs/%s is listed payload-only but a wire object reaches it', $name);
                }
                continue;
            }
            if (!isset($wire[$name])) {
                $this->problems[] = \sprintf('$defs/%s is not reachable from the root oneOf', $name);
            }
            if ((Wire::TYPES[$name] ?? null) !== self::NS . $name) {
                $this->problems[] = \sprintf('$defs/%s has no class in Wire::TYPES', $name);
                continue;
            }
            self::assertInstanceOf(JsonObject::class, $def);
            $this->checkClass($name, $def, $name);
        }
        foreach (Wire::TYPES as $name => $class) {
            if (!$defs->has($name) && !\in_array($name, self::INLINE, true)) {
                $this->problems[] = \sprintf('class %s has no $defs entry', $class);
            }
            if (!isset($this->reached[$name])) {
                $this->problems[] = \sprintf('class %s is not reachable from the schema', $class);
            }
        }
        foreach (Wire::ENUMS as $name => $class) {
            $values = array_map(static fn(\BackedEnum $c): string => (string) $c->value, $class::cases());
            if (!isset($this->enumUses[$class])) {
                $this->problems[] = \sprintf('enum %s is not used by any schema enum', $name);
            } elseif ($this->enumUses[$class] !== $values) {
                $this->problems[] = \sprintf('enum %s cases differ from the schema values', $name);
            }
        }
        self::assertSame([], $this->problems, implode("\n", $this->problems));
    }

    private function checkClass(string $path, JsonObject $sch, string $name): void
    {
        $class = self::NS . $name;
        if (!class_exists($class)) {
            $this->problems[] = \sprintf('%s: no class %s', $path, $class);

            return;
        }
        $this->reached[$name] = true;
        $rc = new \ReflectionClass($class);
        if (!$rc->isFinal() || !$rc->isReadOnly()) {
            $this->problems[] = \sprintf('%s: %s is not final readonly', $path, $class);
        }
        if ($sch->get('type') !== 'object' || $sch->get('additionalProperties') !== false) {
            $this->problems[] = \sprintf('%s: not a closed object (unknown members must stay rejected)', $path);
        }
        $props = $sch->get('properties');
        self::assertInstanceOf(JsonObject::class, $props);
        $required = $sch->get('required', []);
        self::assertIsArray($required);

        $members = $rc->getConstant('MEMBERS');
        if (!\is_array($members) || array_keys($members) !== $props->names()) {
            $this->problems[] = \sprintf('%s: MEMBERS keys differ from the schema members %s', $path, implode(', ', $props->names()));

            return;
        }
        $params = [];
        foreach ($rc->getConstructor()?->getParameters() ?? [] as $p) {
            $params[$p->getName()] = $p;
        }
        $names = array_keys($params);
        sort($names);
        $want = $props->names();
        sort($want);
        if ($names !== $want) {
            $this->problems[] = \sprintf('%s: constructor parameters [%s], schema members [%s]', $path, implode(', ', $names), implode(', ', $want));

            return;
        }
        foreach ($props as $m => $p) {
            self::assertInstanceOf(JsonObject::class, $p);
            $row = $this->row($path . '.' . $m, $name, $m, $p);
            $row['required'] = \in_array($m, $required, true);
            if ($members[$m] !== $row) {
                $this->problems[] = \sprintf('%s.%s: MEMBERS row %s, want %s', $path, $m, json_encode($members[$m]), json_encode($row));
            }
            $param = $params[$m];
            $type = self::phpType($row);
            if ((string) $param->getType() !== $type) {
                $this->problems[] = \sprintf('%s.%s: type %s, want %s', $path, $m, $param->getType(), $type);
            }
            if (!$param->isPromoted()) {
                $this->problems[] = \sprintf('%s.%s: not a promoted property', $path, $m);
            }
            if ($row['required'] === $param->isDefaultValueAvailable()) {
                $this->problems[] = \sprintf('%s.%s: required %s, has default %s', $path, $m, var_export($row['required'], true), var_export($param->isDefaultValueAvailable(), true));
            } elseif (!$row['required'] && $param->getDefaultValue() !== null) {
                $this->problems[] = \sprintf('%s.%s: optional member must default to null', $path, $m);
            }
        }
    }

    /**
     * The MEMBERS row a schema member wants, required still false.
     *
     * @return array{kind: string, items: ?string, required: bool, nullable: bool, ref: ?string, enum: ?string}
     */
    private function row(string $path, string $owner, string $member, JsonObject $p, bool $nested = false): array
    {
        $row = ['kind' => '?', 'items' => null, 'required' => false, 'nullable' => false, 'ref' => null, 'enum' => null];
        if ($p->has('anyOf') && !$p->has('type')) {
            $alts = $p->get('anyOf');
            self::assertIsArray($alts);
            $types = array_map(static fn(mixed $a): string => $a instanceof JsonObject && $a->names() === ['type'] ? (string) json_encode($a->get('type')) : '?', $alts);
            if (\count($alts) === 2 && $alts[0] instanceof JsonObject && $types[1] === '"null"') {
                return [...$this->row($path, $owner, $member, $alts[0], $nested), 'nullable' => true];
            }
            sort($types);
            if ($types === ['"boolean"', '"object"']) {
                return [...$row, 'kind' => 'object|boolean'];
            }
            $this->problems[] = $path . ': unhandled anyOf';

            return $row;
        }
        if ($p->has('$ref')) {
            $ref = $p->get('$ref');
            $name = \is_string($ref) ? substr($ref, \strlen('#/$defs/')) : '';
            if (!self::defs()->has($name)) {
                $this->problems[] = \sprintf('%s: $ref to unknown def %s', $path, $name);
            }

            return [...$row, 'kind' => 'object', 'ref' => self::NS . $name];
        }
        if ($p->has('enum')) {
            return [...$row, 'kind' => 'string', 'enum' => $this->enumFor($path, $p->get('enum'))];
        }
        if ($p->has('const')) {
            $c = $p->get('const');

            return [...$row, 'kind' => \is_string($c) ? 'string' : (\is_int($c) ? 'integer' : '?')];
        }
        $t = $p->get('type');
        if ($t === null) {
            return [...$row, 'kind' => 'any'];
        }
        if (\in_array($t, ['string', 'integer', 'number', 'boolean'], true)) {
            return [...$row, 'kind' => $t];
        }
        $sub = $t === 'array' ? $p->get('items', new JsonObject()) : $p->get('additionalProperties');
        if (!$nested && ($t === 'array' || $sub instanceof JsonObject)) {
            self::assertInstanceOf(JsonObject::class, $sub);
            $inner = $this->row($path . '[]', $owner, $member, $sub, true);
            if ($inner['nullable']) {
                $this->problems[] = $path . ': nullable items';
            }

            return [...$row, 'kind' => $t === 'array' ? 'array' : 'object', 'items' => $inner['kind'], 'ref' => $inner['ref'], 'enum' => $inner['enum']];
        }
        if ($t === 'object' && $p->has('properties')) {
            $name = self::INLINE[$owner . '.' . $member] ?? null;
            if ($name === null) {
                $this->problems[] = $path . ': inline object without a class name';

                return $row;
            }
            $this->checkClass($path, $p, $name);

            return [...$row, 'kind' => 'object', 'ref' => self::NS . $name];
        }
        if ($t === 'object') {
            return [...$row, 'kind' => 'object'];
        }
        $this->problems[] = $path . ': unhandled schema shape';

        return $row;
    }

    private function enumFor(string $path, mixed $values): ?string
    {
        if (!\is_array($values) || array_filter($values, 'is_string') !== $values) {
            $this->problems[] = $path . ': not a string enum';

            return null;
        }
        $want = $values;
        sort($want);
        $hits = [];
        foreach (Wire::ENUMS as $class) {
            $have = array_map(static fn(\BackedEnum $c): string => (string) $c->value, $class::cases());
            sort($have);
            if ($have === $want) {
                $hits[] = $class;
            }
        }
        if (\count($hits) !== 1) {
            $this->problems[] = \sprintf('%s: schema enum matches %d enum classes, want one', $path, \count($hits));

            return null;
        }
        if (isset($this->enumUses[$hits[0]]) && $this->enumUses[$hits[0]] !== $values) {
            $this->problems[] = \sprintf('%s: enum %s stands for two value lists', $path, $hits[0]);
        }
        /** @var list<string> $values */
        $this->enumUses[$hits[0]] = $values;

        return $hits[0];
    }

    /** @param array{kind: string, items: ?string, required: bool, nullable: bool, ref: ?string, enum: ?string} $row */
    private static function phpType(array $row): string
    {
        $t = match ($row['kind']) {
            'string' => 'string',
            'integer' => 'int',
            'number' => 'float',
            'boolean' => 'bool',
            'array' => 'array',
            'object' => $row['items'] === null && $row['ref'] !== null ? $row['ref'] : JsonObject::class,
            default => 'mixed',
        };
        if ($t !== 'mixed' && ($row['nullable'] || !$row['required'])) {
            return '?' . $t;
        }

        return $t;
    }

    /** @return array<string, true> the $defs entries reachable from the root oneOf */
    private static function reachable(JsonObject $schema): array
    {
        $defs = self::defs();
        $seen = [];
        $todo = self::refs($schema->get('oneOf'));
        while ($todo !== []) {
            $name = array_pop($todo);
            if (!isset($seen[$name])) {
                $seen[$name] = true;
                array_push($todo, ...self::refs($defs->get($name)));
            }
        }

        return $seen;
    }

    /** @return list<string> */
    private static function refs(mixed $node): array
    {
        $out = [];
        if ($node instanceof JsonObject) {
            $ref = $node->get('$ref');
            if (\is_string($ref) && str_starts_with($ref, '#/$defs/')) {
                $out[] = substr($ref, \strlen('#/$defs/'));
            }
            foreach ($node as $v) {
                array_push($out, ...self::refs($v));
            }
        } elseif (\is_array($node)) {
            foreach ($node as $v) {
                array_push($out, ...self::refs($v));
            }
        }

        return $out;
    }

    /** @return list<JsonObject> every schema object in $node */
    private static function walk(mixed $node): array
    {
        $out = [];
        if ($node instanceof JsonObject) {
            $out[] = $node;
        }
        if ($node instanceof JsonObject || \is_array($node)) {
            foreach ($node as $v) {
                array_push($out, ...self::walk($v));
            }
        }

        return $out;
    }

    public function testConstantsFollowTheSchema(): void
    {
        $versions = [];
        $patterns = 0;
        foreach (self::walk(self::schema()) as $n) {
            $props = $n->get('properties');
            $pv = $props instanceof JsonObject ? $props->get('pact_version') : null;
            if ($pv instanceof JsonObject) {
                $versions[json_encode($pv->get('const'))] = true;
            }
            if ($n->get('pattern') === self::DIGEST_PATTERN) {
                ++$patterns;
            }
        }
        self::assertSame([json_encode(Core::VERSION) => true], $versions);
        self::assertGreaterThan(0, $patterns, 'the schema has no digest pattern');
        self::assertSame(43, Core::DIGEST_LEN);
    }

    public function testEveryGeneratedFileIsListed(): void
    {
        $listed = [...array_keys(Wire::TYPES), ...array_keys(Wire::ENUMS), 'Wire'];
        $generated = [];
        foreach (glob(Repo::package() . '/src/Core/*.php') ?: [] as $path) {
            if (str_contains((string) file_get_contents($path), '// Code generated by scripts/gen-types.php')) {
                $generated[] = basename($path, '.php');
            }
        }
        sort($listed);
        sort($generated);
        self::assertSame($listed, $generated);
    }

    public function testGeneratorCheckPasses(): void
    {
        $cmd = [\PHP_BINARY, Repo::package() . '/scripts/gen-types.php', '--check'];
        $proc = proc_open($cmd, [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        self::assertIsResource($proc);
        $out = stream_get_contents($pipes[1]) . stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        self::assertSame(0, proc_close($proc), (string) $out);
    }
}
