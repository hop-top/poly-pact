<?php

declare(strict_types=1);

namespace HopTop\Pact\Core\StrictJson;

use HopTop\Pact\Core\JsonObject;

/**
 * What the walk checks one value against: the counterpart of the Go
 * reflect.Type the walker resolves, read from a MEMBERS table.
 *
 * A class target ("struct") is a class with a MEMBERS constant, as the
 * generated wire classes have, and a constructor that takes each member as a
 * named parameter of the same name, the members not required having a
 * default. MEMBERS rows have the keys kind (string, integer, number,
 * boolean, object, array, object|boolean or any), items (the kind of the
 * items of an array or the values of a map, or null), required, nullable, ref
 * (the class of an object member, its items or its values) and enum (not
 * read here: the decoder does not apply enum sets).
 *
 * @internal
 */
final class Target
{
    public const STRING = 0;
    public const INT = 1;
    public const FLOAT = 2;
    public const BOOL = 3;
    public const STRUCT = 4;
    public const MAP = 5;
    public const SLICE = 6;
    public const RAW = 7;

    private const KIND_NAMES = ['string', 'integer', 'number', 'boolean', 'object', 'object', 'array', 'any'];

    private const SCALARS = ['string' => self::STRING, 'integer' => self::INT, 'number' => self::FLOAT, 'boolean' => self::BOOL];

    /** @var array<string, array{fields: array<string, Target>, required: list<string>}> */
    private static array $structs = [];

    private static ?self $free = null;

    /** @param string|null $class the class of a STRUCT target */
    private function __construct(
        public readonly int $kind,
        public readonly bool $nullable = false,
        public readonly ?self $elem = null,
        public readonly ?string $class = null,
    ) {}

    /** A free-form value: any JSON value, null included (Go json.RawMessage, any). */
    public static function free(): self
    {
        return self::$free ??= new self(self::RAW, true);
    }

    /**
     * The target of a decode into $class: a class with a MEMBERS table, or
     * JsonObject for an object of free-form values (Go map[string]any). Every
     * class it reaches is checked here, before the input is read.
     *
     * @throws StrictJsonError TARGET
     */
    public static function of(string $class): self
    {
        if ($class === JsonObject::class) {
            return new self(self::MAP, false, self::free());
        }
        self::struct($class);

        return new self(self::STRUCT, false, null, $class);
    }

    /** The type name of the target, for a detail message. */
    public function name(): string
    {
        if ($this->kind === self::STRUCT && $this->class !== null) {
            $i = strrpos($this->class, '\\');

            return $i === false ? $this->class : substr($this->class, $i + 1);
        }
        if ($this->elem !== null && $this->kind === self::MAP) {
            return 'map of ' . $this->elem->name();
        }
        if ($this->elem !== null && $this->kind === self::SLICE) {
            return 'list of ' . $this->elem->name();
        }

        return self::KIND_NAMES[$this->kind];
    }

    /**
     * The member targets and required members of a struct class.
     *
     * @return array{fields: array<string, Target>, required: list<string>}
     *
     * @throws StrictJsonError TARGET
     */
    public static function struct(string $class): array
    {
        if (isset(self::$structs[$class])) {
            return self::$structs[$class];
        }
        $fail = static fn(string $why): StrictJsonError => new StrictJsonError(StrictJsonErrorKind::TARGET, '', 0, \sprintf('got %s: %s', json_encode($class, \JSON_UNESCAPED_SLASHES | \JSON_INVALID_UTF8_SUBSTITUTE), $why));
        if ($class === '' || !class_exists($class) || enum_exists($class)) {
            throw $fail('not a class');
        }
        $rc = new \ReflectionClass($class);
        $members = $rc->hasConstant('MEMBERS') ? $rc->getConstant('MEMBERS') : null;
        if (!\is_array($members)) {
            throw $fail('no MEMBERS table');
        }
        $params = [];
        foreach ($rc->getConstructor()?->getParameters() ?? [] as $p) {
            $params[$p->getName()] = $p->isOptional();
        }
        // Entered before the members are read, so a class that reaches itself
        // does not recurse; replaced below once its table is complete.
        self::$structs[$class] = ['fields' => [], 'required' => []];
        try {
            $fields = [];
            $required = [];
            foreach ($members as $name => $row) {
                $name = (string) $name;
                if (!\is_array($row) || !\is_string($row['kind'] ?? null) || !\is_bool($row['required'] ?? null) || !\is_bool($row['nullable'] ?? null)) {
                    throw $fail(\sprintf('MEMBERS row %s is malformed', $name));
                }
                $ref = $row['ref'] ?? null;
                $items = $row['items'] ?? null;
                if (($ref !== null && !\is_string($ref)) || ($items !== null && !\is_string($items))) {
                    throw $fail(\sprintf('MEMBERS row %s is malformed', $name));
                }
                if (!isset($params[$name])) {
                    throw $fail(\sprintf('member %s is not a constructor parameter', $name));
                }
                if (!$row['required'] && !$params[$name]) {
                    throw $fail(\sprintf('optional member %s has no default', $name));
                }
                $t = self::member($row['kind'], $items, $ref, $fail);
                if ($row['nullable'] && $t->kind !== self::RAW) {
                    $t = new self($t->kind, true, $t->elem, $t->class);
                }
                $fields[$name] = $t;
                if ($row['required']) {
                    $required[] = $name;
                }
            }
            foreach ($params as $name => $optional) {
                if (!$optional && !isset($fields[(string) $name])) {
                    throw $fail(\sprintf('constructor parameter %s is not a member', $name));
                }
            }
        } catch (StrictJsonError $e) {
            unset(self::$structs[$class]);
            throw $e;
        }

        return self::$structs[$class] = ['fields' => $fields, 'required' => $required];
    }

    /** @param \Closure(string): StrictJsonError $fail */
    private static function member(string $kind, ?string $items, ?string $ref, \Closure $fail): self
    {
        if ($kind === 'array') {
            return new self(self::SLICE, false, $items === null ? self::free() : self::member($items, null, $ref, $fail));
        }
        if ($kind === 'object' && $items !== null) {
            return new self(self::MAP, false, self::member($items, null, $ref, $fail));
        }
        if ($kind === 'object' && $ref !== null) {
            self::struct($ref);

            return new self(self::STRUCT, false, null, $ref);
        }
        if ($kind === 'object') {
            // An open object (Go core.Object): free-form member values.
            return new self(self::MAP, false, self::free());
        }
        if ($kind === 'any' || $kind === 'object|boolean') {
            return self::free();
        }
        if (isset(self::SCALARS[$kind])) {
            return new self(self::SCALARS[$kind]);
        }
        throw $fail(\sprintf('unknown member kind %s', $kind));
    }

    /**
     * The value of an absent required member: the Go zero value of its type.
     *
     * @throws StrictJsonError TARGET
     */
    public function zero(): mixed
    {
        return match (true) {
            $this->nullable => null,
            $this->kind === self::STRING => '',
            $this->kind === self::INT => 0,
            $this->kind === self::FLOAT => 0.0,
            $this->kind === self::BOOL => false,
            $this->kind === self::SLICE => [],
            $this->kind === self::MAP => new JsonObject(),
            $this->kind === self::STRUCT && $this->class !== null => self::build($this->class, []),
            default => null,
        };
    }

    /**
     * An instance of the struct class $class from its decoded members; an
     * absent required member holds its zero value.
     *
     * @param array<string, mixed> $values
     *
     * @throws StrictJsonError TARGET
     */
    public static function build(string $class, array $values): object
    {
        $s = self::struct($class);
        foreach ($s['required'] as $name) {
            if (!\array_key_exists($name, $values)) {
                $values[$name] = $s['fields'][$name]->zero();
            }
        }

        try {
            return new $class(...$values);
        } catch (\TypeError $e) {
            // A hand-written target whose constructor types disagree with MEMBERS.
            throw new StrictJsonError(StrictJsonErrorKind::TARGET, '', 0, \sprintf('%s: %s', $class, $e->getMessage()), $e);
        }
    }
}
