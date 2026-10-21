<?php

declare(strict_types=1);

namespace HopTop\Pact\Core;

/**
 * An immutable JSON object with its members in document order.
 *
 * The parsed value model of the package: a JSON object is a JsonObject, an
 * array a PHP list, a string a UTF-8 string, an integer literal an int, any
 * other number a float, and true, false and null the PHP values. A PHP
 * array cannot stand for an object, because `{}` and `[]` would collide and
 * an integer-like name such as `"1"` would turn into an int key; a stdClass
 * cannot hold a name that starts with NUL. Names are strings here, always.
 *
 * @implements \IteratorAggregate<string, mixed>
 */
final class JsonObject implements \IteratorAggregate, \Countable
{
    /** @var list<string> */
    private array $names;

    /** @var array<array-key, mixed> member values by name */
    private array $values;

    /**
     * @param iterable<string|int, mixed> $members name => value pairs; an int
     *                                            key is read as its decimal name
     */
    public function __construct(iterable $members = [])
    {
        $this->names = [];
        $this->values = [];
        foreach ($members as $name => $value) {
            $name = (string) $name;
            if (\array_key_exists($name, $this->values)) {
                throw new \InvalidArgumentException(\sprintf('duplicate member %s', json_encode($name, \JSON_UNESCAPED_SLASHES | \JSON_UNESCAPED_UNICODE | \JSON_INVALID_UTF8_SUBSTITUTE)));
            }
            $this->names[] = $name;
            $this->values[$name] = $value;
        }
    }

    /**
     * An object from a list of [name, value] pairs, in that order.
     *
     * @param iterable<array{string, mixed}> $pairs
     */
    public static function fromPairs(iterable $pairs): self
    {
        $o = new self();
        foreach ($pairs as [$name, $value]) {
            if (\array_key_exists($name, $o->values)) {
                throw new \InvalidArgumentException(\sprintf('duplicate member %s', json_encode($name, \JSON_UNESCAPED_SLASHES | \JSON_UNESCAPED_UNICODE | \JSON_INVALID_UTF8_SUBSTITUTE)));
            }
            $o->names[] = $name;
            $o->values[$name] = $value;
        }

        return $o;
    }

    /** Whether the object has a member of this name. */
    public function has(string $name): bool
    {
        return \array_key_exists($name, $this->values);
    }

    /** The value of a member, or $default when the object has none of that name. */
    public function get(string $name, mixed $default = null): mixed
    {
        return \array_key_exists($name, $this->values) ? $this->values[$name] : $default;
    }

    /**
     * The member names, in document order.
     *
     * @return list<string>
     */
    public function names(): array
    {
        return $this->names;
    }

    /**
     * The members as [name, value] pairs, in document order.
     *
     * @return list<array{string, mixed}>
     */
    public function pairs(): array
    {
        $out = [];
        foreach ($this->names as $name) {
            $out[] = [$name, $this->values[$name]];
        }

        return $out;
    }

    /** A copy with one member set: replaced in place, or appended when new. */
    public function with(string $name, mixed $value): self
    {
        $o = clone $this;
        if (!\array_key_exists($name, $o->values)) {
            $o->names[] = $name;
        }
        $o->values[$name] = $value;

        return $o;
    }

    /** A copy without the member of this name. */
    public function without(string $name): self
    {
        if (!\array_key_exists($name, $this->values)) {
            return $this;
        }
        $o = clone $this;
        unset($o->values[$name]);
        $o->names = array_values(array_filter($o->names, static fn(string $n): bool => $n !== $name));

        return $o;
    }

    public function count(): int
    {
        return \count($this->names);
    }

    /** @return \Generator<string, mixed> names stay strings, "1" included */
    public function getIterator(): \Generator
    {
        foreach ($this->names as $name) {
            yield $name => $this->values[$name];
        }
    }
}
