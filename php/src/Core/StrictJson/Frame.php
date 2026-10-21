<?php

declare(strict_types=1);

namespace HopTop\Pact\Core\StrictJson;

/**
 * One open object or array of the walk.
 *
 * @internal
 */
final class Frame
{
    /** @var array<string, Target>|null the member targets of a struct, null otherwise */
    public readonly ?array $fields;

    /** The target of the items or member values when there is no member table. */
    public readonly Target $elem;

    /** @var list<mixed> the array items */
    public array $items = [];

    /** @var list<array{string, mixed}> the object members, as [name, value] pairs */
    public array $pairs = [];

    /** @var array<array-key, true> the member names seen so far */
    public array $seen = [];

    /** @param Target|null $target null: free-form, or a container that does not fit its target */
    public function __construct(public readonly bool $isObject, public readonly ?Target $target)
    {
        $fields = null;
        $elem = Target::free();
        if ($target !== null && $target->kind === Target::STRUCT && $target->class !== null) {
            $fields = Target::struct($target->class)['fields'];
        } elseif ($target?->elem !== null) {
            $elem = $target->elem;
        }
        $this->fields = $fields;
        $this->elem = $elem;
    }
}
