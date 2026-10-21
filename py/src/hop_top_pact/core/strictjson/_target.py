"""Decode targets: what the walk checks a value against, read from dataclass annotations."""

from __future__ import annotations

import contextlib
import dataclasses
import types
import typing
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final

from hop_top_pact.core.types import JSONValue

STRING, INT, FLOAT, BOOL, STRUCT, MAP, SLICE, RAW = range(8)
_KIND_NAMES: Final = ("string", "integer", "number", "boolean", "object", "object", "array", "")


@dataclass(frozen=True, slots=True)
class Target:
    kind: int
    nullable: bool = False
    elem: Target | None = None
    cls: type | None = None

    def name(self) -> str:
        if self.kind == STRUCT and self.cls is not None:
            return self.cls.__name__
        if self.kind == MAP and self.elem is not None:
            return f"Mapping[str, {self.elem.name()}]"
        if self.kind == SLICE and self.elem is not None:
            return f"tuple[{self.elem.name()}, ...]"
        return _KIND_NAMES[self.kind] or "JSONValue"


FREE: Final = Target(RAW, True)


@dataclass(frozen=True, slots=True)
class Struct:
    fields: Mapping[str, Target]
    required: tuple[str, ...]


_TARGETS: dict[Any, Target] = {}
_STRUCTS: dict[type, Struct] = {}
_UNIONS: Final = (typing.Union, types.UnionType)
_MAPPINGS: Final = (Mapping, dict, typing.Mapping, typing.Dict)  # noqa: UP006


def target_of(tp: Any) -> Target:
    try:
        return _TARGETS[tp]
    except (KeyError, TypeError):
        pass
    t = _compile(tp)
    with contextlib.suppress(TypeError):  # an unhashable annotation is compiled each time
        _TARGETS[tp] = t
    return t


def _compile(tp: Any) -> Target:
    if isinstance(tp, typing.ForwardRef):
        tp = tp.__forward_arg__
    if isinstance(tp, str):
        # JSONValue is a recursive alias spelled as a string.
        if tp == JSONValue:
            return FREE
        raise TypeError(f"unresolved annotation {tp!r}")
    if tp is Any or tp is object:
        return FREE
    origin, args = typing.get_origin(tp), typing.get_args(tp)
    if origin in _UNIONS:
        rest = [a for a in args if a is not type(None)]
        if len(rest) == 1 and len(rest) < len(args):
            return dataclasses.replace(target_of(rest[0]), nullable=True)
        return FREE  # a union of JSON kinds holds any value, like json.RawMessage
    if origin in _MAPPINGS:
        if len(args) != 2 or args[0] is not str:
            raise TypeError(f"{tp!r}: mapping keys must be str")
        return Target(MAP, elem=target_of(args[1]))
    if origin is tuple:
        if len(args) != 2 or args[1] is not Ellipsis:
            raise TypeError(f"{tp!r}: only tuple[X, ...] is supported")
        return Target(SLICE, elem=target_of(args[0]))
    if origin in (list, Sequence, typing.Sequence, typing.List):  # noqa: UP006
        if len(args) != 1:
            raise TypeError(f"{tp!r}: element type missing")
        return Target(SLICE, elem=target_of(args[0]))
    if isinstance(tp, type) and origin is None:
        if issubclass(tp, bool):
            return Target(BOOL)
        if issubclass(tp, str):
            return Target(STRING)
        if issubclass(tp, int):
            return Target(INT)
        if issubclass(tp, float):
            return Target(FLOAT)
        if dataclasses.is_dataclass(tp):
            return Target(STRUCT, cls=tp)
    raise TypeError(f"{tp!r} is not a decode target")


_PREPARED: set[Target] = set()


def prepare(top: Target) -> None:
    """Resolve the field tables of every dataclass the target reaches, so that an
    unusable annotation is a TARGET error before the input is read."""
    if top in _PREPARED:
        return
    seen: set[type] = set()
    todo = [top]
    while todo:
        t = todo.pop()
        if t.kind == STRUCT and t.cls is not None:
            if t.cls in seen:
                continue
            seen.add(t.cls)
            todo.extend(struct_of(t.cls).fields.values())
        elif t.elem is not None:
            todo.append(t.elem)
    _PREPARED.add(top)


def struct_of(cls: type) -> Struct:
    s = _STRUCTS.get(cls)
    if s is not None:
        return s
    hints = typing.get_type_hints(cls)
    members: Mapping[str, Any] | None = getattr(cls, "_MEMBERS", None)
    fields: dict[str, Target] = {}
    required: list[str] = []
    for f in dataclasses.fields(cls):
        if not f.init:
            continue
        t = target_of(hints[f.name])
        m = members.get(f.name) if members is not None else None
        if m is not None:
            # The member table says whether null is allowed: an optional
            # annotation of a wire type is an absent member, not a null one.
            t = dataclasses.replace(t, nullable=bool(m.nullable) or t.kind == RAW)
        fields[f.name] = t
        if f.default is dataclasses.MISSING and f.default_factory is dataclasses.MISSING:
            required.append(f.name)
    s = Struct(fields, tuple(required))
    _STRUCTS[cls] = s
    return s


def _zero(t: Target) -> Any:
    """The value of an absent required member: the Go zero value of its type."""
    if t.nullable:
        return None
    if t.kind == STRING:
        return ""
    if t.kind == INT:
        return 0
    if t.kind == FLOAT:
        return 0.0
    if t.kind == BOOL:
        return False
    if t.kind == SLICE:
        return ()
    if t.kind == MAP:
        return {}
    if t.kind == STRUCT and t.cls is not None:
        return build(t.cls, {})
    return None


def build(cls: type, values: dict[str, Any]) -> Any:
    s = struct_of(cls)
    for name in s.required:
        if name not in values:
            values[name] = _zero(s.fields[name])
    return cls(**values)
