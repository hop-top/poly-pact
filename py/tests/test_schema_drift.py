"""Generated wire types against the vendored schema. Port of go/core/schema_drift_test.go.

The expected shape of every class is recomputed here from the schema the
package ships, independently of scripts/gen_types.py: field names and their
order, annotations, defaults, and each ``_MEMBERS`` row. A schema change
that the committed types do not follow fails here.
"""

from __future__ import annotations

import dataclasses
import json
from enum import StrEnum
from importlib.resources import files
from typing import Any, NamedTuple

from hop_top_pact import core
from hop_top_pact.core import enums, types
from hop_top_pact.core.types import TYPES, Member

DIGEST_PATTERN = "^[A-Za-z0-9_-]{43}$"

# Inline object members have classes of their own, named as the Go structs
# of go/core/types.go.
INLINE = {
    ("GatewayMetadata", "endpoints"): "GatewayEndpoints",
    ("ReputationValue", "dimensions"): "ReputationDimensions",
}

# The payload-only $defs entries: payload schemas of extension values, not in
# the root oneOf and reached by no wire object, with no class (go/core
# payloadOnly).
PAYLOAD_ONLY = {"ConformanceDeclaration", "TransportDeclaration"}

# Exported classes of core.types with no wire form, so no schema entry.
PY_ONLY = {"Member"}

ENUM_CLASSES: list[type[StrEnum]] = [getattr(enums, n) for n in enums.__all__]


def load_schema() -> dict[str, Any]:
    text = files("hop_top_pact").joinpath("schema/pact.schema.json").read_text(encoding="utf-8")
    schema: dict[str, Any] = json.loads(text)
    return schema


class Shape(NamedTuple):
    annotation: str
    kind: str
    nullable: bool
    ref: str | None


class Drift:
    def __init__(self, defs: dict[str, Any]) -> None:
        self.defs = defs
        self.problems: list[str] = []
        self.reached: set[str] = set()
        self.enums: dict[str, frozenset[str]] = {}

    def fail(self, msg: str) -> None:
        self.problems.append(msg)

    def check_class(self, path: str, sch: dict[str, Any], cls: type | None) -> None:
        if cls is None or not dataclasses.is_dataclass(cls):
            self.fail(f"{path}: schema object has properties, Python type is {cls!r}")
            return
        self.reached.add(cls.__name__)
        params = cls.__dataclass_params__  # type: ignore[attr-defined]
        if not params.frozen:
            self.fail(f"{path}: {cls.__name__} is not frozen")
        if "__slots__" not in cls.__dict__:
            self.fail(f"{path}: {cls.__name__} has no slots")

        if sch.get("type") != "object":
            self.fail(f"{path}: schema type is {sch.get('type')!r}, want object")
        if sch.get("additionalProperties") is not False:
            self.fail(
                f"{path}: additionalProperties is not false (unknown members must stay rejected)"
            )
        props: dict[str, Any] = sch.get("properties", {})
        required = set(sch.get("required", []))
        for r in sorted(required - set(props)):
            self.fail(f"{path}: required {r!r} is not a property")

        fields = {f.name: f for f in dataclasses.fields(cls)}
        if list(fields) != list(props):
            self.fail(f"{path}: fields {list(fields)}, schema members {list(props)}")
        members: Any = getattr(cls, "_MEMBERS", None)
        if members is None or list(members) != list(props):
            self.fail(f"{path}: _MEMBERS {list(members or [])}, schema members {list(props)}")
            members = {}

        for name, p in props.items():
            f = fields.get(name)
            if f is None:
                self.fail(f"{path}: schema property {name!r} has no field")
                continue
            want = self.shape(f"{path}.{name}", cls.__name__, name, p)
            req = name in required
            ann = want.annotation + (" | None" if want.nullable or not req else "")
            if f.type != ann:
                self.fail(f"{path}.{name}: annotation {f.type!r}, schema wants {ann!r}")
            if not f.kw_only:
                self.fail(f"{path}.{name}: not keyword-only")
            if req and f.default is not dataclasses.MISSING:
                self.fail(f"{path}.{name}: required member has a default")
            if not req and f.default is not None:
                self.fail(f"{path}.{name}: optional member must default to None")
            row = Member(name, want.kind, req, want.nullable, want.ref)
            if members.get(name) != row:
                self.fail(f"{path}.{name}: _MEMBERS row {members.get(name)}, want {row}")
        for name in fields:
            if name not in props:
                self.fail(f"{path}: field {name!r} is not a schema property")

    def enum_for(self, path: str, values: list[Any]) -> str:
        if not all(isinstance(v, str) for v in values):
            self.fail(f"{path}: enum {values} is not a string enum")
            return "?"
        want = frozenset(values)
        hits = [c.__name__ for c in ENUM_CLASSES if frozenset(m.value for m in c) == want]
        if len(hits) != 1:
            self.fail(f"{path}: schema enum {sorted(want)} matches enum classes {hits}, want one")
            return "?"
        prev = self.enums.setdefault(hits[0], want)
        if prev != want:
            self.fail(f"{path}: enum {hits[0]} is used for two different schema enums")
        return hits[0]

    def shape(self, path: str, owner: str, member: str, p: dict[str, Any]) -> Shape:
        # An anyOf beside a type only constrains values of that type (the
        # URI-or-token items of GatewayMetadata.extensions_supported).
        if "anyOf" in p and "type" not in p:
            alts = p["anyOf"]
            if len(alts) == 2 and alts[1] == {"type": "null"}:
                inner = self.shape(path, owner, member, alts[0])
                return Shape(inner.annotation, inner.kind, True, inner.ref)
            if sorted(alts, key=json.dumps) == [{"type": "boolean"}, {"type": "object"}]:
                return Shape("JSONObject | bool", "object|boolean", False, None)
            self.fail(f"{path}: unhandled anyOf {alts}")
            return Shape("?", "?", False, None)
        if "$ref" in p:
            name = p["$ref"].removeprefix("#/$defs/")
            if name not in self.defs:
                self.fail(f"{path}: $ref to unknown def {name}")
            return Shape(name, "object", False, name)
        if "enum" in p:
            return Shape(self.enum_for(path, p["enum"]), "string", False, None)
        if "const" in p:
            c = p["const"]
            if isinstance(c, str):
                return Shape("str", "string", False, None)
            if isinstance(c, int) and not isinstance(c, bool):
                return Shape("int", "integer", False, None)
            self.fail(f"{path}: unhandled const {c!r}")
            return Shape("?", "?", False, None)
        t = p.get("type")
        scalars = {"string": "str", "integer": "int", "number": "float", "boolean": "bool"}
        if t is None:
            return Shape("JSONValue", "any", False, None)  # {} accepts any JSON value
        if t in scalars:
            return Shape(scalars[t], t, False, None)
        if t == "array":
            item = self.shape(f"{path}[]", owner, member, p.get("items", {}))
            if item.nullable:
                self.fail(f"{path}: nullable array items")
            return Shape(f"tuple[{item.annotation}, ...]", "array", False, item.ref)
        if t == "object":
            if "properties" in p:
                name = INLINE.get((owner, member))
                if name is None:
                    self.fail(f"{path}: inline object without a class name")
                    return Shape("?", "object", False, None)
                self.check_class(path, p, TYPES.get(name))
                return Shape(name, "object", False, name)
            extra = p.get("additionalProperties")
            if isinstance(extra, dict):
                value = self.shape(f"{path}{{}}", owner, member, extra)
                if value.nullable:
                    self.fail(f"{path}: nullable map values")
                return Shape(f"Mapping[str, {value.annotation}]", "object", False, value.ref)
            return Shape("JSONObject", "object", False, None)  # open object
        self.fail(f"{path}: unhandled schema shape {p}")
        return Shape("?", "?", False, None)


def refs(node: Any) -> set[str]:
    """The local $ref targets in node."""
    return {
        n["$ref"].removeprefix("#/$defs/") for n in walk(node) if isinstance(n.get("$ref"), str)
    }


def reachable(schema: dict[str, Any]) -> set[str]:
    """The $defs entries reachable from the root oneOf."""
    seen: set[str] = set()
    todo = refs(schema["oneOf"])
    while todo:
        name = todo.pop()
        if name not in seen:
            seen.add(name)
            todo |= refs(schema["$defs"].get(name))
    return seen


def test_schema_drift() -> None:
    schema = load_schema()
    defs: dict[str, Any] = schema["$defs"]
    assert len(defs) == 33, f"schema has {len(defs)} $defs entries, want 33"
    assert len(TYPES) == 33, f"TYPES has {len(TYPES)} entries, want 31 plus 2 inline"

    d = Drift(defs)
    wire = reachable(schema)
    for name in sorted(PAYLOAD_ONLY - defs.keys()):
        d.fail(f"payload-only {name} has no $defs entry")
    for name in sorted(defs):
        if name in PAYLOAD_ONLY:
            if name in wire:
                d.fail(f"$defs/{name} is listed payload-only but a wire object reaches it")
            continue
        if name not in wire:
            d.fail(f"$defs/{name} is not reachable from the root oneOf and not listed payload-only")
        cls = TYPES.get(name)
        if cls is None:
            d.fail(f"$defs/{name} has no class")
            continue
        if cls.__name__ != name:
            d.fail(f"$defs/{name} maps to class {cls.__name__}")
        d.check_class(name, defs[name], cls)
    for name in sorted(TYPES):
        if name not in defs and name not in INLINE.values():
            d.fail(f"class {name} has no $defs entry")

    # Module-level checks: no exported class without a schema counterpart,
    # and each enum's members equal the schema's values.
    for name in types.__all__:
        obj = getattr(types, name)
        if isinstance(obj, type) and name not in d.reached and name not in PY_ONLY:
            d.fail(f"class {name} is not reachable from the schema")
    for cls in ENUM_CLASSES:
        schema_values = d.enums.get(cls.__name__)
        if schema_values is None:
            d.fail(f"enum {cls.__name__} is not used by any schema enum property")
        elif frozenset(m.value for m in cls) != schema_values:
            d.fail(f"enum {cls.__name__} members differ from the schema's {sorted(schema_values)}")

    assert not d.problems, "\n".join(d.problems)


def walk(node: Any) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if isinstance(node, dict):
        out.append(node)
        for v in node.values():
            out.extend(walk(v))
    elif isinstance(node, list):
        for v in node:
            out.extend(walk(v))
    return out


def test_constants_follow_the_schema() -> None:
    schema = load_schema()
    versions = {
        n["properties"]["pact_version"]["const"]
        for n in walk(schema)
        if "pact_version" in n.get("properties", {})
    }
    assert versions == {core.VERSION}
    patterns = {n["pattern"] for n in walk(schema) if n.get("pattern") == DIGEST_PATTERN}
    assert patterns, "the schema has no digest pattern"
    assert core.DIGEST_LEN == 43
