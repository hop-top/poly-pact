"""Strict reading of config.json and native_context.json, and the rules of the case
files that the decoder does not make.

Most members are decoded by core.strictjson straight into the dataclasses of
conformance.types. Three objects are not, as in Go: a native mapping's source,
which Go reads with its own UnmarshalJSON (each member present, bounds, change
feed), and the executor class and executor objects, whose member "class" is no
Python field name. Those three are decoded as free-form values first (strict
syntax, duplicate members, integer range) and then read member by member here.
"""

from __future__ import annotations

import dataclasses
import typing
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Final, TypeVar

from hop_top_pact.conformance.errors import CaseError, q
from hop_top_pact.conformance.types import (
    BINDING_ACTIVE,
    BINDING_COMPROMISED,
    BINDING_REVOKED,
    BINDING_UNKNOWN,
    Authenticated,
    Config,
    Executor,
    ExecutorClass,
    Gateway,
    NativeContext,
    NativeMapping,
    NativeSource,
)
from hop_top_pact.core import strictjson
from hop_top_pact.core.jws import ALG_ED25519, ALG_ES256
from hop_top_pact.core.types import JSONValue

T = TypeVar("T")

# The largest limit with a wire form, 2^53-1 (draft 7.1).
MAX_SECONDS: Final = (1 << 53) - 1


def read_strict(path: Path, cls: type[T]) -> T:
    """Strict-decode the file path into cls. A missing file raises FileNotFoundError."""
    return strictjson.decode(path.read_bytes(), cls)


def _wire(cls: type, **free: Any) -> type:
    """A copy of the dataclass cls for decoding, with the annotations free given for
    some of its fields (object for a free-form value)."""
    hints = typing.get_type_hints(cls)
    specs: list[tuple[str, Any, Any]] = []
    for f in dataclasses.fields(cls):
        spec = dataclasses.field(default=f.default, default_factory=f.default_factory)
        specs.append((f.name, free.get(f.name, hints[f.name]), spec))
    ns = {"_MEMBERS": cls._MEMBERS} if hasattr(cls, "_MEMBERS") else {}
    return dataclasses.make_dataclass(
        "_" + cls.__name__ + "Wire", specs, namespace=ns, frozen=True, slots=True
    )


_NativeMappingWire: Final = _wire(NativeMapping, source=object)
_ConfigWire: Final = _wire(
    Config,
    native_mappings=tuple[_NativeMappingWire, ...],  # type: ignore[valid-type]
    executor_classes=tuple[object, ...],
)
_NativeContextWire: Final = _wire(NativeContext, executor=object)


def _values(w: Any) -> dict[str, Any]:
    return {f.name: getattr(w, f.name) for f in dataclasses.fields(w)}


def decode_config(data: bytes) -> Config:
    """config.json as a Config."""
    w: Any = strictjson.decode(data, _ConfigWire)
    v = _values(w)
    v["native_mappings"] = tuple(
        NativeMapping(m.path, m.native_path, native_source(m.source)) for m in w.native_mappings
    )
    v["executor_classes"] = tuple(
        ExecutorClass(**_flat(e, f"executor_classes[{i}]", _EXECUTOR_CLASS))
        for i, e in enumerate(w.executor_classes)
    )
    return Config(**v)


def decode_native_context(data: bytes) -> NativeContext:
    """native_context.json as a NativeContext."""
    w: Any = strictjson.decode(data, _NativeContextWire)
    v = _values(w)
    if w.executor is not None:
        v["executor"] = Executor(**_flat(w.executor, "executor", _EXECUTOR))
    return NativeContext(**v)


# The members of a flat object read by _flat: the JSON type of each, the field
# name, and whether it may be null.
_Spec = Mapping[str, tuple[type, str, bool]]
_EXECUTOR_CLASS: Final[_Spec] = {
    "principal_id": (str, "principal_id", False),
    "task_id": (str, "task_id", False),
    "operation_id": (str, "operation_id", False),
    "class": (str, "class_", False),
    "executor_id": (str, "executor_id", True),
}
_EXECUTOR: Final[_Spec] = {
    "class": (str, "class_", False),
    "principal_id": (str, "principal_id", False),
}
_TYPE_NAMES: Final = {str: "string", int: "integer", bool: "boolean"}


def _flat(v: JSONValue | object, where: str, spec: _Spec) -> dict[str, Any]:
    """The members of the flat object v by field name, checked as the strict decoder
    checks a struct: an object, no unknown member, each value of its type or, where
    allowed, null. Absent members are left out."""
    if not isinstance(v, Mapping):
        raise CaseError(f"{where}: {_json_type(v)} is not an object")
    out: dict[str, Any] = {}
    for name, value in v.items():
        if name not in spec:
            raise CaseError(f"{where}: unknown member {q(name)}")
        typ, field_name, nullable = spec[name]
        if value is None and nullable:
            out[field_name] = None
            continue
        if not isinstance(value, typ) or (typ is not bool and isinstance(value, bool)):
            raise CaseError(f"{where}: {name} is {_json_type(value)}, not a {_TYPE_NAMES[typ]}")
        out[field_name] = value
    return out


def _json_type(v: object) -> str:
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "boolean"
    if isinstance(v, str):
        return "string"
    if isinstance(v, int):
        return "integer"
    if isinstance(v, float):
        return "number"
    if isinstance(v, tuple | list):
        return "array"
    return "object"


_SOURCE: Final[_Spec] = {
    "source_id": (str, "source_id", True),
    "best_max_age_seconds": (int, "best_max_age_seconds", True),
    "best_status_max_age_seconds": (int, "best_status_max_age_seconds", True),
    "live_check": (bool, "live_check", True),
    "change_feed": (str, "change_feed", True),
}


def native_source(raw: object) -> NativeSource | None:
    """A native mapping's source as Go's NativeSource.UnmarshalJSON reads it: None for
    null; else an object with each member once and present, no other member, bounds
    from 0 to 2^53-1, a change feed of none, poll_delta or push, and, for a source with
    no live check, a status bound of at least 1 (freshness profile, section 4.2)."""
    if raw is None:
        return None
    m = _flat(raw, "native_mappings source", _SOURCE)
    if not m.get("source_id"):
        raise CaseError("native_mappings source: no source_id")
    for name in ("best_max_age_seconds", "best_status_max_age_seconds", "live_check"):
        if m.get(name) is None:
            raise CaseError(f"native_mappings source: no {name}")
    if m.get("change_feed") is None:
        raise CaseError("native_mappings source: no change_feed")
    for name in ("best_max_age_seconds", "best_status_max_age_seconds"):
        if not 0 <= m[name] <= MAX_SECONDS:
            raise CaseError(f"native_mappings source: {name} {m[name]} is not from 0 to 2^53-1")
    if m["change_feed"] not in ("none", "poll_delta", "push"):
        raise CaseError(
            f"native_mappings source: change_feed {q(m['change_feed'])}"
            " is not none, poll_delta or push"
        )
    if not m["live_check"] and m["best_status_max_age_seconds"] < 1:
        raise CaseError(
            "native_mappings source: a source with no live check has a"
            " best_status_max_age_seconds of at least 1"
        )
    return NativeSource(**m)


def check_algorithms(g: Gateway) -> None:
    """jws_algorithms against the type of GatewayMetadata.jws_algorithms (draft A.3):
    when present, one or two distinct algorithms out of ES256 and Ed25519. EdDSA, none
    and HMAC algorithms are never accepted (draft 7.2)."""
    algs = g.jws_algorithms
    if algs is None:
        return
    if not algs:
        raise CaseError('gateway.jws_algorithms is empty; leave it out for the baseline ["ES256"]')
    for i, alg in enumerate(algs):
        if alg not in (ALG_ES256, ALG_ED25519):
            raise CaseError(
                f"gateway.jws_algorithms[{i}] {q(alg)} is not ES256 or Ed25519 (draft 7.2, A.3)"
            )
        if algs.index(alg) != i:
            raise CaseError(f"gateway.jws_algorithms[{i}] {q(alg)} repeats an algorithm")


def check_authenticated(a: Authenticated | None) -> None:
    """The rules of the authenticated member that the decoder does not apply: the
    status set, the null members of an unknown binding, and the members that only an
    unknown binding may carry."""
    if a is None:
        return
    if a.binding_status not in (
        BINDING_ACTIVE,
        BINDING_REVOKED,
        BINDING_COMPROMISED,
        BINDING_UNKNOWN,
    ):
        raise CaseError(
            f"authenticated.binding_status {q(a.binding_status)}"
            " is not active, revoked, compromised or unknown"
        )
    unknown = a.binding_status == BINDING_UNKNOWN
    for name, value in (
        ("agent_id", a.agent_id),
        ("operator_id", a.operator_id),
        ("holder_jkt", a.holder_jkt),
    ):
        if unknown and value is not None:
            raise CaseError(
                f"authenticated.{name} is set, but binding_status unknown has no agent,"
                " operator or key (null)"
            )
        if not unknown and not value:
            raise CaseError(
                f"authenticated.{name} is null or empty, but binding_status"
                f" {a.binding_status} names a binding"
            )
    if a.enrolled_elsewhere and not unknown:
        raise CaseError(
            f"authenticated.enrolled_elsewhere is true with binding_status"
            f" {a.binding_status}; it reports only for unknown"
        )
    if a.binding_error is not None:
        if a.binding_error != "UNSUPPORTED_REQUIREMENT":
            raise CaseError(
                f"authenticated.binding_error {q(a.binding_error)}"
                " is not UNSUPPORTED_REQUIREMENT or null"
            )
        if not unknown:
            raise CaseError(
                f"authenticated.binding_error is set with binding_status"
                f" {a.binding_status}; it comes with unknown"
            )


def check_sources(c: Config, nc: NativeContext) -> None:
    """Every native claim at the native path of a mapping that declares a source names
    that source's source_id."""
    for i, m in enumerate(c.native_mappings):
        if m.source is None:
            continue
        for cl in nc.native_claims:
            if cl.native_path == m.native_path and cl.source_id != m.source.source_id:
                raise CaseError(
                    f"native_mappings[{i}] source source_id {q(m.source.source_id)},"
                    f" but the native claim at {m.native_path} names {q(cl.source_id)}"
                )
