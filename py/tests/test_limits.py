"""Baseline limits of draft section 20.1. Port of go/core/limits_test.go.

test_defaults_match_the_draft reads spec/v1.0/draft.md: it fails when the draft is
absent under PACT_REQUIRE_VECTORS=1 (make py-test) and skips otherwise (a
mirror checkout).

The strictjson tests check the decode bounds each form hands to strictjson
and decode with them: a document of exactly the limit is accepted, one byte
or one level more is refused.
"""

from __future__ import annotations

import dataclasses
import os
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from hop_top_pact.core import limits, strictjson
from hop_top_pact.core.limits import LimitError, LimitErrorKind, Limits
from hop_top_pact.core.types import (
    TYPES,
    FieldRule,
    Intent,
    JSONObject,
    OperationContext,
    Presentation,
    RequirementContract,
)

REPO = Path(__file__).resolve().parents[2]
DRAFT = REPO / "spec" / "v1.0" / "draft.md"

# Every Limits field with its section 20.1 metadata key and baseline, written
# out here from the draft table and not derived from defaults().
LIMIT_FIELDS: list[tuple[str, int, str]] = [
    ("max_presentation_bytes", 262144, "presentation_bytes"),
    ("max_artifact_payload_bytes", 32768, "artifact_payload_bytes"),
    ("max_profile_bytes", 32768, "profile_bytes"),
    ("max_evidence_artifacts", 32, "evidence_artifacts"),
    ("max_field_rules", 128, "field_rules"),
    ("max_json_depth", 16, "depth"),
    ("max_resources", 256, "resources"),
    ("max_description_bytes", 4096, "description_bytes"),
]

ZERO = Limits(**{attr: 0 for _, _, attr in LIMIT_FIELDS})


def read_draft() -> str:
    if not DRAFT.exists():
        if os.environ.get("PACT_REQUIRE_VECTORS") == "1":
            pytest.fail(f"{DRAFT} absent under PACT_REQUIRE_VECTORS=1")
        pytest.skip("no spec/ tree (mirror checkout)")
    return DRAFT.read_text(encoding="utf-8")


def with_field(lim: Limits, attr: str, value: int) -> Limits:
    return dataclasses.replace(lim, **{attr: value})


def zero_of(cls: type) -> Any:
    """Return an instance of the wire type cls with every member at its zero value."""
    kwargs: dict[str, Any] = {}
    for f in dataclasses.fields(cls):
        m = cls._MEMBERS[f.name]  # type: ignore[attr-defined]
        if not m.required:
            continue
        if m.nullable:
            kwargs[f.name] = None
        elif m.kind == "object" and m.ref and not str(f.type).startswith("Mapping["):
            kwargs[f.name] = zero_of(TYPES[m.ref])
        else:
            zeros: dict[str, Any] = {
                "string": "",
                "integer": 0,
                "number": 0.0,
                "boolean": False,
                "array": (),
                "object": {},
                "object|boolean": {},
                "any": None,
            }
            kwargs[f.name] = zeros[m.kind]
    return cls(**kwargs)


P0: Presentation = zero_of(Presentation)
C0: RequirementContract = zero_of(RequirementContract)
F0: FieldRule = zero_of(FieldRule)
O0: OperationContext = zero_of(OperationContext)
I0: Intent = zero_of(Intent)


def test_defaults() -> None:
    d = limits.defaults()
    for key, baseline, attr in LIMIT_FIELDS:
        assert getattr(d, attr) == baseline, key
    limits.check(d)


def test_defaults_match_the_draft() -> None:
    draft = read_draft()
    d = limits.defaults()
    for key, _, attr in LIMIT_FIELDS:
        m = re.search(r"(?m)^\| `" + key + r"` \| (\d+) \|", draft)
        assert m is not None, f"draft 20.1 has no row for {key}"
        assert getattr(d, attr) == int(m.group(1)), f"defaults().{attr}, draft 20.1 says {m[1]}"


def test_keys() -> None:
    assert [key for key, _, _ in LIMIT_FIELDS] == [
        limits.KEY_MAX_PRESENTATION_BYTES,
        limits.KEY_MAX_ARTIFACT_PAYLOAD_BYTES,
        limits.KEY_MAX_PROFILE_BYTES,
        limits.KEY_MAX_EVIDENCE_ARTIFACTS,
        limits.KEY_MAX_FIELD_RULES,
        limits.KEY_MAX_JSON_DEPTH,
        limits.KEY_MAX_RESOURCES,
        limits.KEY_MAX_DESCRIPTION_BYTES,
    ]


@pytest.mark.parametrize(
    ("key", "baseline", "attr"), LIMIT_FIELDS, ids=[k for k, _, _ in LIMIT_FIELDS]
)
def test_check(key: str, baseline: int, attr: str) -> None:
    for v in [1, baseline - 1, baseline]:
        limits.check(with_field(limits.defaults(), attr, v))
    for v in [baseline + 1, 2 * baseline, 0, -1]:
        with pytest.raises(LimitError) as ei:
            limits.check(with_field(limits.defaults(), attr, v))
        assert ei.value.kind is LimitErrorKind.LIMITS_INVALID, (key, v)
        assert ei.value.key == key, (key, v)
        assert ei.value.max == baseline, (key, v)
        assert ei.value.got == v, (key, v)


def test_check_zero_limits() -> None:
    with pytest.raises(LimitError) as ei:
        limits.check(ZERO)
    assert ei.value.kind is LimitErrorKind.LIMITS_INVALID


# How to build an object that holds exactly n units of one limited quantity
# and validate it.
BOUNDARIES: list[tuple[str, Callable[[Limits, int], None]]] = [
    ("max_presentation_bytes", lambda lim, n: limits.validate_presentation(lim, P0, n)),
    ("max_artifact_payload_bytes", lambda lim, n: limits.validate_artifact_size(lim, n)),
    ("max_profile_bytes", lambda lim, n: limits.validate_profile_size(lim, n)),
    (
        "max_evidence_artifacts",
        lambda lim, n: limits.validate_presentation(
            lim, dataclasses.replace(P0, evidence=("",) * n), 0
        ),
    ),
    (
        "max_field_rules",
        lambda lim, n: limits.validate_contract(
            lim, dataclasses.replace(C0, field_rules=(F0,) * n)
        ),
    ),
    (
        "max_resources",
        lambda lim, n: limits.validate_operation(lim, dataclasses.replace(O0, resources=("",) * n)),
    ),
    (
        "max_resources",
        lambda lim, n: limits.validate_presentation(
            lim, dataclasses.replace(P0, operation=dataclasses.replace(O0, resources=("",) * n)), 0
        ),
    ),
    (
        "max_description_bytes",
        lambda lim, n: limits.validate_intent(lim, dataclasses.replace(I0, description="a" * n)),
    ),
    (
        "max_description_bytes",
        lambda lim, n: limits.validate_presentation(
            lim, dataclasses.replace(P0, intent=dataclasses.replace(I0, description="a" * n)), 0
        ),
    ),
]


def baseline_of(key: str) -> tuple[int, str]:
    for k, baseline, attr in LIMIT_FIELDS:
        if k == key:
            return baseline, attr
    raise AssertionError(f"no limit field for key {key!r}")


@pytest.mark.parametrize(
    ("key", "run"), BOUNDARIES, ids=[f"{k}/{i}" for i, (k, _) in enumerate(BOUNDARIES)]
)
def test_boundaries(key: str, run: Callable[[Limits, int], None]) -> None:
    baseline, attr = baseline_of(key)
    d = limits.defaults()

    # Equal passes, plus one fails.
    run(d, baseline)
    run(d, 0)
    with pytest.raises(LimitError) as ei:
        run(d, baseline + 1)
    le = ei.value
    assert le.kind is LimitErrorKind.LIMIT_EXCEEDED
    assert (le.key, le.max, le.got) == (key, baseline, baseline + 1)
    assert key in str(le)

    # A tighter configured limit moves the boundary down.
    tight = with_field(d, attr, baseline - 1)
    run(tight, baseline - 1)
    with pytest.raises(LimitError) as ei:
        run(tight, baseline)
    assert ei.value.kind is LimitErrorKind.LIMIT_EXCEEDED


def test_each_limit_is_independent() -> None:
    # Lowering one limit must not affect the others.
    for key, _, attr in LIMIT_FIELDS:
        lim = with_field(limits.defaults(), attr, 1)
        for bkey, run in BOUNDARIES:
            if bkey == key:
                continue
            baseline, _ = baseline_of(bkey)
            run(lim, baseline)


DESCRIPTIONS = [
    ("2048 two-byte characters are 4096 bytes", "é" * 2048, True),
    ("2049 two-byte characters are 4098 bytes", "é" * 2049, False),
    ("1024 four-byte characters are 4096 bytes", "😀" * 1024, True),
    ("1025 four-byte characters are 4100 bytes", "😀" * 1025, False),
    ("4095 ASCII plus one two-byte character is 4097 bytes", "a" * 4095 + "é", False),
]


@pytest.mark.parametrize(("name", "desc", "ok"), DESCRIPTIONS, ids=[c[0] for c in DESCRIPTIONS])
def test_description_limit_counts_bytes_not_characters(name: str, desc: str, ok: bool) -> None:
    intent = dataclasses.replace(I0, description=desc)
    if ok:
        limits.validate_intent(limits.defaults(), intent)
        return
    with pytest.raises(LimitError) as ei:
        limits.validate_intent(limits.defaults(), intent)
    assert ei.value.kind is LimitErrorKind.LIMIT_EXCEEDED, name


def test_validate_rejects_nil() -> None:
    d = limits.defaults()
    calls: dict[str, Callable[[], None]] = {
        "presentation": lambda: limits.validate_presentation(d, None, 0),
        "contract": lambda: limits.validate_contract(d, None),
        "operation": lambda: limits.validate_operation(d, None),
        "intent": lambda: limits.validate_intent(d, None),
    }
    for name, call in calls.items():
        with pytest.raises(LimitError) as ei:
            call()
        assert ei.value.kind is LimitErrorKind.NIL_OBJECT, name
        assert name in str(ei.value)


def test_validate_on_the_zero_limits_fails_closed() -> None:
    with pytest.raises(LimitError) as ei:
        limits.validate_contract(ZERO, dataclasses.replace(C0, field_rules=(F0,)))
    assert ei.value.kind is LimitErrorKind.LIMIT_EXCEEDED, "zero limits accepted a field rule"
    with pytest.raises(LimitError) as ei:
        limits.validate_artifact_size(ZERO, 1)
    assert ei.value.kind is LimitErrorKind.LIMIT_EXCEEDED, "zero limits accepted a payload"


def decode_object(data: bytes, lim: strictjson.Limits) -> Any:
    """Strict-decode data as an open object (Go: core.Object)."""
    return strictjson.decode(data, JSONObject, lim)  # type: ignore[type-abstract]


def doc_of_size(n: int) -> bytes:
    """A JSON object of exactly n bytes."""
    return b'{"a":"' + b"x" * (n - len(b'{"a":""}')) + b'"}'


def doc_of_depth(d: int) -> bytes:
    """A JSON document whose nesting depth is exactly d."""
    return b'{"a":' + b"[" * (d - 1) + b"]" * (d - 1) + b"}"


FORMS: list[tuple[str, Callable[[Limits], strictjson.Limits], str, int]] = [
    ("presentation", limits.presentation_json, "max_presentation_bytes", 262144),
    ("artifact", limits.artifact_json, "max_artifact_payload_bytes", 32768),
    ("profile", limits.profile_json, "max_profile_bytes", 32768),
]


@pytest.mark.parametrize(("name", "form", "key", "baseline"), FORMS, ids=[f[0] for f in FORMS])
def test_strict_json_limits(
    name: str, form: Callable[[Limits], strictjson.Limits], key: str, baseline: int
) -> None:
    assert form(limits.defaults()) == strictjson.Limits(max_bytes=baseline, max_depth=16), name
    _, attr = baseline_of(key)
    tight = with_field(limits.defaults(), attr, 1000)
    assert form(tight) == strictjson.Limits(max_bytes=1000, max_depth=16), name

    o = decode_object(doc_of_size(baseline), form(limits.defaults()))
    assert len(o["a"]) == baseline - 8, name
    with pytest.raises(strictjson.StrictJSONError) as ei:
        decode_object(doc_of_size(baseline + 1), form(limits.defaults()))
    assert ei.value.kind is strictjson.StrictJSONErrorKind.SIZE, name
    decode_object(doc_of_size(1000), form(tight))
    with pytest.raises(strictjson.StrictJSONError) as ei:
        decode_object(doc_of_size(1001), form(tight))
    assert ei.value.kind is strictjson.StrictJSONErrorKind.SIZE, name


@pytest.mark.parametrize(("name", "form", "key", "baseline"), FORMS, ids=[f[0] for f in FORMS])
def test_strict_json_depth_comes_from_limits_depth(
    name: str, form: Callable[[Limits], strictjson.Limits], key: str, baseline: int
) -> None:
    assert form(limits.defaults()).max_depth == 16, name
    tight = with_field(limits.defaults(), "depth", 3)
    assert form(tight) == strictjson.Limits(max_bytes=baseline, max_depth=3), name

    decode_object(doc_of_depth(16), form(limits.defaults()))
    with pytest.raises(strictjson.StrictJSONError) as ei:
        decode_object(doc_of_depth(17), form(limits.defaults()))
    assert ei.value.kind is strictjson.StrictJSONErrorKind.DEPTH, name
    decode_object(doc_of_depth(3), form(tight))
    with pytest.raises(strictjson.StrictJSONError) as ei:
        decode_object(doc_of_depth(4), form(tight))
    assert ei.value.kind is strictjson.StrictJSONErrorKind.DEPTH, name


def test_strict_json_defaults_agree() -> None:
    # The decoder's own defaults, used when a caller passes no limits, equal
    # the baseline.
    d = limits.defaults()
    assert d.depth == strictjson.DEFAULT_MAX_DEPTH
    assert d.presentation_bytes == strictjson.DEFAULT_MAX_BYTES
