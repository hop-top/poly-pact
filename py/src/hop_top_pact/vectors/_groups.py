"""The binding, digest, jcs, schema and strictjson groups (spec/v1.0/fixtures/vectors/README.md).

Each runner takes the fixture directory and an entry, calls the package
function under test and compares its result with the entry's outcome and
expected file. It returns on a pass and raises Fail or Skipped otherwise;
any other exception, a stub's NotImplementedError included, is a fail.
"""

from __future__ import annotations

import base64
import dataclasses
import math
import struct
from collections.abc import Mapping
from decimal import Decimal
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator  # type: ignore[import-untyped]

from hop_top_pact.core import binding, digest, jcs, schema, strictjson
from hop_top_pact.core.types import JSONValue, OperationContext
from hop_top_pact.vectors._common import (
    SPEC_DEFECT,
    Entry,
    Fail,
    Skipped,
    array,
    dump_json,
    freeze,
    obj,
    read_fixture,
    read_json,
    single_file,
    string,
)

# The body limit the harness configures; no vector tests a limit.
BINDING_MAX_BODY = 1 << 20

BINDING_MEMBERS = (
    "action",
    "config",
    "description",
    "expect",
    "expect_operation_digest",
    "id",
    "operation_id",
    "principal_id",
    "request",
    "resources",
)
CONFIG_MEMBERS = (
    "origin",
    "header_allowlist",
    "normalization_id",
    "mapping_version",
    "environment_id",
)
REQUEST_MEMBERS = ("method", "raw_request_uri", "headers", "body_b64")
DIGEST_MEMBERS = ("appendix_value", "expected_digest", "id", "input", "input_kind", "spec_defect")
SCHEMA_MEMBERS = ("ajv_formats_differs", "expect", "id", "input", "reason")
STRICTJSON_MEMBERS = ("id", "expect", "reason")

# The format each vectors/schema entry tests.
SCHEMA_FORMATS = {"vectors/schema/uri-format": "uri"}


def wire(value: object) -> JSONValue:
    """The JSON value of a wire dataclass, in schema member order; absent optionals left out."""
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        members: Mapping[str, Any] = getattr(type(value), "_MEMBERS")  # noqa: B009
        out: dict[str, JSONValue] = {}
        for name, m in members.items():
            v = getattr(value, name)
            if v is None and not m.required:
                continue
            out[name] = wire(v)
        return out
    if isinstance(value, Mapping):
        return {str(k): wire(v) for k, v in value.items()}
    if isinstance(value, tuple | list):
        return tuple(wire(v) for v in value)
    if value is None or isinstance(value, str | int | float | bool):
        return value
    raise Fail(f"value of type {type(value).__name__} is not JSON")


def same_canonical(got: bytes, want: bytes) -> None:
    """Compare two JSON texts by their RFC 8785 form."""
    g, w = jcs.canonicalize(got), jcs.canonicalize(want)
    if g != w:
        raise Fail(f"got {g.decode('utf-8', 'replace')}, want {w.decode('utf-8', 'replace')}")


def run_binding(root: Path, e: Entry) -> None:
    """Bind the vector's request with core.binding and compare context and object_digest.

    A config_error vector instead requires Config.validate to fail with
    RequestErrorKind.INVALID_CONFIG; no request is bound.
    """
    single_file(e)
    v = obj(read_json(root, e.path), e.path, BINDING_MEMBERS)
    if v["id"] != e.id:
        raise Fail(f"vector id {v['id']!r}, manifest id {e.id!r}")
    cfg_v = obj(v["config"], "config", CONFIG_MEMBERS)
    req_v = obj(v["request"], "request", REQUEST_MEMBERS)
    expect = obj(v["expect"], "expect", (), ("operation_context", "reject_reason", "config_error"))
    ctx = expect.get("operation_context")
    reject = expect.get("reject_reason")
    config_error = "config_error" in expect
    want_digest = v["expect_operation_digest"]
    accept = bool(ctx)
    agree_accept = accept and reject is None and not config_error and isinstance(want_digest, str)
    agree_reject = (
        not accept and reject == "INVALID_MESSAGE" and not config_error and want_digest is None
    )
    agree_config = (
        not accept and reject is None and expect.get("config_error") is True and want_digest is None
    )
    if not (
        (agree_accept and e.outcome == "ACCEPTED")
        or ((agree_reject or agree_config) and e.outcome == "REJECTED")
    ):
        raise Fail(f"expect, expect_operation_digest and outcome {e.outcome!r} do not agree")
    if not isinstance(req_v["headers"], list):
        raise Fail("request.headers: not an array")
    try:
        req = binding.decode_request(req_v)
    except binding.RequestObjectError as err:
        raise Fail(str(err)) from err
    cfg = binding.Config(
        origin=string(cfg_v["origin"], "origin"),
        header_allowlist=tuple(string(x, "header_allowlist") for x in cfg_v["header_allowlist"]),
        header_normalization_id=string(cfg_v["normalization_id"], "normalization_id"),
        mapping_version=string(cfg_v["mapping_version"], "mapping_version"),
        max_body=BINDING_MAX_BODY,
    )
    if config_error:
        try:
            cfg.validate()
        except binding.RequestError as err:
            if err.kind is not binding.RequestErrorKind.INVALID_CONFIG:
                raise Fail(f"{err}: not a configuration error") from err
            return
        raise Fail("configuration accepted, want a configuration error")
    resources = tuple(string(r, "resources") for r in v["resources"])
    try:
        op = binding.from_request(cfg, req, v["principal_id"], v["action"], resources)
    except binding.RequestError as err:
        if err.kind is not binding.RequestErrorKind.INVALID_REQUEST:
            raise Fail(f"{err}: not a refused request") from err
        if accept:
            raise Fail(f"refused ({err}), want an operation context") from err
        return
    if not accept:
        raise Fail("got an operation context, want a refusal (INVALID_MESSAGE)")
    if not isinstance(op, OperationContext):
        raise Fail(f"from_request returned {type(op).__name__}, want OperationContext")
    op = dataclasses.replace(
        op, operation_id=v["operation_id"], environment_id=cfg_v["environment_id"]
    )
    value = wire(op)
    try:
        same_canonical(dump_json(value), dump_json(ctx))
    except Fail as err:
        raise Fail(f"operation context: {err}") from err
    got = digest.object_digest(value)
    if got != want_digest:
        raise Fail(f"object_digest {got}, want {want_digest}")


def compute_digest(v: Mapping[str, Any]) -> str:
    kind, value = v["input_kind"], v["input"]
    if kind == "object":
        return digest.object_digest(freeze(value))
    if kind == "artifact":
        return digest.artifact_digest(string(value, "input"))
    if kind == "bytes":
        s = string(value, "input")
        try:
            b = bytes.fromhex(s)
        except ValueError:
            b = None
        if b is None or s != s.lower() or len(s) % 2:
            raise Fail(f"input {s!r} is not lowercase hex")
        return digest.bytes_digest(b)
    raise Fail(f"input_kind {kind!r} is not object, artifact or bytes")


def run_digest(root: Path, e: Entry) -> None:
    """Digest every vector with core.digest; a flagged draft value that differs is a spec defect."""
    single_file(e)
    vs = array(read_json(root, e.path), e.path)
    seen: set[str] = set()
    notes: list[str] = []
    defects: list[dict[str, str]] = []
    for i, raw in enumerate(vs):
        v = obj(raw, f"vector {i}", DIGEST_MEMBERS)
        vid = v["id"]
        if not isinstance(vid, str) or not vid or vid in seen:
            raise Fail(f"vector {i}: id {vid!r} is empty or repeated")
        seen.add(vid)
        try:
            got = compute_digest(v)
        except Fail as err:
            raise Fail(f"{vid}: {err}") from err
        if got != v["expected_digest"]:
            raise Fail(f"{vid}: digest {got}, want expected_digest {v['expected_digest']}")
        appendix, flagged = v["appendix_value"], v["spec_defect"] is True
        if appendix is None and flagged:
            raise Fail(f"{vid}: spec_defect is set but appendix_value is null")
        if appendix is None:
            continue
        if appendix == got and flagged:
            raise Fail(f"{vid}: spec_defect is set but appendix_value matches")
        if appendix == got:
            continue
        if not flagged:
            raise Fail(
                f"{vid}: appendix_value {appendix} differs from {got} and spec_defect is not set"
            )
        notes.append(f"{vid}: the draft states {appendix}, computed {got}")
        defects.append({"vector": vid, "appendix_value": appendix, "expected_digest": got})
    if defects:
        raise Skipped(SPEC_DEFECT, "spec defect: " + "; ".join(notes), defects=defects)


def go_exponent(f: float) -> str:
    """The literal Go's strconv.FormatFloat(f, 'e', -1, 64) writes: shortest digits, d.ddde±XX."""
    if not math.isfinite(f):
        raise Fail(f"{f!r} is not finite")
    sign = "-" if math.copysign(1.0, f) < 0 else ""
    if f == 0:
        return sign + "0e+00"
    t = Decimal(repr(abs(f))).normalize().as_tuple()
    digits = "".join(map(str, t.digits))
    exp = len(digits) - 1 + int(t.exponent)
    mantissa = digits[0] + ("." + digits[1:] if len(digits) > 1 else "")
    return f"{sign}{mantissa}e{'+' if exp >= 0 else '-'}{abs(exp):02d}"


def run_jcs(root: Path, e: Entry) -> None:
    """Canonicalize the input with core.jcs and compare byte for byte; or the number list."""
    if e.expected is None:
        raise Fail("expected is null")
    if e.path == e.expected:
        run_jcs_numbers(root, e.path)
        return
    data, want = read_fixture(root, e.path), read_fixture(root, e.expected)
    got = jcs.canonicalize(data)
    if got != want:
        raise Fail(f"canonical form {got!r}, want {want!r}")
    if jcs.canonicalize(want) != want:
        raise Fail("the expected output is not canonical")


def run_jcs_numbers(root: Path, rel: str) -> None:
    vs = array(read_json(root, rel), rel)
    for i, raw in enumerate(vs):
        v = obj(raw, f"number {i}", ("ieee754_hex", "expected"))
        hexbits, want = v["ieee754_hex"], v["expected"]
        if not (isinstance(hexbits, str) and len(hexbits) == 16 and isinstance(want, str) and want):
            raise Fail(f"number {i} is malformed")
        try:
            (f,) = struct.unpack(">d", bytes.fromhex(hexbits))
        except ValueError as err:
            raise Fail(f"number {i} is malformed") from err
        got = jcs.canonicalize(go_exponent(f).encode("ascii"))
        if got != want.encode("utf-8"):
            raise Fail(f"{hexbits}: canonical form {got!r}, want {want!r}")


def run_strictjson(root: Path, e: Entry) -> None:
    """Strict-decode the input as an OperationContext; accept or reject as expect says."""
    single_file(e)
    v = obj(read_json(root, e.path), e.path, STRICTJSON_MEMBERS, ("input_text", "input_b64"))
    if v["id"] != e.id or not v["reason"]:
        raise Fail(f"vector id {v['id']!r} (manifest {e.id!r}) or empty reason")
    text = string(v.get("input_text", ""), "input_text")
    b64 = string(v.get("input_b64", ""), "input_b64")
    if text and b64:
        raise Fail("both input_text and input_b64 are set")
    if b64:
        try:
            data = base64.b64decode(b64, validate=True)
        except ValueError as err:
            raise Fail(f"input_b64: {err}") from err
    elif text:
        data = text.encode("utf-8")
    else:
        raise Fail("no input")
    want = {"accept": "ACCEPTED", "reject": "REJECTED"}.get(v["expect"])
    if want is None or want != e.outcome:
        raise Fail(f"expect {v['expect']!r} does not agree with outcome {e.outcome!r}")
    try:
        strictjson.decode(data, OperationContext, strictjson.Limits())
    except strictjson.StrictJSONError as err:
        if v["expect"] == "accept":
            raise Fail(f"rejected ({err}), want accept") from err
        return
    if v["expect"] == "reject":
        raise Fail("accepted, want reject")


def run_schema(root: Path, e: Entry) -> None:
    """Validate each string against a schema asserting the entry's format (package checker)."""
    single_file(e)
    fmt = SCHEMA_FORMATS.get(e.id)
    if fmt is None:
        raise Fail(f"no format for {e.id}")
    if e.outcome != "MATCH":
        raise Fail(f"outcome {e.outcome!r}, want MATCH")
    vs = array(read_json(root, e.path), e.path)
    validator = Draft202012Validator(
        {"type": "string", "format": fmt}, format_checker=schema.format_checker()
    )
    seen: set[str] = set()
    wrong: list[str] = []
    for i, raw in enumerate(vs):
        v = obj(raw, f"vector {i}", SCHEMA_MEMBERS)
        vid = v["id"]
        if not isinstance(vid, str) or not vid or vid in seen:
            raise Fail(f"vector {i}: id {vid!r} is empty or repeated")
        seen.add(vid)
        if v["expect"] not in ("accept", "reject"):
            raise Fail(f"{vid}: expect {v['expect']!r}, want accept or reject")
        got = "accept" if validator.is_valid(string(v["input"], "input")) else "reject"
        if got != v["expect"]:
            wrong.append(f"{vid}: {got}ed, want {v['expect']}")
    if wrong:
        raise Fail(f"format {fmt}: " + "; ".join(wrong))
