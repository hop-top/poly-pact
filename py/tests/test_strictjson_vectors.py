"""The strictjson vectors. Port of go/core/strictjson/vectors_test.go.

Reads spec/v1.0/fixtures/manifest.json of the source repository: fails when it is
absent under PACT_REQUIRE_VECTORS=1 (make py-test) and skips otherwise (a
mirror checkout).
"""

from __future__ import annotations

import base64
import os
from pathlib import Path
from typing import Any

import pytest

from hop_top_pact.core import strictjson
from hop_top_pact.core.strictjson import Limits, StrictJSONError, StrictJSONErrorKind
from hop_top_pact.core.types import OperationContext

FIXTURES = Path(__file__).resolve().parents[2] / "spec" / "v1.0" / "fixtures"
PREFIX = "vectors/strictjson/"
K = StrictJSONErrorKind

# The reason each reject vector fails for. A vector missing here is still run
# for accept or reject; the pin only tightens the check.
WANT_ERR = {
    "duplicate-key-top-level": K.DUPLICATE_KEY,
    "duplicate-key-identical-values": K.DUPLICATE_KEY,
    "duplicate-key-nested": K.DUPLICATE_KEY,
    "duplicate-key-in-headers": K.DUPLICATE_KEY,
    "duplicate-key-escaped-form": K.DUPLICATE_KEY,
    "unknown-core-field": K.UNKNOWN_FIELD,
    "unknown-core-field-case-variant": K.UNKNOWN_FIELD,
    "nesting-depth-17-objects": K.DEPTH,
    "nesting-depth-17-arrays": K.DEPTH,
    "non-finite-number-1e999": K.NON_FINITE,
    "non-finite-number-negative-1e999": K.NON_FINITE,
    "non-finite-number-nan": K.NON_FINITE,
    "non-finite-number-infinity": K.NON_FINITE,
    "non-finite-number-negative-infinity": K.NON_FINITE,
    "invalid-utf8-byte-ff": K.INVALID_UTF8,
    "invalid-utf8-truncated-sequence": K.INVALID_UTF8,
    "invalid-utf8-overlong-encoding": K.INVALID_UTF8,
    "invalid-utf8-encoded-surrogate": K.INVALID_UTF8,
    "lone-surrogate-high": K.LONE_SURROGATE,
    "lone-surrogate-low": K.LONE_SURROGATE,
    "lone-surrogate-high-then-bmp": K.LONE_SURROGATE,
    "integer-overflow-2-pow-53": K.INTEGER,
    "integer-overflow-negative": K.INTEGER,
    "integer-overflow-huge": K.INTEGER,
    "trailing-garbage-text": K.TRAILING_DATA,
    "trailing-garbage-second-value": K.TRAILING_DATA,
    "trailing-garbage-extra-brace": K.TRAILING_DATA,
}

# The cases the vector set must contain, whatever else a later change adds.
REQUIRED_CASES = [
    "duplicate-key-top-level",
    "duplicate-key-nested",
    "unknown-core-field",
    "nesting-depth-17-objects",
    "non-finite-number-1e999",
    "invalid-utf8-byte-ff",
    "lone-surrogate-high",
    "integer-overflow-2-pow-53",
    "trailing-garbage-text",
    "accept-valid-object",
    "accept-depth-16-objects",
    "accept-integer-max-safe",
]


def read_json(rel: str) -> Any:
    path = FIXTURES / rel
    if not path.exists():
        if os.environ.get("PACT_REQUIRE_VECTORS") == "1":
            pytest.fail(f"{path} absent under PACT_REQUIRE_VECTORS=1")
        pytest.skip("no spec/ tree (mirror checkout)")
    return strictjson.parse(path.read_bytes(), Limits(max_bytes=1 << 20))


def entries() -> list[Any]:
    m = read_json("manifest.json")
    assert m["manifest_version"] == 1
    return list(m["entries"])


def test_vectors_via_manifest() -> None:
    es = entries()
    ids = [e["id"] for e in es]
    assert ids == sorted(ids), "manifest entries are not sorted by id"
    assert len(set(ids)) == len(ids), "manifest ids are not unique"
    seen = {e["id"].removeprefix(PREFIX) for e in es if e["id"].startswith(PREFIX)}
    assert seen, "manifest lists no strictjson vectors"
    for c in REQUIRED_CASES:
        assert c in seen, f"manifest lacks required case {c}"
    # Files on disk that the manifest does not list never run: flag them.
    for f in sorted((FIXTURES / PREFIX).iterdir()):
        assert f.name.removesuffix(".json") in seen, f"{PREFIX}{f.name} is not listed"
    for e in es:
        if e["id"].startswith(PREFIX):
            run_entry(e)


def run_entry(e: Any) -> None:
    eid = e["id"]
    assert (e["kind"], e["scope"]) == ("vector", "core"), eid
    assert e["path"] == eid + ".json", eid
    assert e["expected"] == e["path"], eid
    assert e["spec_map_row"], eid
    assert e["draft_section"], eid
    v = read_json(e["path"])
    assert v["id"] == eid
    assert v["reason"], eid
    text, b64 = v.get("input_text", ""), v.get("input_b64", "")
    assert not (text and b64), f"{eid} sets both input_text and input_b64"
    assert text or b64, f"{eid} has no input"
    data = base64.b64decode(b64, validate=True) if b64 else text.encode("utf-8")
    want = {"reject": "REJECTED", "accept": "ACCEPTED"}.get(v["expect"])
    assert want is not None, eid
    assert want == e["outcome"], eid
    # Every vector is decoded as an OperationContext.
    if v["expect"] == "accept":
        assert isinstance(strictjson.decode(data, OperationContext), OperationContext), eid
        return
    with pytest.raises(StrictJSONError) as ei:
        strictjson.decode(data, OperationContext)
    name = eid.removeprefix(PREFIX)
    if name in WANT_ERR:
        assert ei.value.kind is WANT_ERR[name], f"{eid}: {ei.value}"
