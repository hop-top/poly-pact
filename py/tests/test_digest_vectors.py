"""The digest vectors. Port of go/core/digest/vectors_test.go.

Reads spec/v1.0/fixtures/manifest.json of the source repository: fails when it is
absent under PACT_REQUIRE_VECTORS=1 (make py-test) and skips otherwise (a
mirror checkout). A vector that the draft gets wrong (spec_defect) is
reported as a skip that names both values, never as a pass.
"""

from __future__ import annotations

import enum
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from hop_top_pact.core import Digest, digest, strictjson
from hop_top_pact.core.strictjson import Limits

FIXTURES = Path(__file__).resolve().parents[2] / "spec" / "v1.0" / "fixtures"
PREFIX = "vectors/digest/"
APPENDIX_ID = PREFIX + "appendix-b"
VECTOR_FIELDS = ["appendix_value", "expected_digest", "id", "input", "input_kind", "spec_defect"]

BODY_DIGEST_OF_EMPTY = "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"
OPERATION_DIGEST_B3 = "R5nfhv7g_o93VPHK6a2o56-MyyGy75GQwXxDM4M3cn0"
INTENT_DIGEST_B2 = "t79YgXU70gzKitcuPJ_fUp4V_bM5MGooinyuyL8cE5M"


def read_json(rel: str) -> Any:
    path = FIXTURES / rel
    if not path.exists():
        if os.environ.get("PACT_REQUIRE_VECTORS") == "1":
            pytest.fail(f"{path} absent under PACT_REQUIRE_VECTORS=1")
        pytest.skip("no spec/ tree (mirror checkout)")
    return strictjson.parse(path.read_bytes(), Limits(max_bytes=1 << 20))


def digest_entries() -> list[Any]:
    m = read_json("manifest.json")
    assert m["manifest_version"] == 1
    return [e for e in m["entries"] if e["id"].startswith(PREFIX)]


def test_manifest_lists_every_digest_file() -> None:
    entries = digest_entries()
    assert APPENDIX_ID in {e["id"] for e in entries}
    listed = {e["path"] for e in entries} | {e["expected"] for e in entries}
    for p in sorted((FIXTURES / PREFIX).rglob("*")):
        rel = p.relative_to(FIXTURES).as_posix()
        if p.is_file() and p.name != "README.md":
            assert rel in listed, f"{rel} is not listed in manifest.json"


def appendix_path() -> str:
    (path,) = [e["path"] for e in digest_entries() if e["id"] == APPENDIX_ID]
    return str(path)


def test_vectors_required_by_the_draft() -> None:
    # Each vector below must carry the digest the draft prints as its
    # appendix_value, so deleting a vector or editing its input fails here.
    vs = read_json(appendix_path())
    by_id = {v["id"]: v for v in vs}
    want = {
        "empty-body": ("bytes", BODY_DIGEST_OF_EMPTY),
        "operation-b3": ("object", OPERATION_DIGEST_B3),
        "intent-b2": ("object", INTENT_DIGEST_B2),
    }
    for vid, (kind, d) in want.items():
        assert vid in by_id, f"vector {vid} is missing"
        assert by_id[vid]["input_kind"] == kind, vid
        assert by_id[vid]["appendix_value"] == d, vid
    kinds = {v["input_kind"] for v in vs}
    assert {"object", "artifact", "bytes"} <= kinds


def test_vectors_via_manifest() -> None:
    entries = digest_entries()
    assert entries, "manifest lists no digest vectors"
    for e in entries:
        assert (e["kind"], e["scope"], e["outcome"]) == ("vector", "core", "ACCEPTED"), e["id"]
        assert e["spec_map_row"], e["id"]
        assert e["draft_section"] == "7.4", e["id"]
        assert e["path"].endswith(".json"), e["id"]
        assert e["path"] == e["expected"], e["id"]
        run_file(e["path"])


def run_file(rel: str) -> None:
    vs = read_json(rel)
    assert vs, f"{rel} has no vectors"
    seen: set[str] = set()
    defects = []
    for i, v in enumerate(vs):
        assert sorted(v) == VECTOR_FIELDS, f"vector {i} members {sorted(v)}"
        assert v["id"], f"vector {i}: empty id"
        assert v["id"] not in seen, f"vector {i}: id {v['id']!r} repeated"
        seen.add(v["id"])
        defect = run_vector(v)
        if defect:
            defects.append(defect)
    if defects:
        pytest.skip("spec defect: " + "; ".join(defects))


def run_vector(v: Mapping[str, Any]) -> str:
    Digest(v["expected_digest"]).validate()
    got = compute_digest(v)
    assert got == v["expected_digest"], v["id"]
    status = classify_appendix(v)
    if status is Appendix.DEFECT:
        return f"{v['id']}: draft Appendix B states {v['appendix_value']}, computed {got}"
    if status is Appendix.MATCH:
        assert v["appendix_value"] == got, v["id"]
    return ""


def compute_digest(v: Mapping[str, Any]) -> str:
    kind, value = v["input_kind"], v["input"]
    if kind == "object":
        return digest.object_digest(value)
    if kind == "artifact":
        assert isinstance(value, str)
        return digest.artifact_digest(value)
    if kind == "bytes":
        assert isinstance(value, str)
        assert value == value.lower()
        return digest.bytes_digest(bytes.fromhex(value))
    pytest.fail(f"input_kind {kind!r} is not object, artifact or bytes")


class Appendix(enum.Enum):
    NONE = 0  # the draft states no digest for this input
    MATCH = 1  # the draft value equals expected_digest
    DEFECT = 2  # the draft value differs and spec_defect is set


class AppendixError(ValueError):
    pass


def classify_appendix(v: Mapping[str, Any]) -> Appendix:
    """How a vector relates to the draft. A mismatch not marked spec_defect, a
    mark on a matching value and a mark without a draft value are errors."""
    value, flagged, want = (
        v.get("appendix_value"),
        v.get("spec_defect") is True,
        v["expected_digest"],
    )
    if value is None and flagged:
        raise AppendixError(f"{v['id']}: spec_defect is set but appendix_value is null")
    if value is None:
        return Appendix.NONE
    if value == want and flagged:
        raise AppendixError(f"{v['id']}: spec_defect is set but appendix_value matches")
    if value == want:
        return Appendix.MATCH
    if flagged:
        return Appendix.DEFECT
    raise AppendixError(f"{v['id']}: appendix_value {value} differs and spec_defect is not set")


A = "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"
B = "R5nfhv7g_o93VPHK6a2o56-MyyGy75GQwXxDM4M3cn0"


@pytest.mark.parametrize(
    ("name", "v", "want"),
    [
        ("match", {"expected_digest": A, "appendix_value": A}, Appendix.MATCH),
        ("no draft value", {"expected_digest": A}, Appendix.NONE),
        (
            "flagged defect",
            {"expected_digest": A, "appendix_value": B, "spec_defect": True},
            Appendix.DEFECT,
        ),
        ("unflagged mismatch", {"expected_digest": A, "appendix_value": B}, None),
        ("stale flag", {"expected_digest": A, "appendix_value": A, "spec_defect": True}, None),
        ("flag without draft value", {"expected_digest": A, "spec_defect": True}, None),
    ],
)
def test_classify_appendix(name: str, v: dict[str, Any], want: Appendix | None) -> None:
    v = {"id": name, **v}
    if want is None:
        with pytest.raises(AppendixError):
            classify_appendix(v)
    else:
        assert classify_appendix(v) is want
