"""The jcs vectors. Port of go/core/jcs/vectors_test.go, plus the rfc8785 oracle.

Reads spec/v1.0/fixtures/manifest.json of the source repository: fails when it is
absent under PACT_REQUIRE_VECTORS=1 (make py-test) and skips otherwise (a
mirror checkout). rfc8785 (a test-only dependency) is an independent RFC
8785 implementation; it must agree with the vectors and with this package.
"""

from __future__ import annotations

import json
import os
import struct
from pathlib import Path
from typing import Any

import pytest
import rfc8785

from hop_top_pact.core import jcs, strictjson
from hop_top_pact.core.strictjson import Limits

FIXTURES = Path(__file__).resolve().parents[2] / "spec" / "v1.0" / "fixtures"
PREFIX = "vectors/jcs/"
NUMBERS_ID = PREFIX + "numbers"
REQUIRED_PAIRS = ["arrays", "french", "structures", "unicode", "values", "weird"]


def read_fixture(rel: str) -> bytes:
    path = FIXTURES / rel
    if not path.exists():
        if os.environ.get("PACT_REQUIRE_VECTORS") == "1":
            pytest.fail(f"{path} absent under PACT_REQUIRE_VECTORS=1")
        pytest.skip("no spec/ tree (mirror checkout)")
    return path.read_bytes()


def read_json(rel: str) -> Any:
    return strictjson.parse(read_fixture(rel), Limits(max_bytes=1 << 20))


def jcs_entries() -> list[Any]:
    m = read_json("manifest.json")
    assert m["manifest_version"] == 1
    return [e for e in m["entries"] if e["id"].startswith(PREFIX)]


def numbers() -> list[tuple[float, str]]:
    (path,) = [e["path"] for e in jcs_entries() if e["id"] == NUMBERS_ID]
    out = []
    for i, v in enumerate(read_json(path)):
        assert len(v["ieee754_hex"]) == 16, f"entry {i} malformed"
        assert v["expected"], f"entry {i} malformed"
        (f,) = struct.unpack(">d", bytes.fromhex(v["ieee754_hex"]))
        out.append((f, v["expected"]))
    return out


# The source and license notes of the vendored data: no manifest entry lists
# them, as for every file named LICENSE*.
NOTICE_FILES = (
    PREFIX + "LICENSE-NOTE.md",
    PREFIX + "LICENSE.md",
    PREFIX + "LICENSE-2.0.md",
)


def test_manifest_lists_every_jcs_file() -> None:
    entries = jcs_entries()
    ids = {e["id"] for e in entries}
    listed = {e["path"] for e in entries} | {e["expected"] for e in entries}
    for n in [*REQUIRED_PAIRS, "numbers"]:
        assert PREFIX + n in ids, f"manifest lacks required entry {PREFIX}{n}"
    # Files on disk that the manifest does not list never run: flag them.
    for p in sorted((FIXTURES / PREFIX).rglob("*")):
        rel = p.relative_to(FIXTURES).as_posix()
        if p.is_file() and rel not in NOTICE_FILES:
            assert rel in listed, f"{rel} is not listed in manifest.json"


def test_vectors_via_manifest() -> None:
    entries = jcs_entries()
    assert entries, "manifest lists no jcs vectors"
    for e in entries:
        assert (e["kind"], e["scope"], e["outcome"]) == ("vector", "core", "ACCEPTED"), e["id"]
        assert e["spec_map_row"], e["id"]
        assert e["draft_section"], e["id"]
        assert e["path"].endswith(".json"), e["id"]
        assert e["expected"].endswith(".json"), e["id"]
        if e["id"] == NUMBERS_ID:
            assert e["path"] == e["expected"]
            run_numbers()
        else:
            run_pair(e)


def run_pair(e: Any) -> None:
    assert e["path"] != e["expected"], e["id"]
    want = read_fixture(e["expected"])
    src = read_fixture(e["path"])
    assert jcs.canonicalize(src) == want, e["id"]
    # The expected output is canonical, so canonicalizing it is a no-op.
    assert jcs.canonicalize(want) == want, e["id"]
    # The parsed tree and the oracle agree.
    assert jcs.canonicalize_value(strictjson.parse(src)) == want, e["id"]
    assert rfc8785.dumps(json.loads(src)) == want, e["id"]


def run_numbers() -> None:
    # Every number of the list drives the whole of canonicalize: the value is
    # written as an exponent-form literal (valid JSON, whatever its
    # magnitude), then canonicalized.
    rows = numbers()
    assert len(rows) >= 1000, f"only {len(rows)} numbers"
    bad = []
    for f, want in rows:
        literal = format(f, ".16e")
        got = jcs.canonicalize(literal.encode("ascii"))
        if got != want.encode("ascii"):
            bad.append((literal, got, want))
    assert not bad, bad[:20]


def test_numbers_all_rows() -> None:
    rows = numbers()
    assert len(rows) == 10000
    for f, want in rows:
        assert jcs.canonicalize_value(f) == want.encode("ascii"), (f.hex(), want)
        assert jcs.canonicalize_value(-f) == rfc8785.dumps(-f), f.hex()
        assert rfc8785.dumps(f) == want.encode("ascii"), (f.hex(), want)
