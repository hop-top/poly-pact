"""The harness's committed tables against their sources.

The vocabularies of runner.manifest (kinds, scopes, capabilities) against
hop.top/pact-go/runner/manifest, the jws Reason table against
go/core/jws/errors.go, and the repository manifest and vectors against the
tables. The Go sources sit outside the package: a
test that reads them skips when they are absent (a mirror checkout, or the
copy that make py-mutants tests). The fixture tests follow the
PACT_REQUIRE_VECTORS rule.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

import pytest

from hop_top_pact.core.jws import Reason
from hop_top_pact.runner import manifest
from hop_top_pact.vectors import GROUPS, RUN_KINDS

REPO = Path(__file__).resolve().parents[2]
FIXTURES = REPO / "spec" / "v1.0" / "fixtures"
MANIFEST_RULES = REPO / "go" / "runner" / "manifest" / "rules.go"
JWS_ERRORS = REPO / "go" / "core" / "jws" / "errors.go"
# The reason the harness itself reports when a verified payload fails the
# artifact layer (decode_as), as Go's vector tests do.
HARNESS_REASONS = {"payload-schema"}


def go_source(path: Path) -> str:
    if not path.exists():
        pytest.skip(f"{path.relative_to(REPO)} absent")
    return path.read_text(encoding="utf-8")


def fixtures() -> Path:
    if not FIXTURES.exists():
        if os.environ.get("PACT_REQUIRE_VECTORS") == "1":
            pytest.fail(f"{FIXTURES} absent under PACT_REQUIRE_VECTORS=1")
        pytest.skip("no spec/ tree (mirror checkout)")
    return FIXTURES


def go_list(src: str, var: str, typ: str) -> list[str]:
    """The string values of `var <var> = []<typ>{A, B}`: literals, or names resolved
    through the constants."""
    consts = dict(re.findall(r'^\s*(\w+)\s+(?:\w+\s+)?=\s+"([^"]*)"', src, re.MULTILINE))
    m = re.search(rf"^var {var} = \[\]{typ}\{{([^}}]*)\}}", src, re.MULTILINE)
    assert m, f"var {var} not found"
    if '"' in m.group(1):
        return re.findall(r'"([^"]*)"', m.group(1))
    return [consts[name] for name in re.findall(r"\w+", m.group(1))]


def test_kinds_scopes_capabilities_match_go() -> None:
    src = go_source(MANIFEST_RULES)
    assert manifest.kinds() == go_list(src, "kinds", "Kind")
    assert manifest.scopes() == go_list(src, "scopes", "Scope")
    assert manifest.capabilities() == go_list(src, "capabilities", "string")
    assert manifest.outcomes() == go_list(src, "outcomes", "string")
    assert manifest.conformance_profiles() == go_list(src, "conformanceProfiles", "string")
    assert manifest.transports() == go_list(src, "transports", "string")
    assert manifest.layers() == go_list(src, "layers", "string")


def test_reason_matches_go() -> None:
    src = go_source(JWS_ERRORS)
    want = re.findall(r'^\s*Err(\w+)\s+Reason = "([^"]*)"', src, re.MULTILINE)
    assert len(want) == 29
    assert [r.value for r in Reason] == [v for _, v in want]


def manifest_entries() -> list[dict[str, Any]]:
    doc = json.loads((fixtures() / "manifest.json").read_text(encoding="utf-8"))
    entries: list[dict[str, Any]] = doc["entries"]
    return entries


def test_manifest_within_tables() -> None:
    entries = manifest_entries()
    assert {e["kind"] for e in entries} <= set(manifest.kinds())
    assert {e["scope"] for e in entries} <= set(manifest.scopes())
    assert {c for e in entries for c in e.get("capabilities", [])} <= set(manifest.capabilities())


def test_groups_cover_manifest() -> None:
    """Every vector and key entry of scope core and adapter has a group of the harness."""
    for e in manifest_entries():
        if e["kind"] in RUN_KINDS and e["scope"] != "runner":
            segs = e["id"].split("/")
            group = "/".join(segs[:2]) if segs[0] == "vectors" else segs[0]
            assert (e["kind"], group) in GROUPS, e["id"]


def test_reject_reasons_known() -> None:
    known = {r.value for r in Reason} | HARNESS_REASONS
    seen: set[str] = set()
    for path in sorted((fixtures() / "vectors" / "jws").glob("*.json")):
        doc = json.loads(path.read_text(encoding="utf-8"))
        for v in doc if isinstance(doc, list) else [doc]:
            if v.get("reject_reason") is not None:
                seen.add(v["reject_reason"])
    assert seen, "no reject_reason under vectors/jws"
    assert seen <= known, sorted(seen - known)
