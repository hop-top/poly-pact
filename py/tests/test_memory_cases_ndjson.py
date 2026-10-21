"""The adapter-case leg of the parity check (port of
go/adapters/memory/cases_ndjson_test.go).

Go's test binary of adapters/memory doubles as that leg; here the vectors
harness, python -m hop_top_pact.vectors, prints the adapter-case lines: the
conformance suite against the memory adapter in both workload modes, one line
per common case, {"id","kind","result"}, the id being the case's manifest id.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

import broken
from hop_top_pact.adapter.adaptertest import Result
from hop_top_pact.vectors._adapters import (
    MEMORY_MODES,
    CaseLine,
    CaseMode,
    common_case_id,
    evaluate_modes,
    merge_case_results,
)

PY_ROOT = Path(__file__).resolve().parents[1]
FIXTURES = PY_ROOT.parent / "spec" / "v1.0" / "fixtures"


def fixtures() -> Path:
    if not (FIXTURES / "manifest.json").exists():
        if os.environ.get("PACT_REQUIRE_VECTORS") == "1":
            pytest.fail(f"{FIXTURES} absent under PACT_REQUIRE_VECTORS=1")
        pytest.skip("no spec/ tree (mirror checkout)")
    return FIXTURES


def manifest_case_ids() -> list[str]:
    """The ids of the adapter-case entries of the real manifest whose files are
    common cases."""
    m = json.loads((fixtures() / "manifest.json").read_text(encoding="utf-8"))
    return sorted(
        e["id"]
        for e in m["entries"]
        if e["kind"] == "adapter-case" and e["id"].startswith("adapters/_common/")
    )


def test_case_results_ndjson() -> None:
    """One line per common adapter-case entry of the manifest, and every one passes."""
    lines = evaluate_modes(fixtures())
    for line in lines:
        assert (line.kind, line.result) == ("adapter-case", "pass"), (line.id, line.failures)
    assert [line.id for line in lines] == manifest_case_ids()


def test_case_results_ndjson_broken() -> None:
    """Against the broken adapter that resolves a shared workload to its first agent,
    the lines still cover every case, and the shared-workload cases that defect breaks
    are fail; they run only in the shared mode."""
    lines = evaluate_modes(
        fixtures(),
        (
            CaseMode("dedicated", broken.factory(broken.Defect.FIRST_OF_SHARED), False),
            CaseMode("shared", broken.shared_factory(broken.Defect.FIRST_OF_SHARED), True),
        ),
    )
    got = {line.id: line.result for line in lines}
    assert [line.id for line in lines] == manifest_case_ids()
    for cid in ("IDENT-09.shared-workload", "IDENT-09.other-agent", "IDENT-09.unenrolled-agent"):
        assert got[common_case_id(cid)] == "fail", cid
    assert got[common_case_id("COMMON-01.credential-wins")] == "pass"


def test_merge_case_results() -> None:
    """A case passes only when it passed in every mode that ran it; a case that ran
    in one mode takes that mode's result; the failures name their mode."""
    fail = ("wrong outcome",)
    got = merge_case_results(
        ["dedicated", "shared"],
        [
            [
                Result(id="COMMON-02.b"),
                Result(id="IDENT-10.a", failures=fail),
                Result(id="COMMON-01.a"),
                Result(id="COMMON-03.c", failures=fail),
            ],
            [
                Result(id="COMMON-02.b", failures=fail),
                Result(id="IDENT-09.a"),
                Result(id="COMMON-01.a"),
                Result(id="IDENT-09.b", failures=fail),
                Result(id="COMMON-03.c"),
            ],
        ],
    )
    k = "adapter-case"
    assert got == [
        CaseLine("adapters/_common/common-01.a", k, "pass"),
        CaseLine("adapters/_common/common-02.b", k, "fail", ["shared: wrong outcome"]),
        CaseLine("adapters/_common/common-03.c", k, "fail", ["dedicated: wrong outcome"]),
        CaseLine("adapters/_common/ident-09.a", k, "pass"),
        CaseLine("adapters/_common/ident-09.b", k, "fail", ["shared: wrong outcome"]),
        CaseLine("adapters/_common/ident-10.a", k, "fail", ["dedicated: wrong outcome"]),
    ]
    assert [m.name for m in MEMORY_MODES] == ["dedicated", "shared"]


def test_case_results_ndjson_binary() -> None:
    """python -m hop_top_pact.vectors prints exactly one adapter-case pass line per
    common case, with the three members of the result grammar; a common case is
    no longer skipped."""
    want = manifest_case_ids()
    proc = subprocess.run(
        [sys.executable, "-m", "hop_top_pact.vectors"],
        cwd=PY_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode in (0, 1), proc.stderr
    ids = []
    for raw in proc.stdout.splitlines():
        line = json.loads(raw)
        if line["kind"] != "adapter-case" or not line["id"].startswith("adapters/_common/"):
            continue
        assert line == {"id": line["id"], "kind": "adapter-case", "result": "pass"}, line
        ids.append(line["id"])
    assert ids == want
