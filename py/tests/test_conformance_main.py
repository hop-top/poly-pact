"""The evaluate skeleton, python -m hop_top_pact.conformance, run as a child process
the way pactc runs an evaluate command ("tool evaluate {dir} {state}", go/runner
package documentation): one response line per submission and per handoff attempt of
each exchange, each an RFC 9457 Problem (draft 13.4) with the code
UNSUPPORTED_REQUIREMENT and status 422; a usage or case error prints nothing on
standard output and exits 2."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest


def run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "hop_top_pact.conformance", *args],
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )


def want_lines(fixtures: Path, id: str) -> int:
    """The response lines a case asks for, counted from its files: per exchange, the
    expected responses (the top level as one, or responses) and the expected handoff
    results (spec/v1.0/fixtures/README.md, decision.json)."""
    seq = fixtures / id / "sequence.json"
    exchanges = json.loads(seq.read_bytes())["exchanges"] if seq.exists() else [""]
    n = 0
    for x in exchanges:
        d = json.loads((fixtures / "expected" / id / x / "decision.json").read_bytes())
        n += len(d["responses"]) if isinstance(d.get("responses"), list) else 1
        n += len(d["handoff"]) if isinstance(d.get("handoff"), list) else 0
    return n


@pytest.mark.parametrize(
    "id",
    [
        "admission/valid",
        "admission/attestation-reuse",
        "admission/replay-same-nonce-two-replicas",
        "approval/approved-fresh-exchange",
    ],
)
def test_skeleton_prints_unsupported_requirement(ec: Any, tmp_path: Path, id: str) -> None:
    fixtures = ec.repo_fixtures()
    r = run("evaluate", str(ec.at(fixtures, id)), str(tmp_path / "state"))
    assert r.returncode == 0, r.stderr
    assert r.stdout.endswith("\n"), "output ends with a newline"
    lines = r.stdout.split("\n")[:-1]
    assert len(lines) == want_lines(fixtures, id)
    ids = set()
    for i, line in enumerate(lines):
        p = json.loads(line)
        assert sorted(p) == ["code", "request_id", "status", "title", "type"], i
        assert p["code"] == "UNSUPPORTED_REQUIREMENT", i
        assert p["status"] == 422, i
        assert isinstance(p["request_id"], str), i
        assert p["request_id"], i
        ids.add(p["request_id"])
    assert len(ids) == len(lines), "request_id repeats"


@pytest.mark.parametrize(
    "args",
    [(), ("evaluate",), ("receipt", "dir", "x"), ("evaluate", "a", "b", "c")],
)
def test_skeleton_usage(args: tuple[str, ...]) -> None:
    r = run(*args)
    assert r.returncode == 2
    assert r.stdout == ""
    assert "usage: " in r.stderr


def test_skeleton_not_a_case_directory(ec: Any) -> None:
    r = run("evaluate", str(ec.at(ec.repo_fixtures(), "keys")))
    assert r.returncode == 2
    assert r.stdout == ""
    assert "keys" in r.stderr
