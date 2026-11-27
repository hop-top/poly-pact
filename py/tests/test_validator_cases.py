"""The shared evaluation cases of spec/v1.0/fixtures run through the validator and the test
gateway of tests/validator_support, and judged against each case's expected decision: the
decision or transport code of every response and the result and reason code of every check
the case lists."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from hop_top_pact import conformance
from hop_top_pact.core.jws import base64url
from validator_support import run_case

FIXTURES = Path(__file__).resolve().parents[2] / "spec" / "v1.0" / "fixtures"


def case_ids() -> list[str]:
    if not FIXTURES.exists():
        return []
    m = json.loads((FIXTURES / "manifest.json").read_bytes())
    return sorted(e["id"] for e in m["entries"] if e["kind"] == "evaluate")


def response(line: str) -> dict[str, Any]:
    """A response line as the expected file's fields: the receipt's decision and checks, or
    the problem's code."""
    if line.startswith("{"):
        doc = json.loads(line)
        if "handoff" in doc:
            return {"handoff": doc["handoff"]}
        return {"transport_code": doc["code"]}
    claims = json.loads(base64url.decode(line.split(".")[1]))
    return {
        "decision": claims["decision"],
        "checks": {c["check_id"]: (c["result"], c["reason_code"]) for c in claims["checks"]},
    }


@pytest.mark.parametrize("id_", case_ids() or ["none"])
def test_case(id_: str) -> None:
    if not FIXTURES.exists():
        pytest.skip("no spec/ tree (mirror checkout)")
    c = conformance.read(FIXTURES, id_)
    if len(c.exchanges) != 1:
        pytest.skip("a sequence of exchanges")
    want = c.exchanges[0].expected
    expected: list[Any] = list(want.responses) if want.responses is not None else [want]
    lines = run_case(FIXTURES / c.path)
    got = [response(ln) for ln in lines[: len(expected)]]
    assert len(got) == len(expected)
    for g, w in zip(got, expected, strict=True):
        if w.transport_code is not None:
            assert g.get("transport_code") == w.transport_code, (id_, g)
            continue
        assert g.get("decision") == w.decision, (id_, g.get("decision"))
        for ec in w.checks:
            assert g["checks"].get(ec.check_id) == (ec.result, ec.reason_code), (id_, ec.check_id)
