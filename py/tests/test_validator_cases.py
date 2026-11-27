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
from validator_support import run_exchanges

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
    ran = run_exchanges(FIXTURES / c.path)
    assert len(ran) == len(c.exchanges)
    for x, lines in zip(c.exchanges, ran, strict=True):
        want = x.expected
        expected: list[Any] = list(want.responses) if want.responses is not None else [want]
        got = [response(ln) for ln in lines[: len(expected)]]
        assert len(got) == len(expected), (id_, x.name)
        for g, w in zip(got, expected, strict=True):
            if w.transport_code is not None:
                assert g.get("transport_code") == w.transport_code, (id_, x.name, g)
                continue
            assert g.get("decision") == w.decision, (id_, x.name, g.get("decision"))
            for ec in w.checks:
                assert g["checks"].get(ec.check_id) == (ec.result, ec.reason_code), (
                    id_,
                    x.name,
                    ec.check_id,
                )


def test_state_carries_across_exchanges() -> None:
    # The replay store, receipts and attestations of one case carry from an exchange to the
    # next (spec/v1.0/fixtures/README.md, Multi-exchange cases): the first exchange of a
    # sequence case, run again over the state it left, finds its nonce consumed (REPLAY),
    # where over a fresh state it is admitted again. The two sequence cases of the fixtures
    # present a different nonce in each exchange, so they cannot show it themselves.
    if not FIXTURES.exists():
        pytest.skip("no spec/ tree (mirror checkout)")
    from validator_support.gateway import GatewayState
    from validator_support.keys import load_private_keys
    from validator_support.run import _run_exchange

    c = conformance.read(FIXTURES, "approval/approved-fresh-exchange")
    keys = load_private_keys(FIXTURES)
    x = c.exchanges[0]
    gs = GatewayState()
    first = response(_run_exchange(FIXTURES, x, keys, gs)[0])
    again = response(_run_exchange(FIXTURES, x, keys, gs)[0])
    fresh = response(_run_exchange(FIXTURES, x, keys, GatewayState())[0])
    assert "decision" in first
    assert again == {"transport_code": "REPLAY"}
    assert "decision" in fresh
