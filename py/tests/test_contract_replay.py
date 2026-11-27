"""The replay store. Port of go/contract/replay_test.go.

The Go test of a cancelled context has no counterpart: the calls take no
context argument (docs/sdk/parity-ledger.md, deviation adapter calls).
"""

from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from typing import Any

import pytest

from hop_top_pact import contract
from hop_top_pact.adapter import Code, Realm

NONCE = "N8WrKpg8XNb9Wh_QuWlHbw"


def record(ck: Any, nonce: str) -> contract.NonceRecord:
    return contract.NonceRecord(
        nonce=nonce,
        agent_id=ck.B4_AGENT,
        holder_jkt=ck.B4_HOLDER_JKT,
        realm=ck.B4_REALM,
        operation_digest=ck.B4_OP_DIGEST,
        requirements_digest=ck.B4_INTENT_DIGEST,
    )


def test_reused_nonce_rejected(ck: Any) -> None:
    # The second consumption of a nonce is REPLAY, and so is a nonce that was never
    # registered (draft 7.5).
    m = contract.MemoryReplay()
    r, t = record(ck, NONCE), ck.B4_TIME
    with ck.raises(contract.CODE_REPLAY):
        m.consume(r, ck.at(t), ck.at(t + 65))
    m.register(r, ck.at(t), ck.at(t + 65))
    with ck.raises(contract.CODE_REPLAY):
        m.register(r, ck.at(t), ck.at(t + 65))
    m.consume(r, ck.at(t + 1), ck.at(t + 66))
    with ck.raises(contract.CODE_REPLAY):
        m.consume(r, ck.at(t + 2), ck.at(t + 67))
    with ck.raises(contract.CODE_REPLAY):
        m.register(r, ck.at(t + 2), ck.at(t + 67))


BINDING: dict[str, Callable[[contract.NonceRecord], contract.NonceRecord]] = {
    "agent": lambda r: replace(r, agent_id="https://identity.example/agents/other"),
    "holder": lambda r: replace(r, holder_jkt="ahxE1XEYqxvLIZy3r4nx9RE4E0683KndykyuZTK9xQg"),
    "tenant": lambda r: replace(r, realm=replace(r.realm, tenant_id="globex")),
    "env": lambda r: replace(r, realm=Realm(tenant_id=r.realm.tenant_id, environment_id="x")),
    "operation": lambda r: replace(
        r, operation_digest="t79YgXU70gzKitcuPJ_fUp4V_bM5MGooinyuyL8cE5M"
    ),
    "contract": lambda r: replace(
        r, requirements_digest="R5nfhv7g_o93VPHK6a2o56-MyyGy75GQwXxDM4M3cn0"
    ),
}


@pytest.mark.parametrize("name", sorted(BINDING))
def test_consume_binding(ck: Any, name: str) -> None:
    # A nonce consumed with another agent, key, realm, operation or contract is
    # CONTEXT_MISMATCH and stays unconsumed.
    m = contract.MemoryReplay()
    r, t = record(ck, NONCE), ck.B4_TIME
    m.register(r, ck.at(t), ck.at(t + 65))
    with ck.raises(Code.CONTEXT_MISMATCH):
        m.consume(BINDING[name](r), ck.at(t), ck.at(t + 65))
    m.consume(r, ck.at(t), ck.at(t + 65))  # the registered record after a mismatch


def test_consume_concurrent(ck: Any) -> None:
    # Of many concurrent consumptions of one nonce, exactly one succeeds; every other
    # is REPLAY (draft 7.5, fixture admission/replay-same-nonce-two-replicas).
    m = contract.MemoryReplay()
    r, t = record(ck, NONCE), ck.B4_TIME
    m.register(r, ck.at(t), ck.at(t + 65))

    def consume(_: int) -> str:
        try:
            m.consume(r, ck.at(t), ck.at(t + 65))
        except contract.ContractError as e:
            return e.code
        return "ok"

    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(consume, range(64)))
    assert results.count("ok") == 1, f"{results.count('ok')} consumptions succeeded, want 1"
    assert set(results) <= {"ok", "REPLAY"}


def test_retention(ck: Any) -> None:
    # A record is kept until its retention bound, under load too: a full store defers
    # (DEPENDENCY_UNAVAILABLE) rather than evict a record early. A consumption extends
    # the bound; once it has passed, the record may go (fixture
    # admission/old-presentation-after-eviction).
    m = contract.MemoryReplay(2)
    t = ck.B4_TIME
    a, b, c, d = (record(ck, ch * 22) for ch in "abcd")
    m.register(a, ck.at(t), ck.at(t + 65))
    m.register(b, ck.at(t), ck.at(t + 65))
    with ck.raises(Code.DEPENDENCY_UNAVAILABLE):
        m.register(c, ck.at(t + 65), ck.at(t + 130))
    # a is consumed and kept to t + 75.
    m.consume(a, ck.at(t + 10), ck.at(t + 75))
    # At t + 66 b may go, a may not.
    m.register(c, ck.at(t + 66), ck.at(t + 130))
    with ck.raises(contract.CODE_REPLAY):
        m.consume(a, ck.at(t + 66), ck.at(t + 130))
    with ck.raises(Code.DEPENDENCY_UNAVAILABLE):
        m.register(d, ck.at(t + 75), ck.at(t + 140))
    with ck.raises(contract.CODE_REPLAY):
        m.consume(a, ck.at(t + 75), ck.at(t + 140))
    m.register(d, ck.at(t + 76), ck.at(t + 140))  # after a's bound
    # An earlier until never shortens a bound.
    e = record(ck, "e" * 22)
    m = contract.MemoryReplay(1)
    m.register(e, ck.at(t), ck.at(t + 65))
    m.consume(e, ck.at(t), ck.at(t + 1))
    with ck.raises(Code.DEPENDENCY_UNAVAILABLE):
        m.register(d, ck.at(t + 64), ck.at(t + 100))
    with ck.raises(contract.CODE_REPLAY):
        m.consume(e, ck.at(t + 64), ck.at(t + 100))


def test_retention_bound(ck: Any) -> None:
    # A record is kept through its bound and goes after it.
    m = contract.MemoryReplay()
    r, t = record(ck, NONCE), ck.B4_TIME
    m.register(r, ck.at(t), ck.at(t + 65))
    with ck.raises(contract.CODE_REPLAY):
        m.register(r, ck.at(t + 65), ck.at(t + 130))
    with ck.raises(contract.CODE_REPLAY):
        m.consume(r, ck.at(t + 66), ck.at(t + 130))
