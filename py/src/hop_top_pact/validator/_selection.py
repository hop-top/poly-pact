"""The check selection-consistency-v1 (draft 11.3 step 9)."""

from __future__ import annotations

from hop_top_pact.core.types import ReputationValue
from hop_top_pact.validator._checks import CHECK_SELECTION_CONSISTENCY
from hop_top_pact.validator._config import SelectionInput
from hop_top_pact.validator._decide import (
    REASON_SELECTION_INPUT_CHANGED,
    REASON_UNAVAILABLE,
    REASON_UNSUPPORTED,
)
from hop_top_pact.validator._eval import Evaluation
from hop_top_pact.validator._outcome import Outcome, fail, ok, unknown


def selection_consistency(e: Evaluation) -> Outcome:
    """The check selection-consistency-v1 of draft 11.3 step 9: the contract's pinned selector
    re-derives the set from (i) the presented snapshot and (ii) the gateway's own current
    trusted selection input, with the holds in force. A set stricter than the contract's is
    FAIL with SELECTION_INPUT_CHANGED, which defers: the contract is stale. Equal or weaker
    leaves the contract's set as it is."""
    o = _result(e)
    if e.snapshot_jti:
        o.evidence = [e.snapshot_jti]
    if e.sel_err is None and e.sel.record_ref:
        o.source_ref = e.sel.record_ref
    return o


def _result(e: Evaluation) -> Outcome:
    assert e.v.clock is not None
    if CHECK_SELECTION_CONSISTENCY not in e.v.config.installed_checks:
        return unknown(REASON_UNSUPPORTED)
    if e.sel_err is not None or e.holds_err is not None:
        return unknown(REASON_UNAVAILABLE)
    s = e.sel.selector
    if s is None:
        return unknown(REASON_UNSUPPORTED)
    order = list(s.order())

    def rank(set_: str) -> int:
        return order.index(set_) if set_ in order else -1

    selected = rank(e.con.claims.selected_set)
    if selected < 0:
        return unknown(REASON_UNSUPPORTED)
    presented: ReputationValue | None = e.snapshot.value if e.snapshot is not None else None
    current = e.sel.current if e.sel.current is not None else presented
    for in_ in (presented, current):
        try:
            set_ = s.select(SelectionInput(snapshot=in_, holds=list(e.holds)))
        except Exception:
            return unknown(REASON_UNAVAILABLE)
        r = rank(set_)
        if r < 0:
            return unknown(REASON_UNSUPPORTED)
        if r < selected:
            return fail(REASON_SELECTION_INPUT_CHANGED)
    return ok().at(e.v.clock.now())
