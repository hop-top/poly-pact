"""A presentation the holder builds is evaluated by the validator. Port of
go/holder/validator_integration_test.go, with the hook wired to the validator."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest

from hop_top_pact.core.enums import Decision
from hop_top_pact.core.types import OperationContext
from validator_support import prepare

FIXTURES = Path(__file__).resolve().parents[2] / "spec" / "v1.0" / "fixtures"


def decision(
    hk: Any, presentation: str, actual: OperationContext, now: datetime
) -> Decision | None:
    """Evaluate a presentation with the validator of the admission/valid configuration, whose
    Appendix B values apply, at now, and return its decision; None when the request is
    rejected before an evaluation."""
    if not FIXTURES.exists():
        pytest.skip("no spec/ tree (mirror checkout)")
    f = prepare(FIXTURES / "admission/valid")
    f.clock.set(now)
    f.request = replace(f.request, presentation=presentation, operation=actual)
    try:
        return f.validator.evaluate(f.request).attestation.decision
    except Exception:
        return None


def test_presentation_passes_validator(ck: Any, hk: Any) -> None:
    # The Appendix B presentation the holder builds is ADMISSIBLE under the validator, and
    # its stale-contract and modified-operation variants are not.
    h = hk.b_holder(hk.memory_key(1))
    p = h.present(hk.b_input(), ck.at(ck.B4_TIME))
    d = decision(hk, p.compact, hk.b_operation(), ck.at(ck.B4_TIME))
    assert d == Decision.ADMISSIBLE
    modified = replace(hk.b_operation(), resources=("https://invoices.example/invoices/INV-1043",))
    variants = {
        "stale contract": (hk.b_operation(), ck.at(hk.B_CONTRACT_EXP)),
        "modified operation": (modified, ck.at(ck.B4_TIME)),
    }
    for name, (actual, now) in variants.items():
        got = decision(hk, p.compact, actual, now)
        assert got != Decision.ADMISSIBLE, name
