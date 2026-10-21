"""The body that test_run_fails_every_case of test_broken.py runs in a pytest
subprocess (Go TestRunAgainstBroken): the public entry points, conformance_cases
and run_case applied with pytest.mark.parametrize as an adapter author applies
them, against the adapter with every defect on, in each mode. It fails, by
design, and runs only when the parent test asks for it; its name keeps it out of
test collection."""

from __future__ import annotations

import os

import pytest

from broken import MODES, Mode, defects
from hop_top_pact.adapter.adaptertest import Case, LoadError, conformance_cases, run_case


def _params() -> list[tuple[Mode, Case]]:
    out: list[tuple[Mode, Case]] = []
    for m in MODES:
        try:
            cases, _ = conformance_cases(m.options)
        except LoadError:
            return []
        out.extend((m, c) for c in cases)
    return out


PARAMS = _params()


@pytest.mark.skipif(
    os.environ.get("PACT_RUN_BROKEN") != "1",
    reason="runs as a subprocess of test_run_fails_every_case",
)
@pytest.mark.parametrize(("m", "case"), PARAMS, ids=[f"{m.name}-{c.id}" for m, c in PARAMS])
def test_run_against_broken(m: Mode, case: Case) -> None:
    run_case(m.build(*defects()), case, m.options)
