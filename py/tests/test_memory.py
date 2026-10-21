"""The conformance suite against the reference adapter (port of
go/adapters/memory/memory_test.go).

The suite runs in both workload modes: by default the adapter's workloads are
dedicated, the default of every profile, and with with_shared_workloads they
may be shared by several agents (identity mapping IM-19). This is how an
adapter author applies the suite: conformance_cases gives the cases and ids
of one mode, pytest.mark.parametrize runs one test per case, and run_case
raises when the adapter fails it.
"""

from __future__ import annotations

import os

import pytest

from hop_top_pact.adapter.adaptertest import (
    Case,
    Factory,
    LoadError,
    Options,
    conformance_cases,
    run_case,
)
from hop_top_pact.adapters import memory

MODES: dict[str, tuple[Factory, Options]] = {
    "dedicated": (memory.factory, Options()),
    "shared": (memory.factory_with(memory.with_shared_workloads()), Options(shared_workloads=True)),
}


def _params() -> list[tuple[str, Case | None]]:
    out: list[tuple[str, Case | None]] = []
    for mode, (_, opts) in MODES.items():
        try:
            cases, _ = conformance_cases(opts)
        except LoadError:
            # No fixture tree (a mirror checkout): test_suite reports it.
            return [("no-fixtures", None)]
        out.extend((mode, c) for c in cases)
    return out


PARAMS = _params()


@pytest.mark.parametrize(
    ("mode", "case"),
    PARAMS,
    ids=[f"{m}-{c.id}" if c is not None else m for m, c in PARAMS],
)
def test_suite(mode: str, case: Case | None) -> None:
    if case is None:
        if os.environ.get("PACT_REQUIRE_VECTORS") == "1":
            pytest.fail("no fixture tree under PACT_REQUIRE_VECTORS=1")
        pytest.skip("no spec/ tree (mirror checkout)")
    factory, opts = MODES[mode]
    run_case(factory, case, opts)


def test_suite_runs_every_mode() -> None:
    """Both modes contribute cases: IDENT-09 runs shared only, IDENT-10 dedicated
    only, and every other case in both."""
    modes = {m for m, c in PARAMS if c is not None}
    if not modes:
        pytest.skip("no spec/ tree (mirror checkout)")
    assert modes == {"dedicated", "shared"}
    shared = {c.id.split(".")[0] for m, c in PARAMS if m == "shared" and c is not None}
    dedicated = {c.id.split(".")[0] for m, c in PARAMS if m == "dedicated" and c is not None}
    assert "IDENT-09" in shared - dedicated
    assert "IDENT-10" in dedicated - shared
