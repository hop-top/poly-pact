"""The adapter-case leg of the harness: the common adapter cases against the
memory adapter (the counterpart of the Go test binary of adapters/memory run
with -ndjson; docs/sdk/ports-plan.md of the source repository, section 5.1).

The suite runs the memory adapter in both workload modes: dedicated
workloads, the default of every profile, and workloads shared by several
agents (identity mapping IM-19). Each mode runs the cases that apply to it,
so every common case runs in at least one. A case passes when it passed in
every mode that ran it.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from importlib.resources.abc import Traversable

from hop_top_pact.adapter.adaptertest import Factory, Options, Result, evaluate_conformance
from hop_top_pact.adapters import memory

KIND = "adapter-case"
PREFIX = "adapters/_common"


@dataclass(frozen=True, slots=True)
class CaseMode:
    """One workload mode the suite runs an adapter in."""

    name: str
    factory: Factory
    shared_workloads: bool


MEMORY_MODES: tuple[CaseMode, ...] = (
    CaseMode("dedicated", memory.factory, False),
    CaseMode("shared", memory.factory_with(memory.with_shared_workloads()), True),
)


@dataclass(slots=True)
class CaseLine:
    """One result line, with the failures that go to standard error."""

    id: str
    kind: str
    result: str
    failures: list[str] = field(default_factory=list)


def common_case_id(case_id: str) -> str:
    """The manifest id of a common case: its file, adapters/_common/<id in lowercase>.json,
    without .json (spec/v1.0/fixtures/adapters/README.md)."""
    return PREFIX + "/" + case_id.lower()


def merge_case_results(modes: Sequence[str], runs: Sequence[Sequence[Result]]) -> list[CaseLine]:
    """One line per case, sorted by id, from the results of each mode, runs[i] being
    those of modes[i]. A case passes when it passed in every mode that ran it, and
    fails otherwise; a failure names its mode."""
    by_id: dict[str, CaseLine] = {}
    for mode, results in zip(modes, runs, strict=True):
        for r in results:
            cid = common_case_id(r.id)
            line = by_id.setdefault(cid, CaseLine(cid, KIND, "pass"))
            if not r.passed():
                line.result = "fail"
                line.failures.extend(mode + ": " + f for f in r.failures)
    return [by_id[k] for k in sorted(by_id)]


def evaluate_modes(
    fixtures: Traversable, modes: Sequence[CaseMode] = MEMORY_MODES
) -> list[CaseLine]:
    """Run the common cases in every mode and merge the results. Raises the suite's
    LoadError when the cases cannot be loaded."""
    runs = [
        evaluate_conformance(
            m.factory, Options(fixtures=fixtures, shared_workloads=m.shared_workloads)
        )
        for m in modes
    ]
    return merge_case_results([m.name for m in modes], runs)


def is_common_case(kind: str, scope: str, eid: str) -> bool:
    """Whether a manifest entry is a common adapter case, which this leg runs."""
    return kind == KIND and scope == "adapter" and eid.startswith(PREFIX + "/")
