"""The proof that the adapter conformance suite can fail (port of
go/adapters/internal/broken/broken_test.go).

With no defect on, the broken adapter is the memory adapter and passes every
case; with one defect on, the cases that defect targets fail; with every
defect on, every case fails; every case is targeted by some defect; and
run_case under pytest, the counterpart of Go's Run, not only
evaluate_conformance, reports a failure for every case.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from broken import CATALOGUE, MODES, Defect, Mode, Spec, defects
from hop_top_pact.adapter.adaptertest import LoadError, Result, evaluate_conformance

PY_ROOT = Path(__file__).resolve().parents[2]
RUN_AGAINST_BROKEN = Path(__file__).with_name("run_against_broken.py")


def evaluate(m: Mode, *on: Defect) -> dict[str, Result]:
    """Run the suite against the broken adapter with the given defects on, in mode m,
    and return the results by case id. Skips without a fixture tree, unless
    PACT_REQUIRE_VECTORS=1."""
    try:
        results = evaluate_conformance(m.build(*on), m.options)
    except LoadError as e:
        if os.environ.get("PACT_REQUIRE_VECTORS") == "1":
            pytest.fail(f"no fixture tree under PACT_REQUIRE_VECTORS=1: {e}")
        pytest.skip("no spec/ tree (mirror checkout)")
    assert results, "the suite has no cases"
    return {r.id: r for r in results}


def test_no_defects_passes_the_suite() -> None:
    """With every defect off, the wrapper is the memory adapter and passes every case
    of each mode, so a failure below is the defect's doing."""
    errors = [
        f"{m.name}: {cid} fails with no defect on: {r.failures}"
        for m in MODES
        for cid, r in sorted(evaluate(m).items())
        if not r.passed()
    ]
    assert errors == []


def test_catalogue_is_consistent() -> None:
    """Defects are unique, each one is a member of Defect that the catalogue lists
    once, and every target is a case that exists in a mode. A case that no defect
    targets cannot be shown to catch anything, so it fails."""
    res: dict[str, Result] = {}
    for m in MODES:
        res.update(evaluate(m))
    errors: list[str] = []
    seen: set[Defect] = set()
    targeted: set[str] = set()
    for s in CATALOGUE:
        if s.defect in seen:
            errors.append(f"defect {s.defect.value!r} is listed twice")
        seen.add(s.defect)
        if not s.what or not s.targets:
            errors.append(f"defect {s.defect.value!r} has no description or no target")
        for cid in s.targets:
            if cid not in res:
                errors.append(f"defect {s.defect.value!r} targets {cid!r}, which is not a case")
            targeted.add(cid)
    for d in Defect:
        if d not in seen:
            errors.append(f"defect {d.value!r} is not in the catalogue")
    for cid in sorted(res):
        if cid not in targeted:
            errors.append(f"no defect targets case {cid}: add a mutant that it catches")
    assert errors == []


@pytest.mark.parametrize("s", CATALOGUE, ids=[s.defect.value for s in CATALOGUE])
def test_each_defect_fails_its_cases(s: Spec) -> None:
    """The mutation proof, one defect at a time. The cases a defect targets must fail
    with only that defect on, in every mode that runs them, so no defect passes the
    whole suite. Other cases that fail with it are printed, not required: some
    defects spoil several cases."""
    errors: list[str] = []
    ran: set[str] = set()
    for m in MODES:
        res = evaluate(m, s.defect)
        for cid in s.targets:
            r = res.get(cid)
            if r is None:
                continue
            ran.add(cid)
            if r.passed():
                errors.append(
                    f"{m.name}: case {cid} passes although {s.defect.value!r} ({s.what}) is on"
                )
        collateral = [cid for cid in sorted(res) if not res[cid].passed() and cid not in s.targets]
        if collateral:
            print(f"{m.name}: also fails: {', '.join(collateral)}")
    errors.extend(f"no case {cid} in any mode" for cid in s.targets if cid not in ran)
    assert errors == []


def test_all_defects_fail_every_case() -> None:
    """The adapter with every defect on fails every case of the suite, in each
    mode."""
    errors = [
        f"{m.name}: case {cid} passes against the adapter with every defect on"
        for m in MODES
        for cid, r in sorted(evaluate(m, *defects()).items())
        if r.passed()
    ]
    assert errors == []


# A line of pytest -v for one case of run_against_broken.py.
_LINE = re.compile(
    r"::test_run_against_broken\[(dedicated|shared)-(\S+)\] "
    r"(PASSED|FAILED|SKIPPED|ERROR|XFAIL|XPASS)"
)


def test_run_fails_every_case() -> None:
    """run_case itself, as an adapter author applies it under pytest (the counterpart
    of Go's Run), not only evaluate_conformance, reports a failure for every case of
    each mode when the adapter is broken. run_against_broken.py runs in a pytest
    subprocess and its verbose output is read: one test per mode and case."""
    want = {m.name: sorted(evaluate(m)) for m in MODES}
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-v",
            "-p",
            "no:cacheprovider",
            "-o",
            "console_output_style=classic",
            str(RUN_AGAINST_BROKEN),
        ],
        cwd=PY_ROOT,
        env={**os.environ, "PACT_RUN_BROKEN": "1"},
        capture_output=True,
        text=True,
        check=False,
    )
    out = proc.stdout + proc.stderr
    assert proc.returncode != 0, f"run_case against the broken adapter succeeded:\n{out}"
    errors: list[str] = []
    failed: dict[str, set[str]] = {}
    for line in proc.stdout.splitlines():
        mt = _LINE.search(line)
        if mt is None:
            continue
        mode, cid, status = mt.groups()
        if status != "FAILED":
            errors.append(f"{mode}: case {cid} is reported {status}")
        failed.setdefault(mode, set()).add(cid)
    for name, ids in want.items():
        got = failed.get(name, set())
        errors.extend(
            f"{name}: run_case reports no failure for case {cid}" for cid in ids if cid not in got
        )
        if len(got) != len(ids):
            errors.append(f"{name}: run_case reported {len(got)} cases, the suite has {len(ids)}")
    assert errors == [], out if len(out) < 4000 else "\n".join(errors)
