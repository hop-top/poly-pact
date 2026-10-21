"""The entry points of the suite (Go adaptertest, suite.go).

Go's Run fails one subtest per case through the testing package. This package
imports no test framework, so Run is split in two: conformance_cases loads the
cases a run applies and checks the replacement declarations, and run_case
runs one of them and raises CaseFailure, an AssertionError, when the adapter
fails it. An adapter author applies pytest.mark.parametrize to the cases and
ids conformance_cases returns, or loops over them under unittest:

    cases, ids = conformance_cases(Options(adapter="mymechanism"))

    @pytest.mark.parametrize("case", cases, ids=ids)
    def test_conformance(case: Case) -> None:
        run_case(new_factory, case, Options(adapter="mymechanism"))

evaluate_conformance runs the same cases and returns their results instead of
raising: it is how a test proves that a deliberately broken adapter fails the
suite.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from importlib.resources.abc import Traversable
from pathlib import Path
from typing import Final, cast

from hop_top_pact.adapter.adaptertest import (
    checks_identity,
    checks_native,
    checks_operation,
    checks_record,
)
from hop_top_pact.adapter.adaptertest.casefile import (
    FN_AUTHENTICATE,
    FN_AUTHORIZE,
    FN_BINDING,
    FN_CHECK,
    FN_CLAIM,
    FN_MAP_OPERATION,
    FN_RECORD,
    Case,
    LoadError,
    accepted,
    applies_to,
    load_tree,
)
from hop_top_pact.adapter.adaptertest.compare import CaseRun, at, error_text
from hop_top_pact.adapter.adaptertest.harness import (
    Env,
    Factory,
    Hooks,
    Options,
    Replacement,
    Subject,
)
from hop_top_pact.core.clock import FakeClock
from hop_top_pact.errors import PactError

__all__ = [
    "DEFAULT_NOW",
    "CaseFailure",
    "Result",
    "conformance_cases",
    "default_fixtures",
    "evaluate_conformance",
    "run_case",
]

DEFAULT_NOW: Final = 1_792_080_000
"""The current time of a case that states none, in Unix seconds:
2026-10-15T16:00:00Z, the timestamp of the draft's worked example."""


@dataclass(frozen=True, slots=True, kw_only=True)
class Result:
    """The outcome of one case. failures lists every assertion the adapter failed,
    one line each; it is empty when the adapter passed the case."""

    id: str
    failures: tuple[str, ...] = ()

    def passed(self) -> bool:
        """Whether the adapter passed the case."""
        return not self.failures


class CaseFailure(PactError, AssertionError):
    """The adapter failed a case that run_case ran: failures are the failed
    assertions, one line each, and logs what run_case reports beside them."""

    def __init__(self, case_id: str, failures: Sequence[str], logs: Sequence[str] = ()) -> None:
        self.case_id = case_id
        self.failures = tuple(failures)
        self.logs = tuple(logs)
        super().__init__("\n".join([f"{case_id}:", *self.logs, *self.failures]))


def default_fixtures() -> Path:
    """The fixture tree of the source repository: the ../spec/v1.0/fixtures directory
    relative to the directory that holds pyproject.toml, found by walking up from
    the working directory. A package installed outside the source repository
    passes the v1.0/fixtures directory of the spec mirror in
    Options.fixtures instead. Raises LoadError when there is none."""
    wd = Path.cwd()
    for d in (wd, *wd.parents):
        if (d / "pyproject.toml").is_file():
            root = d.parent / "spec" / "v1.0" / "fixtures"
            if not root.is_dir():
                raise LoadError(
                    f"adaptertest: no fixture directory at {root}; set Options.fixtures to"
                    " the spec mirror's v1.0/fixtures"
                )
            return root
    raise LoadError(f"adaptertest: no pyproject.toml above {wd}; set Options.fixtures")


def _fixtures(o: Options) -> Traversable:
    return o.fixtures if o.fixtures is not None else default_fixtures()


def _applicable(cases: list[Case], o: Options) -> list[Case]:
    return [c for c in cases if applies_to(c, o.shared_workloads)]


def conformance_cases(options: Options | None = None) -> tuple[list[Case], list[str]]:
    """The common cases, and the adapter's own cases when options.adapter is set, of
    the workload mode of options.shared_workloads, with their ids: the
    arguments of pytest.mark.parametrize. It checks every declaration of
    options.replaced first: the id is a common authenticate_native or
    authorize_native case, by is a case of adapters/<adapter> for the same
    function with the same outcome class (accepted or rejected, as the fixture
    manifest classifies outcomes), and reason is not blank. Raises LoadError when
    the cases cannot be loaded or a declaration breaks a rule."""
    o = options if options is not None else Options()
    cases, common = load_tree(_fixtures(o), o.adapter)
    check_replaced(cases, common, o)
    run = _applicable(cases, o)
    return run, [c.id for c in run]


def run_case(factory: Factory, case: Case, options: Options | None = None) -> list[str]:
    """Run one case against a fresh adapter from factory. Raises CaseFailure when the
    adapter fails the case. A case that options.replaced declares replaced is
    expected to fail: run_case then returns the failures as log lines, with the
    replacement first, and raises CaseFailure when the case passes, since the
    declaration is no longer needed."""
    o = options if options is not None else Options()
    rep = o.replaced.get(case.id)
    errs, logs = verdict(case.id, case_failures(factory, case), rep)
    if errs:
        raise CaseFailure(case.id, errs, logs)
    return logs


def evaluate_conformance(factory: Factory, options: Options | None = None) -> list[Result]:
    """Run the same cases as conformance_cases and return their results. It ignores
    options.replaced and reports every case as run. Raises LoadError when the
    cases cannot be loaded."""
    o = options if options is not None else Options()
    cases, _ = load_tree(_fixtures(o), o.adapter)
    return [
        Result(id=c.id, failures=tuple(case_failures(factory, c))) for c in _applicable(cases, o)
    ]


def verdict(case_id: str, fails: list[str], rep: Replacement | None) -> tuple[list[str], list[str]]:
    """The errors and the log lines of a case. A case that is not replaced fails with
    its failures. A replaced case is expected to fail: its failures are logged,
    and a pass is the error, because the declaration is no longer needed."""
    if rep is None:
        return fails, []
    if not fails:
        return [f"{case_id} is declared replaced by {rep.by} but passes; drop the declaration"], []
    logs = [f"{case_id} is replaced by {rep.by} ({rep.reason}); it fails here as declared:"]
    return [], logs + fails


def check_replaced(cases: list[Case], common: frozenset[str], o: Options) -> None:
    """Check every declaration of o.replaced against the loaded cases, the common
    cases and the adapter's own cases of every workload mode."""
    by_id = {c.id: c for c in cases}
    for cid in sorted(o.replaced):
        rep = o.replaced[cid]
        orig = by_id.get(cid)
        if orig is None or cid not in common:
            raise LoadError(f"adaptertest: replaced: {cid} is not a common case")
        f = orig.expect.function
        if f not in (FN_AUTHENTICATE, FN_AUTHORIZE):
            raise LoadError(
                f"adaptertest: replaced: {cid} is a {f} case; only {FN_AUTHENTICATE} and"
                f" {FN_AUTHORIZE} cases may be replaced"
            )
        if not rep.reason.strip():
            raise LoadError(f"adaptertest: replaced: {cid} gives no reason")
        if not rep.by:
            raise LoadError(f"adaptertest: replaced: {cid} names no replacement case")
        by = by_id.get(rep.by)
        if by is None or rep.by in common:
            raise LoadError(
                f"adaptertest: replaced: {cid} is replaced by {rep.by}, which is not a case"
                f" of adapters/{o.adapter}"
            )
        if by.expect.function != f:
            raise LoadError(
                f"adaptertest: replaced: {cid} is a {f} case, but its replacement {rep.by}"
                f" is a {by.expect.function} case"
            )
        if accepted(by.expect.outcome) != accepted(orig.expect.outcome):
            raise LoadError(
                f"adaptertest: replaced: {cid} expects {orig.expect.outcome}, but its"
                f" replacement {rep.by} expects {by.expect.outcome}, of the other outcome"
                " class"
            )


_RUNNERS: Final = {
    FN_AUTHENTICATE: checks_identity.authenticate,
    FN_BINDING: checks_identity.binding,
    FN_MAP_OPERATION: checks_operation.map_operation,
    FN_CLAIM: checks_native.claim,
    FN_CHECK: checks_native.check,
    FN_AUTHORIZE: checks_native.authorize,
    FN_RECORD: checks_record.record,
}


def case_failures(factory: Factory, case: Case) -> list[str]:
    """Run one case against a fresh adapter and return its failures (Go's runCase)."""
    now = at(DEFAULT_NOW if case.now is None else case.now)
    r = CaseRun(case, now, Hooks())
    env = Env(state=case.native_state, clock=FakeClock(now), hooks=r.hooks)
    try:
        subj: object = factory(env)
    except PactError as e:
        r.fail(f"factory: {error_text(e)}")
        return r.fails
    except Exception as e:
        r.fail(f"factory raised {type(e).__name__}: {error_text(e)}")
        return r.fails
    if not isinstance(subj, Subject):
        r.fail(f"factory returned {type(subj).__name__}, want a Subject")
        return r.fails
    if cast(object, subj.adapter) is None:
        r.fail("factory returned no adapter")
        return r.fails
    if not callable(cast(object, subj.arrive)):
        r.fail(
            "factory returned no arrive hook: the suite cannot tell a request through the"
            " enforcement point from a bypass"
        )
        return r.fails
    r.subject = subj

    runner = _RUNNERS.get(case.expect.function)
    if runner is not None:
        runner(r)

    fired = r.hooks.fired()
    for name in case.expect.must_not_call:
        if name in fired:
            r.fail(f"hook {name!r} fired; it must not (fired: {fired})")
    return r.fails
