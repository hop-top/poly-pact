"""The suite against an adapter that implements nothing, and the package's
imports.

Every common case the manifest registers loads, and a stub whose functions all
raise NotImplementedError fails every one of them in both workload modes:
the suite has no case that an adapter passes by doing nothing. The package
is published, so no module of it imports a test framework.
"""

from __future__ import annotations

import ast
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from hop_top_pact.adapter import adaptertest
from hop_top_pact.adapter.adaptertest import Env, Options, Subject, evaluate_conformance
from hop_top_pact.core import strictjson
from hop_top_pact.core.binding import RawRequest

PACKAGE = Path(adaptertest.__file__).parent
TEST_FRAMEWORKS = ("pytest", "_pytest", "unittest", "doctest", "hypothesis", "nose")


class StubAdapter:
    """An adapter whose every function is not implemented."""

    def __getattr__(self, name: str) -> Any:
        def stub(*args: Any) -> Any:
            raise NotImplementedError(name)

        return stub


def stub_factory(env: Env) -> Subject:
    return Subject(adapter=StubAdapter(), arrive=lambda r: r, credential=_credential)


def _credential(r: RawRequest, ref: str) -> RawRequest:
    return r


def registered_common_ids(at: Any) -> list[str]:
    data = (at.repo_fixtures() / "manifest.json").read_bytes()
    m: Any = strictjson.parse(data, strictjson.Limits(max_bytes=4 << 20, max_depth=8))
    assert isinstance(m, Mapping)
    return sorted(
        e["id"]
        for e in m["entries"]
        if e["kind"] == "adapter-case" and e["id"].startswith("adapters/_common/")
    )


def test_every_registered_common_case_loads(at: Any) -> None:
    registered = registered_common_ids(at)
    cases = at.common_cases()
    assert sorted("adapters/_common/" + c.id.lower() for c in cases) == registered
    assert len(cases) == len(registered)


def test_stub_adapter_fails_every_case(at: Any) -> None:
    fixtures = at.repo_fixtures()
    run: set[str] = set()
    for shared in (False, True):
        results = evaluate_conformance(
            stub_factory, Options(fixtures=fixtures, shared_workloads=shared)
        )
        passed = [r.id for r in results if r.passed()]
        assert not passed, f"the stub passes {passed} (shared workloads {shared})"
        run.update(r.id for r in results)
    assert sorted(run) == sorted(c.id for c in at.common_cases()), (
        "the two workload modes together run every common case"
    )


def test_the_suite_imports_no_test_framework() -> None:
    files = sorted(PACKAGE.glob("*.py"))
    assert files
    for f in files:
        tree = ast.parse(f.read_text(encoding="utf-8"), str(f))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module or ""]
            else:
                continue
            for name in names:
                top = name.split(".", 1)[0]
                assert top not in TEST_FRAMEWORKS, f"{f.name} imports {name}"
