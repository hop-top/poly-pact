"""The shared manifest case table, tools/spec/manifest-parity-cases.json, against
runner.manifest (tools/spec/README.md, Manifest parity cases).

Each case's mutation is applied to a scratch copy of the spec tree by
scripts/paritycases.py, the applier of the table that
scripts/check-manifest-parity.py uses, and check must report the case's rule
(or nothing, for a control), never a rule of its forbid list, and never the
rule of a gap case. The copy is put back between cases. The table, the
applier and the Go rule list sit outside the package: where one is absent (a
mirror checkout, the copy make py-mutants tests) the tests are skipped.
"""

from __future__ import annotations

import functools
import importlib.util
import os
import re
import shutil
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from hop_top_pact.runner import manifest

REPO = Path(__file__).resolve().parents[2]
SPEC = REPO / "spec" / "v1.0"
CASES_FILE = REPO / "tools" / "spec" / "manifest-parity-cases.json"
APPLIER = REPO / "scripts" / "paritycases.py"
GO_RULES = REPO / "go" / "runner" / "manifest" / "problem.go"

# The rule ids of the module: the values of its RULE_* names.
RULES = sorted(getattr(manifest, n) for n in dir(manifest) if n.startswith("RULE_"))


def absent() -> str:
    """Why the table cannot run here, or ""."""
    for path in (CASES_FILE, APPLIER, SPEC / "fixtures" / "manifest.json"):
        if not path.exists():
            return f"{path.relative_to(REPO)} absent"
    return ""


@functools.cache
def _applier() -> ModuleType:
    spec = importlib.util.spec_from_file_location("paritycases", APPLIER)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def applier() -> ModuleType:
    """scripts/paritycases.py, loaded by path as the check scripts load it."""
    if why := absent():
        pytest.skip(why)
    return _applier()


def cases() -> list[dict[str, Any]]:
    loaded: list[dict[str, Any]] = applier().load(str(CASES_FILE), "manifest-parity-cases.json")
    return loaded


def test_rules_are_those_of_go() -> None:
    if not GO_RULES.exists():
        pytest.skip(f"{GO_RULES.relative_to(REPO)} absent")
    src = GO_RULES.read_text(encoding="utf-8")
    go = re.findall(r'^\s*Rule\w+\s*=\s*"([a-z][a-z-]*)"', src, re.MULTILINE)
    assert len(go) == 30
    assert sorted(go) == RULES


def test_every_rule_has_a_case() -> None:
    table = cases()
    named = {c["rule"] for c in table if c["rule"] is not None}
    assert sorted(named - set(RULES)) == [], "cases name unknown rules"
    covered = {c["rule"] for c in table if c["rule"] is not None and not c["gap"]}
    assert sorted(set(RULES) - covered) == [], "rules without a case"
    assert any(c["rule"] is None for c in table), "no control case"


class Copy:
    """One scratch copy of spec/v1.0/fixtures, spec-map.md and draft.md, put back between cases."""

    def __init__(self, dst: Path) -> None:
        self.root = dst
        self.fixtures = dst / "spec" / "v1.0" / "fixtures"
        self.map_path = dst / "spec" / "v1.0" / "spec-map.md"
        shutil.copytree(SPEC / "fixtures", self.fixtures, symlinks=True)
        for name in ("spec-map.md", "draft.md"):
            shutil.copy2(SPEC / name, dst / "spec" / "v1.0" / name)
        self.saved = {
            p: p.read_bytes() for p in (self.fixtures / manifest.FILE_NAME, self.map_path)
        }
        self.files, self.dirs = self.listing()

    def listing(self) -> tuple[dict[str, tuple[int, bool]], set[str]]:
        """Every non-directory with its inode and link flag, and every directory. A step
        writes only new files (and manifest.json and spec-map.md, which restore rewrites),
        so a file a step replaced has another inode."""
        files: dict[str, tuple[int, bool]] = {}
        dirs: set[str] = set()
        stack = [str(self.fixtures)]
        cut = len(str(self.fixtures)) + 1
        while stack:
            with os.scandir(stack.pop()) as it:
                for e in it:
                    rel = e.path[cut:].replace(os.sep, "/")
                    if e.is_dir(follow_symlinks=False):
                        dirs.add(rel)
                        stack.append(e.path)
                    else:
                        files[rel] = (e.inode(), e.is_symlink())
        return files, dirs

    def restore(self) -> None:
        files, dirs = self.listing()
        changed = {rel for rel, key in files.items() if self.files.get(rel) != key}
        for rel in changed:
            os.unlink(self.fixtures / rel)
        for rel in sorted(dirs - self.dirs, key=len, reverse=True):
            os.rmdir(self.fixtures / rel)
        for rel in self.files.keys() - (files.keys() - changed):
            dst = self.fixtures / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(SPEC / "fixtures" / rel, dst, follow_symlinks=False)
            st = os.lstat(dst)
            self.files[rel] = (st.st_ino, os.path.islink(dst))
        for p, data in self.saved.items():
            p.write_bytes(data)


@pytest.fixture(scope="module")
def copy(tmp_path_factory: pytest.TempPathFactory) -> Copy:
    applier()
    return Copy(tmp_path_factory.mktemp("parity"))


def check(c: Copy) -> manifest.Problems:
    return manifest.check(c.fixtures, c.map_path)


def test_unmodified_copy_is_clean(copy: Copy) -> None:
    ps = check(copy)
    assert not ps, str(ps)


def case_params() -> list[Any]:
    if why := absent():
        return [pytest.param(None, id="(table absent)", marks=pytest.mark.skip(reason=why))]
    out = []
    for c in cases():
        links = any(s["op"] == "symlink" for s in c["mutation"])
        marks = (
            [pytest.mark.skip(reason="symbolic links need privileges on windows")]
            if links and sys.platform == "win32"
            else []
        )
        out.append(pytest.param(c, id=f"{c['rule'] or '(control)'} {c['name']}", marks=marks))
    return out


@pytest.mark.parametrize("case", case_params())
def test_case_yields_its_rule(copy: Copy, case: dict[str, Any] | None) -> None:
    """Every case of the shared table yields its expected rule."""
    assert case is not None
    applier().Copy(str(copy.root)).apply(case["mutation"])
    try:
        ps = check(copy)
    finally:
        copy.restore()
    found = {p.rule for p in ps}
    rule = case["rule"]
    if rule is None:
        assert not ps, f"the control fails:\n{ps}"
    elif case["gap"]:
        assert rule not in found, f"reports [{rule}] now: remove the gap mark"
    else:
        assert rule in found, f"does not report [{rule}]; got:\n{ps}"
    for f in case["forbid"]:
        assert f not in found, f"reports [{f}], which this copy must not trigger"


def test_restored_copy_is_clean(copy: Copy) -> None:
    ps = check(copy)
    assert not ps, str(ps)
