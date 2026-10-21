"""Dependency guard: the counterpart of Go's internal/depcheck.

Reads pyproject.toml with tomllib and walks the imports of src/, tests/,
examples/ and scripts/ with ast. The sets below are the vetted ones of
docs/sdk/deps-py.md in the source repository; a change here is a change of
that file first.
"""

from __future__ import annotations

import ast
import re
import shutil
import sys
import tomllib
from pathlib import Path

PY_ROOT = Path(__file__).resolve().parents[1]
PACKAGE = "hop_top_pact"

RUNTIME = frozenset({"cryptography", "jsonschema", "referencing"})
DEV = frozenset({"build", "mypy", "pytest", "rfc8785", "ruff"})
BUILD = frozenset({"flit-core"})
BUILD_BACKEND = "flit_core.buildapi"
# Import names per tree, on top of the standard library.
SRC_IMPORTS = RUNTIME | {PACKAGE}
# broken is the test tree's own package (tests/broken), not a dependency.
TEST_IMPORTS = SRC_IMPORTS | {"pytest", "rfc8785", "broken"}
EXAMPLE_IMPORTS = SRC_IMPORTS
SCRIPT_IMPORTS: frozenset[str] = frozenset()

STDLIB = frozenset(sys.stdlib_module_names)
NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")


def normalize(name: str) -> str:
    """PEP 503 normalized distribution name."""
    return re.sub(r"[-_.]+", "-", name).lower()


def requirement_names(reqs: list[str]) -> set[str]:
    names = set()
    for r in reqs:
        m = NAME.match(r)
        if m is None:
            raise ValueError(f"unparsable requirement {r!r}")
        names.add(normalize(m.group(1)))
    return names


def imported_modules(path: Path) -> list[tuple[str, int]]:
    """Absolute imports of one file, as (dotted module, line)."""
    tree = ast.parse(path.read_bytes(), filename=str(path))
    out: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            out.extend((a.name, node.lineno) for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            out.append((node.module, node.lineno))
    return out


def import_problems(root: Path, tree: str, allowed: frozenset[str]) -> list[str]:
    problems: list[str] = []
    base = root / tree
    if not base.is_dir():
        return problems
    for path in sorted(base.rglob("*.py")):
        rel = path.relative_to(root).as_posix()
        for module, line in imported_modules(path):
            top = module.split(".")[0]
            if top in STDLIB:
                continue
            if top not in allowed:
                problems.append(f"{rel}:{line}: import of {module!r} outside the vetted set")
            elif top != PACKAGE and any(p.startswith("_") for p in module.split(".")[1:]):
                problems.append(f"{rel}:{line}: import of the private module {module!r}")
    return problems


def problems(root: Path) -> list[str]:
    """Every dependency-rule violation under root (a copy of py/)."""
    meta = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    out = []
    runtime = requirement_names(meta["project"].get("dependencies", []))
    if runtime != RUNTIME:
        out.append(f"runtime dependencies {sorted(runtime)} != vetted {sorted(RUNTIME)}")
    extras = meta["project"].get("optional-dependencies", {})
    if set(extras) != {"dev"}:
        out.append(f"optional dependency groups {sorted(extras)} != ['dev']")
    dev = requirement_names(extras.get("dev", []))
    if dev != DEV:
        out.append(f"dev dependencies {sorted(dev)} != vetted {sorted(DEV)}")
    system = meta.get("build-system", {})
    build = requirement_names(system.get("requires", []))
    if not build <= BUILD:
        out.append(f"build-system requires {sorted(build - BUILD)} outside {sorted(BUILD)}")
    if system.get("build-backend") != BUILD_BACKEND:
        out.append(f"build-backend {system.get('build-backend')!r} != {BUILD_BACKEND!r}")
    out += import_problems(root, "src", SRC_IMPORTS)
    out += import_problems(root, "tests", TEST_IMPORTS)
    out += import_problems(root, "examples", EXAMPLE_IMPORTS)
    out += import_problems(root, "scripts", SCRIPT_IMPORTS)
    return out


def test_package_dependencies_are_vetted() -> None:
    assert problems(PY_ROOT) == []


def copy_tree(dst: Path) -> Path:
    root = dst / "py"
    root.mkdir()
    shutil.copy2(PY_ROOT / "pyproject.toml", root / "pyproject.toml")
    for tree in ("src", "tests", "scripts"):
        shutil.copytree(PY_ROOT / tree, root / tree, ignore=shutil.ignore_patterns("__pycache__"))
    return root


def test_guard_negative_control(tmp_path: Path) -> None:
    root = copy_tree(tmp_path)
    assert problems(root) == [], "an unmodified copy must pass"

    meta = root / "pyproject.toml"
    text = meta.read_text(encoding="utf-8")
    text = text.replace("dependencies = [\n", 'dependencies = [\n    "requests>=2,<3",\n', 1)
    text = text.replace('requires = ["flit_core==4.1.0"]', 'requires = ["hatchling==1.27.0"]')
    meta.write_text(text, encoding="utf-8")
    (root / "src" / PACKAGE / "bad.py").write_text(
        "import requests\nfrom referencing._core import Resource\nimport attrs\n",
        encoding="utf-8",
    )
    (root / "tests" / "bad.py").write_text("import hypothesis\n", encoding="utf-8")
    (root / "examples").mkdir()
    (root / "examples" / "bad.py").write_text("import pytest\n", encoding="utf-8")
    (root / "scripts" / "bad.py").write_text("import jsonschema\n", encoding="utf-8")

    found = "\n".join(problems(root))
    for needle in (
        "runtime dependencies",
        "build-system requires ['hatchling']",
        "src/hop_top_pact/bad.py:1: import of 'requests'",
        "src/hop_top_pact/bad.py:2: import of the private module 'referencing._core'",
        "src/hop_top_pact/bad.py:3: import of 'attrs'",
        "tests/bad.py:1: import of 'hypothesis'",
        "examples/bad.py:1: import of 'pytest'",
        "scripts/bad.py:1: import of 'jsonschema'",
    ):
        assert needle in found, f"guard missed: {needle}\n{found}"
