#!/usr/bin/env python3
"""Run committed mutation patches against a package's tests.

Mutation checks of the SDK packages (tools/parity/README.md, Mutation checks)
are committed patches, for example ts/test/mutants/<module>-<name>.patch and
py/tests/mutants/<module>-<name>.patch. Each patch must make the package's
test command fail.

For every *.patch file of the patch directory, in name order, the runner
builds a fresh copy in a new temporary directory, at the same relative paths
as in the repository:

- the package directory (--package) and every --copy tree are copied, without
  installed dependencies, caches and build outputs (.venv, node_modules,
  __pycache__, .pytest_cache, .mypy_cache, .ruff_cache, dist, build,
  *.egg-info, target) and without the --link entries;
- every --link NAME, an entry of the package directory such as node_modules,
  is symlinked into the copied package instead of copied;
- every --with PATH, a repository path such as spec, is symlinked into the
  copy instead of copied.

It then applies the patch with `git apply` and runs the test command from the
copy's package directory, and requires a non-zero exit status. A patch whose
tests still pass survives, and the run fails naming it. The unpatched copy
runs first and must pass, so a red run means the patch, not the setup. The
source tree is never modified.

Patch paths are relative to the repository root, as `git diff` writes them
(--patch-paths repo, the default), or relative to the package directory, as
`git diff --relative` writes them from inside it (--patch-paths package). A
patch may change only copied files; git apply refuses a path beyond a
symbolic link, so a --with or --link target is never written.

Usage, from the repository root:

  python3 -I tools/mutants.py --package DIR --patches DIR
      [--copy PATH]... [--with PATH]... [--link NAME]...
      [--patch-paths repo|package] [-q] -- COMMAND [ARG]...

The command's output goes to standard error; with -q it is kept and shown
only when the unpatched copy fails. Anything the command needs to see the
copy instead of an installed package (for example PYTHONPATH=src) belongs in
the command. An empty patch directory prints a NOTICE on standard error and
succeeds.

Standard library only (Python 3.9 and later); run it with python3 -I. Exit
status: 0 when every patch is killed (or there is none), 1 when a patch
survives or the unpatched copy fails, 2 on a usage or setup error (a missing
directory or path, a patch that does not apply).
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
IGNORED = (
    ".venv",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "dist",
    "build",
    "*.egg-info",
    "target",
)


class SetupError(Exception):
    pass


def make_copy(dest: Path, package: str, copies: list[str], withs: list[str], links: list[str]) -> Path:
    """Build one copy under dest and return its package directory."""
    for tree in [package, *[t for t in copies if t != package]]:
        src = ROOT / tree
        if not src.is_dir():
            raise SetupError(f"{tree}: not a directory under {ROOT}")
        extra = links if tree == package else []
        shutil.copytree(src, dest / tree, ignore=shutil.ignore_patterns(*IGNORED, *extra), symlinks=True)
    pkg = dest / package
    for name in links:
        target = ROOT / package / name
        if target.exists() or target.is_symlink():
            (pkg / name).symlink_to(target)
    for path in withs:
        target = ROOT / path
        if not (target.exists() or target.is_symlink()):
            raise SetupError(f"--with {path}: no such path under {ROOT}")
        link = dest / path
        link.parent.mkdir(parents=True, exist_ok=True)
        link.symlink_to(target)
    return pkg


def run(cmd: list[str], cwd: Path, quiet: bool) -> tuple[int, str]:
    print(f"mutants: running {' '.join(cmd)} in {cwd}", file=sys.stderr)
    if not quiet:
        sys.stderr.flush()
        return subprocess.run(cmd, cwd=cwd, check=False, stdout=sys.stderr).returncode, ""
    proc = subprocess.run(cmd, cwd=cwd, check=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return proc.returncode, proc.stdout.decode("utf-8", "replace")


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="mutants.py", description="Require every mutation patch to fail the tests.")
    ap.add_argument("--package", required=True, help="package directory, relative to the repository root (py, ts)")
    ap.add_argument("--patches", required=True, help="directory of *.patch files, relative to the repository root")
    ap.add_argument("--copy", action="append", default=[], metavar="PATH", help="extra tree to copy (repeatable)")
    ap.add_argument("--with", dest="withs", action="append", default=[], metavar="PATH", help="repository path to symlink into the copy (repeatable)")
    ap.add_argument("--link", action="append", default=[], metavar="NAME", help="package entry to symlink, not copy (repeatable)")
    ap.add_argument("--patch-paths", choices=("repo", "package"), default="repo", help="what patch paths are relative to")
    ap.add_argument("-q", "--quiet", action="store_true", help="show the command output only when the unpatched copy fails")
    ap.add_argument("command", nargs=argparse.REMAINDER, help="test command, after --")
    args = ap.parse_args(argv)
    cmd = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not cmd:
        ap.error("no test command after --")
    for name in args.link:
        if "/" in name or name in ("", ".", ".."):
            ap.error(f"--link takes an entry name of the package directory: {name!r}")
    patch_dir = ROOT / args.patches
    if not patch_dir.is_dir():
        print(f"mutants: {args.patches}: not a directory", file=sys.stderr)
        return 2
    patches = sorted(patch_dir.glob("*.patch"))
    if not patches:
        print(f"NOTICE: mutants: no patches in {args.patches}", file=sys.stderr)
        return 0

    def copy(dest: Path) -> Path:
        return make_copy(dest, args.package, args.copy, args.withs, args.link)

    survived: list[str] = []
    try:
        with tempfile.TemporaryDirectory(prefix="mutants-") as tmp:
            base = Path(tmp) / "base"
            status, out = run(cmd, copy(base), args.quiet)
            if status != 0:
                sys.stderr.write(out)
                print(f"mutants: the unpatched copy fails its tests (exit {status})", file=sys.stderr)
                return 1
            shutil.rmtree(base)
            for patch in patches:
                work = Path(tmp) / patch.stem
                pkg = copy(work)
                applied = subprocess.run(
                    ["git", "apply", "--whitespace=nowarn", str(patch)],
                    cwd=pkg if args.patch_paths == "package" else work,
                    check=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                )
                if applied.returncode != 0:
                    detail = applied.stdout.decode("utf-8", "replace").strip()
                    raise SetupError(f"{patch.name}: does not apply: {detail}")
                status, _ = run(cmd, pkg, args.quiet)
                verdict = "killed" if status != 0 else "SURVIVED"
                print(f"mutants: {patch.name}: {verdict} (exit {status})", file=sys.stderr)
                if status == 0:
                    survived.append(patch.name)
                shutil.rmtree(work)
    except SetupError as e:
        print(f"mutants: {e}", file=sys.stderr)
        return 2
    if survived:
        print(f"mutants: {len(survived)} of {len(patches)} survived: {', '.join(survived)}", file=sys.stderr)
        return 1
    print(f"mutants: all {len(patches)} killed", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
